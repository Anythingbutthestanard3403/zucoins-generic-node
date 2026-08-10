// Node-origin admin sessions for the /admin/v1/* operator surface.
//
// The node keeps its own admin auth: session policy is 8 h absolute / 30 m idle.
//
// Session id is an opaque 32-byte base64url CSPRNG token. It lives ONLY in a
// `__Host-` HttpOnly Secure SameSite=Strict cookie — never in a
// response body a platform page could read cross-origin. CSRF is a
// second independent 32-byte token bound to the same row and returned in the
// body so the SPA can echo it via X-CSRF-Token.
//
// CSRF origin enforcement and TOTP mutation burn are scope; this module
// only issues/validates the session substrate those gates compose on top of.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { TotpOpenError } from "../totp/seal.js";

// --- Constants ---

/** Absolute session cap fixed at create time; never extended (admin lockout model). */
export const ADMIN_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

/** Sliding idle timeout independent of the absolute cap. */
export const ADMIN_SESSION_IDLE_MS = 30 * 60 * 1000;

/**
 * `__Host-` prefix forces Secure + Path=/ + no Domain at the browser — host-scoped
 * to exactly this origin. Local plain-HTTP dev cannot store it; that is a
 * documented dev caveat, never relaxed in prod.
 */
export const ADMIN_SESSION_COOKIE = "__Host-zp_admin_session";

const TOKEN_BYTES = 32;

// --- Types ---

export interface AdminSession {
  readonly sessionId: string;
  readonly userId: string;
  readonly nodeId: string;
  readonly csrfToken: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly lastSeenAt: number;
  readonly ip: string | null;
  readonly userAgent: string | null;
}

export interface AdminUser {
  readonly id: string;
  readonly username: string;
  readonly passwordHash: string;
  readonly role: "admin" | "viewer";
  readonly mustChangePassword: boolean;
  readonly mustEnrolTotp: boolean;
  readonly disabledAt: number | null;
  readonly createdAt: number;
}

export interface AdminSessionConfig {
  readonly nodeId: string;
  readonly ttlMs?: number;
  readonly idleMs?: number;
  readonly now?: () => number;
}

export type SessionRejectionReason =
  | "missing_cookie"
  | "unknown_session"
  | "expired"
  | "idle"
  | "revoked"
  | "node_mismatch"
  | "user_disabled"
  | "user_missing";

export type SessionValidationResult =
  | { readonly ok: true; readonly session: AdminSession; readonly user: AdminUser }
  | { readonly ok: false; readonly reason: SessionRejectionReason };

// --- Store ports ---

export interface AdminSessionStore {
  save(session: AdminSession): Promise<void>;
  find(sessionId: string): Promise<AdminSession | null>;
  /** Touch last_seen_at so the idle window slides. */
  touch(sessionId: string, lastSeenAt: number): Promise<void>;
  revoke(sessionId: string): Promise<void>;
  isRevoked(sessionId: string): Promise<boolean>;
  /** Revoke every OTHER live session for userId (password / privilege change). */
  revokeOtherForUser(userId: string, keepSessionId: string): Promise<number>;
  /** Revoke every live session for userId (TOTP re-enrolment rotation). */
  revokeAllForUser(userId: string): Promise<number>;
}

/**
 * Operator TOTP factor state. Base32 secret is held only in the store — never
 * serialized on AdminUser public responses. Sealed-at-rest (operator surface) is deferred
 * for v2 PG adapter (sealed-store registry DEFERRED_NO_SEAL_RUNTIME).
 */
export type AdminTotpFactorState =
  | { readonly status: "none" }
  | { readonly status: "pending"; readonly secretBase32: string }
  | { readonly status: "active"; readonly secretBase32: string };

export interface AdminUserStore {
  findById(id: string): Promise<AdminUser | null>;
  findByUsername(username: string): Promise<AdminUser | null>;
  /** Returns true when at least one admin row exists. */
  anyExists(): Promise<boolean>;
  insert(user: AdminUser): Promise<void>;
  updatePassword(
    id: string,
    passwordHash: string,
    mustChangePassword: boolean,
  ): Promise<void>;
  /** Mark TOTP enrolled (mustEnrolTotp → false). Used by rotation tests. */
  setMustEnrolTotp(id: string, mustEnrolTotp: boolean): Promise<void>;
  /** Disable / re-enable an operator (null = active). */
  setDisabledAt(id: string, disabledAt: number | null): Promise<void>;
  count(): Promise<number>;
  /** Pending or active base32 factor; never logs the secret. */
  getTotpFactor(id: string): Promise<AdminTotpFactorState>;
  /**
   * Store a pending enrolment secret without clearing mustEnrolTotp.
   * Overwrites a prior pending; refuses if already active (rotation is separate).
   */
  setPendingTotpSecret(id: string, secretBase32: string): Promise<"ok" | "already_active" | "missing">;
  /**
   * Activate the pending secret and clear mustEnrolTotp. Refuses with no_pending when absent.
   */
  activateTotpEnrolment(id: string): Promise<"ok" | "no_pending" | "missing">;
  /**
   * Lab / test shortcut: write an already-active factor and clear mustEnrolTotp.
   * Production public path uses enrol → confirm instead.
   */
  setActiveTotpSecret(id: string, secretBase32: string): Promise<"ok" | "missing">;
}

// --- In-memory stores (unit tests + Layer-1) ---

/** Durable snapshot of an in-memory session store — restart / rehydrate tests. */
export interface AdminSessionStoreSnapshot {
  readonly sessions: readonly AdminSession[];
  readonly revoked: readonly string[];
}

export class InMemoryAdminSessionStore implements AdminSessionStore {
  private readonly sessions = new Map<string, AdminSession>();
  private readonly revoked = new Set<string>();

  async save(session: AdminSession): Promise<void> {
    this.sessions.set(session.sessionId, session);
  }

  async find(sessionId: string): Promise<AdminSession | null> {
    return this.sessions.get(sessionId) ?? null;
  }

  async touch(sessionId: string, lastSeenAt: number): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (existing === undefined) return;
    this.sessions.set(sessionId, { ...existing, lastSeenAt });
  }

  async revoke(sessionId: string): Promise<void> {
    this.revoked.add(sessionId);
    this.sessions.delete(sessionId);
  }

  async isRevoked(sessionId: string): Promise<boolean> {
    return this.revoked.has(sessionId);
  }

  async revokeOtherForUser(userId: string, keepSessionId: string): Promise<number> {
    let n = 0;
    for (const [id, s] of this.sessions) {
      if (s.userId === userId && id !== keepSessionId) {
        this.revoked.add(id);
        this.sessions.delete(id);
        n += 1;
      }
    }
    return n;
  }

  async revokeAllForUser(userId: string): Promise<number> {
    let n = 0;
    for (const [id, s] of this.sessions) {
      if (s.userId === userId) {
        this.revoked.add(id);
        this.sessions.delete(id);
        n += 1;
      }
    }
    return n;
  }

  /**
   * Export durable state for a process-restart simulation. Production PG
   * adapters persist the same rows; Layer-1 tests rehydrate via `hydrate`.
   */
  snapshot(): AdminSessionStoreSnapshot {
    return {
      sessions: [...this.sessions.values()].map((s) => ({ ...s })),
      revoked: [...this.revoked],
    };
  }

  /** Replace in-memory state from a prior snapshot (boot reconciliation). */
  hydrate(snap: AdminSessionStoreSnapshot): void {
    this.sessions.clear();
    this.revoked.clear();
    for (const s of snap.sessions) {
      this.sessions.set(s.sessionId, { ...s });
    }
    for (const id of snap.revoked) {
      this.revoked.add(id);
    }
  }
}

/** Durable snapshot of operator rows + TOTP factors (restart / rehydrate). */
export interface AdminUserStoreSnapshot {
  readonly users: readonly AdminUser[];
  readonly factors: ReadonlyArray<{
    readonly userId: string;
    readonly factor: AdminTotpFactorState;
  }>;
}

export class InMemoryAdminUserStore implements AdminUserStore {
  private readonly byId = new Map<string, AdminUser>();
  private readonly byUsername = new Map<string, string>();
  private readonly totpById = new Map<string, AdminTotpFactorState>();

  async findById(id: string): Promise<AdminUser | null> {
    return this.byId.get(id) ?? null;
  }

  async findByUsername(username: string): Promise<AdminUser | null> {
    const id = this.byUsername.get(username);
    if (id === undefined) return null;
    return this.byId.get(id) ?? null;
  }

  async anyExists(): Promise<boolean> {
    return this.byId.size > 0;
  }

  async insert(user: AdminUser): Promise<void> {
    if (this.byUsername.has(user.username)) {
      throw new Error(`admin username already exists: ${user.username}`);
    }
    this.byId.set(user.id, user);
    this.byUsername.set(user.username, user.id);
    this.totpById.set(user.id, { status: "none" });
  }

  async updatePassword(
    id: string,
    passwordHash: string,
    mustChangePassword: boolean,
  ): Promise<void> {
    const existing = this.byId.get(id);
    if (existing === undefined) throw new Error(`admin user missing: ${id}`);
    this.byId.set(id, { ...existing, passwordHash, mustChangePassword });
  }

  async setMustEnrolTotp(id: string, mustEnrolTotp: boolean): Promise<void> {
    const existing = this.byId.get(id);
    if (existing === undefined) throw new Error(`admin user missing: ${id}`);
    this.byId.set(id, { ...existing, mustEnrolTotp });
  }

  async setDisabledAt(id: string, disabledAt: number | null): Promise<void> {
    const existing = this.byId.get(id);
    if (existing === undefined) throw new Error(`admin user missing: ${id}`);
    this.byId.set(id, { ...existing, disabledAt });
  }

  async count(): Promise<number> {
    return this.byId.size;
  }

  async getTotpFactor(id: string): Promise<AdminTotpFactorState> {
    return this.totpById.get(id) ?? { status: "none" };
  }

  async setPendingTotpSecret(
    id: string,
    secretBase32: string,
  ): Promise<"ok" | "already_active" | "missing"> {
    if (!this.byId.has(id)) return "missing";
    const cur = this.totpById.get(id) ?? { status: "none" as const };
    if (cur.status === "active") return "already_active";
    this.totpById.set(id, { status: "pending", secretBase32 });
    return "ok";
  }

  async activateTotpEnrolment(id: string): Promise<"ok" | "no_pending" | "missing"> {
    const existing = this.byId.get(id);
    if (existing === undefined) return "missing";
    const cur = this.totpById.get(id);
    if (cur === undefined || cur.status !== "pending") return "no_pending";
    this.totpById.set(id, { status: "active", secretBase32: cur.secretBase32 });
    this.byId.set(id, { ...existing, mustEnrolTotp: false });
    return "ok";
  }

  async setActiveTotpSecret(id: string, secretBase32: string): Promise<"ok" | "missing"> {
    const existing = this.byId.get(id);
    if (existing === undefined) return "missing";
    this.totpById.set(id, { status: "active", secretBase32 });
    this.byId.set(id, { ...existing, mustEnrolTotp: false });
    return "ok";
  }

  /**
   * Export durable operator + factor state for a process-restart simulation.
   * Production SQL adapters persist the same fields.
   */
  snapshot(): AdminUserStoreSnapshot {
    const factors: Array<{ userId: string; factor: AdminTotpFactorState }> = [];
    for (const [userId, factor] of this.totpById) {
      factors.push({ userId, factor: { ...factor } as AdminTotpFactorState });
    }
    return {
      users: [...this.byId.values()].map((u) => ({ ...u })),
      factors,
    };
  }

  /** Replace in-memory state from a prior snapshot (boot reconciliation). */
  hydrate(snap: AdminUserStoreSnapshot): void {
    this.byId.clear();
    this.byUsername.clear();
    this.totpById.clear();
    for (const u of snap.users) {
      this.byId.set(u.id, { ...u });
      this.byUsername.set(u.username, u.id);
    }
    for (const { userId, factor } of snap.factors) {
      this.totpById.set(userId, { ...factor } as AdminTotpFactorState);
    }
  }
}

// --- Token helpers ---

function newToken(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

export function newAdminUserId(): string {
  // uuid-shaped opaque id — no DB dependency; durable stores may replace.
  const b = randomBytes(16);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = Buffer.from(b).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Constant-time string compare via fixed-length SHA-256 digests. */
export function safeEqual(a: string, b: string): boolean {
  const da = createHash("sha256").update(a).digest();
  const db = createHash("sha256").update(b).digest();
  return timingSafeEqual(da, db);
}

// --- Cookie serialization (framework-free) ---

export interface SessionCookieOptions {
  readonly expiresAt: number;
  /** When true, emit Max-Age=0 + empty value (logout). */
  readonly clear?: boolean;
}

/**
 * Build the Set-Cookie header value for the admin session.
 * Attributes are independently checkable:
 * Secure, HttpOnly, SameSite=Strict, Path=/, no Domain (host-scoped via __Host-).
 */
export function buildSessionSetCookie(
  sessionId: string,
  options: SessionCookieOptions,
): string {
  if (options.clear === true) {
    return [
      `${ADMIN_SESSION_COOKIE}=`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Strict",
      "Max-Age=0",
    ].join("; ");
  }

  const expires = new Date(options.expiresAt).toUTCString();
  return [
    `${ADMIN_SESSION_COOKIE}=${sessionId}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Expires=${expires}`,
  ].join("; ");
}

/** Assert cookie attributes match the frozen policy. Throws on any violation. */
export function assertSecureSessionCookie(setCookie: string): void {
  if (!setCookie.startsWith(`${ADMIN_SESSION_COOKIE}=`)) {
    throw new Error("session cookie name must be __Host-prefixed");
  }
  if (!/HttpOnly/i.test(setCookie)) throw new Error("session cookie missing HttpOnly");
  if (!/Secure/i.test(setCookie)) throw new Error("session cookie missing Secure");
  if (!/SameSite=Strict/i.test(setCookie)) {
    throw new Error("session cookie missing SameSite=Strict");
  }
  if (!/Path=\//i.test(setCookie)) throw new Error("session cookie missing Path=/");
  // Host-scoped: __Host- forbids Domain=; reject any Domain attribute.
  if (/;\s*Domain=/i.test(setCookie)) {
    throw new Error("session cookie must not set Domain (host-scoped)");
  }
}

/**
 * Extract the admin session id from a Cookie header. Returns null when absent.
 * Does NOT accept Authorization: Bearer — session tokens are cookie-only so a
 * platform page cannot exfiltrate them via a body/header the SPA would otherwise
 * store in JS-reachable state.
 */
export function extractSessionIdFromCookie(cookieHeader: string | undefined): string | null {
  if (cookieHeader === undefined || cookieHeader === "") return null;
  const re = new RegExp(`(?:^|;\\s*)${ADMIN_SESSION_COOKIE}=([^;]+)`);
  const match = re.exec(cookieHeader);
  if (match === null || match[1] === undefined || match[1].length === 0) return null;
  return match[1];
}

// --- Session service ---

export interface CreateSessionInput {
  readonly userId: string;
  readonly ip?: string | null;
  readonly userAgent?: string | null;
}

export interface CreatedSession {
  readonly session: AdminSession;
  /** Set-Cookie header value — the ONLY place the session id is delivered. */
  readonly setCookie: string;
}

export interface AdminSessionService {
  createSession(input: CreateSessionInput): Promise<CreatedSession>;
  /**
   * Validate the cookie-bound session id, load the operator, slide idle.
   * All reject paths collapse to a reason — callers map every reason to the
   * same generic 401 (no session-state oracle).
   */
  validateSession(sessionId: string): Promise<SessionValidationResult>;
  revokeSession(sessionId: string): Promise<void>;
  /**
   * Privilege-change rotation — the session is rotated on privilege change:
   * revoke every live session for the user, mint a fresh one, return new Set-Cookie.
   */
  rotateSession(
    userId: string,
    currentSessionId: string,
    meta?: { ip?: string | null; userAgent?: string | null },
  ): Promise<CreatedSession>;
  /** Full revoke of every session for user (TOTP re-enrolment). */
  revokeAllForUser(userId: string): Promise<number>;
}

export function createAdminSessionService(
  config: AdminSessionConfig,
  sessionStore: AdminSessionStore,
  userStore: AdminUserStore,
): AdminSessionService {
  const ttlMs = config.ttlMs ?? ADMIN_SESSION_TTL_MS;
  const idleMs = config.idleMs ?? ADMIN_SESSION_IDLE_MS;
  const now = config.now ?? (() => Date.now());

  return {
    async createSession(input) {
      const createdAt = now();
      const session: AdminSession = {
        sessionId: newToken(),
        userId: input.userId,
        nodeId: config.nodeId,
        csrfToken: newToken(),
        createdAt,
        expiresAt: createdAt + ttlMs,
        lastSeenAt: createdAt,
        ip: input.ip ?? null,
        userAgent: input.userAgent ?? null,
      };
      await sessionStore.save(session);
      const setCookie = buildSessionSetCookie(session.sessionId, {
        expiresAt: session.expiresAt,
      });
      return { session, setCookie };
    },

    async validateSession(sessionId) {
      if (await sessionStore.isRevoked(sessionId)) {
        return { ok: false, reason: "revoked" };
      }

      const session = await sessionStore.find(sessionId);
      if (session === null) {
        return { ok: false, reason: "unknown_session" };
      }

      if (session.nodeId !== config.nodeId) {
        return { ok: false, reason: "node_mismatch" };
      }

      const t = now();
      if (session.expiresAt <= t) {
        return { ok: false, reason: "expired" };
      }
      if (t - session.lastSeenAt > idleMs) {
        return { ok: false, reason: "idle" };
      }

      const user = await userStore.findById(session.userId);
      if (user === null) {
        return { ok: false, reason: "user_missing" };
      }
      if (user.disabledAt !== null) {
        return { ok: false, reason: "user_disabled" };
      }

      await sessionStore.touch(sessionId, t);
      const touched: AdminSession = { ...session, lastSeenAt: t };
      return { ok: true, session: touched, user };
    },

    async revokeSession(sessionId) {
      await sessionStore.revoke(sessionId);
    },

    async rotateSession(userId, currentSessionId, meta = {}) {
      // Invalidate every live session (including current), then mint fresh.
      // Privilege-change rotation must not leave the pre-change cookie valid.
      await sessionStore.revokeAllForUser(userId);
      void currentSessionId;
      return this.createSession({
        userId,
        ip: meta.ip ?? null,
        userAgent: meta.userAgent ?? null,
      });
    },

    async revokeAllForUser(userId) {
      return sessionStore.revokeAllForUser(userId);
    },
  };
}

// --- Auth gates (framework-free middleware outcomes) ---

export interface AuthRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
}

export type AuthGateOutcome =
  | {
      readonly ok: true;
      readonly session: AdminSession;
      readonly user: AdminUser;
    }
  | {
      readonly ok: false;
      readonly status: 401 | 403;
      readonly code: string;
      readonly message: string;
      readonly reason:
        | SessionRejectionReason
        | "csrf_invalid"
        | "password_change_required"
        | "totp_enrolment_required";
    };

const DEFAULT_ADMIN_PREFIX = "/admin/v1";

/**
 * Require a live node-origin admin session for /admin/v1/* .
 * Session id is read ONLY from the __Host- cookie — never Authorization Bearer.
 */
export async function requireAdminSession(
  service: AdminSessionService,
  request: AuthRequest,
  options: {
    readonly adminPathPrefix?: string;
    readonly publicPaths?: readonly string[];
  } = {},
): Promise<AuthGateOutcome> {
  const prefix = options.adminPathPrefix ?? DEFAULT_ADMIN_PREFIX;
  if (!request.path.startsWith(prefix)) {
    return {
      ok: false,
      status: 401,
      code: "invalid_credentials",
      message: "authentication required",
      reason: "missing_cookie",
    };
  }

  const publicPaths = options.publicPaths ?? [];
  if (publicPaths.some((p) => request.path === p || request.path.startsWith(`${p}/`))) {
    return {
      ok: false,
      status: 401,
      code: "invalid_credentials",
      message: "authentication required",
      reason: "missing_cookie",
    };
  }

  const sessionId = extractSessionIdFromCookie(request.headers["cookie"]);
  if (sessionId === null) {
    return {
      ok: false,
      status: 401,
      code: "invalid_credentials",
      message: "authentication required",
      reason: "missing_cookie",
    };
  }

  const result = await service.validateSession(sessionId);
  if (!result.ok) {
    return {
      ok: false,
      status: 401,
      code: "invalid_credentials",
      message: "authentication required",
      reason: result.reason,
    };
  }

  return { ok: true, session: result.session, user: result.user };
}

/**
 * CSRF double-submit check. Mount AFTER requireAdminSession on state-changing
 * methods. owns origin enforcement; this is the session-bound token half.
 */
export function requireSessionCsrf(
  session: AdminSession,
  request: AuthRequest,
): AuthGateOutcome | { readonly ok: true } {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return { ok: true };
  }
  const provided = request.headers["x-csrf-token"];
  // Same generic envelope as a missing/unknown session — no CSRF-vs-session
  // factor oracle on the wire: never reveal which factor failed.
  if (provided === undefined || provided === "" || !safeEqual(provided, session.csrfToken)) {
    return {
      ok: false,
      status: 401,
      code: "invalid_credentials",
      message: "authentication required",
      reason: "csrf_invalid",
    };
  }
  return { ok: true };
}

/**
 * First-login mandatory password-change gate (platform auth model; admin password-change step-up).
 * Scoped to money-mutating routes — auth routes and reads stay reachable so
 * the flag can ever be cleared. Returns 403 password_change_required.
 */
export function requirePasswordChanged(user: AdminUser): AuthGateOutcome | { readonly ok: true } {
  if (user.mustChangePassword) {
    return {
      ok: false,
      status: 403,
      code: "password_change_required",
      message: "password change required before this action",
      reason: "password_change_required",
    };
  }
  return { ok: true };
}

/**
 * First-login mandatory TOTP enrolment gate. Money mutations refuse until
 * enrol+confirm (or lab active bind) clears mustEnrolTotp. Returns 401
 * totp_required so the SPA can route to /setup.
 */
export function requireTotpEnrolled(
  user: AdminUser,
): AuthGateOutcome | { readonly ok: true } {
  if (user.mustEnrolTotp) {
    return {
      ok: false,
      status: 401,
      code: "totp_required",
      message: "totp enrolment required",
      reason: "totp_enrolment_required",
    };
  }
  return { ok: true };
}

/**
 * Active factor must exist when money opens. Covers reboot/in-mem wipe
 * desync where mustEnrolTotp was cleared but secret is gone — fail closed
 * until re-enrol or durable store rehydrates an active factor.
 */
export async function requireActiveTotpFactor(
  userStore: AdminUserStore,
  user: AdminUser,
): Promise<AuthGateOutcome | { readonly ok: true }> {
  const enrol = requireTotpEnrolled(user);
  if (!enrol.ok) return enrol;
  let factor;
  try {
    factor = await userStore.getTotpFactor(user.id);
  } catch (err) {
    // Unreadable sealed factor (wrong root / tamper) — same as missing factor.
    // Never 500 the money path on TotpOpenError (ZTR-1134 B2).
    if (err instanceof TotpOpenError) {
      return {
        ok: false,
        status: 401,
        code: "totp_required",
        message: "totp enrolment required",
        reason: "totp_enrolment_required",
      };
    }
    throw err;
  }
  if (factor.status !== "active" || factor.secretBase32.length < 16) {
    return {
      ok: false,
      status: 401,
      code: "totp_required",
      message: "totp enrolment required",
      reason: "totp_enrolment_required",
    };
  }
  return { ok: true };
}
