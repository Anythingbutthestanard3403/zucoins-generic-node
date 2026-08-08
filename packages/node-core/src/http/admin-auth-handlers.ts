// Framework-free admin auth handlers: login, logout, me, password change.
//
// The shell (apps/generic-node or apps/node) mounts these behind its HTTP
// framework; this module owns the session/cookie/password substrate only.
//
// Hard line: the session id is delivered ONLY via HttpOnly Set-Cookie.
// Response bodies never carry the session token — only csrfToken + operator
// posture flags a same-origin SPA needs.
//
// CSRF origin enforcement + TOTP mutation burn are; password change
// here rotates the session (privilege-change rotation) without a TOTP
// gate so a first-boot admin (mustEnrolTotp) can clear mustChangePassword.
// An enrolled operator's TOTP step-up on password change is concern
// when it composes the mutation chain on top of rotateSession.

import {
  generateTotpSecret,
  otpauthUri,
  totpSecretBytes,
  type TotpConfig,
} from "../totp/index.js";
import {
  DEFAULT_ADMIN_USERNAME,
  MIN_PASSWORD_LENGTH,
  bootstrapInitialAdmin,
} from "./admin-bootstrap.js";
import {
  ADMIN_SESSION_COOKIE,
  buildSessionSetCookie,
  extractSessionIdFromCookie,
  requireActiveTotpFactor,
  requirePasswordChanged,
  requireSessionCsrf,
  requireTotpEnrolled,
  type AdminSession,
  type AdminSessionService,
  type AdminUser,
  type AdminUserStore,
  type AuthRequest,
} from "./admin-session.js";
import { checkCsrf, type CsrfConfig } from "./csrf.js";
import {
  clearIpFailures,
  isIpPairLocked,
  registerIpFailure,
} from "./ip-lockout.js";
import { DUMMY_PASSWORD_HASH, hashPassword, verifyPassword } from "./password.js";
import {
  verifyTotp,
  type TotpBurnStore,
} from "./totp-chain.js";

/** Audit sink for enrolment (never receives the TOTP secret). */
export interface AdminAuthAudit {
  record(event: {
    readonly eventType: "user.totp_enrol_started" | "user.totp_enrolled";
    readonly actorUserId: string;
    readonly ip?: string | null;
    readonly userAgent?: string | null;
  }): void | Promise<void>;
}

// --- Shared response shape ---

export interface AuthHttpResult {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: unknown;
}

function json(
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
): AuthHttpResult {
  return {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
    body,
  };
}

function errorJson(
  status: number,
  code: string,
  message: string,
): AuthHttpResult {
  return json(status, { error: { code, message } });
}

// --- Login ---

export interface LoginBody {
  readonly username: string;
  readonly password: string;
}

export interface LoginDeps {
  readonly userStore: AdminUserStore;
  readonly sessions: AdminSessionService;
  readonly ip?: string | null;
  readonly userAgent?: string | null;
}

/**
 * Password login → issue session cookie. CSRF-exempt (no session yet).
 * Constant-work bcrypt against a dummy hash on unknown user. Session id is
 * NOT in the body — only in Set-Cookie.
 */
export async function handleAdminLogin(
  deps: LoginDeps,
  body: LoginBody,
): Promise<AuthHttpResult> {
  const { username, password } = body;
  if (typeof username !== "string" || username.length === 0) {
    return errorJson(400, "validation_error", "username required");
  }
  if (typeof password !== "string" || password.length === 0) {
    return errorJson(400, "validation_error", "password required");
  }

  const ip = deps.ip ?? null;
  // Password brute force: same admin lockout model primary pair lock as
  // confirm-TOTP (5/15 min). Read the lock here, but branch on it only after the
  // compare below — a locked pair must still pay exactly one bcrypt, or the lock
  // becomes the timing oracle DUMMY_PASSWORD_HASH exists to close.
  // Ceiling: ip-lockout state is in-memory per process, so an N-replica
  // deployment gives an attacker N× the threshold before any pair locks.
  const locked = isIpPairLocked(ip, username);

  const user = await deps.userStore.findByUsername(username);

  // Constant work: exactly one bcrypt compare regardless of whether the user exists.
  const passwordMatches = await verifyPassword(
    password,
    user?.passwordHash ?? DUMMY_PASSWORD_HASH,
  );

  if (locked || user === null || !passwordMatches || user.disabledAt !== null) {
    // Silent lockout: a locked pair answers with the wrong-password envelope,
    // byte for byte (ip-lockout.ts:6-7). Registering while already locked only
    // touches lastFailureMs — it never extends the lock.
    registerIpFailure(ip, username);
    return errorJson(401, "invalid_credentials", "invalid credentials");
  }

  clearIpFailures(ip, username);

  const { session, setCookie } = await deps.sessions.createSession({
    userId: user.id,
    ip,
    userAgent: deps.userAgent ?? null,
  });

  // Body carries operator posture + CSRF only. Grep-guard: session id / cookie
  // name must never appear here.
  const responseBody = {
    userId: user.id,
    username: user.username,
    role: user.role,
    mustChangePassword: user.mustChangePassword,
    mustEnrolTotp: user.mustEnrolTotp,
    csrfToken: session.csrfToken,
  };

  return json(200, responseBody, { "set-cookie": setCookie });
}

// --- Logout ---

export async function handleAdminLogout(
  sessions: AdminSessionService,
  request: AuthRequest,
): Promise<AuthHttpResult> {
  const sessionId = extractSessionIdFromCookie(request.headers["cookie"]);
  if (sessionId === null) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }
  const validated = await sessions.validateSession(sessionId);
  if (!validated.ok) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }

  const csrf = requireSessionCsrf(validated.session, request);
  if (!csrf.ok) {
    return errorJson(csrf.status, csrf.code, csrf.message);
  }

  await sessions.revokeSession(sessionId);
  const clearCookie = buildSessionSetCookie("", { expiresAt: 0, clear: true });
  return json(200, { ok: true }, { "set-cookie": clearCookie });
}

// --- Me ---

export async function handleAdminMe(
  sessions: AdminSessionService,
  request: AuthRequest,
): Promise<AuthHttpResult> {
  const sessionId = extractSessionIdFromCookie(request.headers["cookie"]);
  if (sessionId === null) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }
  const validated = await sessions.validateSession(sessionId);
  if (!validated.ok) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }

  const { session, user } = validated;
  return json(200, {
    userId: user.id,
    username: user.username,
    role: user.role,
    mustChangePassword: user.mustChangePassword,
    mustEnrolTotp: user.mustEnrolTotp,
    csrfToken: session.csrfToken,
  });
}

// --- Password change ---

export interface ChangePasswordBody {
  readonly current_password: string;
  readonly new_password: string;
}

export interface ChangePasswordDeps {
  readonly userStore: AdminUserStore;
  readonly sessions: AdminSessionService;
  /** Origin allowlist — required for privilege POSTs. */
  readonly csrf?: CsrfConfig;
  readonly ip?: string | null;
  readonly userAgent?: string | null;
}

/**
 * Rotate password, clear mustChangePassword, rotate session.
 * Deliberately NOT gated by requirePasswordChanged — that would lock out the
 * first-boot admin. CSRF origin + token required. TOTP step-up for enrolled
 * operators is composed by on top of this substrate.
 */
export async function handleAdminChangePassword(
  deps: ChangePasswordDeps,
  request: AuthRequest,
  body: ChangePasswordBody,
): Promise<AuthHttpResult> {
  const sessionId = extractSessionIdFromCookie(request.headers["cookie"]);
  if (sessionId === null) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }
  const validated = await deps.sessions.validateSession(sessionId);
  if (!validated.ok) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }

  const originDenied = denyIfOriginForbidden(deps.csrf, request);
  if (originDenied !== null) return originDenied;

  const csrf = requireSessionCsrf(validated.session, request);
  if (!csrf.ok) {
    return errorJson(csrf.status, csrf.code, csrf.message);
  }

  const { current_password, new_password } = body;
  if (typeof current_password !== "string" || current_password.length === 0) {
    return errorJson(400, "validation_error", "current_password required");
  }
  if (typeof new_password !== "string" || new_password.length < MIN_PASSWORD_LENGTH) {
    return errorJson(
      400,
      "validation_error",
      `new_password must be at least ${MIN_PASSWORD_LENGTH} characters`,
    );
  }

  const user = validated.user;
  if (!(await verifyPassword(current_password, user.passwordHash))) {
    return errorJson(401, "invalid_credentials", "invalid credentials");
  }

  const newHash = await hashPassword(new_password);
  await deps.userStore.updatePassword(user.id, newHash, false);

  // Privilege-change rotation: invalidate the pre-change cookie and every other
  // live session; issue a fresh session cookie.
  const rotated = await deps.sessions.rotateSession(user.id, sessionId, {
    ip: deps.ip ?? null,
    userAgent: deps.userAgent ?? null,
  });

  const responseBody = {
    ok: true,
    mustChangePassword: false,
    csrfToken: rotated.session.csrfToken,
  };

  return json(200, responseBody, { "set-cookie": rotated.setCookie });
}

// TOTP first-boot enrolment ---

export interface EnrolTotpBody {
  readonly password: string;
}

export interface EnrolTotpDeps {
  readonly userStore: AdminUserStore;
  readonly sessions: AdminSessionService;
  /** Origin allowlist — required for privilege POSTs. */
  readonly csrf?: CsrfConfig;
  readonly audit?: AdminAuthAudit;
  readonly ip?: string | null;
  readonly userAgent?: string | null;
  readonly issuer?: string;
}

/**
 * POST /admin/v1/enrol-totp — mint a pending secret, return once for QR.
 * Password re-entry gated. Does NOT clear mustEnrolTotp (confirm does).
 * Secret never appears in audit detail.
 */
export async function handleAdminEnrolTotp(
  deps: EnrolTotpDeps,
  request: AuthRequest,
  body: EnrolTotpBody,
): Promise<AuthHttpResult> {
  const sessionId = extractSessionIdFromCookie(request.headers["cookie"]);
  if (sessionId === null) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }
  const validated = await deps.sessions.validateSession(sessionId);
  if (!validated.ok) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }

  const originDenied = denyIfOriginForbidden(deps.csrf, request);
  if (originDenied !== null) return originDenied;

  const csrf = requireSessionCsrf(validated.session, request);
  if (!csrf.ok) {
    return errorJson(csrf.status, csrf.code, csrf.message);
  }

  const password = body.password;
  if (typeof password !== "string" || password.length === 0) {
    return errorJson(400, "validation_error", "password required");
  }

  const user = validated.user;
  if (!(await verifyPassword(password, user.passwordHash))) {
    return errorJson(401, "invalid_credentials", "invalid credentials");
  }

  const secret = generateTotpSecret();
  const stored = await deps.userStore.setPendingTotpSecret(user.id, secret);
  if (stored === "missing") {
    return errorJson(500, "internal_error", "internal error");
  }
  if (stored === "already_active") {
    return errorJson(400, "validation_error", "totp already enrolled");
  }

  const otpauthUrl = otpauthUri(user.username, secret, deps.issuer);

  await deps.audit?.record({
    eventType: "user.totp_enrol_started",
    actorUserId: user.id,
    ip: deps.ip ?? null,
    userAgent: deps.userAgent ?? null,
  });

  // Secret returned ONCE — never logged.
  return json(200, { secret, otpauthUrl });
}

export interface ConfirmTotpBody {
  readonly totp: string;
}

export interface ConfirmTotpDeps {
  readonly userStore: AdminUserStore;
  readonly sessions: AdminSessionService;
  /** Shared global burn registry with money approve/reject (confirm-code cannot re-auth money). */
  readonly totpLog: TotpBurnStore;
  readonly nodeId: string;
  /** Origin allowlist — required for privilege POSTs. */
  readonly csrf?: CsrfConfig;
  readonly audit?: AdminAuthAudit;
  readonly ip?: string | null;
  readonly userAgent?: string | null;
  readonly nowMs?: () => number;
}

/**
 * POST /admin/v1/confirm-totp — verify first real code against pending secret,
 * burn the step (same single-use as money), activate, rotate session
 * (privilege change). Sole writer of active enrolment.
 */
export async function handleAdminConfirmTotp(
  deps: ConfirmTotpDeps,
  request: AuthRequest,
  body: ConfirmTotpBody,
): Promise<AuthHttpResult> {
  const sessionId = extractSessionIdFromCookie(request.headers["cookie"]);
  if (sessionId === null) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }
  const validated = await deps.sessions.validateSession(sessionId);
  if (!validated.ok) {
    return errorJson(401, "invalid_credentials", "authentication required");
  }

  const originDenied = denyIfOriginForbidden(deps.csrf, request);
  if (originDenied !== null) return originDenied;

  const csrf = requireSessionCsrf(validated.session, request);
  if (!csrf.ok) {
    return errorJson(csrf.status, csrf.code, csrf.message);
  }

  const code = body.totp;
  if (typeof code !== "string" || !/^\d{6}$/u.test(code)) {
    return errorJson(400, "validation_error", "totp must be 6 digits");
  }

  const ip = deps.ip ?? null;
  const username = validated.user.username;
  // Confirm-code brute force: same admin lockout model primary pair lock as login (5/15 min).
  // Silent — generic totp_invalid envelope (no lock oracle on enrol surface).
  if (isIpPairLocked(ip, username)) {
    return errorJson(401, "totp_invalid", "invalid or reused totp code");
  }

  const factor = await deps.userStore.getTotpFactor(validated.user.id);
  if (factor.status !== "pending") {
    return errorJson(400, "validation_error", "no pending enrolment");
  }

  const secretBytes = totpSecretBytes(factor.secretBase32);
  if (secretBytes === null) {
    return errorJson(500, "internal_error", "internal error");
  }

  const nowMs = deps.nowMs?.() ?? Date.now();
  // Burn-on-attempt into shared global registry (TOTP confirm + money approve/reject).
  const burned = await verifyTotp(
    { secret: secretBytes, windowSteps: 1 },
    { nodeId: deps.nodeId, code, nowMs },
    deps.totpLog,
  );
  if (!burned.ok) {
    registerIpFailure(ip, username);
    return errorJson(401, "totp_invalid", "invalid or reused totp code");
  }

  const activated = await deps.userStore.activateTotpEnrolment(validated.user.id);
  if (activated !== "ok") {
    return errorJson(400, "validation_error", "no pending enrolment");
  }

  clearIpFailures(ip, username);

  // Privilege-change rotation: pre-confirm cookie must not survive activate.
  const rotated = await deps.sessions.rotateSession(validated.user.id, sessionId, {
    ip,
    userAgent: deps.userAgent ?? null,
  });

  await deps.audit?.record({
    eventType: "user.totp_enrolled",
    actorUserId: validated.user.id,
    ip,
    userAgent: deps.userAgent ?? null,
  });

  return json(
    200,
    { ok: true, mustEnrolTotp: false, csrfToken: rotated.session.csrfToken },
    { "set-cookie": rotated.setCookie },
  );
}

// --- TOTP re-enrolment session rotation hook (substrate only) ---

/**
 * Called by the TOTP re-enrolment flow after a successful factor
 * rotation. Revokes every live session so a stolen pre-enrolment cookie cannot
 * outlive the privilege change. Returns the count revoked.
 */
export async function rotateSessionsOnTotpReenrolment(
  sessions: AdminSessionService,
  userId: string,
): Promise<number> {
  return sessions.revokeAllForUser(userId);
}

/**
 * Resolve TotpConfig for a money mutation: active per-operator factor first,
 * then optional lab process-level fallback (ADMIN_TOTP_LAB_MODE path only).
 */
export async function resolveOperatorTotpConfig(
  userStore: AdminUserStore,
  userId: string,
  labFallback: TotpConfig | null | undefined,
): Promise<TotpConfig | null> {
  const factor = await userStore.getTotpFactor(userId);
  if (factor.status === "active") {
    const bytes = totpSecretBytes(factor.secretBase32);
    if (bytes !== null) return { secret: bytes, windowSteps: 1 };
  }
  if (isUsableLabTotp(labFallback)) {
    return labFallback ?? null;
  }
  return null;
}

/** True when a process-level lab secret is present and usable (not zero-filled). */
export function isUsableLabTotp(
  lab: TotpConfig | null | undefined,
): lab is TotpConfig {
  if (lab === undefined || lab === null || lab.secret.length < 16) return false;
  for (const b of lab.secret) {
    if (b !== 0) return true;
  }
  return false;
}

/**
 * Origin allowlist gate (step 1). When `csrf` is provided, fail closed on
 * missing/wrong Origin before inspecting the CSRF token.
 */
function denyIfOriginForbidden(
  csrf: CsrfConfig | undefined,
  request: AuthRequest,
): AuthHttpResult | null {
  if (csrf === undefined) return null;
  const originCheck = checkCsrf(csrf, request);
  if (!originCheck.ok) {
    return errorJson(403, "origin_forbidden", "origin not allowed");
  }
  return null;
}

// --- Money-mutation gate helper ---

export interface GateMoneyMutationOptions {
  readonly userStore?: AdminUserStore;
  /**
   * Origin allowlist. Required on every money / privilege state-mutating route
   * so Origin CSRF matches runGuardedAdminMutation. GET callers may
   * omit it — checkCsrf is a no-op for safe methods when provided.
   */
  readonly csrf?: CsrfConfig;
  /**
   * Process-level lab TOTP (never durable). When usable, satisfies the enrolment
   * / active-factor gate without writing mustEnrolTotp=false into storage.
   */
  readonly labTotp?: TotpConfig | null;
}

/**
 * Compose session + Origin CSRF + CSRF token + password-change + TOTP-enrolment
 * gates for a money-mutating route. When `userStore` is provided, also requires
 * an active factor unless a usable process-level labTotp is present (lab
 * is undurable — production must never bind lab).
 *
 * Third arg accepts legacy `AdminUserStore` or full `GateMoneyMutationOptions`.
 */
export async function gateMoneyMutation(
  sessions: AdminSessionService,
  request: AuthRequest,
  userStoreOrOpts?: AdminUserStore | GateMoneyMutationOptions,
  legacyCsrf?: CsrfConfig,
): Promise<
  | { readonly ok: true; readonly session: AdminSession; readonly user: AdminUser }
  | { readonly ok: false; readonly result: AuthHttpResult }
> {
  const opts = normalizeGateOpts(userStoreOrOpts, legacyCsrf);
  const sessionId = extractSessionIdFromCookie(request.headers["cookie"]);
  if (sessionId === null) {
    return {
      ok: false,
      result: errorJson(401, "invalid_credentials", "authentication required"),
    };
  }
  const validated = await sessions.validateSession(sessionId);
  if (!validated.ok) {
    return {
      ok: false,
      result: errorJson(401, "invalid_credentials", "authentication required"),
    };
  }

  // Origin before CSRF token (same order as runGuardedAdminMutation). // contract-allow:order:frozen structural vocabulary
  const originDenied = denyIfOriginForbidden(opts.csrf, request);
  if (originDenied !== null) {
    return { ok: false, result: originDenied };
  }

  const csrf = requireSessionCsrf(validated.session, request);
  if (!csrf.ok) {
    return { ok: false, result: errorJson(csrf.status, csrf.code, csrf.message) };
  }

  const pw = requirePasswordChanged(validated.user);
  if (!pw.ok) {
    return { ok: false, result: errorJson(pw.status, pw.code, pw.message) };
  }

  const labOk = isUsableLabTotp(opts.labTotp);

  if (opts.userStore !== undefined) {
    const factorGate = await requireActiveTotpFactor(opts.userStore, validated.user);
    if (!factorGate.ok && !labOk) {
      return {
        ok: false,
        result: errorJson(factorGate.status, factorGate.code, factorGate.message),
      };
    }
  } else {
    const totpGate = requireTotpEnrolled(validated.user);
    if (!totpGate.ok && !labOk) {
      return { ok: false, result: errorJson(totpGate.status, totpGate.code, totpGate.message) };
    }
  }

  return { ok: true, session: validated.session, user: validated.user };
}

function normalizeGateOpts(
  userStoreOrOpts: AdminUserStore | GateMoneyMutationOptions | undefined,
  legacyCsrf: CsrfConfig | undefined,
): GateMoneyMutationOptions {
  if (userStoreOrOpts === undefined) {
    return { csrf: legacyCsrf };
  }
  if (isAdminUserStore(userStoreOrOpts)) {
    return { userStore: userStoreOrOpts, csrf: legacyCsrf };
  }
  return {
    userStore: userStoreOrOpts.userStore,
    csrf: userStoreOrOpts.csrf ?? legacyCsrf,
    labTotp: userStoreOrOpts.labTotp,
  };
}

function isAdminUserStore(
  v: AdminUserStore | GateMoneyMutationOptions,
): v is AdminUserStore {
  return typeof (v as AdminUserStore).findByUsername === "function";
}

// --- Bootstrap re-export for shell boot wiring ---

export {
  bootstrapInitialAdmin,
  DEFAULT_ADMIN_USERNAME,
  MIN_PASSWORD_LENGTH,
};

// Re-export cookie name so shells never hard-code a second spelling.
export { ADMIN_SESSION_COOKIE };
