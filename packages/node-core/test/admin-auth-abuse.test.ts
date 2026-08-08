/**
 * Adversarial tests over the real admin auth stack.
 *
 * Subject under test is production code only:
 *   packages/node-core/src/http/{admin-session,admin-auth-handlers,admin-cors,
 *     admin-mutation-chain,csrf,totp-chain,ip-lockout}.ts
 * ip-lockout is the enforcement path the suite defers to for brute force
 * (relocated into node-core — no frozen apps/node import).
 *
 * Checklist: fixation, CSRF, CORS, stale sessions, brute force,
 * TOTP replay/burn races, malformed-before-TOTP, wrong origin, restart,
 * no-factor-oracle.
 *
 * Acceptance (C-08): body validates before burn; one timestep → one global
 * winner; downstream failure never restores the burn.
 *
 */

import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ADMIN_SESSION_COOKIE,
  AUTH_FACTOR_FAILURE,
  DEFAULT_ADMIN_USERNAME,
  IP_LOCK_DURATION_MS,
  IP_LOCK_THRESHOLD,
  IP_LOCK_WINDOW_MS,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  TotpConsumptionLog,
  _resetIpLockoutForTests,
  adminCorsFromAllowlist,
  bootstrapInitialAdmin,
  checkCsrf,
  clearIpFailures,
  createAdminSessionService,
  decideAdminCors,
  extractSessionIdFromCookie,
  gateMoneyMutation,
  handleAdminChangePassword,
  handleAdminLogin,
  handleAdminLogout,
  handleAdminMe,
  isIpPairLocked,
  registerIpFailure,
  requireAdminSession,
  requireSessionCsrf,
  rotateSessionsOnTotpReenrolment,
  runGuardedAdminMutation,
  verifyTotp,
  type AdminSessionConfig,
  type AdminUser,
  type AdminUserStore,
  type AuthHttpResult,
  type AuthRequest,
  type BodyValidationResult,
  type TotpConfig,
} from "../src/http/index.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NODE_A = "node-a-uuid";
const NODE_B = "node-b-uuid";
const ORIGIN = "https://node.example.com";
const PASSWORD = "correct-horse-battery-staple";
const NEW_PASSWORD = "new-correct-horse-battery";
const TOTP_SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const TOTP_CFG: TotpConfig = {
  secret: TOTP_SECRET,
  periodSeconds: 30,
  digits: 6,
  windowSteps: 1,
};
const CSRF_CFG = { allowedOrigins: [ORIGIN] as const };
const NOW_MS = 1_700_000_000_000;

function hotp(secret: Uint8Array, counter: number, digits = 6): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

function timestepAt(nowMs: number, period = 30): number {
  return Math.floor(nowMs / 1000 / period);
}

function codeAt(nowMs: number): string {
  return hotp(TOTP_SECRET, timestepAt(nowMs));
}

function makeConfig(overrides: Partial<AdminSessionConfig> = {}): AdminSessionConfig {
  return { nodeId: NODE_A, ...overrides };
}

function cookieHeader(setCookie: string): string {
  return setCookie.split(";")[0]!;
}

function req(
  overrides: Partial<AuthRequest> & {
    cookie?: string;
    csrf?: string;
    totp?: string;
    origin?: string;
  } = {},
): AuthRequest {
  const headers: Record<string, string | undefined> = {
    ...(overrides.headers ?? {}),
  };
  if (overrides.cookie !== undefined) headers["cookie"] = overrides.cookie;
  if (overrides.csrf !== undefined) headers["x-csrf-token"] = overrides.csrf;
  if (overrides.totp !== undefined) headers["x-zp-totp"] = overrides.totp;
  if (overrides.origin !== undefined) headers["origin"] = overrides.origin;
  return {
    method: overrides.method ?? "POST",
    path: overrides.path ?? "/admin/v1/outbound",
    headers,
  };
}

function envelopeBytes(result: AuthHttpResult): string {
  return JSON.stringify({ status: result.status, body: result.body });
}

function factorEnvelopeBytes(status: number, code: string, message: string): string {
  return JSON.stringify({
    status,
    body: { error: { code, message } },
  });
}

async function seedClearedPassword() {
  const users = new InMemoryAdminUserStore();
  const sessions = new InMemoryAdminSessionStore();
  const outcome = await bootstrapInitialAdmin(users, {
    INITIAL_ADMIN_PASSWORD: PASSWORD,
  });
  expect(outcome.seeded).toBe(true);
  const userId = (outcome as { userId: string }).userId;
  const u = await users.findById(userId);
  // Clear first-login gate so money mutations are reachable under the session.
  await users.updatePassword(userId, u!.passwordHash, false);
  await users.setMustEnrolTotp(userId, false);
  const service = createAdminSessionService(makeConfig(), sessions, users);
  return { users, sessions, service, userId };
}

async function loginSession(
  users: InMemoryAdminUserStore,
  service: ReturnType<typeof createAdminSessionService>,
) {
  const login = await handleAdminLogin(
    { userStore: users, sessions: service },
    { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
  );
  expect(login.status).toBe(200);
  const cookie = cookieHeader(login.headers["set-cookie"]!);
  const csrf = (login.body as { csrfToken: string }).csrfToken;
  const sessionId = extractSessionIdFromCookie(cookie)!;
  return { login, cookie, csrf, sessionId };
}

function validBody(): BodyValidationResult<{ amount: string }> {
  return { ok: true, body: { amount: "1.00" } };
}

function invalidBody(): BodyValidationResult<{ amount: string }> {
  return {
    ok: false,
    status: 400,
    code: "validation_error",
    message: "amount required",
  };
}

// ---------------------------------------------------------------------------
// Session fixation / stale sessions (custody privilege-change rotation)
// ---------------------------------------------------------------------------

describe("session fixation / stale sessions", () => {
  it("login always mints a server-chosen session id — attacker pre-seed cannot stick", async () => {
    const { users, sessions, service } = await seedClearedPassword();

    // Attacker tries to pre-seed a known id into the store (fixation attempt).
    const attackerId = "attacker-chosen-session-id-32b!!!!!!!!!!!";
    await sessions.save({
      sessionId: attackerId,
      userId: "nobody",
      nodeId: NODE_A,
      csrfToken: "attacker-csrf",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      lastSeenAt: Date.now(),
      ip: null,
      userAgent: null,
    });

    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    expect(login.status).toBe(200);
    const issued = extractSessionIdFromCookie(cookieHeader(login.headers["set-cookie"]!))!;
    // Production createSession uses CSPRNG — never echoes a client-supplied id.
    expect(issued).not.toBe(attackerId);
    expect(issued.length).toBeGreaterThanOrEqual(32);
    // Body never carries the session id.
    expect(JSON.stringify(login.body)).not.toContain(issued);
    expect(JSON.stringify(login.body)).not.toContain(ADMIN_SESSION_COOKIE);
  });

  it("pre-privilege-change cookie is rejected after password change (stale session)", async () => {
    const { users, service } = await seedClearedPassword();
    const s1 = await loginSession(users, service);
    const s2 = await loginSession(users, service);

    const changed = await handleAdminChangePassword(
      { userStore: users, sessions: service },
      req({
        method: "POST",
        path: "/admin/v1/password",
        cookie: s1.cookie,
        csrf: s1.csrf,
      }),
      { current_password: PASSWORD, new_password: NEW_PASSWORD },
    );
    expect(changed.status).toBe(200);
    const newSid = extractSessionIdFromCookie(
      cookieHeader(changed.headers["set-cookie"]!),
    )!;
    expect(newSid).not.toBe(s1.sessionId);

    // Pre-change cookies (both the mutating session and a sibling) are dead.
    expect((await handleAdminMe(service, req({ method: "GET", cookie: s1.cookie }))).status).toBe(
      401,
    );
    expect((await handleAdminMe(service, req({ method: "GET", cookie: s2.cookie }))).status).toBe(
      401,
    );
  });

  it("TOTP re-enrolment rotation kills every live session", async () => {
    const { users, service, userId } = await seedClearedPassword();
    const a = await loginSession(users, service);
    const b = await loginSession(users, service);
    expect(await rotateSessionsOnTotpReenrolment(service, userId)).toBe(2);
    expect((await handleAdminMe(service, req({ method: "GET", cookie: a.cookie }))).status).toBe(
      401,
    );
    expect((await handleAdminMe(service, req({ method: "GET", cookie: b.cookie }))).status).toBe(
      401,
    );
  });
});

// ---------------------------------------------------------------------------
// CSRF / wrong origin / CORS
// ---------------------------------------------------------------------------

describe("CSRF / wrong origin / CORS", () => {
  it("valid session + missing CSRF token fails the money gate", async () => {
    const { users, service } = await seedClearedPassword();
    const { cookie } = await loginSession(users, service);
    const gate = await gateMoneyMutation(
      service,
      req({ method: "POST", path: "/admin/v1/outbound", cookie }),
    );
    expect(gate.ok).toBe(false);
    if (!gate.ok) {
      expect(gate.result.status).toBe(401);
      expect((gate.result.body as { error: { code: string } }).error.code).toBe(
        "invalid_credentials",
      );
    }
  });

  it("valid session + wrong CSRF token fails the money gate", async () => {
    const { users, service } = await seedClearedPassword();
    const { cookie } = await loginSession(users, service);
    const gate = await gateMoneyMutation(
      service,
      req({
        method: "POST",
        path: "/admin/v1/outbound",
        cookie,
        csrf: "not-the-bound-token",
      }),
    );
    expect(gate.ok).toBe(false);
    if (!gate.ok) expect(gate.result.status).toBe(401);
  });

  it("gateMoneyMutation rejects missing/wrong Origin when csrf allowlist is bound", async () => {
    const { users, service } = await seedClearedPassword();
    const { cookie, csrf } = await loginSession(users, service);

    const missingOrigin = await gateMoneyMutation(
      service,
      req({
        method: "POST",
        path: "/admin/v1/external-sends/x/approve",
        cookie,
        csrf,
      }),
      { csrf: CSRF_CFG },
    );
    expect(missingOrigin.ok).toBe(false);
    if (!missingOrigin.ok) {
      expect(missingOrigin.result.status).toBe(403);
      expect((missingOrigin.result.body as { error: { code: string } }).error.code).toBe(
        "origin_forbidden",
      );
    }

    const evilOrigin = await gateMoneyMutation(
      service,
      req({
        method: "POST",
        path: "/admin/v1/external-sends/x/approve",
        cookie,
        csrf,
        origin: "https://evil.example",
      }),
      { csrf: CSRF_CFG },
    );
    expect(evilOrigin.ok).toBe(false);
    if (!evilOrigin.ok) {
      expect(evilOrigin.result.status).toBe(403);
      expect((evilOrigin.result.body as { error: { code: string } }).error.code).toBe(
        "origin_forbidden",
      );
    }

    const okOrigin = await gateMoneyMutation(
      service,
      req({
        method: "POST",
        path: "/admin/v1/external-sends/x/approve",
        cookie,
        csrf,
        origin: ORIGIN,
      }),
      { csrf: CSRF_CFG },
    );
    expect(okOrigin.ok).toBe(true);
  });

  it("checkCsrf rejects missing origin, wrong origin, null origin, and subdomain spoof", () => {
    expect(checkCsrf(CSRF_CFG, { method: "POST", headers: {} })).toEqual({
      ok: false,
      reason: "origin_missing",
    });
    expect(
      checkCsrf(CSRF_CFG, {
        method: "POST",
        headers: { origin: "https://evil.example" },
      }),
    ).toEqual({ ok: false, reason: "origin_mismatch" });
    expect(
      checkCsrf(CSRF_CFG, {
        method: "POST",
        headers: { origin: "null" },
      }),
    ).toEqual({ ok: false, reason: "origin_mismatch" });
    // Subdomain of an allowed host is NOT an exact-origin match.
    expect(
      checkCsrf(CSRF_CFG, {
        method: "POST",
        headers: { origin: "https://evil.node.example.com" },
      }),
    ).toEqual({ ok: false, reason: "origin_mismatch" });
    // javascript:/data: referers fail closed. URL() may yield origin "null"
    // (mismatch) or throw (missing) — both are reject paths, never allow.
    for (const referer of ["javascript:alert(1)", "data:text/html,hi", "not-a-url"]) {
      const r = checkCsrf(CSRF_CFG, { method: "POST", headers: { referer } });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(["origin_missing", "origin_mismatch"]).toContain(r.reason);
      }
    }
  });

  it("admin CORS never resolves to wildcard-with-credentials", async () => {
    expect(() => adminCorsFromAllowlist(["*"], true)).toThrow(/wildcard/);
    expect(() => adminCorsFromAllowlist(["*"], false)).toThrow(/wildcard/);
    const illegal = {
      allowedOrigins: ["*"] as readonly string[],
      allowCredentials: true,
    };
    const d = decideAdminCors(illegal, "https://anything.example");
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("wildcard_with_credentials");
  });

  it("runGuardedAdminMutation rejects wrong origin even with valid session+CSRF+TOTP", async () => {
    const { users, service } = await seedClearedPassword();
    const { cookie, csrf } = await loginSession(users, service);
    const log = new TotpConsumptionLog();
    const code = codeAt(NOW_MS);
    let mutated = false;
    const out = await runGuardedAdminMutation({
      sessions: service,
      request: req({
        cookie,
        csrf,
        totp: code,
        origin: "https://evil.example",
      }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => {
        mutated = true;
        return "done";
      },
    });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.reason).toBe("csrf_origin");
      expect(out.status).toBe(403);
    }
    expect(mutated).toBe(false);
    // Origin reject happens before TOTP — code must remain unburned.
    expect(log.isConsumed(NODE_A, timestepAt(NOW_MS))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Brute force (primary pair lock — node-core src/http/ip-lockout)
// ---------------------------------------------------------------------------

describe("brute force — per-(IP, username) lockout", () => {
  beforeEach(() => {
    _resetIpLockoutForTests();
  });
  afterEach(() => {
    _resetIpLockoutForTests();
  });

  it(`locks the pair after ${IP_LOCK_THRESHOLD} failures in the window`, () => {
    const ip = "203.0.113.9";
    const user = "admin";
    for (let i = 0; i < IP_LOCK_THRESHOLD - 1; i++) {
      expect(isIpPairLocked(ip, user)).toBe(false);
      const r = registerIpFailure(ip, user);
      expect(r.tripped).toBe(false);
    }
    const trip = registerIpFailure(ip, user);
    expect(trip.tripped).toBe(true);
    expect(isIpPairLocked(ip, user)).toBe(true);
  });

  it("lock is pair-scoped — same username from another IP is unaffected", () => {
    const user = "admin";
    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) registerIpFailure("1.1.1.1", user);
    expect(isIpPairLocked("1.1.1.1", user)).toBe(true);
    expect(isIpPairLocked("2.2.2.2", user)).toBe(false);
  });

  it("success clears the pair window", () => {
    const ip = "9.9.9.9";
    for (let i = 0; i < 3; i++) registerIpFailure(ip, "admin");
    clearIpFailures(ip, "admin");
    expect(isIpPairLocked(ip, "admin")).toBe(false);
    // Fresh window after clear — need full threshold again.
    for (let i = 0; i < IP_LOCK_THRESHOLD - 1; i++) {
      expect(registerIpFailure(ip, "admin").tripped).toBe(false);
    }
  });

  it("lock expires after the flat duration (no escalation)", () => {
    const realNow = Date.now;
    let t = 1_000_000;
    Date.now = () => t;
    try {
      const ip = "10.0.0.1";
      for (let i = 0; i < IP_LOCK_THRESHOLD; i++) registerIpFailure(ip, "admin");
      expect(isIpPairLocked(ip, "admin")).toBe(true);
      t += IP_LOCK_DURATION_MS + 1;
      expect(isIpPairLocked(ip, "admin")).toBe(false);
      // Constants pin the documented flat model.
      expect(IP_LOCK_THRESHOLD).toBe(5);
      expect(IP_LOCK_WINDOW_MS).toBe(15 * 60 * 1000);
      expect(IP_LOCK_DURATION_MS).toBe(IP_LOCK_WINDOW_MS);
    } finally {
      Date.now = realNow;
    }
  });
});

// ---------------------------------------------------------------------------
// Login lockout — the same pair lock applied to the password surface
// ---------------------------------------------------------------------------

describe("login — per-(IP, username) lockout", () => {
  const IP = "203.0.113.44";
  const UA = "Mozilla/5.0 (operator console)";
  const WRONG = "wrong-password-xx";

  beforeEach(() => {
    _resetIpLockoutForTests();
  });
  afterEach(() => {
    _resetIpLockoutForTests();
  });

  function attempt(
    userStore: AdminUserStore,
    sessions: ReturnType<typeof createAdminSessionService>,
    password: string,
    ip: string | null = IP,
    username = DEFAULT_ADMIN_USERNAME,
  ): Promise<AuthHttpResult> {
    return handleAdminLogin({ userStore, sessions, ip, userAgent: UA }, { username, password });
  }

  /**
   * Wraps a seeded store to observe whether the handler reached the bcrypt
   * compare: passwordHash is read only when building verifyPassword's arguments.
   */
  function watchHashReads(users: InMemoryAdminUserStore): {
    readonly store: AdminUserStore;
    reads(): number;
  } {
    let reads = 0;
    const store: AdminUserStore = Object.assign(Object.create(users) as AdminUserStore, {
      async findByUsername(username: string): Promise<AdminUser | null> {
        const user = await users.findByUsername(username);
        if (user === null) return null;
        return new Proxy(user, {
          get(target, prop, receiver) {
            if (prop === "passwordHash") reads += 1;
            return Reflect.get(target, prop, receiver);
          },
        });
      },
    });
    return { store, reads: () => reads };
  }

  it(`locks the pair after ${IP_LOCK_THRESHOLD} failures — the correct password is then refused`, async () => {
    const { users, service } = await seedClearedPassword();

    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) {
      expect((await attempt(users, service, WRONG)).status).toBe(401);
    }
    expect(isIpPairLocked(IP, DEFAULT_ADMIN_USERNAME)).toBe(true);

    const correct = await attempt(users, service, PASSWORD);
    expect(correct.status).toBe(401);
    expect(correct.headers["set-cookie"]).toBeUndefined();
  });

  it("a locked response is byte-identical to a wrong-password response", async () => {
    const { users, service } = await seedClearedPassword();

    const wrongPw = await attempt(users, service, WRONG);
    for (let i = 1; i < IP_LOCK_THRESHOLD; i++) await attempt(users, service, WRONG);
    expect(isIpPairLocked(IP, DEFAULT_ADMIN_USERNAME)).toBe(true);

    const locked = await attempt(users, service, PASSWORD);
    expect(envelopeBytes(locked)).toBe(envelopeBytes(wrongPw));
    // No lock oracle smuggled in via a header (no Retry-After, no distinct code).
    expect(JSON.stringify(locked.headers)).toBe(JSON.stringify(wrongPw.headers));
  });

  it("a locked attempt still pays exactly one bcrypt compare — no timing oracle", async () => {
    const { users, service } = await seedClearedPassword();
    const spy = watchHashReads(users);

    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) await attempt(spy.store, service, WRONG);
    expect(isIpPairLocked(IP, DEFAULT_ADMIN_USERNAME)).toBe(true);

    const before = spy.reads();
    expect((await attempt(spy.store, service, PASSWORD)).status).toBe(401);
    // Short-circuiting on the lock would return before verifyPassword's arguments
    // are built and leave this counter unchanged.
    expect(spy.reads()).toBe(before + 1);
  });

  it("the lock is pair-scoped — another IP and another username are unaffected", async () => {
    const { users, service } = await seedClearedPassword();
    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) await attempt(users, service, WRONG);
    expect(isIpPairLocked(IP, DEFAULT_ADMIN_USERNAME)).toBe(true);

    // Same username from another IP still authenticates.
    expect((await attempt(users, service, PASSWORD, "198.51.100.7")).status).toBe(200);
    // Another username from the locked IP carries no lock of its own.
    expect(isIpPairLocked(IP, "someone-else")).toBe(false);
  });

  it("a successful login clears the pair counter", async () => {
    const { users, service } = await seedClearedPassword();
    for (let i = 0; i < IP_LOCK_THRESHOLD - 1; i++) await attempt(users, service, WRONG);

    expect((await attempt(users, service, PASSWORD)).status).toBe(200);

    // Fresh window after the clear — the full threshold is needed again.
    for (let i = 0; i < IP_LOCK_THRESHOLD - 1; i++) {
      expect((await attempt(users, service, WRONG)).status).toBe(401);
    }
    expect(isIpPairLocked(IP, DEFAULT_ADMIN_USERNAME)).toBe(false);
    expect((await attempt(users, service, PASSWORD)).status).toBe(200);
  });

  it("the issued session records the caller's ip and user agent", async () => {
    const { users, sessions, service } = await seedClearedPassword();

    const login = await attempt(users, service, PASSWORD);
    expect(login.status).toBe(200);

    const sessionId = extractSessionIdFromCookie(cookieHeader(login.headers["set-cookie"]!))!;
    const stored = await sessions.find(sessionId);
    expect(stored?.ip).toBe(IP);
    expect(stored?.userAgent).toBe(UA);
  });
});

// ---------------------------------------------------------------------------
// TOTP replay / burn races (C-08, custody steps 6/8)
// ---------------------------------------------------------------------------

describe("TOTP replay / burn races", () => {
  it("sequential replay of the same code fails after first consume", async () => {
    const log = new TotpConsumptionLog();
    const code = codeAt(NOW_MS);
    const first = await verifyTotp(TOTP_CFG, { nodeId: NODE_A, code, nowMs: NOW_MS }, log);
    expect(first.ok).toBe(true);
    const second = await verifyTotp(TOTP_CFG, { nodeId: NODE_A, code, nowMs: NOW_MS }, log);
    expect(second).toEqual({ ok: false, reason: "replay" });
  });

  it("genuine concurrent claims of the same fresh code yield exactly one winner", async () => {
    const log = new TotpConsumptionLog();
    const code = codeAt(NOW_MS);
    // Fire many concurrent verifyTotp calls on the same (node, code). The
    // consume() path is synchronous Set mutation — at most one can observe
    // an empty slot. We use Promise.all so scheduling is concurrent at the
    // event-loop level — not sequential calls dressed up as concurrent.
    const N = 32;
    const results = await Promise.all(
      Array.from({ length: N }, () =>
        Promise.resolve().then(() =>
          verifyTotp(TOTP_CFG, { nodeId: NODE_A, code, nowMs: NOW_MS }, log),
        ),
      ),
    );
    const wins = results.filter((r) => r.ok);
    const losses = results.filter((r) => !r.ok);
    expect(wins).toHaveLength(1);
    expect(losses).toHaveLength(N - 1);
    expect(losses.every((r) => !r.ok && r.reason === "replay")).toBe(true);
    expect(log.isConsumed(NODE_A, timestepAt(NOW_MS))).toBe(true);
  });

  it("downstream mutation failure never restores the burned timestep (C-08)", async () => {
    const { users, service } = await seedClearedPassword();
    const { cookie, csrf } = await loginSession(users, service);
    const log = new TotpConsumptionLog();
    const code = codeAt(NOW_MS);
    const step = timestepAt(NOW_MS);

    const out = await runGuardedAdminMutation({
      sessions: service,
      request: req({ cookie, csrf, totp: code, origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => {
        throw new Error("downstream persistence failed");
      },
    });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).toBe("mutation_threw");
    expect(log.isConsumed(NODE_A, step)).toBe(true);

    // Retry with the same code cannot succeed.
    const retry = await runGuardedAdminMutation({
      sessions: service,
      request: req({ cookie, csrf, totp: code, origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => "should-not-run",
    });
    expect(retry.ok).toBe(false);
    if (!retry.ok) expect(retry.reason).toBe("totp");
  });

  it("per-node isolation — same code may burn independently on another nodeId", async () => {
    const log = new TotpConsumptionLog();
    const code = codeAt(NOW_MS);
    expect((await verifyTotp(TOTP_CFG, { nodeId: NODE_A, code, nowMs: NOW_MS }, log)).ok).toBe(true);
    expect((await verifyTotp(TOTP_CFG, { nodeId: NODE_B, code, nowMs: NOW_MS }, log)).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Malformed-before-TOTP (custody step 2)
// ---------------------------------------------------------------------------

describe("malformed body before TOTP inspection", () => {
  it("rejects invalid body without consuming TOTP state", async () => {
    const { users, service } = await seedClearedPassword();
    const { cookie, csrf } = await loginSession(users, service);
    const log = new TotpConsumptionLog();
    const code = codeAt(NOW_MS);
    const step = timestepAt(NOW_MS);
    let mutateCalls = 0;

    const out = await runGuardedAdminMutation({
      sessions: service,
      request: req({ cookie, csrf, totp: code, origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { not: "valid" },
      validateBody: invalidBody,
      nowMs: NOW_MS,
      mutate: async () => {
        mutateCalls += 1;
        return "nope";
      },
    });

    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.reason).toBe("body_invalid");
      expect(out.status).toBe(400);
      expect(out.code).toBe("validation_error");
    }
    expect(mutateCalls).toBe(0);
    expect(log.isConsumed(NODE_A, step)).toBe(false);

    // Same code still usable after a body reject — proves TOTP was never reached.
    const second = await runGuardedAdminMutation({
      sessions: service,
      request: req({ cookie, csrf, totp: code, origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => "ok",
    });
    expect(second.ok).toBe(true);
    expect(log.isConsumed(NODE_A, step)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Restart durability (sessions + timestep burns survive rehydrate)
// ---------------------------------------------------------------------------

describe("restart durability", () => {
  it("live session survives store snapshot → new process hydrate", async () => {
    const users = new InMemoryAdminUserStore();
    const storeA = new InMemoryAdminSessionStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const u = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    await users.updatePassword(u!.id, u!.passwordHash, false);

    const serviceA = createAdminSessionService(makeConfig(), storeA, users);
    const { cookie, sessionId } = await loginSession(users, serviceA);

    // "Crash": snapshot durable rows, drop the live store, boot a fresh one.
    const snap = storeA.snapshot();
    expect(snap.sessions.some((s) => s.sessionId === sessionId)).toBe(true);

    const storeB = new InMemoryAdminSessionStore();
    storeB.hydrate(snap);
    const serviceB = createAdminSessionService(makeConfig(), storeB, users);

    const me = await handleAdminMe(serviceB, req({ method: "GET", cookie }));
    expect(me.status).toBe(200);
    expect((me.body as { userId: string }).userId).toBe(u!.id);
  });

  it("revoked session stays revoked across restart (no silent un-revoke)", async () => {
    const users = new InMemoryAdminUserStore();
    const storeA = new InMemoryAdminSessionStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const u = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    await users.updatePassword(u!.id, u!.passwordHash, false);
    const serviceA = createAdminSessionService(makeConfig(), storeA, users);
    const { cookie, csrf, sessionId } = await loginSession(users, serviceA);

    const logout = await handleAdminLogout(
      serviceA,
      req({ method: "POST", path: "/admin/v1/logout", cookie, csrf }),
    );
    expect(logout.status).toBe(200);

    const snap = storeA.snapshot();
    expect(snap.revoked).toContain(sessionId);

    const storeB = new InMemoryAdminSessionStore();
    storeB.hydrate(snap);
    const serviceB = createAdminSessionService(makeConfig(), storeB, users);
    expect((await handleAdminMe(serviceB, req({ method: "GET", cookie }))).status).toBe(401);
  });

  it("consumed TOTP timestep stays burned across restart (never silently un-reserved)", async () => {
    const logA = new TotpConsumptionLog();
    const code = codeAt(NOW_MS);
    const step = timestepAt(NOW_MS);
    expect((await verifyTotp(TOTP_CFG, { nodeId: NODE_A, code, nowMs: NOW_MS }, logA)).ok).toBe(true);

    const snap = logA.snapshot();
    const logB = new TotpConsumptionLog();
    logB.hydrate(snap);

    expect(logB.isConsumed(NODE_A, step)).toBe(true);
    expect(await verifyTotp(TOTP_CFG, { nodeId: NODE_A, code, nowMs: NOW_MS }, logB)).toEqual({
      ok: false,
      reason: "replay",
    });
  });

  it("restart does not wipe every live session (no lockout-via-restart DoS)", async () => {
    const users = new InMemoryAdminUserStore();
    const storeA = new InMemoryAdminSessionStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const u = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    await users.updatePassword(u!.id, u!.passwordHash, false);
    const serviceA = createAdminSessionService(makeConfig(), storeA, users);

    const a = await loginSession(users, serviceA);
    const b = await loginSession(users, serviceA);

    const storeB = new InMemoryAdminSessionStore();
    storeB.hydrate(storeA.snapshot());
    const serviceB = createAdminSessionService(makeConfig(), storeB, users);

    expect((await handleAdminMe(serviceB, req({ method: "GET", cookie: a.cookie }))).status).toBe(
      200,
    );
    expect((await handleAdminMe(serviceB, req({ method: "GET", cookie: b.cookie }))).status).toBe(
      200,
    );
  });
});

// ---------------------------------------------------------------------------
// No-factor-oracle — byte/status identity across failure modes
// ---------------------------------------------------------------------------

describe("no-factor-oracle — auth factor failures are byte-indistinguishable", () => {
  it("login unknown-user vs wrong-password vs disabled produce identical envelopes", async () => {
    const { users, service, userId } = await seedClearedPassword();

    const unknown = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: "no-such-user", password: PASSWORD },
    );
    const wrongPw = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: "wrong-password-xx" },
    );

    await users.setDisabledAt(userId, Date.now());
    const disabled = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );

    const expected = factorEnvelopeBytes(401, "invalid_credentials", "invalid credentials");
    expect(envelopeBytes(unknown)).toBe(expected);
    expect(envelopeBytes(wrongPw)).toBe(expected);
    expect(envelopeBytes(disabled)).toBe(expected);
  });

  it("session / CSRF-token / TOTP failures collapse to AUTH_FACTOR_FAILURE bytes", async () => {
    const { users, service } = await seedClearedPassword();
    const { cookie, csrf } = await loginSession(users, service);
    const log = new TotpConsumptionLog();
    const goodCode = codeAt(NOW_MS);

    // 1. Missing session cookie.
    const noSession = await runGuardedAdminMutation({
      sessions: service,
      request: req({ csrf, totp: goodCode, origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => "x",
    });

    // 2. Valid session, wrong CSRF token.
    const badCsrf = await runGuardedAdminMutation({
      sessions: service,
      request: req({
        cookie,
        csrf: "totally-wrong-csrf-token",
        totp: goodCode,
        origin: ORIGIN,
      }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => "x",
    });

    // 3. Valid session + CSRF, wrong TOTP.
    const badTotp = await runGuardedAdminMutation({
      sessions: service,
      request: req({ cookie, csrf, totp: "000000", origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => "x",
    });

    // 4. Valid session + CSRF, missing TOTP header.
    const noTotp = await runGuardedAdminMutation({
      sessions: service,
      request: req({ cookie, csrf, origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => "x",
    });

    const expected = factorEnvelopeBytes(
      AUTH_FACTOR_FAILURE.status,
      AUTH_FACTOR_FAILURE.code,
      AUTH_FACTOR_FAILURE.message,
    );

    for (const out of [noSession, badCsrf, badTotp, noTotp]) {
      expect(out.ok).toBe(false);
      if (!out.ok) {
        const bytes = factorEnvelopeBytes(out.status, out.code, out.message);
        expect(bytes).toBe(expected);
      }
    }

    // requireSessionCsrf alone matches the same message as requireAdminSession miss.
    const sess = await service.validateSession(
      extractSessionIdFromCookie(cookie)!,
    );
    expect(sess.ok).toBe(true);
    if (sess.ok) {
      const csrfFail = requireSessionCsrf(
        sess.session,
        req({ method: "POST", cookie, csrf: "nope" }),
      );
      expect(csrfFail.ok).toBe(false);
      if (!csrfFail.ok) {
        expect(csrfFail.status).toBe(AUTH_FACTOR_FAILURE.status);
        expect(csrfFail.code).toBe(AUTH_FACTOR_FAILURE.code);
        expect(csrfFail.message).toBe(AUTH_FACTOR_FAILURE.message);
      }
    }

    const missing = await requireAdminSession(
      service,
      req({ method: "GET", path: "/admin/v1/me" }),
    );
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.status).toBe(AUTH_FACTOR_FAILURE.status);
      expect(missing.code).toBe(AUTH_FACTOR_FAILURE.code);
      expect(missing.message).toBe(AUTH_FACTOR_FAILURE.message);
    }
  });
});

// ---------------------------------------------------------------------------
// Absolute TTL cannot be extended by activity (stale-session / hijack bound)
// ---------------------------------------------------------------------------

describe("session absolute TTL is not activity-extendable", () => {
  it("activity inside the idle window cannot push past absolute expiresAt", async () => {
    const users = new InMemoryAdminUserStore();
    const sessions = new InMemoryAdminSessionStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const u = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    await users.updatePassword(u!.id, u!.passwordHash, false);

    let clock = 1_000_000;
    const ttlMs = 10_000;
    const idleMs = 60_000; // idle longer than absolute so absolute is the binding cap
    const service = createAdminSessionService(
      makeConfig({ ttlMs, idleMs, now: () => clock }),
      sessions,
      users,
    );
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);

    // Touch repeatedly inside the absolute window.
    for (let i = 0; i < 5; i++) {
      clock += 1_500;
      const me = await handleAdminMe(service, req({ method: "GET", cookie }));
      expect(me.status).toBe(200);
    }

    // Cross absolute TTL — activity cannot save it.
    clock = 1_000_000 + ttlMs + 1;
    const expired = await handleAdminMe(service, req({ method: "GET", cookie }));
    expect(expired.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// Happy-path control — chain admits a fully authenticated mutation
// ---------------------------------------------------------------------------

describe("control: fully authenticated guarded mutation succeeds once", () => {
  it("session + origin + CSRF + body + fresh TOTP → one success, replay fails", async () => {
    const { users, service } = await seedClearedPassword();
    const { cookie, csrf } = await loginSession(users, service);
    const log = new TotpConsumptionLog();
    const code = codeAt(NOW_MS);

    const first = await runGuardedAdminMutation({
      sessions: service,
      request: req({ cookie, csrf, totp: code, origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async ({ body, timestep }) => ({ body, timestep }),
    });
    expect(first.ok).toBe(true);
    if (first.ok) {
      expect(first.result.body.amount).toBe("1.00");
      expect(first.timestep).toBe(timestepAt(NOW_MS));
    }

    const replay = await runGuardedAdminMutation({
      sessions: service,
      request: req({ cookie, csrf, totp: code, origin: ORIGIN }),
      csrf: CSRF_CFG,
      totp: TOTP_CFG,
      totpLog: log,
      nodeId: NODE_A,
      rawBody: { amount: "1.00" },
      validateBody: validBody,
      nowMs: NOW_MS,
      mutate: async () => "replayed",
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.reason).toBe("totp");
  });
});
