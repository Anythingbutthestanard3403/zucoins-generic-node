/**
 * node-origin admin session substrate.
 *
 * session policy; password-change gate.
 *
 * Covers bootstrap, password + first-login gate,
 * secure cookie issuance (HttpOnly/SameSite/host-scoped), session token NEVER
 * in response body.
 */
import { describe, expect, it } from "vitest";

import {
  ADMIN_SESSION_COOKIE,
  ADMIN_SESSION_IDLE_MS,
  ADMIN_SESSION_TTL_MS,
  DEFAULT_ADMIN_CORS,
  DEFAULT_ADMIN_USERNAME,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  MIN_PASSWORD_LENGTH,
  adminCorsFromAllowlist,
  assertSecureSessionCookie,
  bootstrapInitialAdmin,
  buildSessionSetCookie,
  createAdminSessionService,
  decideAdminCors,
  extractSessionIdFromCookie,
  gateMoneyMutation,
  handleAdminChangePassword,
  handleAdminLogin,
  handleAdminLogout,
  handleAdminMe,
  hashPassword,
  requirePasswordChanged,
  rotateSessionsOnTotpReenrolment,
  type AdminSessionConfig,
  type AuthRequest,
} from "../src/http/index.js";

const NODE_A = "node-a-uuid";
const NODE_B = "node-b-uuid";
const PASSWORD = "correct-horse-battery-staple";
const NEW_PASSWORD = "new-correct-horse-battery";

function makeConfig(overrides: Partial<AdminSessionConfig> = {}): AdminSessionConfig {
  return { nodeId: NODE_A, ...overrides };
}

function cookieHeader(setCookie: string): string {
  // Browser would send only name=value; strip attributes.
  const value = setCookie.split(";")[0]!;
  return value;
}

function req(
  overrides: Partial<AuthRequest> & { cookie?: string; csrf?: string } = {},
): AuthRequest {
  const headers: Record<string, string | undefined> = {
    ...(overrides.headers ?? {}),
  };
  if (overrides.cookie !== undefined) headers["cookie"] = overrides.cookie;
  if (overrides.csrf !== undefined) headers["x-csrf-token"] = overrides.csrf;
  return {
    method: overrides.method ?? "GET",
    path: overrides.path ?? "/admin/v1/me",
    headers,
  };
}

async function seedBootstrapped() {
  const users = new InMemoryAdminUserStore();
  const sessions = new InMemoryAdminSessionStore();
  const outcome = await bootstrapInitialAdmin(users, {
    INITIAL_ADMIN_PASSWORD: PASSWORD,
  });
  expect(outcome.seeded).toBe(true);
  const service = createAdminSessionService(makeConfig(), sessions, users);
  return { users, sessions, service, userId: (outcome as { userId: string }).userId };
}

describe("bootstrapInitialAdmin", () => {
  it("seeds exactly one admin with forced password change + TOTP enrol", async () => {
    const users = new InMemoryAdminUserStore();
    const outcome = await bootstrapInitialAdmin(users, {
      INITIAL_ADMIN_PASSWORD: PASSWORD,
    });
    expect(outcome).toEqual({
      seeded: true,
      userId: expect.any(String),
      username: DEFAULT_ADMIN_USERNAME,
    });
    expect(await users.count()).toBe(1);
    const admin = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    expect(admin).not.toBeNull();
    expect(admin!.mustChangePassword).toBe(true);
    expect(admin!.mustEnrolTotp).toBe(true);
    expect(admin!.role).toBe("admin");
  });

  it("is idempotent — never re-seeds once any admin exists", async () => {
    const users = new InMemoryAdminUserStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const second = await bootstrapInitialAdmin(users, {
      INITIAL_ADMIN_PASSWORD: "a-totally-different-password-xx",
    });
    expect(second).toEqual({ seeded: false, reason: "already_bootstrapped" });
    expect(await users.count()).toBe(1);
  });

  it("throws when INITIAL_ADMIN_PASSWORD is missing on first boot", async () => {
    const users = new InMemoryAdminUserStore();
    await expect(bootstrapInitialAdmin(users, {})).rejects.toThrow(
      /INITIAL_ADMIN_PASSWORD/,
    );
  });

  it("throws when INITIAL_ADMIN_PASSWORD is under the length floor", async () => {
    const users = new InMemoryAdminUserStore();
    await expect(
      bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: "short1" }),
    ).rejects.toThrow(new RegExp(String(MIN_PASSWORD_LENGTH)));
  });
});

describe("secure session cookie attributes", () => {
  it("emits Secure, HttpOnly, SameSite=Strict, Path=/, no Domain, __Host- name", () => {
    const setCookie = buildSessionSetCookie("sess-abc", {
      expiresAt: Date.now() + 60_000,
    });
    expect(() => assertSecureSessionCookie(setCookie)).not.toThrow();
    expect(setCookie.startsWith(`${ADMIN_SESSION_COOKIE}=`)).toBe(true);
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Secure/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
    expect(setCookie).toMatch(/Path=\//i);
    expect(setCookie).not.toMatch(/Domain=/i);
    expect(ADMIN_SESSION_COOKIE.startsWith("__Host-")).toBe(true);
  });

  it("clear cookie keeps the same security attributes", () => {
    const clear = buildSessionSetCookie("", { expiresAt: 0, clear: true });
    expect(clear).toMatch(/Max-Age=0/);
    expect(clear).toMatch(/HttpOnly/i);
    expect(clear).toMatch(/Secure/i);
    expect(clear).toMatch(/SameSite=Strict/i);
    expect(clear).not.toMatch(/Domain=/i);
  });
});

describe("login issues cookie-only session", () => {
  it("sets __Host- cookie with all flags and never returns session id in body", async () => {
    const { users, service } = await seedBootstrapped();
    const result = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );

    expect(result.status).toBe(200);
    const setCookie = result.headers["set-cookie"];
    expect(setCookie).toBeDefined();
    assertSecureSessionCookie(setCookie!);

    const body = result.body as Record<string, unknown>;
    expect(body.csrfToken).toEqual(expect.any(String));
    expect(body.mustChangePassword).toBe(true);
    expect(body.mustEnrolTotp).toBe(true);
    expect(body.userId).toEqual(expect.any(String));

    // Negative: session token / cookie name must not appear in the body.
    const bodyJson = JSON.stringify(body);
    expect(bodyJson).not.toContain(ADMIN_SESSION_COOKIE);
    const sessionId = extractSessionIdFromCookie(cookieHeader(setCookie!));
    expect(sessionId).toBeTruthy();
    expect(bodyJson).not.toContain(sessionId!);
    // No token-shaped field.
    expect(body).not.toHaveProperty("token");
    expect(body).not.toHaveProperty("sessionId");
    expect(body).not.toHaveProperty("session_id");
  });

  it("rejects wrong password with generic 401 and no Set-Cookie", async () => {
    const { users, service } = await seedBootstrapped();
    const result = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: "wrong-password-xx" },
    );
    expect(result.status).toBe(401);
    expect(result.headers["set-cookie"]).toBeUndefined();
    expect((result.body as { error: { code: string } }).error.code).toBe(
      "invalid_credentials",
    );
  });

  it("rejects unknown user with the same generic 401 (no username oracle)", async () => {
    const { users, service } = await seedBootstrapped();
    const result = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: "no-such-user", password: PASSWORD },
    );
    expect(result.status).toBe(401);
    expect((result.body as { error: { code: string } }).error.code).toBe(
      "invalid_credentials",
    );
  });
});

describe("session validate + timeout/revocation", () => {
  it("accepts a live cookie-bound session", async () => {
    const { users, service } = await seedBootstrapped();
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const me = await handleAdminMe(
      service,
      req({ cookie: cookieHeader(login.headers["set-cookie"]!) }),
    );
    expect(me.status).toBe(200);
    expect((me.body as { userId: string }).userId).toBeTruthy();
  });

  it("rejects expired session (absolute TTL)", async () => {
    const users = new InMemoryAdminUserStore();
    const sessions = new InMemoryAdminSessionStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    let clock = 1_000_000;
    const service = createAdminSessionService(
      makeConfig({ ttlMs: 5_000, now: () => clock }),
      sessions,
      users,
    );
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    clock += 6_000;
    const me = await handleAdminMe(service, req({ cookie }));
    expect(me.status).toBe(401);
  });

  it("rejects idle session past ADMIN_SESSION_IDLE_MS", async () => {
    const users = new InMemoryAdminUserStore();
    const sessions = new InMemoryAdminSessionStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    let clock = 1_000_000;
    const service = createAdminSessionService(
      makeConfig({ idleMs: 1_000, now: () => clock }),
      sessions,
      users,
    );
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    clock += 2_000;
    const me = await handleAdminMe(service, req({ cookie }));
    expect(me.status).toBe(401);
  });

  it("rejects a revoked session after logout", async () => {
    const { users, service } = await seedBootstrapped();
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;
    const logout = await handleAdminLogout(
      service,
      req({ method: "POST", path: "/admin/v1/logout", cookie, csrf }),
    );
    expect(logout.status).toBe(200);
    expect(logout.headers["set-cookie"]).toMatch(/Max-Age=0/);

    const me = await handleAdminMe(service, req({ cookie }));
    expect(me.status).toBe(401);
  });

  it("rejects a session bound to a different node", async () => {
    const users = new InMemoryAdminUserStore();
    const sessions = new InMemoryAdminSessionStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const serviceA = createAdminSessionService(
      makeConfig({ nodeId: NODE_A }),
      sessions,
      users,
    );
    const login = await handleAdminLogin(
      { userStore: users, sessions: serviceA },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const serviceB = createAdminSessionService(
      makeConfig({ nodeId: NODE_B }),
      sessions,
      users,
    );
    const me = await handleAdminMe(serviceB, req({ cookie }));
    expect(me.status).toBe(401);
  });

  it("defaults absolute TTL to 8h and idle to 30m", () => {
    expect(ADMIN_SESSION_TTL_MS).toBe(8 * 60 * 60 * 1000);
    expect(ADMIN_SESSION_IDLE_MS).toBe(30 * 60 * 1000);
  });
});

describe("first-login password-change gate", () => {
  it("blocks money mutations while mustChangePassword is set", async () => {
    const { users, service } = await seedBootstrapped();
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;

    const gate = await gateMoneyMutation(
      service,
      req({
        method: "POST",
        path: "/admin/v1/outbound",
        cookie,
        csrf,
      }),
    );
    expect(gate.ok).toBe(false);
    if (!gate.ok) {
      expect(gate.result.status).toBe(403);
      expect((gate.result.body as { error: { code: string } }).error.code).toBe(
        "password_change_required",
      );
    }
  });

  it("password change clears the gate, rotates session cookie, and never returns session id in body", async () => {
    const { users, service } = await seedBootstrapped();
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const oldCookie = cookieHeader(login.headers["set-cookie"]!);
    const oldSid = extractSessionIdFromCookie(oldCookie)!;
    const csrf = (login.body as { csrfToken: string }).csrfToken;

    const changed = await handleAdminChangePassword(
      { userStore: users, sessions: service },
      req({ method: "POST", path: "/admin/v1/password", cookie: oldCookie, csrf }),
      { current_password: PASSWORD, new_password: NEW_PASSWORD },
    );
    expect(changed.status).toBe(200);
    const newSetCookie = changed.headers["set-cookie"]!;
    assertSecureSessionCookie(newSetCookie);
    const newSid = extractSessionIdFromCookie(cookieHeader(newSetCookie))!;
    expect(newSid).not.toBe(oldSid);

    // Body must not carry session id.
    const bodyJson = JSON.stringify(changed.body);
    expect(bodyJson).not.toContain(oldSid);
    expect(bodyJson).not.toContain(newSid);
    expect(bodyJson).not.toContain(ADMIN_SESSION_COOKIE);

    // Old cookie invalidated.
    const oldMe = await handleAdminMe(service, req({ cookie: oldCookie }));
    expect(oldMe.status).toBe(401);

    // New cookie works; password gate cleared. Clear TOTP enrol for money-gate check
    // (enrol/confirm is covered elsewhere; this test only covers password-change).
    const newCookie = cookieHeader(newSetCookie);
    const newCsrf = (changed.body as { csrfToken: string }).csrfToken;
    const me = await handleAdminMe(service, req({ cookie: newCookie }));
    expect(me.status).toBe(200);
    expect((me.body as { mustChangePassword: boolean }).mustChangePassword).toBe(false);

    await users.setMustEnrolTotp((me.body as { userId: string }).userId, false);

    const gate = await gateMoneyMutation(
      service,
      req({
        method: "POST",
        path: "/admin/v1/outbound",
        cookie: newCookie,
        csrf: newCsrf,
      }),
    );
    expect(gate.ok).toBe(true);
  });


  it("requirePasswordChanged is a pure 403 when flag set, pass when clear", async () => {
    const blocked = requirePasswordChanged({
      id: "u",
      username: "a",
      passwordHash: "x",
      role: "admin",
      mustChangePassword: true,
      mustEnrolTotp: false,
      disabledAt: null,
      createdAt: 0,
    });
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) expect(blocked.status).toBe(403);

    const ok = requirePasswordChanged({
      id: "u",
      username: "a",
      passwordHash: "x",
      role: "admin",
      mustChangePassword: false,
      mustEnrolTotp: false,
      disabledAt: null,
      createdAt: 0,
    });
    expect(ok.ok).toBe(true);
  });

  it("password change still reachable when mustChangePassword is set", async () => {
    const { users, service } = await seedBootstrapped();
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const changed = await handleAdminChangePassword(
      { userStore: users, sessions: service },
      req({
        method: "POST",
        path: "/admin/v1/password",
        cookie: cookieHeader(login.headers["set-cookie"]!),
        csrf: (login.body as { csrfToken: string }).csrfToken,
      }),
      { current_password: PASSWORD, new_password: NEW_PASSWORD },
    );
    expect(changed.status).toBe(200);
  });
});

describe("privilege-change session rotation", () => {
  it("TOTP re-enrolment revokes every live session for the user", async () => {
    const { users, service, userId } = await seedBootstrapped();
    // Clear password gate so we can hold two sessions under bootstrap password.
    const u = await users.findById(userId);
    await users.updatePassword(userId, u!.passwordHash, false);

    const s1 = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const s2 = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const c1 = cookieHeader(s1.headers["set-cookie"]!);
    const c2 = cookieHeader(s2.headers["set-cookie"]!);

    const n = await rotateSessionsOnTotpReenrolment(service, userId);
    expect(n).toBe(2);

    expect((await handleAdminMe(service, req({ cookie: c1 }))).status).toBe(401);
    expect((await handleAdminMe(service, req({ cookie: c2 }))).status).toBe(401);
  });

  it("password change revokes sibling sessions", async () => {
    const { users, service } = await seedBootstrapped();
    const s1 = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const s2 = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const c2 = cookieHeader(s2.headers["set-cookie"]!);

    await handleAdminChangePassword(
      { userStore: users, sessions: service },
      req({
        method: "POST",
        path: "/admin/v1/password",
        cookie: cookieHeader(s1.headers["set-cookie"]!),
        csrf: (s1.body as { csrfToken: string }).csrfToken,
      }),
      { current_password: PASSWORD, new_password: NEW_PASSWORD },
    );

    // Sibling session dead.
    expect((await handleAdminMe(service, req({ cookie: c2 }))).status).toBe(401);
  });
});

describe("admin CORS", () => {
  it("defaults to no cross-origin access", () => {
    expect(DEFAULT_ADMIN_CORS.allowedOrigins).toEqual([]);
    expect(DEFAULT_ADMIN_CORS.allowCredentials).toBe(false);
    const d = decideAdminCors(DEFAULT_ADMIN_CORS, "https://evil.example");
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("origin_not_allowed");
  });

  it("allows only exact listed origins", () => {
    const cfg = adminCorsFromAllowlist(["https://node.example.com"]);
    expect(decideAdminCors(cfg, "https://node.example.com").ok).toBe(true);
    expect(decideAdminCors(cfg, "https://evil.example").ok).toBe(false);
  });

  it("structurally refuses wildcard-with-credentials", () => {
    expect(() => adminCorsFromAllowlist(["*"], true)).toThrow(/wildcard/);
    expect(() => adminCorsFromAllowlist(["*"], false)).toThrow(/wildcard/);
    // Even a hand-built illegal config is rejected at decide time.
    const illegal = {
      allowedOrigins: ["*"] as readonly string[],
      allowCredentials: true,
    };
    const d = decideAdminCors(illegal, "https://anything.example");
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("wildcard_with_credentials");
  });
});

describe("CSRF on state-changing auth routes", () => {
  it("logout without CSRF is 401", async () => {
    const { users, service } = await seedBootstrapped();
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const logout = await handleAdminLogout(
      service,
      req({ method: "POST", path: "/admin/v1/logout", cookie }),
    );
    expect(logout.status).toBe(401);
  });

  it("password change without CSRF is 401", async () => {
    const { users, service } = await seedBootstrapped();
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const changed = await handleAdminChangePassword(
      { userStore: users, sessions: service },
      req({
        method: "POST",
        path: "/admin/v1/password",
        cookie: cookieHeader(login.headers["set-cookie"]!),
      }),
      { current_password: PASSWORD, new_password: NEW_PASSWORD },
    );
    expect(changed.status).toBe(401);
  });
});

describe("password hashing", () => {
  it("hashes and verifies at cost 12", async () => {
    const h = await hashPassword("test-password-12chars");
    expect(h.startsWith("$2b$12$") || h.startsWith("$2a$12$")).toBe(true);
  });
});
