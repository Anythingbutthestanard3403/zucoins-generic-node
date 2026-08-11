/**
 * POST /admin/v1/login request-volume throttle (ZTR-1201 / ZTR-1218).
 *
 * Subject under test is production code only:
 *   packages/node-core/src/http/{login-rate-limit,admin-auth-handlers,ip-lockout}.ts
 *
 * Production admits each attempt at the app-router pre-decode chokepoint
 * (`consumeLoginAttempt`) and then calls `handleAdminLogin` without re-consuming.
 * The `login()` helper below mirrors that contract so these cases stay faithful
 * to the live path without pulling the generic-node router into node-core.
 *
 * The throttle is the spray-facing complement to the per-(IP, username) failure
 * lockout ZTR-1192 landed in ip-lockout.ts. These tests pin the three properties that
 * make it worth having and the one property that makes it safe:
 *   - over-rate callers are shed with the frozen 429 `rate_limited`;
 *   - an under-rate caller is never shed, and one IP's flood never sheds another's;
 *   - the 429 is credential-blind — decided before the user store is ever consulted,
 *     so it cannot become an account-existence oracle;
 *   - the lockout is undisturbed, and a shed request consumes none of its budget.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_ADMIN_USERNAME,
  IP_LOCK_THRESHOLD,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  LOGIN_RATE_MAX_REQUESTS,
  LOGIN_RATE_WINDOW_MS,
  _resetIpLockoutForTests,
  _resetLoginRateLimitForTests,
  bootstrapInitialAdmin,
  consumeLoginAttempt,
  createAdminSessionService,
  handleAdminLogin,
  isIpPairLocked,
  type AdminUser,
  type AdminUserStore,
  type AuthHttpResult,
} from "../src/http/index.js";

const PASSWORD = "correct-horse-battery-staple";
const IP_A = "203.0.113.11";
const IP_B = "203.0.113.12";

/**
 * The real in-memory store with findByUsername shadowed by a recording delegate, so a
 * shed request's *zero* credential work is observable. Shadowing an own property keeps
 * the bound original — the store's internal state is untouched.
 */
async function seedAdmin(): Promise<{
  readonly store: AdminUserStore;
  readonly lookups: string[];
  readonly sessions: ReturnType<typeof createAdminSessionService>;
}> {
  const users = new InMemoryAdminUserStore();
  const outcome = await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
  expect(outcome.seeded).toBe(true);
  const sessions = createAdminSessionService(
    { nodeId: "node-rate-limit" },
    new InMemoryAdminSessionStore(),
    users,
  );

  const lookups: string[] = [];
  const realFindByUsername = users.findByUsername.bind(users);
  (users as { findByUsername: (u: string) => Promise<AdminUser | null> }).findByUsername = (
    username: string,
  ) => {
    lookups.push(username);
    return realFindByUsername(username);
  };

  return { store: users, lookups, sessions };
}

/**
 * Mirrors the production admit-then-handle order (admin-router pre-decode
 * chokepoint → handleAdminLogin). Sheds with the same 429 envelope the router
 * returns when the budget is exhausted.
 */
function login(
  deps: { store: AdminUserStore; sessions: ReturnType<typeof createAdminSessionService> },
  ip: string,
  username: string,
  password: string,
): Promise<AuthHttpResult> {
  if (!consumeLoginAttempt(ip)) {
    return Promise.resolve({
      status: 429,
      headers: { "retry-after": String(LOGIN_RATE_WINDOW_MS / 1000) },
      body: { error: { code: "rate_limited", message: "too many login attempts" } },
    });
  }
  return handleAdminLogin(
    { userStore: deps.store, sessions: deps.sessions, ip },
    { username, password },
  );
}

const envelopeBytes = (result: AuthHttpResult): string =>
  JSON.stringify({ status: result.status, headers: result.headers, body: result.body });

/**
 * Spends `units` of one address's budget through the production limiter entry point.
 * Driving the bulk of the budget here rather than through 30 real logins keeps every
 * case to a couple of bcrypt compares — 30 real logins is ~10s idle and >30s under a
 * loaded suite, which times the case out and leaves its orphaned loop spending the
 * next case's budget. The "login() admits via consumeLoginAttempt per request" claim
 * is proved at the boundary by the first case below, not by volume.
 */
function spendBudget(ip: string, units: number = LOGIN_RATE_MAX_REQUESTS): void {
  for (let i = 0; i < units; i += 1) {
    expect(consumeLoginAttempt(ip)).toBe(true);
  }
}

describe("login volume throttle — per source IP", () => {
  beforeEach(() => {
    _resetLoginRateLimitForTests();
    _resetIpLockoutForTests();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    _resetLoginRateLimitForTests();
    _resetIpLockoutForTests();
  });

  it("admits the last request inside the budget and sheds the next with 429 rate_limited", async () => {
    // The budget is a fixed window on the wall clock, so pin the clock: a case that
    // straddles a real window boundary measures the boundary, not the ceiling.
    vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
    const deps = await seedAdmin();

    // One unit left. login() must spend it via consumeLoginAttempt (the production
    // pre-decode chokepoint) before handleAdminLogin runs — if admit is skipped the
    // shed below would come back 401.
    spendBudget(IP_A, LOGIN_RATE_MAX_REQUESTS - 1);

    const lastInsideBudget = await login(deps, IP_A, "spray-last", "wrong");
    expect(lastInsideBudget.status).toBe(401);

    const shed = await login(deps, IP_A, "spray-over", "wrong");
    expect(shed.status).toBe(429);
    expect(shed.body).toEqual({
      error: { code: "rate_limited", message: "too many login attempts" },
    });
    expect(shed.headers["retry-after"]).toBe(String(LOGIN_RATE_WINDOW_MS / 1000));
  });

  it("sheds the correct password exactly as it sheds an unknown username — no oracle", async () => {
    const deps = await seedAdmin();
    spendBudget(IP_A);

    const realUserRightPassword = await login(deps, IP_A, DEFAULT_ADMIN_USERNAME, PASSWORD);
    const absentUser = await login(deps, IP_A, "no-such-operator", "whatever");

    expect(realUserRightPassword.status).toBe(429);
    expect(envelopeBytes(realUserRightPassword)).toBe(envelopeBytes(absentUser));
  });

  it("decides the 429 before the user store is consulted", async () => {
    const deps = await seedAdmin();
    spendBudget(IP_A);

    const shed = await login(deps, IP_A, DEFAULT_ADMIN_USERNAME, PASSWORD);

    expect(shed.status).toBe(429);
    // Zero credential work on a shed request: no lookup, therefore no timing or
    // behavioural difference an attacker could read as "this username exists".
    expect(deps.lookups).toEqual([]);
  });

  it("keys on the source IP alone — one flooded IP never sheds another", async () => {
    const deps = await seedAdmin();
    spendBudget(IP_A);

    expect((await login(deps, IP_A, DEFAULT_ADMIN_USERNAME, PASSWORD)).status).toBe(429);
    expect((await login(deps, IP_B, DEFAULT_ADMIN_USERNAME, PASSWORD)).status).toBe(200);
  });
});

describe("login volume throttle — the ZTR-1192 lockout is undisturbed", () => {
  beforeEach(() => {
    _resetLoginRateLimitForTests();
    _resetIpLockoutForTests();
  });
  afterEach(() => {
    _resetLoginRateLimitForTests();
    _resetIpLockoutForTests();
  });

  it("still locks the (IP, username) pair after the threshold, silently", async () => {
    const deps = await seedAdmin();

    for (let i = 0; i < IP_LOCK_THRESHOLD; i += 1) {
      expect((await login(deps, IP_A, DEFAULT_ADMIN_USERNAME, "wrong")).status).toBe(401);
    }
    expect(isIpPairLocked(IP_A, DEFAULT_ADMIN_USERNAME)).toBe(true);

    // Silent lockout preserved: the right password against a locked pair still
    // answers with the wrong-password envelope, not a 429 and not a distinct code.
    const locked = await login(deps, IP_A, DEFAULT_ADMIN_USERNAME, PASSWORD);
    expect(locked.status).toBe(401);
    expect(locked.body).toEqual({
      error: { code: "invalid_credentials", message: "invalid credentials" },
    });
  });

  it("a shed request consumes none of the lockout budget", async () => {
    const deps = await seedAdmin();
    spendBudget(IP_A);

    // Every request from this IP is now shed. If the throttle double-counted into the
    // lockout, these would register failures against "bravo" and lock that pair too.
    for (let i = 0; i < IP_LOCK_THRESHOLD * 2; i += 1) {
      expect((await login(deps, IP_A, "bravo", "wrong")).status).toBe(429);
    }
    expect(isIpPairLocked(IP_A, "bravo")).toBe(false);
  });
});
