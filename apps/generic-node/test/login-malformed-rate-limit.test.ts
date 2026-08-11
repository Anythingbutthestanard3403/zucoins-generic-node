/**
 * ZTR-1218 — malformed-JSON POST /admin/v1/login bodies share the login volume
 * throttle with well-formed ones. The pre-decode chokepoint in admin-router is
 * the single production call site for consumeLoginAttempt.
 */
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  LOGIN_RATE_MAX_REQUESTS,
  LOGIN_RATE_WINDOW_MS,
  _resetLoginRateLimitForTests,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter, createFailClosedAdminRouteDeps } from "../src/admin-router.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";

async function seedAdmin(store: InMemoryAdminUserStore, password: string): Promise<AdminUser> {
  const user: AdminUser = {
    id: randomUUID(),
    username: "admin",
    passwordHash: await hashPassword(password),
    role: "admin",
    mustChangePassword: false,
    mustEnrolTotp: false,
    disabledAt: null,
    createdAt: Date.now(),
  };
  await store.insert(user);
  return user;
}

function buildRouter(userStore: InMemoryAdminUserStore) {
  const sessionStore = new InMemoryAdminSessionStore();
  const sessions = createAdminSessionService({ nodeId: NODE_ID }, sessionStore, userStore);
  const deps = createFailClosedAdminRouteDeps({
    sessions,
    userStore,
    csrf: { allowedOrigins: ["https://node.example"] },
    totp: { secret: new Uint8Array(32), windowSteps: 1 },
    nodeId: NODE_ID,
    destinationService: createFailClosedDestinationService(),
    newRequestId: () => randomUUID(),
  });
  return { router: createAdminRouter(deps) };
}

describe("ZTR-1218 malformed login body volume throttle", () => {
  beforeEach(() => {
    _resetLoginRateLimitForTests();
    // Fixed-window limiter keys Math.floor(Date.now()/windowMs). Shared-budget
    // cases spend ~half the budget on real bcrypt wrong-password compares and
    // can cross a real 60s bucket mid-case under load — pin the clock so the
    // suite measures the ceiling, not wall-clock placement (same pattern as
    // packages/node-core/test/login-rate-limit.test.ts).
    vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    _resetLoginRateLimitForTests();
  });

  it("flood of malformed JSON bodies is shed with 429 after the per-IP budget", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "pw-malformed-rl");
    const { router } = buildRouter(userStore);
    const remote = "203.0.113.77";
    const headers = { "content-type": "application/json" };
    // Not valid JSON — decodeBody throws before handleAdminLogin.
    const bad = Buffer.from("{not-json");

    const statuses: number[] = [];
    for (let i = 0; i < LOGIN_RATE_MAX_REQUESTS; i += 1) {
      const res = await router("POST", "/admin/v1/login", bad, headers, remote);
      statuses.push(res.status);
    }
    // Every in-budget malformed body is a validation 400, never a silent drop.
    expect(new Set(statuses)).toEqual(new Set([400]));

    const shed = await router("POST", "/admin/v1/login", bad, headers, remote);
    expect(shed.status).toBe(429);
    expect(shed.headers["retry-after"]).toBe(String(LOGIN_RATE_WINDOW_MS / 1000));
    const body = JSON.parse(shed.body) as { error?: { code?: string } };
    expect(body.error?.code).toBe("rate_limited");
  });

  it("malformed and well-formed bodies share one per-IP budget (no second limiter)", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "pw-shared-rl");
    const { router } = buildRouter(userStore);
    const remote = "203.0.113.78";
    const headers = { "content-type": "application/json" };
    const bad = Buffer.from("not-json-at-all");
    const well = Buffer.from(JSON.stringify({ username: "admin", password: "wrong" }));

    // Spend half the budget on malformed, half-1 on well-formed, then one more of each shape.
    const half = Math.floor(LOGIN_RATE_MAX_REQUESTS / 2);
    for (let i = 0; i < half; i += 1) {
      expect((await router("POST", "/admin/v1/login", bad, headers, remote)).status).toBe(400);
    }
    for (let i = 0; i < LOGIN_RATE_MAX_REQUESTS - half - 1; i += 1) {
      // wrong password → 401; still spends one unit at the pre-decode chokepoint
      expect((await router("POST", "/admin/v1/login", well, headers, remote)).status).toBe(401);
    }
    // Last in-budget unit via malformed
    expect((await router("POST", "/admin/v1/login", bad, headers, remote)).status).toBe(400);
    // Next of either shape is shed — shared budget, single limiter
    expect((await router("POST", "/admin/v1/login", bad, headers, remote)).status).toBe(429);
    expect((await router("POST", "/admin/v1/login", well, headers, remote)).status).toBe(429);
  });

  it("keys on socket-peer remoteAddress, not X-Forwarded-For", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "pw-xff-rl");
    const { router } = buildRouter(userStore);
    const peer = "203.0.113.79";
    const forged = "198.51.100.50";
    const bad = Buffer.from("{");
    // Exhaust the real peer budget while advertising a rotating forged XFF.
    for (let i = 0; i < LOGIN_RATE_MAX_REQUESTS; i += 1) {
      const res = await router(
        "POST",
        "/admin/v1/login",
        bad,
        { "content-type": "application/json", "x-forwarded-for": `${forged},${i}` },
        peer,
      );
      expect(res.status).toBe(400);
    }
    const shed = await router(
      "POST",
      "/admin/v1/login",
      bad,
      { "content-type": "application/json", "x-forwarded-for": forged },
      peer,
    );
    expect(shed.status).toBe(429);
    // A different socket peer is unaffected even if it claims the exhausted XFF.
    const other = await router(
      "POST",
      "/admin/v1/login",
      bad,
      { "content-type": "application/json", "x-forwarded-for": peer },
      "203.0.113.80",
    );
    expect(other.status).toBe(400);
  });
});
