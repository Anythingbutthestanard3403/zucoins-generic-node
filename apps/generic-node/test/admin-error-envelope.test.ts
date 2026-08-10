/**
 * ZTR-1196 — every admin non-2xx body parses as AdminErrorEnvelopeSchema
 * (details present, code ∈ ADMIN_ERROR_CODES).
 */
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  AdminErrorEnvelopeSchema,
  ADMIN_ERROR_CODE_SET,
} from "@zucoins/generic-node-contracts/admin-auth-errors";
import {
  ADMIN_SESSION_COOKIE,
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
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

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  const part = setCookie.split(";")[0] ?? "";
  return part;
}

describe("admin error envelope (ZTR-1196)", () => {
  it("401 unauthenticated inventory GET carries details + frozen code", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "pw-envelope-1");
    const { router } = buildRouter(userStore);
    const res = await router("GET", "/admin/v1/operations", new Uint8Array(), {});
    expect(res.status).toBe(401);
    const raw = JSON.parse(res.body) as unknown;
    const parsed = AdminErrorEnvelopeSchema.safeParse(raw);
    expect(parsed.success, JSON.stringify(raw)).toBe(true);
    if (parsed.success) {
      expect(parsed.data.error.details).toEqual({});
      expect(ADMIN_ERROR_CODE_SET.has(parsed.data.error.code)).toBe(true);
      expect(parsed.data.error.code).toBe("invalid_credentials");
    }
  });

  it("404 unknown admin route carries details + not_found", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "pw-envelope-2");
    const { router } = buildRouter(userStore);
    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password: "pw-envelope-2" })),
      { "content-type": "application/json" },
    );
    expect(login.status).toBe(200);
    const cookie = cookieFrom(login.headers["set-cookie"]);
    expect(cookie).toContain(ADMIN_SESSION_COOKIE);
    const res = await router("GET", "/admin/v1/definitely-not-a-route", new Uint8Array(), {
      cookie,
    });
    expect(res.status).toBe(404);
    const raw = JSON.parse(res.body) as unknown;
    const parsed = AdminErrorEnvelopeSchema.safeParse(raw);
    expect(parsed.success, JSON.stringify(raw)).toBe(true);
    if (parsed.success) {
      expect(parsed.data.error.code).toBe("not_found");
      expect(parsed.data.error.details).toEqual({});
    }
  });

  it("login validation error is canonical envelope", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "pw-envelope-3");
    const { router } = buildRouter(userStore);
    const res = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "", password: "" })),
      { "content-type": "application/json" },
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
    const raw = JSON.parse(res.body) as unknown;
    const parsed = AdminErrorEnvelopeSchema.safeParse(raw);
    expect(parsed.success, JSON.stringify(raw)).toBe(true);
    if (parsed.success) {
      expect(parsed.data.error.details).toEqual({});
      expect(ADMIN_ERROR_CODE_SET.has(parsed.data.error.code)).toBe(true);
    }
  });

  it("unauthenticated me returns envelope via fromAuthResult path", async () => {
    const userStore = new InMemoryAdminUserStore();
    const { router } = buildRouter(userStore);
    const res = await router("GET", "/admin/v1/me", new Uint8Array(), {});
    expect(res.status).toBe(401);
    const raw = JSON.parse(res.body) as unknown;
    const parsed = AdminErrorEnvelopeSchema.safeParse(raw);
    expect(parsed.success, JSON.stringify(raw)).toBe(true);
  });
});
