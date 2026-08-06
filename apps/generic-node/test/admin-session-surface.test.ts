// Session bootstrap surface: login/me/logout/password for the operator SPA.
// Money routes stay under fail-closed engines without ADMIN_TOTP_SECRET.

import {
  ADMIN_SESSION_COOKIE,
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  type AdminUser,
} from "@zucoins/node-core";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
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

function buildRouter(userStore: InMemoryAdminUserStore, sessionStore = new InMemoryAdminSessionStore()) {
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
  return { router: createAdminRouter(deps), sessions, sessionStore };
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  const part = setCookie.split(";")[0] ?? "";
  return part;
}

describe("admin-router session surface (SPA contract)", () => {
  it("POST /admin/v1/login sets session cookie and posture body", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-1");
    const { router } = buildRouter(userStore);
    const res = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password: "bootstrap-secret-1" })),
      { "content-type": "application/json" },
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      userId: string;
      username: string;
      csrfToken: string;
      mustChangePassword: boolean;
    };
    expect(body.username).toBe("admin");
    expect(body.csrfToken.length).toBeGreaterThan(8);
    expect(res.headers["set-cookie"] ?? "").toContain(ADMIN_SESSION_COOKIE);
  });

  it("GET /admin/v1/me returns session posture with cookie", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-2");
    const { router } = buildRouter(userStore);
    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password: "bootstrap-secret-2" })),
      {},
    );
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const me = await router("GET", "/admin/v1/me", new Uint8Array(), { cookie });
    expect(me.status).toBe(200);
    const body = JSON.parse(me.body) as { username: string; csrfToken: string };
    expect(body.username).toBe("admin");
    expect(body.csrfToken.length).toBeGreaterThan(0);
  });

  it("POST /admin/v1/logout revokes session with CSRF", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-3");
    const { router } = buildRouter(userStore);
    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password: "bootstrap-secret-3" })),
      {},
    );
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;
    const out = await router("POST", "/admin/v1/logout", new Uint8Array(), {
      cookie,
      "x-csrf-token": csrf,
    });
    expect(out.status).toBe(200);
    const me = await router("GET", "/admin/v1/me", new Uint8Array(), { cookie });
    expect(me.status).toBe(401);
  });

  it("GET /admin/v1/operations/needs-attention empty under fail-closed recovery", async () => {
    const userStore = new InMemoryAdminUserStore();
    const user = await seedAdmin(userStore, "bootstrap-secret-4");
    // Money-adjacent gates require an active factor (not just mustEnrolTotp=false).
    await userStore.setActiveTotpSecret(user.id, "JBSWY3DPEHPK3PXP");
    const { router } = buildRouter(userStore);
    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password: "bootstrap-secret-4" })),
      {},
    );
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const list = await router("GET", "/admin/v1/operations/needs-attention", new Uint8Array(), {
      cookie,
    });
    expect(list.status).toBe(200);
    const body = JSON.parse(list.body) as { operations: unknown[]; summary: { total: number } };
    expect(body.operations).toEqual([]);
    expect(body.summary.total).toBe(0);
  });
});
