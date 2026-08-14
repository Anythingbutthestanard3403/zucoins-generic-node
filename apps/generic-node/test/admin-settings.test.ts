// GET /admin/v1/settings — secret-safe effective config.

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import {
  EFFECTIVE_CONFIG_ALLOWLIST_KEYS,
  findForbiddenKeys,
} from "../src/config/effective-config.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const ALLOW = new Set<string>(EFFECTIVE_CONFIG_ALLOWLIST_KEYS);

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

async function loginRouter() {
  const userStore = new InMemoryAdminUserStore();
  const password = "settings-pass-12";
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
  await userStore.insert(user);
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const router = createAdminRouter({
    sessions,
    userStore,
    csrf: { allowedOrigins: [ORIGIN] },
    totp: { secret: SECRET, windowSteps: 1 },
    totpLog: new TotpConsumptionLog(),
    nodeId: NODE_ID,
    challengeStore: {
      findIssuedByOperation: async () => null,
      findByNonce: async () => null,
      insertIssued: async () => {},
      commitApprovalMutation: async () => {
        throw new Error("unused");
      },
    },
    loadOperation: async () => null,
    sendDecisionStore: {
      rejectCreated: async () => {
        throw new Error("unused");
      },
      approveCreated: async () => {
        throw new Error("unused");
      },
    },
    deviceStore: null,
    recoveryStore: {
      listNeedsAttention: async () => ({ items: [], total: 0, has_more: false, next_cursor: null }),
      loadRecoveryFacts: async () => null,
      issueRecoveryNonce: async () => {
        throw new Error("unused");
      },
    },
    recoveryActionStore: {
      lookupIdempotency: async () => ({ kind: "miss" }),
      loadRecoveryFactsLocked: async () => null,
      commitRecoveryAction: async () => {
        throw new Error("unused");
      },
      storeIdempotency: async () => {},
    },
    destinationService: createFailClosedDestinationService(),
    newRequestId: () => randomUUID(),
    effectiveConfig: {
      publicBaseUrl: "https://node.example",
      nodeId: NODE_ID,
      gatewayUrls: ["https://gw.splitchain.example/v1"],
      version: "0.0.0-test",
      backupScheduleEnabled: true,
      pushConfigured: true,
    },
  });

  const login = await router(
    "POST",
    "/admin/v1/login",
    new TextEncoder().encode(JSON.stringify({ username: "admin", password })),
    { origin: ORIGIN, "content-type": "application/json" },
  );
  expect(login.status).toBe(200);
  const cookie = cookieFrom(login.headers["set-cookie"]);
  expect(cookie).toMatch(/session=/);
  return { router, cookie };
}

describe("GET /admin/v1/settings", () => {
  it("requires session", async () => {
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    const router = createAdminRouter({
      sessions,
      userStore,
      csrf: { allowedOrigins: [ORIGIN] },
      totp: { secret: SECRET, windowSteps: 1 },
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE_ID,
      challengeStore: {
        findIssuedByOperation: async () => null,
        findByNonce: async () => null,
        insertIssued: async () => {},
        commitApprovalMutation: async () => {
          throw new Error("unused");
        },
      },
      loadOperation: async () => null,
      sendDecisionStore: {
        rejectCreated: async () => {
          throw new Error("unused");
        },
        approveCreated: async () => {
          throw new Error("unused");
        },
      },
      deviceStore: null,
      recoveryStore: {
        listNeedsAttention: async () => ({ items: [], total: 0, has_more: false, next_cursor: null }),
        loadRecoveryFacts: async () => null,
        issueRecoveryNonce: async () => {
          throw new Error("unused");
        },
      },
      recoveryActionStore: {
        lookupIdempotency: async () => ({ kind: "miss" }),
        loadRecoveryFactsLocked: async () => null,
        commitRecoveryAction: async () => {
          throw new Error("unused");
        },
        storeIdempotency: async () => {},
      },
      destinationService: createFailClosedDestinationService(),
      newRequestId: () => randomUUID(),
      effectiveConfig: {
        publicBaseUrl: "https://node.example",
        nodeId: NODE_ID,
        gatewayUrls: [],
        version: "0",
        backupScheduleEnabled: false,
        pushConfigured: false,
      },
    });
    const res = await router("GET", "/admin/v1/settings", new Uint8Array(), {});
    expect(res.status).toBe(401);
  });

  it("returns allowlisted DTO matching wired process values", async () => {
    const { router, cookie } = await loginRouter();
    const res = await router("GET", "/admin/v1/settings", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as Record<string, unknown>;
    expect(body).toEqual({
      public_base_url: "https://node.example",
      node_id: NODE_ID,
      gateway_hosts: ["gw.splitchain.example"],
      version: "0.0.0-test",
      backup_schedule_enabled: true,
      push_configured: true,
    });
    expect(Object.keys(body).sort()).toEqual([...EFFECTIVE_CONFIG_ALLOWLIST_KEYS].sort());
    expect(findForbiddenKeys(body, { topLevelAllowlist: ALLOW })).toEqual([]);
  });

  it("fails closed with 503 when effectiveConfig is not wired", async () => {
    const userStore = new InMemoryAdminUserStore();
    const password = "settings-pass-12";
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
    await userStore.insert(user);
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    const router = createAdminRouter({
      sessions,
      userStore,
      csrf: { allowedOrigins: [ORIGIN] },
      totp: { secret: SECRET, windowSteps: 1 },
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE_ID,
      challengeStore: {
        findIssuedByOperation: async () => null,
        findByNonce: async () => null,
        insertIssued: async () => {},
        commitApprovalMutation: async () => {
          throw new Error("unused");
        },
      },
      loadOperation: async () => null,
      sendDecisionStore: {
        rejectCreated: async () => {
          throw new Error("unused");
        },
        approveCreated: async () => {
          throw new Error("unused");
        },
      },
      deviceStore: null,
      recoveryStore: {
        listNeedsAttention: async () => ({ items: [], total: 0, has_more: false, next_cursor: null }),
        loadRecoveryFacts: async () => null,
        issueRecoveryNonce: async () => {
          throw new Error("unused");
        },
      },
      recoveryActionStore: {
        lookupIdempotency: async () => ({ kind: "miss" }),
        loadRecoveryFactsLocked: async () => null,
        commitRecoveryAction: async () => {
          throw new Error("unused");
        },
        storeIdempotency: async () => {},
      },
      destinationService: createFailClosedDestinationService(),
      newRequestId: () => randomUUID(),
      // effectiveConfig omitted
    });
    const login = await router(
      "POST",
      "/admin/v1/login",
      new TextEncoder().encode(JSON.stringify({ username: "admin", password })),
      { origin: ORIGIN, "content-type": "application/json" },
    );
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const res = await router("GET", "/admin/v1/settings", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
    });
    expect(res.status).toBe(503);
  });

  it("rejects POST (read-only — no secret edit creep)", async () => {
    const { router, cookie } = await loginRouter();
    const res = await router(
      "POST",
      "/admin/v1/settings",
      new TextEncoder().encode(JSON.stringify({ public_base_url: "https://evil.example" })),
      {
        cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": "dummy",
      },
    );
    // No POST handler — 404 not_found (or 403 csrf). Must not be 2xx.
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).not.toBe(200);
  });
});
