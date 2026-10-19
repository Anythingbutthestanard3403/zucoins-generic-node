// Operator retry for a signed hook delivery (ZTR-1333).

import { createHmac, randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  InMemoryWebhookDeliveryStore,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPL = "22222222-2222-4222-8222-222222222222";
const OTHER = "55555555-5555-4555-8555-555555555555";
const ORIGIN = "https://node.example";
const TOTP_SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");

function cookieFrom(setCookie: string | undefined): string {
  return setCookie?.split(";")[0] ?? "";
}

function totpNow(nowMs: number = Date.now()): string {
  const step = Math.floor(nowMs / 1000 / 30);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const hmac = createHmac("sha1", TOTP_SECRET).update(msg).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

function encodeBase32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31]!;
  return output;
}

function makeRouter(store?: InMemoryWebhookDeliveryStore) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const atomic = createTestAdminAtomicDeps(
    store === undefined ? {} : { webhookDeliveryStore: store },
  );
  return {
    userStore,
    store,
    router: createAdminRouter({
      sessions,
      userStore,
      csrf: { allowedOrigins: [ORIGIN] },
      totp: { secret: TOTP_SECRET, windowSteps: 1 },
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
      adminIdempotencyStore: atomic.adminIdempotencyStore,
      atomicAdminMutation: atomic.atomicAdminMutation,
      sendDecisionStore: {
        rejectCreated: async () => {
          throw new Error("unused");
        },
        approveCreated: async () => {
          throw new Error("unused");
        },
      },
      deviceStore: null,
      ...(store !== undefined ? { webhookDeliveryStore: store } : {}),
      recoveryStore: {
        listNeedsAttention: async () => ({ items: [], total: 0, has_more: false, next_cursor: null }),
        loadRecoveryFacts: async () => null,
        issueRecoveryNonce: async () => {
          throw new Error("unused");
        },
      },
      recoveryActionStore: {
        lookupIdempotency: async () => ({ kind: "miss" as const }),
        loadRecoveryFactsLocked: async () => null,
        commitRecoveryAction: async () => {
          throw new Error("unused");
        },
        storeIdempotency: async () => {},
      },
      destinationService: createFailClosedDestinationService(),
      newRequestId: () => randomUUID(),
      halt: {
        gate: createHaltGate(RUNNING),
        store: createInMemoryOperatorHaltStore(RUNNING),
        evidence: createInMemoryHaltEvidenceRecorder(),
      },
    }),
  };
}

async function login(router: ReturnType<typeof makeRouter>["router"], userStore: InMemoryAdminUserStore) {
  const password = "correct-horse-battery-staple";
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
  await userStore.setActiveTotpSecret(user.id, encodeBase32(TOTP_SECRET));
  const response = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: user.username, password })),
    { "content-type": "application/json" },
  );
  expect(response.status).toBe(200);
  return {
    cookie: cookieFrom(response.headers["set-cookie"]),
    csrf: (JSON.parse(response.body) as { csrfToken: string }).csrfToken,
  };
}

describe("admin hook delivery retry (ZTR-1333)", () => {
  it("resets a delivery for the same implementer and rejects a mismatch", async () => {
    const store = new InMemoryWebhookDeliveryStore();
    const saved = await store.enqueue(
      {
        nodeId: NODE_ID,
        implementerId: IMPL,
        eventType: "receive.settled",
        operationId: null,
        externalRef: null,
        occurredAt: "2026-10-19T09:00:00.000Z",
        data: { amount: "15" },
        sourceKind: "DURABLE_EVENT",
        sourceId: "33333333-3333-4333-8333-333333333333",
      },
      { sign: () => "c2ln" },
    );
    expect(saved).not.toBeNull();
    store.rows.set(saved!.delivery_id, {
      ...saved!,
      status: "FAILED_PERMANENT",
      attempt_count: 5,
      last_error: "non_success",
    });

    const { router, userStore } = makeRouter(store);
    const session = await login(router, userStore);
    const headers = {
      origin: ORIGIN,
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
      "x-zp-totp": totpNow(),
      "idempotency-key": randomUUID(),
      "content-type": "application/json",
    };
    const res = await router(
      "POST",
      `/admin/v1/connectors/${IMPL}/webhooks/${saved!.delivery_id}/retry`,
      Buffer.from("{}"),
      headers,
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as { delivery: { status: string; attempt_count: number } };
    expect(body.delivery.status).toBe("PENDING");
    expect(body.delivery.attempt_count).toBe(0);
    expect(store.rows.get(saved!.delivery_id)?.last_error).toBeNull();

    const mismatch = await router(
      "POST",
      `/admin/v1/connectors/${OTHER}/webhooks/${saved!.delivery_id}/retry`,
      Buffer.from("{}"),
      { ...headers, "idempotency-key": randomUUID(), "x-zp-totp": totpNow(Date.now() + 30_000) },
    );
    expect(mismatch.status).toBe(404);
    expect(JSON.parse(mismatch.body).error.code).toBe("not_found");
  });

  it("fails closed when the store is omitted and rejects an extra field", async () => {
    const closed = makeRouter();
    const closedSession = await login(closed.router, closed.userStore);
    const missing = await closed.router(
      "POST",
      `/admin/v1/connectors/${IMPL}/webhooks/${OTHER}/retry`,
      Buffer.from("{}"),
      {
        origin: ORIGIN,
        cookie: closedSession.cookie,
        "x-csrf-token": closedSession.csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(missing.status).toBe(503);

    const store = new InMemoryWebhookDeliveryStore();
    const open = makeRouter(store);
    const session = await login(open.router, open.userStore);
    const extra = await open.router(
      "POST",
      `/admin/v1/connectors/${IMPL}/webhooks/${OTHER}/retry`,
      Buffer.from(JSON.stringify({ note: "no" })),
      {
        origin: ORIGIN,
        cookie: session.cookie,
        "x-csrf-token": session.csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(extra.status).toBe(400);
    expect(JSON.parse(extra.body).error.code).toBe("unknown_field");
  });
});
