// POST /admin/v1/operations/:operation_id/attention-retraction HTTP surface.
// Mirrors operator-halt.test.ts's router-construction conventions for this other
// live-but-uncensused admin extension route. No Idempotency-Key on this route (see
// admin-router.ts:1358-1414) — replay safety is the store's row_version CAS, proven
// against the real store in sql-attention-retraction-store.pg.test.ts (not here: a
// fake-store HTTP replay would only prove the fake, not the CAS).

import { createHmac, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  TotpConsumptionLog,
  type AdminUser,
  type AttentionRetractionCommitResult,
  type AttentionRetractionStore,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const OPERATION_ID = "22222222-2222-4222-8222-222222222222";
const FIXED_NOW_MS = 1_700_000_030_000;

function generateTotp(secret: Uint8Array, nowMs: number): string {
  const timestep = Math.floor(nowMs / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestep));
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 1_000_000).toString().padStart(6, "0");
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
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

class FakeAttentionRetractionStore implements AttentionRetractionStore {
  constructor(private readonly result: AttentionRetractionCommitResult) {}
  calls: unknown[] = [];
  async commit(input: unknown): Promise<AttentionRetractionCommitResult> {
    this.calls.push(input);
    return this.result;
  }
}

function baseDeps() {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  return {
    userStore,
    router: (attentionRetractionStore?: AttentionRetractionStore) =>
      createAdminRouter({
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
          listNeedsAttention: async () => [],
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
        nowMs: () => FIXED_NOW_MS,
        attentionRetractionStore,
      }),
  };
}

async function loginAndGetSessionCsrf(
  router: ReturnType<ReturnType<typeof baseDeps>["router"]>,
  userStore: InMemoryAdminUserStore,
): Promise<{ cookie: string; csrf: string; user: AdminUser }> {
  const password = "attention-retraction-pass";
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
  await userStore.setActiveTotpSecret(user.id, encodeBase32(SECRET));

  const login = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: "admin", password })),
    { "content-type": "application/json" },
  );
  expect(login.status).toBe(200);
  return {
    cookie: cookieFrom(login.headers["set-cookie"]),
    csrf: (JSON.parse(login.body) as { csrfToken: string }).csrfToken,
    user,
  };
}

const REQUEST_BODY = { reason: "classifier fixed", expected_row_version: 1 };

describe("admin-router POST attention-retraction", () => {
  it("no session -> 401", async () => {
    const { router: makeRouter } = baseDeps();
    const router = makeRouter(new FakeAttentionRetractionStore({ ok: false, reason: "operation_not_found" }));
    const res = await router(
      "POST",
      `/admin/v1/operations/${OPERATION_ID}/attention-retraction`,
      Buffer.from(JSON.stringify(REQUEST_BODY)),
      { "content-type": "application/json" },
    );
    expect(res.status).toBe(401);
  });

  it("store omitted -> 503 (fails closed)", async () => {
    const { router: makeRouter, userStore } = baseDeps();
    const router = makeRouter(undefined);
    const { cookie, csrf } = await loginAndGetSessionCsrf(router, userStore);
    const nowMs = FIXED_NOW_MS;
    const res = await router(
      "POST",
      `/admin/v1/operations/${OPERATION_ID}/attention-retraction`,
      Buffer.from(JSON.stringify(REQUEST_BODY)),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(503);
  });

  it("operation_not_found -> 404", async () => {
    const { router: makeRouter, userStore } = baseDeps();
    const store = new FakeAttentionRetractionStore({ ok: false, reason: "operation_not_found" });
    const router = makeRouter(store);
    const { cookie, csrf } = await loginAndGetSessionCsrf(router, userStore);
    const nowMs = FIXED_NOW_MS;
    const res = await router(
      "POST",
      `/admin/v1/operations/${OPERATION_ID}/attention-retraction`,
      Buffer.from(JSON.stringify(REQUEST_BODY)),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(404);
  });

  it("conflict (stale expected_row_version) -> 409", async () => {
    const { router: makeRouter, userStore } = baseDeps();
    const store = new FakeAttentionRetractionStore({ ok: false, reason: "conflict" });
    const router = makeRouter(store);
    const { cookie, csrf } = await loginAndGetSessionCsrf(router, userStore);
    const nowMs = FIXED_NOW_MS;
    const res = await router(
      "POST",
      `/admin/v1/operations/${OPERATION_ID}/attention-retraction`,
      Buffer.from(JSON.stringify(REQUEST_BODY)),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(409);
  });

  it("not_flagged (already retracted / never flagged) -> 422", async () => {
    const { router: makeRouter, userStore } = baseDeps();
    const store = new FakeAttentionRetractionStore({ ok: false, reason: "not_flagged" });
    const router = makeRouter(store);
    const { cookie, csrf } = await loginAndGetSessionCsrf(router, userStore);
    const nowMs = FIXED_NOW_MS;
    const res = await router(
      "POST",
      `/admin/v1/operations/${OPERATION_ID}/attention-retraction`,
      Buffer.from(JSON.stringify(REQUEST_BODY)),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(422);
  });

  it("happy path -> 200 with operation_id/row_version/retracted_at/prior_attention_reason", async () => {
    const { router: makeRouter, userStore } = baseDeps();
    const store = new FakeAttentionRetractionStore({
      ok: true,
      rowVersion: 2,
      retractedAt: "2026-08-02T00:00:00.000Z",
      priorAttentionReason: "classifier flagged this",
    });
    const router = makeRouter(store);
    const { cookie, csrf, user } = await loginAndGetSessionCsrf(router, userStore);
    const nowMs = FIXED_NOW_MS;
    const res = await router(
      "POST",
      `/admin/v1/operations/${OPERATION_ID}/attention-retraction`,
      Buffer.from(JSON.stringify({ reason: "classifier fixed", expected_row_version: 1, superseded_by: "classifier-v2" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({
      operation_id: OPERATION_ID,
      row_version: 2,
      retracted_at: "2026-08-02T00:00:00.000Z",
      prior_attention_reason: "classifier flagged this",
    });
    expect(store.calls).toEqual([
      {
        operationId: OPERATION_ID,
        reason: "classifier fixed",
        supersededBy: "classifier-v2",
        expectedRowVersion: 1,
        actorId: user.id,
      },
    ]);
  });

  // C2 (plan review): a naive blind replay of an already-succeeded retraction is NOT
  // proven safe by a fake-store HTTP test — the fake always returns whatever result it
  // was constructed with, so "replay -> 422" here would only prove the fake, not the
  // real CAS. That double-effect proof lives in sql-attention-retraction-store.pg.test.ts
  // ("replaying the identical retraction after success returns not_flagged, not
  // conflict"), against the real store. Do not add a replay case to this file.
});
