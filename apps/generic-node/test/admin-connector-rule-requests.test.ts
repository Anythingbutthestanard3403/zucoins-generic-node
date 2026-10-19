// Operator inbox for spend-rule requests (ZTR-1331).

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
  InMemoryAutoApprovePolicy,
  InMemoryConnectorRuleRequestStore,
  RUNNING,
  TotpConsumptionLog,
  evaluateAutoApproveRule,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPL = "22222222-2222-4222-8222-222222222222";
const ORIGIN = "https://node.example";

function cookieFrom(setCookie: string | undefined): string {
  return setCookie?.split(";")[0] ?? "";
}

const TOTP_SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");

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

function makeRouter(opts?: {
  readonly store?: InMemoryConnectorRuleRequestStore;
  readonly policy?: InMemoryAutoApprovePolicy;
  readonly omitStore?: boolean;
}) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const store = opts?.omitStore === true ? undefined : (opts?.store ?? new InMemoryConnectorRuleRequestStore());
  const policy = opts?.policy ?? new InMemoryAutoApprovePolicy();
  const router = createAdminRouter({
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
    ...createTestAdminAtomicDeps({
      autoApprovePolicy: policy,
      ...(store !== undefined ? { connectorRuleRequestStore: store } : {}),
    }),
    sendDecisionStore: {
      rejectCreated: async () => {
        throw new Error("unused");
      },
      approveCreated: async () => {
        throw new Error("unused");
      },
    },
    deviceStore: null,
    autoApprovePolicy: policy,
    ...(store !== undefined ? { connectorRuleRequestStore: store } : {}),
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
  });
  return { router, userStore, store, policy };
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

async function seedRequest(store: InMemoryConnectorRuleRequestStore) {
  return store.create({
    nodeId: NODE_ID,
    implementerId: IMPL,
    ruleId: "winter-promo-2026",
    label: "Winter Promo",
    reserveWalletId: null,
    totalCapZkz: "200",
    perSendMaxZkz: "20",
    perSendMinZkz: null,
    windowHours: 24,
    windowCapZkz: "100",
    expiresAt: null,
    webhookEnabled: false,
    actorId: IMPL,
  });
}

describe("admin connector rule requests (ZTR-1331)", () => {
  it("admits a pending rule so a later send matches", async () => {
    const store = new InMemoryConnectorRuleRequestStore();
    const policy = new InMemoryAutoApprovePolicy();
    policy.setPolicy(JSON.stringify({ enabled: true, rules: [] }), { actorId: IMPL, nodeId: NODE_ID });
    const pending = await seedRequest(store);
    const before = evaluateAutoApproveRule(policy.getPolicy(), {
      implementerId: IMPL,
      amountZkz: "15",
      requestedRuleId: "winter-promo-2026",
    });
    expect(before).toEqual({ decision: "fall_through", reason: "no_rule" });

    const { router, userStore } = makeRouter({ store, policy });
    const session = await login(router, userStore);
    const listed = await router("GET", "/admin/v1/connector-rules/requests?status=PENDING", new Uint8Array(), {
      origin: ORIGIN,
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
    });
    expect(listed.status).toBe(200);
    expect(JSON.parse(listed.body).requests).toHaveLength(1);

    const res = await router(
      "POST",
      `/admin/v1/connector-rules/requests/${pending.request_id}/approve`,
      Buffer.from("{}"),
      {
        origin: ORIGIN,
        cookie: session.cookie,
        "x-csrf-token": session.csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).request.status).toBe("APPROVED");
    const after = evaluateAutoApproveRule(policy.getPolicy(), {
      implementerId: IMPL,
      amountZkz: "15",
      requestedRuleId: "winter-promo-2026",
    });
    expect(after.decision).toBe("approve");
    if (after.decision === "approve") {
      expect(after.rule.rule_id).toBe("winter-promo-2026");
      expect(after.rule.label).toBe("Winter Promo");
      expect(after.rule.total_cap_zkz).toBe("200");
      expect(after.rule.per_send_max_zkz).toBe("20");
      expect(after.rule.window_hours).toBe(24);
      expect(after.rule.window_cap_zkz).toBe("100");
    }
  });

  it("declines a pending rule and leaves the policy unmatched", async () => {
    const store = new InMemoryConnectorRuleRequestStore();
    const policy = new InMemoryAutoApprovePolicy();
    policy.setPolicy(JSON.stringify({ enabled: true, rules: [] }), { actorId: IMPL, nodeId: NODE_ID });
    const pending = await seedRequest(store);
    const { router, userStore } = makeRouter({ store, policy });
    const session = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/connector-rules/requests/${pending.request_id}/reject`,
      Buffer.from("{}"),
      {
        origin: ORIGIN,
        cookie: session.cookie,
        "x-csrf-token": session.csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).request.status).toBe("REJECTED");
    const decision = evaluateAutoApproveRule(policy.getPolicy(), {
      implementerId: IMPL,
      amountZkz: "15",
      requestedRuleId: "winter-promo-2026",
    });
    expect(decision).toEqual({ decision: "fall_through", reason: "no_rule" });
  });

  it("fails closed when the store is omitted and rejects an unknown status", async () => {
    const closed = makeRouter({ omitStore: true });
    const closedSession = await login(closed.router, closed.userStore);
    const missing = await closed.router("GET", "/admin/v1/connector-rules/requests", new Uint8Array(), {
      origin: ORIGIN,
      cookie: closedSession.cookie,
      "x-csrf-token": closedSession.csrf,
    });
    expect(missing.status).toBe(503);

    const open = makeRouter();
    const session = await login(open.router, open.userStore);
    const bad = await open.router("GET", "/admin/v1/connector-rules/requests?status=NOPE", new Uint8Array(), {
      origin: ORIGIN,
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
    });
    expect(bad.status).toBe(400);
    expect(JSON.parse(bad.body).error.code).toBe("invalid_scalar");
  });
});
