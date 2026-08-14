// Admin routes for auto-approve policy (ZTR-1237).

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
  InMemoryDeviceSignaturePolicy,
  InMemoryDualControlPolicy,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const IMP_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

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
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31]!;
  }
  return output;
}

function validRule(over: Record<string, unknown> = {}) {
  return {
    rule_id: "r1",
    implementer_id: IMP_A,
    per_send_max_zkz: "10",
    per_send_min_zkz: null,
    window_hours: 24,
    window_cap_zkz: "100",
    expires_at: null,
    enabled: true,
    ...over,
  };
}

function makeRouter(opts?: {
  omitAutoApprovePolicy?: boolean;
  autoApprovePolicy?: InMemoryAutoApprovePolicy;
  windowSpend?: string;
}) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const autoApprovePolicy =
    opts?.autoApprovePolicy ?? new InMemoryAutoApprovePolicy();
  const dualControlPolicy = new InMemoryDualControlPolicy("single_operator");
  const deviceSignaturePolicy = new InMemoryDeviceSignaturePolicy("optional");
  const omit = opts?.omitAutoApprovePolicy === true;
  const spend = opts?.windowSpend ?? "0";

  const router = createAdminRouter({
    sessions,
    userStore,
    csrf: { allowedOrigins: [ORIGIN] },
    totp: {
      secret: new TextEncoder().encode("test-secret-key-32-bytes-long!!"),
      windowSteps: 1,
    },
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
      dualControlPolicy,
      deviceSignaturePolicy,
      ...(omit ? {} : { autoApprovePolicy }),
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
    dualControlPolicy,
    deviceSignaturePolicy,
    ...(omit ? {} : { autoApprovePolicy }),
    ...(omit
      ? {}
      : {
          queryAutoApproveWindowSpend: async () => spend,
        }),
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
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
  });

  return { router, userStore, autoApprovePolicy };
}

async function login(
  router: ReturnType<typeof makeRouter>["router"],
  userStore: InMemoryAdminUserStore,
) {
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
    userId: user.id,
  };
}

describe("auto-approve policy admin routes (ZTR-1237)", () => {
  it("GET without port surfaces disabled/absent", async () => {
    const { router, userStore } = makeRouter({ omitAutoApprovePolicy: true });
    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/auto-approve-policy", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      status: string;
      disabledReason: string;
      rules: unknown[];
    };
    expect(body.status).toBe("disabled");
    expect(body.disabledReason).toBe("absent");
    expect(body.rules).toEqual([]);
  });

  it("GET returns rules enriched with window spend", async () => {
    const policy = new InMemoryAutoApprovePolicy();
    policy.setPolicy(
      JSON.stringify({ enabled: true, rules: [validRule()] }),
      { actorId: "seed", nodeId: NODE_ID },
    );
    const { router, userStore } = makeRouter({
      autoApprovePolicy: policy,
      windowSpend: "37.2",
    });
    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/auto-approve-policy", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      status: string;
      rules: Array<{ current_window_spend_zkz: string; rule_id: string }>;
      server_time: string;
    };
    expect(body.status).toBe("enabled");
    expect(body.rules).toHaveLength(1);
    expect(body.rules[0]?.rule_id).toBe("r1");
    expect(body.rules[0]?.current_window_spend_zkz).toBe("37.2");
    expect(typeof body.server_time).toBe("string");
  });

  it("POST persists valid document under fresh TOTP", async () => {
    const { router, userStore, autoApprovePolicy } = makeRouter();
    const auth = await login(router, userStore);
    const doc = { enabled: true, rules: [validRule({ rule_id: "posted" })] };
    const res = await router(
      "POST",
      "/admin/v1/auto-approve-policy",
      Buffer.from(JSON.stringify(doc)),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
        "idempotency-key": randomUUID(),
        "x-zp-totp": totpNow(),
      },
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      status: string;
      rules: Array<{ rule_id: string }>;
    };
    expect(body.status).toBe("enabled");
    expect(body.rules[0]?.rule_id).toBe("posted");
    const stored = autoApprovePolicy.getPolicy();
    expect(stored.status).toBe("enabled");
    if (stored.status === "enabled") {
      expect(stored.rules[0]?.rule_id).toBe("posted");
    }
    expect(autoApprovePolicy.auditEntries).toHaveLength(1);
  });

  it("POST invalid document is 422 and stores nothing", async () => {
    const { router, userStore, autoApprovePolicy } = makeRouter();
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/auto-approve-policy",
      Buffer.from(JSON.stringify({ enabled: true, rules: [{ bad: true }] })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
        "idempotency-key": randomUUID(),
        "x-zp-totp": totpNow(),
      },
    );
    expect(res.status).toBe(422);
    expect(autoApprovePolicy.getPolicy()).toEqual({
      status: "disabled",
      disabledReason: "absent",
    });
    expect(autoApprovePolicy.auditEntries).toHaveLength(0);
  });

  it("POST without TOTP is refused", async () => {
    const { router, userStore, autoApprovePolicy } = makeRouter();
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/auto-approve-policy",
      Buffer.from(JSON.stringify({ enabled: true, rules: [validRule()] })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
        "idempotency-key": randomUUID(),
      },
    );
    expect(res.status).toBeGreaterThanOrEqual(401);
    expect(res.status).toBeLessThan(500);
    expect(autoApprovePolicy.getPolicy().status).toBe("disabled");
  });

  it("idempotent replay returns identical bytes without second setPolicy", async () => {
    const { router, userStore, autoApprovePolicy } = makeRouter();
    const auth = await login(router, userStore);
    const idem = randomUUID();
    const doc = { enabled: true, rules: [validRule({ rule_id: "idem" })] };
    const headers = {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
      "content-type": "application/json",
      "idempotency-key": idem,
      "x-zp-totp": totpNow(),
    };
    const first = await router(
      "POST",
      "/admin/v1/auto-approve-policy",
      Buffer.from(JSON.stringify(doc)),
      headers,
    );
    expect(first.status).toBe(200);
    expect(autoApprovePolicy.auditEntries).toHaveLength(1);

    // Second call: same key+body. TOTP may be burned; replay must short-circuit
    // before a second mutation (and must not require a fresh code).
    const second = await router(
      "POST",
      "/admin/v1/auto-approve-policy",
      Buffer.from(JSON.stringify(doc)),
      {
        ...headers,
        "x-zp-totp": totpNow(Date.now() + 60_000),
      },
    );
    expect(second.status).toBe(200);
    expect(second.body).toBe(first.body);
    expect(second.headers["idempotency-replayed"]).toBe("true");
    expect(autoApprovePolicy.auditEntries).toHaveLength(1);
  });
});
