// Admin routes for allow-node-verified policy (ZTR-1305).

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
  InMemoryAllowNodeVerifiedPolicy,
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

function makeRouter(opts?: {
  omitPolicy?: boolean;
  policy?: InMemoryAllowNodeVerifiedPolicy;
}) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const allowNodeVerifiedPolicy = opts?.policy ?? new InMemoryAllowNodeVerifiedPolicy();
  const dualControlPolicy = new InMemoryDualControlPolicy("single_operator");
  const deviceSignaturePolicy = new InMemoryDeviceSignaturePolicy("optional");
  const omit = opts?.omitPolicy === true;

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
      ...(omit ? {} : { allowNodeVerifiedPolicy }),
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
    ...(omit ? {} : { allowNodeVerifiedPolicy }),
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

  return { router, userStore, allowNodeVerifiedPolicy };
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

describe("allow-node-verified policy admin routes (ZTR-1305)", () => {
  it("GET without port surfaces disabled/absent", async () => {
    const { router, userStore } = makeRouter({ omitPolicy: true });
    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/allow-node-verified-policy", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      status: string;
      disabledReason: string;
      implementers: unknown[];
    };
    expect(body.status).toBe("disabled");
    expect(body.disabledReason).toBe("absent");
    expect(body.implementers).toEqual([]);
  });

  it("GET returns enabled document", async () => {
    const policy = new InMemoryAllowNodeVerifiedPolicy();
    policy.allowImplementer(IMP_A);
    const { router, userStore } = makeRouter({ policy });
    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/allow-node-verified-policy", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      status: string;
      implementers: Array<{ implementer_id: string; enabled: boolean }>;
      server_time: string;
    };
    expect(body.status).toBe("enabled");
    expect(body.implementers).toEqual([{ implementer_id: IMP_A, enabled: true }]);
    expect(typeof body.server_time).toBe("string");
  });

  it("POST persists valid document under fresh TOTP", async () => {
    const { router, userStore, allowNodeVerifiedPolicy } = makeRouter();
    const auth = await login(router, userStore);
    const doc = {
      enabled: true,
      implementers: [{ implementer_id: IMP_A, enabled: true }],
    };
    const res = await router(
      "POST",
      "/admin/v1/allow-node-verified-policy",
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
      implementers: Array<{ implementer_id: string }>;
    };
    expect(body.status).toBe("enabled");
    expect(body.implementers[0]?.implementer_id).toBe(IMP_A);
    const stored = allowNodeVerifiedPolicy.getPolicy();
    expect(stored.status).toBe("enabled");
    expect(allowNodeVerifiedPolicy.auditEntries).toHaveLength(1);
  });

  it("POST invalid document is 422 and stores nothing", async () => {
    const { router, userStore, allowNodeVerifiedPolicy } = makeRouter();
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/allow-node-verified-policy",
      Buffer.from(JSON.stringify({ enabled: true, implementers: [{ bad: true }] })),
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
    expect(allowNodeVerifiedPolicy.getPolicy()).toEqual({
      status: "disabled",
      disabledReason: "absent",
    });
    expect(allowNodeVerifiedPolicy.auditEntries).toHaveLength(0);
  });

  it("POST without TOTP is refused", async () => {
    const { router, userStore, allowNodeVerifiedPolicy } = makeRouter();
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/allow-node-verified-policy",
      Buffer.from(
        JSON.stringify({
          enabled: true,
          implementers: [{ implementer_id: IMP_A, enabled: true }],
        }),
      ),
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
    expect(allowNodeVerifiedPolicy.getPolicy().status).toBe("disabled");
  });

  it("POST disable then isNodeVerifiedAllowed is false (fail-closed, no stale allow)", async () => {
    const { router, userStore, allowNodeVerifiedPolicy } = makeRouter();
    allowNodeVerifiedPolicy.allowImplementer(IMP_A);
    expect(allowNodeVerifiedPolicy.isNodeVerifiedAllowed(IMP_A)).toBe(true);
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/allow-node-verified-policy",
      Buffer.from(
        JSON.stringify({
          enabled: false,
          implementers: [{ implementer_id: IMP_A, enabled: true }],
        }),
      ),
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
    expect(allowNodeVerifiedPolicy.isNodeVerifiedAllowed(IMP_A)).toBe(false);
  });
});
