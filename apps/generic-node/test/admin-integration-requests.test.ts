// Admin routes for integration-request approve inbox (ZTR-1240).

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
  InMemoryImplementerRegistry,
  InMemoryIntegrationRequestStore,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
  type IntegrationRequestRecord,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const REQ_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

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
    rule_id: "r-integration",
    per_send_max_zkz: "10",
    per_send_min_zkz: null,
    window_hours: 24,
    window_cap_zkz: "100",
    expires_at: null,
    enabled: true,
    ...over,
  };
}

function pendingRow(over: Partial<IntegrationRequestRecord> = {}): IntegrationRequestRecord {
  return {
    id: REQ_ID,
    node_id: NODE_ID,
    display_name: "Platform Alpha",
    requested_scopes: ["send:create", "send:read"],
    proposed_rule_json: JSON.stringify(validRule({ per_send_max_zkz: "25" })),
    approved_rule_json: null,
    status: "PENDING",
    row_version: 1,
    created_at: "2026-08-01T00:00:00.000Z",
    expires_at: "2099-08-08T00:00:00.000Z",
    decided_at: null,
    decided_by: null,
    implementer_id: null,
    ...over,
  };
}

function makeRouter(opts?: {
  readonly omitStore?: boolean;
  readonly policy?: InMemoryAutoApprovePolicy;
  readonly store?: InMemoryIntegrationRequestStore;
  readonly registry?: InMemoryImplementerRegistry;
}) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const integrationRequestStore =
    opts?.omitStore === true
      ? undefined
      : (opts?.store ?? new InMemoryIntegrationRequestStore());
  const implementerRegistry = opts?.registry ?? new InMemoryImplementerRegistry();
  const autoApprovePolicy = opts?.policy ?? new InMemoryAutoApprovePolicy();
  const dualControlPolicy = new InMemoryDualControlPolicy("single_operator");
  const deviceSignaturePolicy = new InMemoryDeviceSignaturePolicy("optional");

  const router = createAdminRouter({
    sessions,
    userStore,
    csrf: { allowedOrigins: [ORIGIN] },
    totp: {
      secret: TOTP_SECRET,
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
      autoApprovePolicy,
      implementerRegistry,
      ...(integrationRequestStore !== undefined ? { integrationRequestStore } : {}),
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
    autoApprovePolicy,
    implementerRegistry,
    ...(integrationRequestStore !== undefined ? { integrationRequestStore } : {}),
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

  return {
    router,
    userStore,
    integrationRequestStore,
    implementerRegistry,
    autoApprovePolicy,
  };
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

describe("admin integration-requests", () => {
  it("GET lists PENDING rows", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const { router, userStore } = makeRouter({ store });
    const { cookie, csrf } = await login(router, userStore);
    const res = await router("GET", "/admin/v1/integration-requests?status=PENDING", new Uint8Array(), {
      origin: ORIGIN,
      cookie,
      "x-csrf-token": csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as { data: Array<{ id: string; display_name: string }> };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]!.id).toBe(REQ_ID);
    expect(body.data[0]!.display_name).toBe("Platform Alpha");
  });

  it("GET fails closed when store omitted", async () => {
    const { router, userStore } = makeRouter({ omitStore: true });
    const { cookie, csrf } = await login(router, userStore);
    const res = await router("GET", "/admin/v1/integration-requests", new Uint8Array(), {
      origin: ORIGIN,
      cookie,
      "x-csrf-token": csrf,
    });
    expect(res.status).toBe(503);
  });

  it("approve creates implementer + rule + APPROVED", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const registry = new InMemoryImplementerRegistry();
    const policy = new InMemoryAutoApprovePolicy();
    const { router, userStore } = makeRouter({ store, registry, policy });
    const { cookie, csrf } = await login(router, userStore);
    const body = {
      expected_row_version: 1,
      rule: validRule({ per_send_max_zkz: "7" }),
    };
    const res = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/approve`,
      Buffer.from(JSON.stringify(body)),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(200);
    const out = JSON.parse(res.body) as {
      request: { status: string; implementer_id: string; approved_rule_json: string };
      implementer: { id: string; name: string };
      rule: { implementer_id: string; per_send_max_zkz: string };
    };
    expect(out.request.status).toBe("APPROVED");
    expect(out.implementer.name).toBe("Platform Alpha");
    expect(out.rule.implementer_id).toBe(out.implementer.id);
    expect(out.rule.per_send_max_zkz).toBe("7");
    expect(out.request.implementer_id).toBe(out.implementer.id);
    expect(JSON.parse(out.request.approved_rule_json).per_send_max_zkz).toBe("7");
    const row = await store.get(REQ_ID);
    expect(row!.proposed_rule_json).toContain("25");
    const pol = policy.getPolicy();
    expect(pol.status).toBe("enabled");
    if (pol.status === "enabled") {
      expect(pol.rules).toHaveLength(1);
      expect(pol.rules[0]!.implementer_id).toBe(out.implementer.id);
      expect(pol.rules[0]!.per_send_max_zkz).toBe("7");
    }
    expect(await registry.get(out.implementer.id)).not.toBeNull();
    expect(store.audit.some((a) => a.action === "integration_request.approved")).toBe(true);
    expect(registry.audit.some((a) => a.action === "implementer.created")).toBe(true);
  });

  it("approve rejects invalid rule with 422", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const registry = new InMemoryImplementerRegistry();
    const { router, userStore } = makeRouter({ store, registry });
    const { cookie, csrf } = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/approve`,
      Buffer.from(
        JSON.stringify({
          expected_row_version: 1,
          rule: { rule_id: "!!", per_send_max_zkz: "nope" },
        }),
      ),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(422);
    expect((await store.get(REQ_ID))!.status).toBe("PENDING");
    expect(await registry.list()).toHaveLength(0);
  });

  it("approve rejects when policy document is fail-closed invalid", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const policy = new InMemoryAutoApprovePolicy({
      status: "disabled",
      disabledReason: "invalid",
    });
    const { router, userStore } = makeRouter({ store, policy });
    const { cookie, csrf } = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/approve`,
      Buffer.from(JSON.stringify({ expected_row_version: 1, rule: validRule() })),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(409);
    const err = JSON.parse(res.body) as { error: { code: string; message: string } };
    expect(err.error.code).toBe("conflict");
    expect(err.error.message).toMatch(/policy document first/i);
    expect((await store.get(REQ_ID))!.status).toBe("PENDING");
  });

  it("decline CAS only — no implementer, no policy rule", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const registry = new InMemoryImplementerRegistry();
    const policy = new InMemoryAutoApprovePolicy();
    const { router, userStore } = makeRouter({ store, registry, policy });
    const { cookie, csrf } = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/decline`,
      Buffer.from(JSON.stringify({ expected_row_version: 1 })),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(200);
    const out = JSON.parse(res.body) as { request: { status: string } };
    expect(out.request.status).toBe("DECLINED");
    expect(await registry.list()).toHaveLength(0);
    expect(policy.getPolicy().status).toBe("disabled");
    expect(store.audit.some((a) => a.action === "integration_request.declined")).toBe(true);
  });

  it("missing TOTP is rejected", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const { router, userStore } = makeRouter({ store });
    const { cookie, csrf } = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/decline`,
      Buffer.from(JSON.stringify({ expected_row_version: 1 })),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect((await store.get(REQ_ID))!.status).toBe("PENDING");
  });

  it("idempotent approve replay returns identical bytes", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const { router, userStore } = makeRouter({ store });
    const { cookie, csrf } = await login(router, userStore);
    const headers = {
      origin: ORIGIN,
      cookie,
      "x-csrf-token": csrf,
      "x-zp-totp": totpNow(),
      "idempotency-key": randomUUID(),
      "content-type": "application/json",
    };
    const payload = Buffer.from(
      JSON.stringify({ expected_row_version: 1, rule: validRule() }),
    );
    const first = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/approve`,
      payload,
      headers,
    );
    expect(first.status).toBe(200);
    const second = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/approve`,
      payload,
      { ...headers, "x-zp-totp": totpNow(Date.now() + 30_000) },
    );
    expect(second.status).toBe(200);
    expect(second.body).toBe(first.body);
    expect(second.headers["idempotency-replayed"]).toBe("true");
  });

  it("concurrent approve then decline: decline loses with 409", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const { router, userStore } = makeRouter({ store });
    const { cookie, csrf } = await login(router, userStore);
    const approveRes = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/approve`,
      Buffer.from(JSON.stringify({ expected_row_version: 1, rule: validRule() })),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(approveRes.status).toBe(200);
    const declineRes = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/decline`,
      Buffer.from(JSON.stringify({ expected_row_version: 1 })),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "x-zp-totp": totpNow(Date.now() + 30_000),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(declineRes.status).toBe(409);
    expect((await store.get(REQ_ID))!.status).toBe("APPROVED");
  });

  it("approve against parked enabled:false policy keeps document disabled and adds rule (ZTR-1258)", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow());
    const registry = new InMemoryImplementerRegistry();
    const policy = new InMemoryAutoApprovePolicy({
      status: "disabled",
      disabledReason: "off",
      rules: [],
    });
    const { router, userStore } = makeRouter({ store, registry, policy });
    const { cookie, csrf } = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/approve`,
      Buffer.from(JSON.stringify({ expected_row_version: 1, rule: validRule({ per_send_max_zkz: "3" }) })),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(200);
    const pol = policy.getPolicy();
    expect(pol.status).toBe("disabled");
    if (pol.status === "disabled") {
      expect(pol.disabledReason).toBe("off");
      expect(pol.rules).toBeDefined();
      expect(pol.rules!.length).toBe(1);
      expect(pol.rules![0]!.per_send_max_zkz).toBe("3");
    }
  });

  it("approve refuses expired PENDING with integration_request_expired (ZTR-1258)", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(
      pendingRow({
        expires_at: "2020-01-01T00:00:00.000Z",
      }),
    );
    const registry = new InMemoryImplementerRegistry();
    const { router, userStore } = makeRouter({ store, registry });
    const { cookie, csrf } = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/integration-requests/${REQ_ID}/approve`,
      Buffer.from(JSON.stringify({ expected_row_version: 1, rule: validRule() })),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": randomUUID(),
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(409);
    const body = JSON.parse(res.body) as { error: { code: string } };
    expect(body.error.code).toBe("integration_request_expired");
    expect((await store.get(REQ_ID))!.status).toBe("PENDING");
    expect(await registry.list()).toHaveLength(0);
  });

  it("GET PENDING omits clock-expired rows; they appear as EXPIRED (ZTR-1258)", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pendingRow({ expires_at: "2020-01-01T00:00:00.000Z" }));
    store.seed(
      pendingRow({
        id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        expires_at: "2099-01-01T00:00:00.000Z",
        display_name: "Still Live",
      }),
    );
    const { router, userStore } = makeRouter({ store });
    const { cookie, csrf } = await login(router, userStore);
    const pendingRes = await router("GET", "/admin/v1/integration-requests?status=PENDING", new Uint8Array(), {
      origin: ORIGIN,
      cookie,
      "x-csrf-token": csrf,
    });
    expect(pendingRes.status).toBe(200);
    const pendingBody = JSON.parse(pendingRes.body) as { data: Array<{ id: string; display_name: string }> };
    expect(pendingBody.data).toHaveLength(1);
    expect(pendingBody.data[0]!.display_name).toBe("Still Live");

    const expiredRes = await router("GET", "/admin/v1/integration-requests?status=EXPIRED", new Uint8Array(), {
      origin: ORIGIN,
      cookie,
      "x-csrf-token": csrf,
    });
    expect(expiredRes.status).toBe(200);
    const expiredBody = JSON.parse(expiredRes.body) as { data: Array<{ id: string; status: string }> };
    // list filter EXPIRED only returns durable EXPIRED; projection maps PENDING→EXPIRED when status filter is EXPIRED
    expect(expiredBody.data.some((r) => r.id === REQ_ID && r.status === "EXPIRED")).toBe(true);
  });
});
