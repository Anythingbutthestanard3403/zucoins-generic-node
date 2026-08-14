// GET/POST /admin/v1/halt + MoneyPathGates honoring halt + audit rows.

import { createHmac, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  createMoneyPathAdmissionPortsFromRuntime,
  createStorageBackpressure,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  NodeCoreReadinessState,
  OperatorHaltError,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");

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

describe("operator halt", () => {
  it("MoneyPathGates: MOVE/SEND refuse while halted; RECEIVE_EXTERNAL + shared admit stay open", () => {
    const readiness = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    readiness.markSchemaMigrated();
    readiness.setVaultAvailable(true);
    readiness.recordObservationReadSuccess();
    readiness.setEventSignerAvailable(true);
    const bp = createStorageBackpressure();
    const gate = createHaltGate(RUNNING);
    const ports = createMoneyPathAdmissionPortsFromRuntime({
      snapshotReadiness: () => readiness.snapshot(),
      isDatabaseReachable: () => true,
      backpressure: bp,
      haltGate: gate,
    });

    // Running: all paths open.
    expect(() => ports.assertMoneyAdmitted()).not.toThrow();
    expect(() => ports.assertHaltAdmitsKind("RECEIVE_EXTERNAL")).not.toThrow();
    expect(() => ports.assertHaltAdmitsKind("MOVE_INTERNAL")).not.toThrow();
    expect(() => ports.assertHaltAdmitsKind("SEND_EXTERNAL")).not.toThrow();

    gate.engage();
    // Shared admit (tick / captureReceiveT0) must not freeze RECEIVE during halt.
    expect(() => ports.assertMoneyAdmitted()).not.toThrow();
    expect(() => ports.assertHaltAdmitsKind("RECEIVE_EXTERNAL")).not.toThrow();
    // Outflows gated.
    expect(() => ports.assertHaltAdmitsKind("MOVE_INTERNAL")).toThrow(OperatorHaltError);
    expect(() => ports.assertHaltAdmitsKind("SEND_EXTERNAL")).toThrow(OperatorHaltError);

    gate.release();
    expect(() => ports.assertHaltAdmitsKind("SEND_EXTERNAL")).not.toThrow();
    expect(() => ports.assertMoneyAdmitted()).not.toThrow();
  });

  it("GET requires session", async () => {
    const userStore = new InMemoryAdminUserStore();
    const gate = createHaltGate(RUNNING);
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
      halt: {
        gate,
        store: createInMemoryOperatorHaltStore(RUNNING),
        evidence: createInMemoryHaltEvidenceRecorder(),
      },
    });
    const res = await router("GET", "/admin/v1/halt", new Uint8Array(), {});
    expect(res.status).toBe(401);
  });

  it("POST without TOTP is refused and does not flip the gate", async () => {
    const userStore = new InMemoryAdminUserStore();
    const password = "halt-pass-2";
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
    const gate = createHaltGate(RUNNING);
    const halt = {
      gate,
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    };
    const atomic = createTestAdminAtomicDeps({ halt });
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
      halt,
      adminIdempotencyStore: atomic.adminIdempotencyStore,
      atomicAdminMutation: atomic.atomicAdminMutation,
    });

    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password })),
      { "content-type": "application/json" },
    );
    expect(login.status).toBe(200);
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;

    const res = await router(
      "POST",
      "/admin/v1/halt",
      Buffer.from(JSON.stringify({ engaged: true })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "content-type": "application/json",
        "idempotency-key": "halt-no-totp-test-key-01",
      },
    );
    expect(res.status).toBe(401);
    expect(gate.isHalted()).toBe(false);
  });

  it("GET/POST engage then clear writes audit rows and stamps", async () => {
    const userStore = new InMemoryAdminUserStore();
    const password = "halt-pass-totp";
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

    let nowMs = 1_700_000_030_000;
    const gate = createHaltGate(RUNNING);
    const store = createInMemoryOperatorHaltStore(RUNNING);
    const evidence = createInMemoryHaltEvidenceRecorder();
    const stamps: boolean[] = [];
    const halt = {
      gate,
      store,
      evidence,
      onToggle: (engaged: boolean) => stamps.push(engaged),
    };
    const atomic = createTestAdminAtomicDeps({ halt });

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
      nowMs: () => nowMs,
      halt,
      adminIdempotencyStore: atomic.adminIdempotencyStore,
      atomicAdminMutation: atomic.atomicAdminMutation,
    });

    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password })),
      { "content-type": "application/json" },
    );
    expect(login.status).toBe(200);
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;

    const get1 = await router("GET", "/admin/v1/halt", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(get1.status).toBe(200);
    expect(JSON.parse(get1.body)).toMatchObject({ engaged: false });

    const code1 = generateTotp(SECRET, nowMs);
    const engage = await router(
      "POST",
      "/admin/v1/halt",
      Buffer.from(JSON.stringify({ engaged: true, reason: "incident" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": code1,
        "content-type": "application/json",
        "idempotency-key": "halt-engage-test-key-01",
      },
    );
    expect(engage.status).toBe(200);
    const engagedBody = JSON.parse(engage.body) as {
      engaged: boolean;
      reason: string | null;
      updated_by: string | null;
    };
    expect(engagedBody.engaged).toBe(true);
    expect(engagedBody.reason).toBe("incident");
    expect(engagedBody.updated_by).toBe(user.id);
    expect(gate.isHalted()).toBe(true);
    expect(stamps).toEqual([true]);

    const trail = await evidence.entries();
    expect(trail.some((e) => e.action === "ENGAGE" && e.outcome === "APPLIED")).toBe(true);

    nowMs += 30_000;
    const code2 = generateTotp(SECRET, nowMs);
    const clear = await router(
      "POST",
      "/admin/v1/halt",
      Buffer.from(JSON.stringify({ engaged: false })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": code2,
        "content-type": "application/json",
        "idempotency-key": "halt-clear-test-key-01",
      },
    );
    expect(clear.status).toBe(200);
    expect(JSON.parse(clear.body).engaged).toBe(false);
    expect(gate.isHalted()).toBe(false);
    expect(stamps.at(-1)).toBe(false);
    expect((await evidence.entries()).some((e) => e.action === "DISENGAGE")).toBe(true);
    expect(await store.read()).toBe(RUNNING);
  });
});
