/**
 * ZTR-1191 — served-surface gate for the OPERATOR_SESSION never-403-for-auth invariant.
 *
 * Drives the real adminRouter over authenticated-but-refused requests and asserts
 * no served 403 outside AUTH_CLASS_POLICY.OPERATOR_SESSION.nonAuthorizationStatuses.
 * A fresh authorization/factor 403 in admin-router.ts turns this red.
 *
 * Also pins APPROVAL_FACTOR_FAILURE_HTTP_STATUS === the approve route's failure status.
 */
import { createHmac, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { AUTH_CLASS_POLICY } from "@zucoins/generic-node-contracts/route-policy";
import {
  APPROVAL_FACTOR_FAILURE_CODE,
  APPROVAL_FACTOR_FAILURE_HTTP_STATUS,
  APPROVAL_POLICY_DENIAL_CODE,
  createAdminSessionService,
  createFailClosedDestinationService,
  type BlessDestinationOutcome,
  type DestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  encodeBase32,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  InMemoryApprovalChallengeIssuerStore,
  InMemoryApprovalChallengeStore,
  InMemoryDeviceKeyStore,
  InMemoryDualControlPolicy,
  InMemoryDeviceSignaturePolicy,
  InMemoryEnrollmentAuditLog,
  InMemoryDeviceRevocationAuditLog,
  InMemoryEnrollmentChallengeStore,
  InMemoryOperatorPushSubscriptionStore,
  InMemorySecondDeviceCeremonyStore,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
  type ApprovalOperationSnapshot,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const TOTP_SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const OP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const WALLET_ID = "55555555-5555-4555-8555-555555555555";

const CARVED_OUT_STATUSES = new Set<number>(
  AUTH_CLASS_POLICY.OPERATOR_SESSION.nonAuthorizationStatuses,
);
const CARVED_OUT_CODES = new Set([
  "origin_forbidden",
  "password_change_required",
  "csrf_required",
  "csrf_origin",
]);

const SAMPLE_OP: ApprovalOperationSnapshot = {
  operationId: OP_ID,
  nodeId: NODE_ID,
  status: "CREATED",
  rowVersion: 1,
  sourceWalletId: WALLET_ID,
  sourcePubkey: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
  destinationAddress: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
  amountZkz: "0.01",
  referencesOperationId: null,
};

function cookieFrom(setCookie: string | undefined): string {
  return setCookie?.split(";")[0] ?? "";
}

function totpNow(nowMs: number = Date.now()): string {
  const step = Math.floor(nowMs / 30_000);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const dig = createHmac("sha1", TOTP_SECRET).update(msg).digest();
  const off = dig[dig.length - 1]! & 0xf;
  const code =
    ((dig[off]! & 0x7f) << 24) |
    ((dig[off + 1]! & 0xff) << 16) |
    ((dig[off + 2]! & 0xff) << 8) |
    (dig[off + 3]! & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

function makeRouter(opts?: {
  dualMode?: "single_operator" | "two_human";
  loadOperation?: (operationId: string) => Promise<ApprovalOperationSnapshot | null>;
  challengeStoreOverride?: InMemoryApprovalChallengeStore;
  userStore?: InMemoryAdminUserStore;
  sessions?: ReturnType<typeof createAdminSessionService>;
  destinationService?: DestinationService;
}) {
  const userStore = opts?.userStore ?? new InMemoryAdminUserStore();
  const sessions =
    opts?.sessions ??
    createAdminSessionService({ nodeId: NODE_ID }, new InMemoryAdminSessionStore(), userStore);
  const deviceStore = new InMemoryDeviceKeyStore();
  const dualControlPolicy = new InMemoryDualControlPolicy(opts?.dualMode ?? "single_operator");
  const deviceSignaturePolicy = new InMemoryDeviceSignaturePolicy("optional");
  const challengeIssuerStore = new InMemoryApprovalChallengeIssuerStore();
  const enrollmentChallengeStore = new InMemoryEnrollmentChallengeStore();
  const ceremonyStore = new InMemorySecondDeviceCeremonyStore();
  const auditLog = new InMemoryEnrollmentAuditLog();
  const operatorPushStore = new InMemoryOperatorPushSubscriptionStore();

  const challengeStore = opts?.challengeStoreOverride ?? {
    findIssuedByOperation: async () => null,
    findByNonce: async () => null,
    insertIssued: async () => {},
    commitApprovalMutation: async () => {
      throw new Error("unused");
    },
  };
  const loadOperation = opts?.loadOperation ?? (async () => null);
  const destinationService =
    opts?.destinationService ?? createFailClosedDestinationService();

  const router = createAdminRouter({
    sessions,
    userStore,
    csrf: { allowedOrigins: [ORIGIN] },
    totp: { secret: TOTP_SECRET, windowSteps: 1 },
    totpLog: new TotpConsumptionLog(),
    nodeId: NODE_ID,
    challengeStore,
    loadOperation,
    ...createTestAdminAtomicDeps({
      challengeStore,
      loadOperation,
      deviceSignaturePolicy,
      dualControlPolicy,
      destinationService,
    }),
    sendDecisionStore: {
      rejectCreated: async () => {
        throw new Error("unused");
      },
      approveCreated: async () => {
        throw new Error("unused");
      },
    },
    deviceStore,
    deviceEnrollmentChallengeStore: enrollmentChallengeStore,
    dualControlPolicy,
    deviceEnrollmentAuditLog: new InMemoryEnrollmentAuditLog(),
    deviceRevocationAuditLog: new InMemoryDeviceRevocationAuditLog(),
    deviceSignaturePolicy,
    challengeIssuerStore,
    secondDeviceEnrol: {
      enrollmentChallengeStore,
      ceremonyStore,
      auditLog,
      nodeOrigin: ORIGIN,
    },
    operatorPush: {
      store: operatorPushStore,
      sealAuth: (auth: string) =>
        `zp-op-push-auth-v1.test.${Buffer.from(auth, "utf8").toString("base64")}`,
    },
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
    destinationService,
    newRequestId: () => randomUUID(),
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
  });

  return { router, userStore, deviceStore };
}

async function login(
  router: ReturnType<typeof makeRouter>["router"],
  userStore: InMemoryAdminUserStore,
  opts?: { mustChangePassword?: boolean; password?: string },
): Promise<{ cookie: string; csrf: string; userId: string }> {
  const password = opts?.password ?? "correct-horse-battery-staple";
  const user: AdminUser = {
    id: randomUUID(),
    username: "admin",
    passwordHash: await hashPassword(password),
    role: "admin",
    mustChangePassword: opts?.mustChangePassword ?? false,
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

function assertAuthFailureNot403(status: number, code: string | undefined, label: string): void {
  if (status === 403) {
    expect(CARVED_OUT_STATUSES.has(403), `${label}: 403 not in carve-out set`).toBe(true);
    expect(CARVED_OUT_CODES.has(code ?? ""), `${label}: 403 code=${code} not carved out`).toBe(
      true,
    );
    return;
  }
  expect(status, `${label}: unexpected status ${status} code=${code}`).not.toBe(403);
}

describe("ZTR-1191 served-surface never-403-for-auth gate", () => {
  it("carve-out is machine-readable data on OPERATOR_SESSION", () => {
    expect(AUTH_CLASS_POLICY.OPERATOR_SESSION.authFailureStatus).toBe(401);
    expect([...AUTH_CLASS_POLICY.OPERATOR_SESSION.nonAuthorizationStatuses]).toEqual([403]);
    expect(APPROVAL_FACTOR_FAILURE_HTTP_STATUS).toBe(401);
    expect(APPROVAL_FACTOR_FAILURE_HTTP_STATUS).toBe(
      AUTH_CLASS_POLICY.OPERATOR_SESSION.authFailureStatus,
    );
  });

  it("admin-router.ts source has no authorization-failure 403 literal", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(here, "../src/admin-router.ts"), "utf8");
    // Carve-outs live in node-core (origin_forbidden / password_change_required).
    // Any 403 literal reintroduced here is an auth/factor oracle.
    expect(src).not.toMatch(/\b403\b/);
  });

  it("APPROVAL_FACTOR_FAILURE_HTTP_STATUS equals the approve route failure status", async () => {
    const { router, userStore } = makeRouter({
      dualMode: "single_operator",
      loadOperation: async (id) => (id === OP_ID ? SAMPLE_OP : null),
      challengeStoreOverride: new InMemoryApprovalChallengeStore(),
    });
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/external-sends/${OP_ID}/approve`,
      Buffer.from(
        JSON.stringify({
          challenge_nonce: randomUUID(),
          expected_row_version: 1,
          preimage_sha256: "a".repeat(64),
          device_key_id: null,
          device_signature: null,
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
    expect(res.status).toBe(APPROVAL_FACTOR_FAILURE_HTTP_STATUS);
    expect(res.status).toBe(401);
    const body = JSON.parse(res.body) as { error: { code: string } };
    expect(body.error.code).toBe(APPROVAL_FACTOR_FAILURE_CODE);
  });

  it("A.9 #14 HTTP: valid device fields with missing x-zp-totp are refused (no approve)", async () => {
    // Served-surface counterpart of the approveExternalSend empty-TOTP mutation:
    // device_key_id + device_signature present, TOTP header absent → 401 before mutation.
    const { router, userStore } = makeRouter({
      dualMode: "single_operator",
      loadOperation: async (id) => (id === OP_ID ? SAMPLE_OP : null),
      challengeStoreOverride: new InMemoryApprovalChallengeStore(),
    });
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      `/admin/v1/external-sends/${OP_ID}/approve`,
      Buffer.from(
        JSON.stringify({
          challenge_nonce: randomUUID(),
          expected_row_version: 1,
          preimage_sha256: "a".repeat(64),
          device_key_id: randomUUID(),
          device_signature: `${"A".repeat(86)}==`,
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
        "idempotency-key": randomUUID(),
        // deliberately omit x-zp-totp
      },
    );
    expect(res.status).toBe(401);
    expect(res.status).not.toBe(200);
    const body = JSON.parse(res.body) as { error: { code: string } };
    expect(body.error.code).toBe("invalid_credentials");
  });

  it("authenticated-but-refused table: no auth 403 outside carve-out", async () => {
    type Case = {
      label: string;
      status: number;
      code: string | undefined;
    };
    const results: Case[] = [];

    // 1. Approve — dual-control self-approval policy denial
    {
      const { router, userStore } = makeRouter({
        dualMode: "two_human",
        loadOperation: async (id) => (id === OP_ID ? SAMPLE_OP : null),
        challengeStoreOverride: new InMemoryApprovalChallengeStore(),
      });
      const auth = await login(router, userStore);
      const issued = await router(
        "GET",
        `/admin/v1/external-sends/${OP_ID}/approval-challenge`,
        new Uint8Array(),
        { cookie: auth.cookie, origin: ORIGIN, "x-csrf-token": auth.csrf },
      );
      expect(issued.status).toBe(200);
      const challenge = JSON.parse(issued.body) as {
        nonce: string;
        preimage_sha256: string;
        row_version: number;
      };
      const res = await router(
        "POST",
        `/admin/v1/external-sends/${OP_ID}/approve`,
        Buffer.from(
          JSON.stringify({
            challenge_nonce: challenge.nonce,
            expected_row_version: challenge.row_version,
            preimage_sha256: challenge.preimage_sha256,
            device_key_id: null,
            device_signature: null,
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
      const body = JSON.parse(res.body) as { error?: { code: string } };
      results.push({
        label: "approve same_operator_both_sides",
        status: res.status,
        code: body.error?.code,
      });
      expect(res.status).toBe(401);
      expect(body.error?.code).toBe(APPROVAL_POLICY_DENIAL_CODE);
    }

    // 2. Approve — opaque factor failure
    {
      const { router, userStore } = makeRouter({
        dualMode: "single_operator",
        loadOperation: async (id) => (id === OP_ID ? SAMPLE_OP : null),
        challengeStoreOverride: new InMemoryApprovalChallengeStore(),
      });
      const auth = await login(router, userStore);
      const res = await router(
        "POST",
        `/admin/v1/external-sends/${OP_ID}/approve`,
        Buffer.from(
          JSON.stringify({
            challenge_nonce: randomUUID(),
            expected_row_version: 1,
            preimage_sha256: "b".repeat(64),
            device_key_id: null,
            device_signature: null,
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
      const body = JSON.parse(res.body) as { error?: { code: string } };
      results.push({
        label: "approve approval_rejected",
        status: res.status,
        code: body.error?.code,
      });
      expect(res.status).toBe(401);
      expect(body.error?.code).toBe(APPROVAL_FACTOR_FAILURE_CODE);
    }

    // 3. Bless — real authorization_rejected (valid BlessBody; nested status must surface 401)
    {
      const destId = "77777777-7777-4777-8777-777777777777";
      const authorizationRejectedService = {
        ...createFailClosedDestinationService(),
        async bless(): Promise<BlessDestinationOutcome> {
          return { status: "authorization_rejected", destinationId: destId as never };
        },
      } as DestinationService;
      const { router, userStore } = makeRouter({
        destinationService: authorizationRejectedService,
      });
      const auth = await login(router, userStore);
      // BlessBody: UUID nonce, RFC3339ms timestamps, padded Ed25519 sig, UUID device_key_id.
      const now = Date.now();
      const issuedAt = new Date(Math.floor(now / 1000) * 1000).toISOString();
      const expiresAt = new Date(Math.floor(now / 1000) * 1000 + 60_000).toISOString();
      const res = await router(
        "POST",
        `/admin/v1/destinations/${destId}/bless`,
        Buffer.from(
          JSON.stringify({
            nonce: randomUUID(),
            issued_at: issuedAt,
            expires_at: expiresAt,
            device_signature: `${"A".repeat(86)}==`,
            device_key_id: randomUUID(),
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
      const body = JSON.parse(res.body) as { error?: { code: string } };
      results.push({ label: "bless authorization_rejected", status: res.status, code: body.error?.code });
      expect(res.status, `bless wire status body=${res.body}`).toBe(401);
      expect(body.error?.code).toBe(APPROVAL_FACTOR_FAILURE_CODE);
      expect(body.error?.code).toBe("approval_rejected");
    }

    // 4. Device revoke — unknown authorizer
    {
      const targetId = "66666666-6666-4666-8666-666666666666";
      const { router, userStore } = makeRouter();
      const auth = await login(router, userStore);
      const res = await router(
        "POST",
        `/admin/v1/device-keys/${targetId}/revoke`,
        Buffer.from(
          JSON.stringify({
            authorizing_device_key_id: randomUUID(),
            authorizing_device_signature: `${"B".repeat(86)}==`,
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
      const body = JSON.parse(res.body) as { error?: { code: string } };
      results.push({
        label: "device revoke authorizer_unknown",
        status: res.status,
        code: body.error?.code,
      });
      expect(res.status).toBe(401);
      expect(body.error?.code).toBe("authorizer_unknown");
    }

    // 5. Device enrol — garbage body under full session (not 403 auth)
    {
      const { router, userStore } = makeRouter();
      const auth = await login(router, userStore);
      const res = await router(
        "POST",
        "/admin/v1/device-keys/enrol",
        Buffer.from(JSON.stringify({ bogus: true })),
        {
          cookie: auth.cookie,
          origin: ORIGIN,
          "x-csrf-token": auth.csrf,
          "content-type": "application/json",
          "idempotency-key": randomUUID(),
          "x-zp-totp": totpNow(),
        },
      );
      const body = JSON.parse(res.body) as { error?: { code: string } };
      results.push({ label: "device enrol malformed", status: res.status, code: body.error?.code });
    }

    // 6. Carved-out: origin_forbidden stays 403
    {
      const { router, userStore } = makeRouter({
        loadOperation: async (id) => (id === OP_ID ? SAMPLE_OP : null),
        challengeStoreOverride: new InMemoryApprovalChallengeStore(),
      });
      const auth = await login(router, userStore);
      const res = await router(
        "POST",
        `/admin/v1/external-sends/${OP_ID}/approve`,
        Buffer.from(
          JSON.stringify({
            challenge_nonce: randomUUID(),
            expected_row_version: 1,
            preimage_sha256: "c".repeat(64),
            device_key_id: null,
            device_signature: null,
          }),
        ),
        {
          cookie: auth.cookie,
          origin: "https://evil.example",
          "x-csrf-token": auth.csrf,
          "content-type": "application/json",
          "idempotency-key": randomUUID(),
          "x-zp-totp": totpNow(),
        },
      );
      const body = JSON.parse(res.body) as { error?: { code: string } };
      results.push({ label: "origin_forbidden carve-out", status: res.status, code: body.error?.code });
      expect(res.status).toBe(403);
      expect(body.error?.code).toBe("origin_forbidden");
    }

    // 7. Carved-out: password_change_required stays 403
    {
      const { router, userStore } = makeRouter({
        loadOperation: async (id) => (id === OP_ID ? SAMPLE_OP : null),
        challengeStoreOverride: new InMemoryApprovalChallengeStore(),
      });
      const auth = await login(router, userStore, { mustChangePassword: true });
      const res = await router(
        "POST",
        `/admin/v1/external-sends/${OP_ID}/approve`,
        Buffer.from(
          JSON.stringify({
            challenge_nonce: randomUUID(),
            expected_row_version: 1,
            preimage_sha256: "d".repeat(64),
            device_key_id: null,
            device_signature: null,
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
      const body = JSON.parse(res.body) as { error?: { code: string } };
      results.push({
        label: "password_change_required carve-out",
        status: res.status,
        code: body.error?.code,
      });
      expect(res.status).toBe(403);
      expect(body.error?.code).toBe("password_change_required");
    }

    for (const r of results) {
      assertAuthFailureNot403(r.status, r.code, r.label);
    }
  });
});
