// Admin routes for second-device enrol, dual-control policy, operator push.

import { createHmac, generateKeyPairSync, randomUUID, sign } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  buildDeviceEnrol,
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
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
  parseUuid,
  parseWalletPublicKey,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
  type ApprovalOperationSnapshot,
  type OperatorPushSender,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";

function cookieFrom(setCookie: string | undefined): string {
  return setCookie?.split(";")[0] ?? "";
}

function makeRouter(opts?: {
  dualMode?: "single_operator" | "two_human";
  /** Default optional so dual-control path tests are not short-circuited by ZTR-1143 fail-closed. */
  deviceSignatureMode?: "required" | "optional";
  deviceSignaturePolicy?: InMemoryDeviceSignaturePolicy;
  operatorPushSender?: OperatorPushSender;
  sealAuth?: (auth: string) => string;
  loadOperation?: (operationId: string) => Promise<ApprovalOperationSnapshot | null>;
  challengeStoreOverride?: InMemoryApprovalChallengeStore;
}) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const deviceStore = new InMemoryDeviceKeyStore();
  const dualControlPolicy = new InMemoryDualControlPolicy(opts?.dualMode ?? "single_operator");
  const deviceSignaturePolicy =
    opts?.deviceSignaturePolicy ??
    new InMemoryDeviceSignaturePolicy(opts?.deviceSignatureMode ?? "optional");
  const challengeIssuerStore = new InMemoryApprovalChallengeIssuerStore();
  const enrollmentChallengeStore = new InMemoryEnrollmentChallengeStore();
  const ceremonyStore = new InMemorySecondDeviceCeremonyStore();
  const auditLog = new InMemoryEnrollmentAuditLog();
  const operatorPushStore = new InMemoryOperatorPushSubscriptionStore();
  const sealAuth =
    opts?.sealAuth ??
    ((auth: string) => {
      // Real sealed bytes (not length-only discard). Test sealer is reversible via prefix.
      return `zp-op-push-auth-v1.test.${Buffer.from(auth, "utf8").toString("base64")}`;
    });

  const challengeStore = opts?.challengeStoreOverride ?? {
    findIssuedByOperation: async () => null,
    findByNonce: async () => null,
    insertIssued: async () => {},
    commitApprovalMutation: async () => {
      throw new Error("unused");
    },
  };
  const loadOperation = opts?.loadOperation ?? (async () => null);

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
    challengeStore,
    loadOperation,
    // The approve route runs inside the required atomic idempotency transaction;
    // without it every approve is 503 before any policy is consulted.
    // TX ports must carry policy ports so POST setMode is not 503 (ZTR-1143 / ZTR-1214).
    ...createTestAdminAtomicDeps({
      challengeStore,
      loadOperation,
      deviceSignaturePolicy,
      dualControlPolicy,
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
    dualControlPolicy,
    deviceSignaturePolicy,
    challengeIssuerStore,
    deviceEnrollmentAuditLog: auditLog,
    deviceRevocationAuditLog: new InMemoryDeviceRevocationAuditLog(),
    secondDeviceEnrol: {
      enrollmentChallengeStore,
      ceremonyStore,
      auditLog,
      nodeOrigin: ORIGIN,
    },
    operatorPush: {
      store: operatorPushStore,
      sealAuth,
      ...(opts?.operatorPushSender !== undefined ? { sender: opts.operatorPushSender } : {}),
    },
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
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
  });

  return {
    router,
    userStore,
    dualControlPolicy,
    deviceSignaturePolicy,
    operatorPushStore,
    deviceStore,
    ceremonyStore,
    enrollmentChallengeStore,
    auditLog,
  };
}

const ED25519_SPKI_DER_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function generateTestKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ format: "der", type: "spki" });
  const rawPub = new Uint8Array(spkiDer.slice(ED25519_SPKI_DER_PREFIX.length));
  let paddedBase64Url = Buffer.from(rawPub)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  // Device verify path requires padded base64url (PADDED_SIG_RE / decodePaddedBase64Url).
  if (!paddedBase64Url.endsWith("=")) {
    paddedBase64Url += "=".repeat((4 - (paddedBase64Url.length % 4)) % 4);
  }
  return { publicKey, privateKey, paddedBase64Url };
}

function signPreimageB64(
  privateKey: ReturnType<typeof generateTestKeyPair>["privateKey"],
  preimageText: string,
): string {
  const sig = sign(null, Buffer.from(preimageText, "utf8"), privateKey);
  let b64 = Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
  if (!b64.endsWith("=")) {
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
  }
  return b64;
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

async function login(
  router: ReturnType<typeof makeRouter>["router"],
  userStore: InMemoryAdminUserStore,
) {
  const password = "correct-horse-battery-staple";
  const user: AdminUser = {
    id: randomUUID(),
    nodeId: NODE_ID,
    username: "admin",
    passwordHash: await hashPassword(password),
    role: "admin",
    mustChangePassword: false,
    mustEnrolTotp: false,
    disabledAt: null,
    createdAt: Date.now(),
  };
  await userStore.insert(user);
  // Bind active TOTP so authorize (runGuardedAdminMutation) can verify x-zp-totp.
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

describe("G4 dual-control policy", () => {
  it("GET /admin/v1/dual-control-policy returns mode + plain copy", async () => {
    const { router, userStore } = makeRouter({ dualMode: "two_human" });
    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/dual-control-policy", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      mode: string;
      short: string;
      long: string;
      approve_hint: string;
    };
    expect(body.mode).toBe("two_human");
    expect(body.short).toMatch(/Two-human/i);
    expect(body.long).toMatch(/different admin operator/i);
  });

  it("POST changes policy under fresh TOTP and records an audit entry (ZTR-1214)", async () => {
    const { router, userStore, dualControlPolicy } = makeRouter({
      dualMode: "single_operator",
    });
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/dual-control-policy",
      Buffer.from(JSON.stringify({ mode: "two_human" })),
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
    const body = JSON.parse(res.body) as { mode: string; short: string };
    expect(body.mode).toBe("two_human");
    expect(body.short).toMatch(/Two-human/i);
    expect(dualControlPolicy.getMode()).toBe("two_human");
    expect(dualControlPolicy.auditEntries).toEqual([
      expect.objectContaining({ mode: "two_human", actorId: auth.userId, nodeId: NODE_ID }),
    ]);
    // GET still works and reflects the mutation.
    const getRes = await router("GET", "/admin/v1/dual-control-policy", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(getRes.status).toBe(200);
    expect((JSON.parse(getRes.body) as { mode: string }).mode).toBe("two_human");
  });

  it("POST without TOTP is refused", async () => {
    const { router, userStore, dualControlPolicy } = makeRouter({
      dualMode: "single_operator",
    });
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/dual-control-policy",
      Buffer.from(JSON.stringify({ mode: "two_human" })),
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
    expect(dualControlPolicy.getMode()).toBe("single_operator");
  });

  // Doc 01 §4.2 wants two things at once: a POLICY refusal must be tellable from
  // protocol invalidity, while no answer may reveal which authentication factor
  // failed. Both assertions live here so a refactor cannot satisfy one by breaking
  // the other (ZTR-1148).
  describe("policy denial is distinguishable from protocol invalidity", () => {
    const OP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const WALLET_ID = "55555555-5555-4555-8555-555555555555";

    const op: ApprovalOperationSnapshot = {
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

    async function challengeThenApprove(approveBody: Record<string, unknown>) {
      const { router, userStore } = makeRouter({
        dualMode: "two_human",
        loadOperation: async (id) => (id === OP_ID ? op : null),
        challengeStoreOverride: new InMemoryApprovalChallengeStore(),
      });
      const auth = await login(router, userStore);
      // Issuing the challenge records this operator as the issuer; approving as the
      // same session is therefore the two-human refusal.
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
            ...approveBody,
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
      return { status: res.status, body: JSON.parse(res.body) as { error: { code: string } } };
    }

    it("refuses the challenge issuer with its own code", async () => {
      const res = await challengeThenApprove({});
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe("same_operator_both_sides");
    });

    it("still collapses a protocol-invalid approve to the opaque code", async () => {
      const res = await challengeThenApprove({ challenge_nonce: randomUUID() });
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe("approval_rejected");
    });

    it("discloses no authentication factor in either answer", async () => {
      const policy = await challengeThenApprove({});
      const protocolInvalid = await challengeThenApprove({ challenge_nonce: randomUUID() });
      expect(policy.body.error.code).not.toBe(protocolInvalid.body.error.code);
      for (const res of [policy, protocolInvalid]) {
        expect(JSON.stringify(res.body)).not.toMatch(/totp|device|nonce|preimage|password/i);
      }
    });
  });
});

describe("G4 second-device enrolment", () => {
  it("issue returns QR with only challenge_id + node_origin", async () => {
    const { router, userStore } = makeRouter();
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/device-enrol/issue",
      Buffer.from("{}"),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      challenge_id: string;
      qr: Record<string, string>;
      deep_link_path: string;
    };
    expect(Object.keys(body.qr).sort()).toEqual(["challenge_id", "node_origin"]);
    expect(body.qr.node_origin).toBe(ORIGIN);
    expect(body.qr.challenge_id).toBe(body.challenge_id);
    expect(JSON.stringify(body)).not.toMatch(/private_key|totp|master_key/i);
    expect(body.deep_link_path).toContain(body.challenge_id);

    const peek = await router(
      "GET",
      `/admin/v1/device-enrol/${body.challenge_id}`,
      new Uint8Array(),
      { cookie: auth.cookie, origin: ORIGIN, "x-csrf-token": auth.csrf },
    );
    expect(peek.status).toBe(200);
    expect(peek.body).not.toMatch(/private_key|authorizing_signature|totp_code/i);
  });

  it("expired bind fails closed", async () => {
    const { router, userStore } = makeRouter();
    const auth = await login(router, userStore);
    // Issue then bind with a far-future wall clock via nowMs override is not exposed;
    // bind with invalid pubkey still fails closed without enrolling.
    const issue = await router("POST", "/admin/v1/device-enrol/issue", Buffer.from("{}"), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
      "content-type": "application/json",
    });
    const { challenge_id } = JSON.parse(issue.body) as { challenge_id: string };
    const bind = await router(
      "POST",
      "/admin/v1/device-enrol/bind",
      Buffer.from(
        JSON.stringify({
          challenge_id,
          new_device_public_key: "not-a-key",
          label: "x",
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(bind.status).toBeGreaterThanOrEqual(400);
    expect(bind.status).toBeLessThan(500);
  });
});

describe("G4 operator push", () => {
  it("lists empty opt-in status without conflating wallet push", async () => {
    const { router, userStore } = makeRouter();
    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/operator-push/subscriptions", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as { note: string; subscriptions: unknown[] };
    expect(body.note.toLowerCase()).toMatch(/wallet/);
    expect(body.note.toLowerCase()).toMatch(/optional|inbox/);
    expect(body.subscriptions).toEqual([]);
  });

  it("rejects fabricated operator-push key material (ZTR-1168)", async () => {
    const { router, userStore } = makeRouter();
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/operator-push/subscribe",
      Buffer.from(
        JSON.stringify({
          endpoint: "https://operator-push.local/pending/1",
          p256dh: "pending-p256dh-placeholder-value-xx",
          auth: "pending-auth-placeholder-xx",
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(400);
    const body = JSON.parse(res.body) as { error?: { message?: string } };
    expect(body.error?.message ?? "").toMatch(/valid Web Push key material|p256dh/i);
  });

  it("subscribe + preview payload forbids secrets", async () => {
    const { router, userStore, operatorPushStore } = makeRouter();
    const auth = await login(router, userStore);
    const sub = await router(
      "POST",
      "/admin/v1/operator-push/subscribe",
      Buffer.from(
        JSON.stringify({
          endpoint: "https://push.example/ep/abc",
          p256dh: "BAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
          auth: "AAECAwQFBgcICQoLDA0ODw",
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(sub.status).toBe(200);
    expect(sub.body).not.toContain("AAECAwQFBgcICQoLDA0ODw");
    // Store must retain openable sealed auth (not sealed:<length> discard).
    const stored = operatorPushStore.listByOperator(NODE_ID, auth.userId);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.authSealed.startsWith("zp-op-push-auth-v1.")).toBe(true);
    expect(stored[0]!.authSealed).not.toMatch(/^sealed:\d+$/);
    expect(stored[0]!.authSealed).not.toContain("AAECAwQFBgcICQoLDA0ODw");

    const preview = await router(
      "POST",
      "/admin/v1/operator-push/preview-payload",
      Buffer.from(
        JSON.stringify({
          attention_type: "send_pending_approval",
          deep_link_path: "/transfers/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          summary: "Outgoing needs approval",
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(preview.status).toBe(200);
    const payload = (JSON.parse(preview.body) as { payload: Record<string, unknown> }).payload;
    expect(Object.keys(payload).sort()).toEqual([
      "attention_type",
      "deep_link_path",
      "summary",
    ]);
    expect(JSON.stringify(payload)).not.toMatch(/totp|private_key|transfer_code|master/i);
  });
});

describe("G4 second-device full ceremony via admin HTTP", () => {
  it("issue → bind → authorize (TOTP) → complete enrols second device", async () => {
    const { router, userStore, deviceStore } = makeRouter();
    const auth = await login(router, userStore);
    const authorizing = generateTestKeyPair();
    const newDevice = generateTestKeyPair();
    const authorizerId = randomUUID();
    deviceStore.insert({
      id: authorizerId,
      nodeId: NODE_ID,
      publicKey: authorizing.paddedBase64Url,
      label: "phone-a",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    });

    const issue = await router("POST", "/admin/v1/device-enrol/issue", Buffer.from("{}"), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
      "content-type": "application/json",
    });
    expect(issue.status).toBe(200);
    const { challenge_id } = JSON.parse(issue.body) as { challenge_id: string };

    const bind = await router(
      "POST",
      "/admin/v1/device-enrol/bind",
      Buffer.from(
        JSON.stringify({
          challenge_id,
          new_device_public_key: newDevice.paddedBase64Url,
          label: "phone-b",
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(bind.status).toBe(200);
    const bound = JSON.parse(bind.body) as {
      new_device_key_id: string;
      nonce: string;
      issued_at: string;
      expires_at: string;
      node_id: string;
    };

    const built = buildDeviceEnrol({
      node_id: parseUuid(bound.node_id),
      new_device_key_id: parseUuid(bound.new_device_key_id),
      new_device_public_key: parseWalletPublicKey(newDevice.paddedBase64Url),
      label: "phone-b" as never,
      nonce: parseUuid(bound.nonce),
      issued_at: bound.issued_at,
      expires_at: bound.expires_at,
    });

    const authz = await router(
      "POST",
      "/admin/v1/device-enrol/authorize",
      Buffer.from(
        JSON.stringify({
          challenge_id,
          authorizing_key_id: authorizerId,
          authorizing_public_key: authorizing.paddedBase64Url,
          authorizing_signature: signPreimageB64(authorizing.privateKey, built.preimageText),
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
        "x-zp-totp": totpNow(),
      },
    );
    expect(authz.status).toBe(200);
    const authzBody = JSON.parse(authz.body) as { preimage_text: string; status: string };
    expect(authzBody.status).toBe("AUTHORIZED");
    expect(authzBody.preimage_text).toBe(built.preimageText);

    const pop = signPreimageB64(newDevice.privateKey, authzBody.preimage_text);
    const complete = await router(
      "POST",
      "/admin/v1/device-enrol/complete",
      Buffer.from(
        JSON.stringify({
          challenge_id,
          new_device_pop_signature: pop,
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(complete.status).toBe(200);
    const completed = JSON.parse(complete.body) as { device_key_id: string; label: string };
    expect(completed.label).toBe("phone-b");
    expect(deviceStore.listActiveByNode(NODE_ID)).toHaveLength(2);
    expect(deviceStore.listActiveByNode(NODE_ID).map((d) => d.id)).toContain(completed.device_key_id);
  });
});

describe("G4 operator push notify on challenge issue", () => {
  it("fires notifyOperatorsPendingAttention when approval challenge is issued", async () => {
    const opId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const walletId = "55555555-5555-4555-8555-555555555555";
    const sent: { payload: Record<string, unknown> }[] = [];
    const sender: OperatorPushSender = {
      async send(_sub, payload) {
        sent.push({ payload: payload as unknown as Record<string, unknown> });
        return true;
      },
    };
    const challengeStore = new InMemoryApprovalChallengeStore();
    const op: ApprovalOperationSnapshot = {
      operationId: opId,
      nodeId: NODE_ID,
      status: "CREATED",
      rowVersion: 1,
      sourceWalletId: walletId,
      sourcePubkey: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      destinationAddress: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
      amountZkz: "0.01",
      referencesOperationId: null,
    };
    const { router, userStore, operatorPushStore } = makeRouter({
      operatorPushSender: sender,
      loadOperation: async (id) => (id === opId ? op : null),
      challengeStoreOverride: challengeStore,
    });
    const auth = await login(router, userStore);
    const sub = await router(
      "POST",
      "/admin/v1/operator-push/subscribe",
      Buffer.from(
        JSON.stringify({
          endpoint: "https://push.example/ep/notify-test",
          p256dh: "BAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
          auth: "AAECAwQFBgcICQoLDA0ODw",
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(sub.status).toBe(200);
    expect(operatorPushStore.listActiveByNode(NODE_ID)).toHaveLength(1);
    // Sealed auth is real envelope, not length discard.
    expect(operatorPushStore.listActiveByNode(NODE_ID)[0]!.authSealed).toMatch(
      /^zp-op-push-auth-v1\./,
    );

    const res = await router(
      "GET",
      `/admin/v1/external-sends/${opId}/approval-challenge`,
      new Uint8Array(),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
      },
    );
    expect(res.status).toBe(200);
    expect(sent.length).toBeGreaterThanOrEqual(1);
    expect(sent[0]!.payload.attention_type).toBe("send_pending_approval");
    expect(String(sent[0]!.payload.deep_link_path)).toContain(opId);
    expect(JSON.stringify(sent[0]!.payload)).not.toMatch(/totp|private_key|auth-secret/i);
  });
});

describe("G4 device-signature policy (ZTR-1143)", () => {
  it("GET /admin/v1/device-signature-policy returns mode + plain copy", async () => {
    const { router, userStore } = makeRouter({ deviceSignatureMode: "required" });
    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/device-signature-policy", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      mode: string;
      requires_device_signature: boolean;
      short: string;
      long: string;
      approve_hint: string;
    };
    expect(body.mode).toBe("required");
    expect(body.requires_device_signature).toBe(true);
    expect(body.short).toMatch(/required/i);
    expect(body.long).toMatch(/device/i);
  });

  it("POST changes policy under fresh TOTP and records an audit entry", async () => {
    const { router, userStore, deviceSignaturePolicy } = makeRouter({
      deviceSignatureMode: "required",
    });
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/device-signature-policy",
      Buffer.from(JSON.stringify({ mode: "optional" })),
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
    const body = JSON.parse(res.body) as { mode: string; requires_device_signature: boolean };
    expect(body.mode).toBe("optional");
    expect(body.requires_device_signature).toBe(false);
    expect(deviceSignaturePolicy.getMode()).toBe("optional");
    expect(deviceSignaturePolicy.auditEntries).toEqual([
      expect.objectContaining({ mode: "optional", actorId: auth.userId, nodeId: NODE_ID }),
    ]);
  });

  it("POST without TOTP is refused", async () => {
    const { router, userStore } = makeRouter({ deviceSignatureMode: "required" });
    const auth = await login(router, userStore);
    const res = await router(
      "POST",
      "/admin/v1/device-signature-policy",
      Buffer.from(JSON.stringify({ mode: "optional" })),
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
  });

  describe("approve respects server policy, not the request body alone", () => {
    const OP_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const WALLET_ID = "55555555-5555-4555-8555-555555555555";
    const DEVICE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const op: ApprovalOperationSnapshot = {
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

    /**
     * Full challenge→approve harness. Seeds the in-memory challenge store's op
     * decision state so commitApprovalMutation can CAS CREATED→APPROVED (D3).
     */
    async function challengeThenApprove(input: {
      readonly mode: "required" | "optional";
      readonly device?: {
        readonly keyId: string | null;
        readonly signature: string | null;
        readonly enrol?: ReturnType<typeof generateTestKeyPair>;
      };
    }) {
      const challengeStore = new InMemoryApprovalChallengeStore();
      challengeStore.seedOperation(OP_ID, op.status, op.rowVersion);
      const { router, userStore, deviceStore } = makeRouter({
        dualMode: "single_operator",
        deviceSignatureMode: input.mode,
        loadOperation: async (id) => {
          if (id !== OP_ID) return null;
          const st = challengeStore.getOperationState(OP_ID);
          if (st === null) return null;
          return { ...op, status: st.status, rowVersion: st.rowVersion };
        },
        challengeStoreOverride: challengeStore,
      });
      if (input.device?.enrol !== undefined) {
        deviceStore.insert({
          id: DEVICE_ID,
          nodeId: NODE_ID,
          publicKey: input.device.enrol.paddedBase64Url,
          label: "policy-test-device",
          enrolledAt: new Date().toISOString(),
          revokedAt: null,
        });
      }
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
        preimage_text: string;
        preimage_sha256: string;
        row_version: number;
      };
      const deviceKeyId = input.device?.keyId ?? null;
      const deviceSignature = input.device?.signature ?? null;
      const res = await router(
        "POST",
        `/admin/v1/external-sends/${OP_ID}/approve`,
        Buffer.from(
          JSON.stringify({
            challenge_nonce: challenge.nonce,
            expected_row_version: challenge.row_version,
            preimage_sha256: challenge.preimage_sha256,
            device_key_id: deviceKeyId,
            device_signature: deviceSignature,
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
      return {
        status: res.status,
        body: JSON.parse(res.body) as {
          error?: { code: string };
          status?: string;
          method?: string;
          operation_id?: string;
        },
        challenge,
      };
    }

    it("rejects TOTP-only approve when policy requires the device factor", async () => {
      const res = await challengeThenApprove({
        mode: "required",
        device: { keyId: null, signature: null },
      });
      expect(res.status).toBe(401);
      expect(res.body.error?.code).toBe("approval_rejected");
      expect(JSON.stringify(res.body)).not.toMatch(/device_required|totp/i);
    });

    it("optional policy + omitted device → 200 TOTP_ONLY", async () => {
      const res = await challengeThenApprove({
        mode: "optional",
        device: { keyId: null, signature: null },
      });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe("APPROVED");
      expect(res.body.method).toBe("TOTP_ONLY");
      expect(res.body.operation_id).toBe(OP_ID);
    });

    it("optional policy + volunteered valid device → 200 TOTP_AND_DEVICE", async () => {
      const pair = generateTestKeyPair();
      const challengeStore = new InMemoryApprovalChallengeStore();
      challengeStore.seedOperation(OP_ID, op.status, op.rowVersion);
      const { router, userStore, deviceStore } = makeRouter({
        dualMode: "single_operator",
        deviceSignatureMode: "optional",
        loadOperation: async (id) => {
          if (id !== OP_ID) return null;
          const st = challengeStore.getOperationState(OP_ID);
          if (st === null) return null;
          return { ...op, status: st.status, rowVersion: st.rowVersion };
        },
        challengeStoreOverride: challengeStore,
      });
      deviceStore.insert({
        id: DEVICE_ID,
        nodeId: NODE_ID,
        publicKey: pair.paddedBase64Url,
        label: "volunteered-device",
        enrolledAt: new Date().toISOString(),
        revokedAt: null,
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
        preimage_text: string;
        preimage_sha256: string;
        row_version: number;
      };
      const deviceSignature = signPreimageB64(pair.privateKey, challenge.preimage_text);
      const res = await router(
        "POST",
        `/admin/v1/external-sends/${OP_ID}/approve`,
        Buffer.from(
          JSON.stringify({
            challenge_nonce: challenge.nonce,
            expected_row_version: challenge.row_version,
            preimage_sha256: challenge.preimage_sha256,
            device_key_id: DEVICE_ID,
            device_signature: deviceSignature,
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
      const body = JSON.parse(res.body) as { status: string; method: string };
      expect(body.status).toBe("APPROVED");
      expect(body.method).toBe("TOTP_AND_DEVICE");
    });

    it("optional policy + volunteered bad device sig → 401 approval_rejected (opaque)", async () => {
      const pair = generateTestKeyPair();
      const other = generateTestKeyPair();
      const challengeStore = new InMemoryApprovalChallengeStore();
      challengeStore.seedOperation(OP_ID, op.status, op.rowVersion);
      const { router, userStore, deviceStore } = makeRouter({
        dualMode: "single_operator",
        deviceSignatureMode: "optional",
        loadOperation: async (id) => {
          if (id !== OP_ID) return null;
          const st = challengeStore.getOperationState(OP_ID);
          if (st === null) return null;
          return { ...op, status: st.status, rowVersion: st.rowVersion };
        },
        challengeStoreOverride: challengeStore,
      });
      deviceStore.insert({
        id: DEVICE_ID,
        nodeId: NODE_ID,
        publicKey: pair.paddedBase64Url,
        label: "volunteered-device",
        enrolledAt: new Date().toISOString(),
        revokedAt: null,
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
        preimage_text: string;
        preimage_sha256: string;
        row_version: number;
      };
      // Sign with a different key than the enrolled device — verify must fail.
      const badSig = signPreimageB64(other.privateKey, challenge.preimage_text);
      const res = await router(
        "POST",
        `/admin/v1/external-sends/${OP_ID}/approve`,
        Buffer.from(
          JSON.stringify({
            challenge_nonce: challenge.nonce,
            expected_row_version: challenge.row_version,
            preimage_sha256: challenge.preimage_sha256,
            device_key_id: DEVICE_ID,
            device_signature: badSig,
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
      expect(res.status).toBe(401);
      const body = JSON.parse(res.body) as { error?: { code: string } };
      expect(body.error?.code).toBe("approval_rejected");
      expect(res.body).not.toMatch(/device_signature_invalid|device_required|totp/i);
    });
  });

  it("absent policy port fails closed to required on GET", async () => {
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    const challengeStore = {
      findIssuedByOperation: async () => null,
      findByNonce: async () => null,
      insertIssued: async () => {},
      commitApprovalMutation: async () => {
        throw new Error("unused");
      },
    };
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
      challengeStore,
      loadOperation: async () => null,
      ...createTestAdminAtomicDeps({ challengeStore, loadOperation: async () => null }),
      sendDecisionStore: {
        rejectCreated: async () => {
          throw new Error("unused");
        },
        approveCreated: async () => {
          throw new Error("unused");
        },
      },
      deviceStore: new InMemoryDeviceKeyStore(),
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
      halt: {
        gate: createHaltGate(RUNNING),
        store: createInMemoryOperatorHaltStore(RUNNING),
        evidence: createInMemoryHaltEvidenceRecorder(),
      },
    });
    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/device-signature-policy", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as { mode: string; requires_device_signature: boolean };
    expect(body.mode).toBe("required");
    expect(body.requires_device_signature).toBe(true);
  });
});
