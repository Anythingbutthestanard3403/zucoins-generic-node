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
  InMemoryDeviceKeyStore,
  InMemoryDeviceRevocationAuditLog,
  InMemoryEnrollmentAuditLog,
  InMemoryEnrollmentChallengeStore,
  NoopDeviceRevocationSideEffects,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { MemoryAdminIdempotencyStore } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const TOTP_SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");

const ED25519_SPKI_DER_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function cookieFrom(setCookie: string | undefined): string {
  return setCookie?.split(";")[0] ?? "";
}

function generateTestKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ format: "der", type: "spki" });
  const rawPub = new Uint8Array(spkiDer.slice(ED25519_SPKI_DER_PREFIX.length));
  const paddedBase64Url = Buffer.from(rawPub)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return { publicKey, privateKey, paddedBase64Url };
}

function signPreimageB64(
  privateKey: ReturnType<typeof generateTestKeyPair>["privateKey"],
  preimageText: string,
): string {
  const sig = sign(null, Buffer.from(preimageText, "utf8"), privateKey);
  return Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function generateTotp(secret: Uint8Array, nowMs: number): string {
  const timestep = Math.floor(nowMs / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestep));
  const h = createHmac("sha1", secret).update(buf).digest();
  const offset = h[h.length - 1]! & 0x0f;
  const code =
    ((h[offset]! & 0x7f) << 24) |
    (h[offset + 1]! << 16) |
    (h[offset + 2]! << 8) |
    h[offset + 3]!;
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

function makeRouter(deviceStore: InMemoryDeviceKeyStore) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  return {
    userStore,
    router: createAdminRouter({
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
      sendDecisionStore: {
        rejectCreated: async () => {
          throw new Error("unused");
        },
        approveCreated: async () => {
          throw new Error("unused");
        },
      },
      deviceStore,
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
    }),
  };
}

function makeRouterWithEnrol(
  deviceStore: InMemoryDeviceKeyStore,
  opts: { readonly nowMs?: () => number } = {},
) {
  const challengeStore = new InMemoryEnrollmentChallengeStore();
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  return {
    userStore,
    deviceStore,
    challengeStore,
    router: createAdminRouter({
      sessions,
      userStore,
      csrf: { allowedOrigins: [ORIGIN] },
      totp: {
        secret: TOTP_SECRET,
        windowSteps: 1,
      },
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE_ID,
      nowMs: opts.nowMs,
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
      deviceStore,
      deviceEnrollmentChallengeStore: challengeStore,
      deviceEnrollmentAuditLog: new InMemoryEnrollmentAuditLog(),
      deviceRevocationAuditLog: new InMemoryDeviceRevocationAuditLog(),
      deviceRevocationSideEffects: new NoopDeviceRevocationSideEffects(),
      adminIdempotencyStore: new MemoryAdminIdempotencyStore(),
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
    }),
  };
}

async function login(
  router: ReturnType<typeof makeRouter>["router"],
  userStore: InMemoryAdminUserStore,
  opts: { readonly withTotp?: boolean } = {},
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
  if (opts.withTotp !== false) {
    await userStore.setActiveTotpSecret(user.id, encodeBase32(TOTP_SECRET));
  }
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

describe("admin active device-key inventory", () => {
  it("requires an operator session", async () => {
    const { router } = makeRouter(new InMemoryDeviceKeyStore());
    const response = await router("GET", "/admin/v1/device-keys", new Uint8Array(), {});
    expect(response.status).toBe(401);
  });

  it("returns active key identifiers and labels without public keys", async () => {
    const devices = new InMemoryDeviceKeyStore();
    devices.insert({
      id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      nodeId: NODE_ID,
      publicKey: "sensitive-public-key-material",
      label: "Operator phone",
      enrolledAt: "2026-07-01T00:00:00.000Z",
      revokedAt: null,
    });
    devices.insert({
      id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      nodeId: NODE_ID,
      publicKey: "revoked-public-key",
      label: "Old phone",
      enrolledAt: "2026-06-01T00:00:00.000Z",
      revokedAt: "2026-07-02T00:00:00.000Z",
    });
    const { router, userStore } = makeRouter(devices);
    const auth = await login(router, userStore);

    const response = await router("GET", "/admin/v1/device-keys", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({
      keys: [
        {
          id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          label: "Operator phone",
          enrolled_at: "2026-07-01T00:00:00.000Z",
        },
      ],
    });
    expect(response.body).not.toContain("public-key");
  });
});

describe("admin device genesis enrol + revoke", () => {
  it("enrols first device under session+CSRF+TOTP and lists it", async () => {
    const devices = new InMemoryDeviceKeyStore();
    const nowMs = 1_700_000_030_000;
    const { router, userStore } = makeRouterWithEnrol(devices, { nowMs: () => nowMs });
    const auth = await login(router, userStore);

    const chRes = await router(
      "POST",
      "/admin/v1/device-keys/enrollment-challenge",
      Buffer.from("{}"),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    expect(chRes.status).toBe(200);
    const challenge = JSON.parse(chRes.body) as {
      nonce: string;
      issued_at: string;
      expires_at: string;
      node_id: string;
    };

    const pair = generateTestKeyPair();
    const deviceId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: deviceId as never,
      new_device_public_key: pair.paddedBase64Url as never,
      label: "Phone",
      nonce: challenge.nonce as never,
      issued_at: challenge.issued_at,
      expires_at: challenge.expires_at,
    });
    const pop = signPreimageB64(pair.privateKey, built.preimageText);
    const code = generateTotp(TOTP_SECRET, nowMs);

    const enrolRes = await router(
      "POST",
      "/admin/v1/device-keys/enrol",
      Buffer.from(
        JSON.stringify({
          label: "Phone",
          new_device_key_id: deviceId,
          new_device_public_key: pair.paddedBase64Url,
          new_device_pop_signature: pop,
          challenge_nonce: challenge.nonce,
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
        "x-zp-totp": code,
        "idempotency-key": "idem-device-enrol-" + "x".repeat(16),
      },
    );
    expect(enrolRes.status).toBe(200);
    expect(JSON.parse(enrolRes.body)).toMatchObject({
      id: deviceId,
      label: "Phone",
    });
    expect(devices.listActiveByNode(NODE_ID)).toHaveLength(1);

    const listRes = await router("GET", "/admin/v1/device-keys", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(listRes.status).toBe(200);
    expect(JSON.parse(listRes.body).keys).toEqual([
      { id: deviceId, label: "Phone", enrolled_at: challenge.issued_at },
    ]);
    expect(listRes.body).not.toContain(pair.paddedBase64Url);
  });

  it("rejects enrol with bad TOTP (fail closed)", async () => {
    const devices = new InMemoryDeviceKeyStore();
    const nowMs = 1_700_000_030_000;
    const { router, userStore } = makeRouterWithEnrol(devices, { nowMs: () => nowMs });
    const auth = await login(router, userStore);

    const chRes = await router(
      "POST",
      "/admin/v1/device-keys/enrollment-challenge",
      Buffer.from("{}"),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
      },
    );
    const challenge = JSON.parse(chRes.body) as {
      nonce: string;
      issued_at: string;
      expires_at: string;
    };
    const pair = generateTestKeyPair();
    const deviceId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: deviceId as never,
      new_device_public_key: pair.paddedBase64Url as never,
      label: "Phone",
      nonce: challenge.nonce as never,
      issued_at: challenge.issued_at,
      expires_at: challenge.expires_at,
    });
    const pop = signPreimageB64(pair.privateKey, built.preimageText);

    const enrolRes = await router(
      "POST",
      "/admin/v1/device-keys/enrol",
      Buffer.from(
        JSON.stringify({
          label: "Phone",
          new_device_key_id: deviceId,
          new_device_public_key: pair.paddedBase64Url,
          new_device_pop_signature: pop,
          challenge_nonce: challenge.nonce,
        }),
      ),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "x-csrf-token": auth.csrf,
        "content-type": "application/json",
        "x-zp-totp": "000000",
        "idempotency-key": "idem-device-badtotp-" + "y".repeat(12),
      },
    );
    expect(enrolRes.status).toBeGreaterThanOrEqual(401);
    expect(devices.listActiveByNode(NODE_ID)).toHaveLength(0);
  });
});
