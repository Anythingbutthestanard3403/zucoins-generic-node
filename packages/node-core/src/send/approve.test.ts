// approval challenge + guarded TOTP approve mutation.
import { createHash, createHmac, generateKeyPairSync, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { InMemoryDeviceKeyStore } from "../device/in-memory-store.js";
import type { EnrolledDeviceKey } from "../device/types.js";
import {
  APPROVAL_CHALLENGE_FRESHNESS_MS,
  APPROVAL_FACTOR_FAILURE_CODE,
  APPROVAL_FACTOR_FAILURE_HTTP_STATUS,
  APPROVAL_POLICY_DENIAL_CODE,
  APPROVAL_PURPOSE,
  APPROVAL_REJECT_REASONS,
  approveExternalSend,
  buildApprovalPreimage,
  issueOrRefreshApprovalChallenge,
  toCanonicalTimestamp,
  toOpaqueApprovalFailure,
  type ApprovalOperationSnapshot,
  type ApprovalTotpConfig,
  type ApproveDeps,
} from "./approve.js";
import { InMemoryApprovalChallengeStore } from "./approval-store.js";
import { InMemoryApprovalChallengeIssuerStore } from "./challenge-issuer-store.js";
import { TotpConsumptionLog } from "../totp/burn-store.js";

const GOLDEN_DIR = new URL("../../../generic-node-contracts/goldens/approval/", import.meta.url);
const readGolden = (name: string): string =>
  readFileSync(new URL(name, GOLDEN_DIR), "utf8").replace(/\n$/, "");
const GOLDEN_PREIMAGE = readFileSync(
  new URL("zp-send-external-approval-v1.preimage.txt", GOLDEN_DIR),
  "utf8",
).replace(/\n$/, "");
const GOLDEN_DIGEST = readGolden("zp-send-external-approval-v1.digest.hex");
const GOLDEN_SIG = readGolden("zp-send-external-approval-v1.sig.b64");

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const WALLET_ID = "55555555-5555-4555-8555-555555555555";
const SOURCE_PUB = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DEST = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const AMOUNT = "2.25";
const GOLDEN_NONCE = "99999999-9999-4999-8999-999999999999";
const GOLDEN_ISSUED = "2026-07-18T00:00:00.000Z";
const GOLDEN_EXPIRES = "2026-07-18T00:05:00.000Z";
const FIXED_NOW = Date.parse(GOLDEN_ISSUED);
const TOTP_SECRET = new Uint8Array(20).fill(7);
const TOTP_CONFIG: ApprovalTotpConfig = {
  secret: TOTP_SECRET,
  periodSeconds: 30,
  digits: 6,
  windowSteps: 1,
};
const DEVICE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function hotp(secret: Uint8Array, counter: number, digits = 6): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

function totpAt(nowMs: number): { code: string; timestep: number } {
  const timestep = Math.floor(nowMs / 1000 / 30);
  return { code: hotp(TOTP_SECRET, timestep), timestep };
}

function baseOp(overrides: Partial<ApprovalOperationSnapshot> = {}): ApprovalOperationSnapshot {
  return {
    operationId: OPERATION_ID,
    nodeId: NODE_ID,
    status: "CREATED",
    rowVersion: 1,
    sourceWalletId: WALLET_ID,
    sourcePubkey: SOURCE_PUB,
    destinationAddress: DEST,
    amountZkz: AMOUNT,
    referencesOperationId: null,
    ...overrides,
  };
}

function makeDeviceStore(device?: EnrolledDeviceKey): InMemoryDeviceKeyStore {
  const store = new InMemoryDeviceKeyStore();
  if (device) store.insert(device);
  return store;
}

function generateDevice(): { key: EnrolledDeviceKey; sign: (p: string) => string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const rawPub = spki.subarray(spki.length - 32);
  let pub = Buffer.from(rawPub).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
  if (!pub.endsWith("=")) pub += "=".repeat((4 - (pub.length % 4)) % 4);
  const key: EnrolledDeviceKey = {
    id: DEVICE_ID,
    nodeId: NODE_ID,
    publicKey: pub,
    label: "test-device",
    enrolledAt: GOLDEN_ISSUED,
    revokedAt: null,
  };
  const sign = (preimage: string): string => {
    const sig = edSign(null, Buffer.from(preimage, "utf8"), privateKey);
    let b64 = Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
    if (!b64.endsWith("==")) b64 += "==".slice(0, (4 - (b64.length % 4)) % 4);
    return b64;
  };
  return { key, sign };
}

function seedOp(
  store: InMemoryApprovalChallengeStore,
  op: ApprovalOperationSnapshot = baseOp(),
): ApprovalOperationSnapshot {
  store.seedOperation(op.operationId, op.status, op.rowVersion);
  return op;
}

async function issueFixture(
  store: InMemoryApprovalChallengeStore,
  op: ApprovalOperationSnapshot,
  nowMs = FIXED_NOW,
  nonce = GOLDEN_NONCE,
  id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
) {
  seedOp(store, op);
  const issuedAt = toCanonicalTimestamp(nowMs);
  const expiresAt = toCanonicalTimestamp(nowMs + APPROVAL_CHALLENGE_FRESHNESS_MS);
  const preimage = buildApprovalPreimage({
    nodeId: op.nodeId,
    operationId: op.operationId,
    sourceWalletId: op.sourceWalletId,
    sourcePubkey: op.sourcePubkey,
    destinationAddress: op.destinationAddress,
    amountZkz: op.amountZkz,
    referencesOperationId: op.referencesOperationId,
    nonce,
    issuedAt,
    expiresAt,
  });
  const challenge = {
    id,
    nodeId: op.nodeId,
    operationId: op.operationId,
    status: "ISSUED" as const,
    purpose: APPROVAL_PURPOSE,
    canonicalVersion: 1 as const,
    nonce,
    preimageText: preimage.preimageText,
    preimageSha256: preimage.preimageSha256,
    issuedAt,
    expiresAt,
    supersededBy: null,
  };
  await store.insertIssued(challenge, null);
  return challenge;
}

function approveDeps(
  store: InMemoryApprovalChallengeStore,
  extras: Partial<ApproveDeps> = {},
): ApproveDeps {
  return {
    challengeStore: store,
    loadOperation: async (id) => {
      const st = store.getOperationState(id);
      if (st === null) return null;
      // Prefer seeded economic fields from OPERATION_ID fixture defaults, override id/status/version.
      const base =
        id === OPERATION_ID
          ? baseOp()
          : baseOp({ operationId: id });
      return {
        ...base,
        operationId: id,
        status: st.status,
        rowVersion: st.rowVersion,
      };
    },
    deviceStore: makeDeviceStore(),
    totpConfig: TOTP_CONFIG,
    totpBurnStore: new TotpConsumptionLog(),
    requireDeviceSignature: false,
    nowMs: () => FIXED_NOW,
    generateId: () => "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    ...extras,
  };
}

describe("buildApprovalPreimage — A.8 golden", () => {
  it("reproduces the exact preimage text and SHA-256", () => {
    const built = buildApprovalPreimage({
      nodeId: NODE_ID,
      operationId: OPERATION_ID,
      sourceWalletId: WALLET_ID,
      sourcePubkey: SOURCE_PUB,
      destinationAddress: DEST,
      amountZkz: AMOUNT,
      referencesOperationId: null,
      nonce: GOLDEN_NONCE,
      issuedAt: GOLDEN_ISSUED,
      expiresAt: GOLDEN_EXPIRES,
    });
    expect(built.preimageText).toBe(GOLDEN_PREIMAGE);
    expect(built.preimageSha256).toBe(GOLDEN_DIGEST);
    expect(built.preimageSha256).toBe(
      "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146",
    );
    expect(createHash("sha256").update(built.preimageText, "utf8").digest("hex")).toBe(
      built.preimageSha256,
    );
  });

  it("purpose literal is zp-send-external-approval-v1 (compatibility-literal allowlist)", () => {
    expect(APPROVAL_PURPOSE).toBe("zp-send-external-approval-v1");
    expect(GOLDEN_PREIMAGE.startsWith("zp-send-external-approval-v1\n")).toBe(true);
  });

  it("carries no split_inner_sha256 field (A.4.1)", () => {
    expect(GOLDEN_PREIMAGE.includes("split_inner")).toBe(false);
    expect(GOLDEN_PREIMAGE.includes("SEND_REDEMPTION_WINDOW")).toBe(false);
  });
});

describe("issueOrRefreshApprovalChallenge", () => {
  it("issues a challenge for a CREATED operation with rebuilt preimage", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const op = baseOp();
    let n = 0;
    const ids = [GOLDEN_NONCE, "cccccccc-cccc-4ccc-8ccc-cccccccccccc"];
    const result = await issueOrRefreshApprovalChallenge(OPERATION_ID, {
      challengeStore: store,
      loadOperation: async () => op,
      nowMs: () => FIXED_NOW,
      generateId: () => ids[n++] ?? "ffffffff-ffff-4fff-8fff-ffffffffffff",
    });
    expect(result.outcome).toBe("ISSUED");
    if (result.outcome !== "ISSUED") return;
    expect(result.challenge.purpose).toBe(APPROVAL_PURPOSE);
    expect(result.challenge.preimageSha256).toBe(GOLDEN_DIGEST);
    expect(result.challenge.preimageText).toBe(GOLDEN_PREIMAGE);
    expect(result.response.amount_zkz).toBe(AMOUNT);
    expect(result.response.source_selector).toEqual({ kind: "WALLET_ID", wallet_id: WALLET_ID });
  });

  it("refresh supersedes prior and changes only nonce/issued_at/expires_at", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const op = baseOp();
    const mkIds = (a: string, b: string) => {
      let i = 0;
      const seq = [a, b];
      return () => seq[i++]!;
    };
    const first = await issueOrRefreshApprovalChallenge(OPERATION_ID, {
      challengeStore: store,
      loadOperation: async () => op,
      nowMs: () => FIXED_NOW,
      generateId: mkIds("11111111-1111-4111-8111-111111111101", "22222222-2222-4222-8222-222222222201"),
    });
    expect(first.outcome).toBe("ISSUED");
    if (first.outcome !== "ISSUED") return;
    const second = await issueOrRefreshApprovalChallenge(OPERATION_ID, {
      challengeStore: store,
      loadOperation: async () => op,
      nowMs: () => FIXED_NOW + 1_000,
      generateId: mkIds("11111111-1111-4111-8111-111111111102", "22222222-2222-4222-8222-222222222202"),
    });
    expect(second.outcome).toBe("ISSUED");
    if (second.outcome !== "ISSUED") return;
    expect(second.response.amount_zkz).toBe(first.response.amount_zkz);
    expect(second.response.destination_address).toBe(first.response.destination_address);
    expect(second.response.source_pubkey).toBe(first.response.source_pubkey);
    expect(second.challenge.nonce).not.toBe(first.challenge.nonce);
    expect(second.challenge.issuedAt).not.toBe(first.challenge.issuedAt);
    const prior = await store.findByNonce(first.challenge.nonce);
    expect(prior?.status).toBe("SUPERSEDED");
    expect(prior?.supersededBy).toBe(second.challenge.id);
  });

  it("rejects non-CREATED and unknown operations", async () => {
    const store = new InMemoryApprovalChallengeStore();
    expect(
      await issueOrRefreshApprovalChallenge(OPERATION_ID, {
        challengeStore: store,
        loadOperation: async () => baseOp({ status: "APPROVED" }),
      }),
    ).toEqual({ outcome: "REJECTED", reason: "operation_not_created" });
    expect(
      await issueOrRefreshApprovalChallenge(OPERATION_ID, {
        challengeStore: store,
        loadOperation: async () => null,
      }),
    ).toEqual({ outcome: "REJECTED", reason: "operation_not_found" });
  });
});

describe("approveExternalSend — guarded mutation", () => {
  it("approves with fresh TOTP_ONLY and transitions CREATED→APPROVED", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp());
    const { code, timestep } = totpAt(FIXED_NOW);
    const result = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: code,
      },
      approveDeps(store),
    );
    expect(result.outcome).toBe("APPROVED");
    if (result.outcome !== "APPROVED") return;
    expect(result.approval.method).toBe("TOTP_ONLY");
    expect(result.approval.totpTimestep).toBe(timestep);
    expect(result.rowVersion).toBe(2);
    expect(store.getOperationState(OPERATION_ID)?.status).toBe("APPROVED");
    expect(store.isTimestepBurned(NODE_ID, timestep)).toBe(true);
    expect((await store.findByNonce(challenge.nonce))?.status).toBe("CONSUMED");
    expect(store.getApproval(OPERATION_ID)?.id).toBe(result.approval.id);
  });

  it("rejects stale row_version BEFORE TOTP", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp({ rowVersion: 5 }));
    const result = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: "000000",
      },
      approveDeps(store, {
        loadOperation: async () => baseOp({ rowVersion: 5 }),
      }),
    );
    expect(result).toEqual({ outcome: "REJECTED", reason: "row_version_mismatch" });
    expect(store.isTimestepBurned(NODE_ID, totpAt(FIXED_NOW).timestep)).toBe(false);
  });

  it("rejects stale/unknown nonce BEFORE TOTP", async () => {
    const store = new InMemoryApprovalChallengeStore();
    await issueFixture(store, baseOp());
    const result = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        expectedRowVersion: 1,
        preimageSha256: "a".repeat(64),
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: "000000",
      },
      approveDeps(store),
    );
    expect(result).toEqual({ outcome: "REJECTED", reason: "challenge_not_found" });
  });

  it("rejects preimage_sha256 mismatch without burning TOTP", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp());
    const result = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: "b".repeat(64),
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: totpAt(FIXED_NOW).code,
      },
      approveDeps(store),
    );
    expect(result).toEqual({ outcome: "REJECTED", reason: "preimage_mismatch" });
    expect(store.isTimestepBurned(NODE_ID, totpAt(FIXED_NOW).timestep)).toBe(false);
  });

  it("rejects substitution of locked economic fields", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp());
    const result = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: totpAt(FIXED_NOW).code,
      },
      approveDeps(store, {
        loadOperation: async () => baseOp({ amountZkz: "9.99" }),
      }),
    );
    expect(result).toEqual({ outcome: "REJECTED", reason: "preimage_mismatch" });
  });

  it("rejects invalid TOTP without burning", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp());
    const result = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: "999999",
      },
      approveDeps(store),
    );
    expect(result).toEqual({ outcome: "REJECTED", reason: "totp_invalid" });
    expect(store.isTimestepBurned(NODE_ID, totpAt(FIXED_NOW).timestep)).toBe(false);
  });

  it("rejects expired challenge before TOTP", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp(), FIXED_NOW);
    const later = FIXED_NOW + APPROVAL_CHALLENGE_FRESHNESS_MS + 1;
    const result = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: totpAt(later).code,
      },
      approveDeps(store, { nowMs: () => later }),
    );
    expect(result).toEqual({ outcome: "REJECTED", reason: "challenge_expired" });
  });

  it("replayed TOTP timestep is rejected by unique claim", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp());
    const { code, timestep } = totpAt(FIXED_NOW);
    const first = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: code,
      },
      approveDeps(store),
    );
    expect(first.outcome).toBe("APPROVED");
    const op2Id = "44444444-4444-4444-8444-444444444444";
    const op2 = baseOp({ operationId: op2Id });
    const challenge2 = await issueFixture(
      store,
      op2,
      FIXED_NOW,
      "88888888-8888-4888-8888-888888888888",
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    );
    const second = await approveExternalSend(
      {
        operationId: op2.operationId,
        challengeNonce: challenge2.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge2.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: code,
      },
      {
        ...approveDeps(store),
        loadOperation: async (id) => {
          const st = store.getOperationState(id);
          if (st === null) return null;
          return { ...op2, status: st.status, rowVersion: st.rowVersion };
        },
      },
    );
    expect(second).toEqual({ outcome: "REJECTED", reason: "totp_replay" });
    expect(store.isTimestepBurned(NODE_ID, timestep)).toBe(true);
  });

  it("CAS miss inside mutation rolls back — no orphan approval, challenge ISSUED, timestep free", async () => {
    const store = new InMemoryApprovalChallengeStore();
    store.failNextApproveCas = true;
    const challenge = await issueFixture(store, baseOp());
    const { code, timestep } = totpAt(FIXED_NOW);
    const result = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: code,
      },
      approveDeps(store),
    );
    expect(result).toEqual({ outcome: "REJECTED", reason: "operation_conflict" });
    // All-or-nothing: no durable evidence of the failed mutation.
    expect(store.getApproval(OPERATION_ID)).toBeNull();
    expect((await store.findByNonce(challenge.nonce))?.status).toBe("ISSUED");
    expect(store.isTimestepBurned(NODE_ID, timestep)).toBe(false);
    expect(store.getOperationState(OPERATION_ID)).toEqual({ status: "CREATED", rowVersion: 1 });

    // Same op can still approve with the same challenge + TOTP after the rolled-back CAS miss.
    const retry = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: code,
      },
      approveDeps(store),
    );
    expect(retry.outcome).toBe("APPROVED");
    if (retry.outcome !== "APPROVED") return;
    expect(store.getOperationState(OPERATION_ID)?.status).toBe("APPROVED");
    expect(store.isTimestepBurned(NODE_ID, timestep)).toBe(true);
    expect(store.getApproval(OPERATION_ID)?.id).toBe(retry.approval.id);
  });

  it("concurrent approveExternalSend: exactly one APPROVED, zero orphan approvals", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp());
    const { code, timestep } = totpAt(FIXED_NOW);
    const req = {
      operationId: OPERATION_ID,
      challengeNonce: challenge.nonce,
      expectedRowVersion: 1,
      preimageSha256: challenge.preimageSha256,
      deviceKeyId: null,
      deviceSignature: null,
      totpCode: code,
    } as const;
    let n = 0;
    const ids = [
      "dddddddd-dddd-4ddd-8ddd-ddddddddddd1",
      "dddddddd-dddd-4ddd-8ddd-ddddddddddd2",
      "dddddddd-dddd-4ddd-8ddd-ddddddddddd3",
      "dddddddd-dddd-4ddd-8ddd-ddddddddddd4",
    ];
    const deps = approveDeps(store, {
      generateId: () => ids[n++] ?? `dddddddd-dddd-4ddd-8ddd-dddddddddd${n}`,
    });
    const results = await Promise.all([
      approveExternalSend(req, deps),
      approveExternalSend(req, deps),
      approveExternalSend(req, deps),
      approveExternalSend(req, deps),
    ]);
    const approved = results.filter((r) => r.outcome === "APPROVED");
    const rejected = results.filter((r) => r.outcome === "REJECTED");
    expect(approved).toHaveLength(1);
    expect(rejected).toHaveLength(3);
    for (const r of rejected) {
      if (r.outcome !== "REJECTED") continue;
      expect([
        "totp_replay",
        "challenge_not_issued",
        "approval_exists",
        "operation_conflict",
      ]).toContain(r.reason);
    }
    expect(store.getOperationState(OPERATION_ID)?.status).toBe("APPROVED");
    expect(store.getApproval(OPERATION_ID)).not.toBeNull();
    expect(store.isTimestepBurned(NODE_ID, timestep)).toBe(true);
    expect(store.getApproval(OPERATION_ID)?.challengeId).toBe(challenge.id);
  });

  it("TOTP_AND_DEVICE verifies signature; rejects bad sig and XOR fields", async () => {
    const store = new InMemoryApprovalChallengeStore();
    const { key, sign } = generateDevice();
    const deviceStore = makeDeviceStore(key);
    const challenge = await issueFixture(store, baseOp());
    const goodSig = sign(challenge.preimageText);
    const ok = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: key.id,
        deviceSignature: goodSig,
        totpCode: totpAt(FIXED_NOW).code,
      },
      approveDeps(store, { deviceStore, requireDeviceSignature: true }),
    );
    expect(ok.outcome).toBe("APPROVED");
    if (ok.outcome === "APPROVED") {
      expect(ok.approval.method).toBe("TOTP_AND_DEVICE");
      expect(ok.approval.deviceSignature).toBe(goodSig);
    }

    const storeB = new InMemoryApprovalChallengeStore();
    const challengeB = await issueFixture(
      storeB,
      baseOp(),
      FIXED_NOW,
      "99999999-9999-4999-8999-999999999991",
      "cccccccc-cccc-4ccc-8ccc-ccccccccccc1",
    );
    const bad = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challengeB.nonce,
        expectedRowVersion: 1,
        preimageSha256: challengeB.preimageSha256,
        deviceKeyId: key.id,
        deviceSignature: "A".repeat(86) + "==",
        totpCode: totpAt(FIXED_NOW).code,
      },
      approveDeps(storeB, {
        deviceStore,
        requireDeviceSignature: true,
      }),
    );
    expect(bad).toEqual({ outcome: "REJECTED", reason: "device_signature_invalid" });

    const xor = await approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challengeB.nonce,
        expectedRowVersion: 1,
        preimageSha256: challengeB.preimageSha256,
        deviceKeyId: DEVICE_ID,
        deviceSignature: null,
        totpCode: totpAt(FIXED_NOW).code,
      },
      approveDeps(storeB, { requireDeviceSignature: true }),
    );
    expect(xor).toEqual({ outcome: "REJECTED", reason: "request_invalid" });
  });

  it("golden device signature wire values match A.8", () => {
    expect(GOLDEN_SIG).toBe(
      "HLd6EN7uw2KHCgRAryuyEh6ljmHsjgvCJ6Ke1Gq3fb0PDV1Vsn3QCzuo51o0VnH9LCbDI3c_s6AFK3NO013ZCA==",
    );
    expect(GOLDEN_DIGEST).toBe(
      "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146",
    );
  });
});

describe("opaque factor failure", () => {
  it("every FACTOR reject reason collapses to the same HTTP code and status", () => {
    const factorReasons = APPROVAL_REJECT_REASONS.filter(
      (r) => r !== APPROVAL_POLICY_DENIAL_CODE,
    );
    expect(factorReasons).toHaveLength(APPROVAL_REJECT_REASONS.length - 1);
    const bodies = factorReasons.map((r) => toOpaqueApprovalFailure(r));
    for (const b of bodies) {
      expect(b.code).toBe(APPROVAL_FACTOR_FAILURE_CODE);
      expect(b.httpStatus).toBe(APPROVAL_FACTOR_FAILURE_HTTP_STATUS);
    }
    expect(new Set(bodies.map((b) => JSON.stringify(b))).size).toBe(1);
  });

  // Doc 01 §4.2: optional policy stays distinguishable from protocol validity.
  // The exception is exactly one reason wide, and it names the deployment's policy
  // rather than a factor — a caller still cannot tell TOTP from device from nonce.
  it("policy denial is the one distinguishable code, at the same status", () => {
    const policy = toOpaqueApprovalFailure(APPROVAL_POLICY_DENIAL_CODE);
    expect(policy.code).toBe(APPROVAL_POLICY_DENIAL_CODE);
    expect(policy.code).not.toBe(APPROVAL_FACTOR_FAILURE_CODE);
    expect(policy.httpStatus).toBe(APPROVAL_FACTOR_FAILURE_HTTP_STATUS);
  });
});

describe("approveExternalSend — two-human dual control", () => {
  const ISSUER = "operator-a";
  const CHALLENGE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

  function issuerStore(): InMemoryApprovalChallengeIssuerStore {
    const store = new InMemoryApprovalChallengeIssuerStore();
    store.recordIssuer(OPERATION_ID, CHALLENGE_ID, ISSUER);
    return store;
  }

  async function approveAs(approverOperatorId: string, extras: Partial<ApproveDeps>) {
    const store = new InMemoryApprovalChallengeStore();
    const challenge = await issueFixture(store, baseOp());
    return approveExternalSend(
      {
        operationId: OPERATION_ID,
        challengeNonce: challenge.nonce,
        expectedRowVersion: 1,
        preimageSha256: challenge.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: totpAt(FIXED_NOW).code,
        approverOperatorId,
      },
      approveDeps(store, extras),
    );
  }

  it("rejects the same operator on both sides", async () => {
    const result = await approveAs(ISSUER, {
      dualControlMode: "two_human",
      challengeIssuerStore: issuerStore(),
    });
    expect(result.outcome).toBe("REJECTED");
    if (result.outcome !== "REJECTED") return;
    expect(result.reason).toBe(APPROVAL_POLICY_DENIAL_CODE);
  });

  it("admits a different operator", async () => {
    const result = await approveAs("operator-b", {
      dualControlMode: "two_human",
      challengeIssuerStore: issuerStore(),
    });
    expect(result.outcome).toBe("APPROVED");
  });

  // Distinctness that cannot be proven is not distinctness.
  it("fails closed when the issuer was never recorded", async () => {
    const result = await approveAs("operator-b", {
      dualControlMode: "two_human",
      challengeIssuerStore: new InMemoryApprovalChallengeIssuerStore(),
    });
    expect(result.outcome).toBe("REJECTED");
    if (result.outcome !== "REJECTED") return;
    expect(result.reason).toBe(APPROVAL_POLICY_DENIAL_CODE);
  });

  it("fails closed when no issuer store is wired at all", async () => {
    const result = await approveAs("operator-b", { dualControlMode: "two_human" });
    expect(result.outcome).toBe("REJECTED");
    if (result.outcome !== "REJECTED") return;
    expect(result.reason).toBe(APPROVAL_POLICY_DENIAL_CODE);
  });

  it("single_operator still admits one operator on both sides", async () => {
    const result = await approveAs(ISSUER, {
      dualControlMode: "single_operator",
      challengeIssuerStore: issuerStore(),
    });
    expect(result.outcome).toBe("APPROVED");
  });
});
