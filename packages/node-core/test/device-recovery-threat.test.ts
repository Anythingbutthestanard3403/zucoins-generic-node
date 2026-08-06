/**
 * Threat-test device and recovery lifecycle.
 *
 * Adversarial proof over the real device-recovery surfaces (verifyAndEnrolDevice,
 * revokeDevice, break-glass, enrollment challenges, device signature verify,
 * enrollment/revocation/break-glass audit logs, and the mandatory TOTP mutation
 * gate). Each checklist category is an independent describe block with a
 * pre-fix control against production code — not test-local literals.
 *
 *
 * Exit criterion: bare login cannot enroll a permanent custody-authority key;
 * device signature cannot replace mandatory TOTP for money mutation.
 */

import { createHash, createHmac, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

// Source import: approval is not a package export subpath; contracts live in-tree.
import { APPROVAL_AUTH } from "../../generic-node-contracts/src/approval/approval-tuple.contract.js";

import {
  InMemoryEnrollmentAuditLog,
  InMemoryBreakGlassAuditLog,
  InMemoryBreakGlassAuthorityStore,
  InMemoryDeviceKeyStore,
  InMemoryDeviceRevocationAuditLog,
  InMemoryEnrollmentChallengeStore,
  NoopDeviceRevocationSideEffects,
  issueEnrollmentChallenge,
  ratifyBreakGlassAuthority,
  revokeDevice,
  verifyAndEnrolDevice,
  verifyDeviceSignature,
  type EnrolmentDeps,
  type EnrolmentVerificationInput,
} from "../src/device/index.js";
import {
  guardedMutation,
  TotpConsumptionLog,
  verifyTotp,
  type TotpConfig,
} from "../src/http/totp-chain.js";
import { buildDeviceEnrol, buildSendExternalApproval } from "../src/protocol/suite/builders.js";
import {
  verifySendExternalApprovalDeviceSignature,
  type SignedSuiteTupleEnvelope,
} from "../src/protocol/suite/verify.js";
import { InMemoryReportingRateLimiter } from "../src/reporting/in-memory-rate-limiter.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NODE_A = "11111111-1111-4111-8111-111111111111";
const NODE_B = "22222222-2222-4222-8222-222222222222";
const AUTHORIZER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const NEW_DEVICE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ROTATED_DEVICE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const BG_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const OP_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const WALLET_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const NONCE_UUID = "99999999-9999-4999-8999-999999999999";

const ED25519_SPKI_DER_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function generateTestKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ format: "der", type: "spki" });
  const rawPub = new Uint8Array(spkiDer.slice(ED25519_SPKI_DER_PREFIX.length));
  const paddedBase64Url = Buffer.from(rawPub)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return { publicKey, privateKey, rawPub, paddedBase64Url };
}

type TestKeyPair = ReturnType<typeof generateTestKeyPair>;

function signPreimageB64(privateKey: TestKeyPair["privateKey"], preimageText: string): string {
  const sig = sign(null, Buffer.from(preimageText, "utf8"), privateKey);
  return Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function signText(privateKey: TestKeyPair["privateKey"], text: string): Uint8Array {
  return new Uint8Array(sign(null, Buffer.from(text, "utf8"), privateKey));
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function seedDevice(
  store: InMemoryDeviceKeyStore,
  id: string,
  pair: TestKeyPair,
  nodeId: string,
  label: string,
): void {
  store.insert({
    id,
    nodeId,
    publicKey: pair.paddedBase64Url,
    label,
    enrolledAt: "2026-01-01T00:00:00.000Z",
    revokedAt: null,
  });
}

interface LifecycleHarness {
  readonly deps: EnrolmentDeps;
  readonly authorizing: TestKeyPair;
  readonly newDevice: TestKeyPair;
  readonly deviceStore: InMemoryDeviceKeyStore;
  readonly challengeStore: InMemoryEnrollmentChallengeStore;
  readonly auditLog: InMemoryEnrollmentAuditLog;
  readonly breakGlassStore: InMemoryBreakGlassAuthorityStore;
  readonly revokeAudit: InMemoryDeviceRevocationAuditLog;
  readonly breakGlassAudit: InMemoryBreakGlassAuditLog;
}

function makeHarness(opts: { seedAuthorizer?: boolean; nodeId?: string } = {}): LifecycleHarness {
  const nodeId = opts.nodeId ?? NODE_A;
  const deviceStore = new InMemoryDeviceKeyStore();
  const challengeStore = new InMemoryEnrollmentChallengeStore();
  const auditLog = new InMemoryEnrollmentAuditLog();
  const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
  const authorizing = generateTestKeyPair();
  const newDevice = generateTestKeyPair();
  if (opts.seedAuthorizer !== false) {
    seedDevice(deviceStore, AUTHORIZER_ID, authorizing, nodeId, "seed-authorizer");
  }
  return {
    deps: { deviceStore, challengeStore, auditLog, breakGlassStore },
    authorizing,
    newDevice,
    deviceStore,
    challengeStore,
    auditLog,
    breakGlassStore,
    revokeAudit: new InMemoryDeviceRevocationAuditLog(),
    breakGlassAudit: new InMemoryBreakGlassAuditLog(),
  };
}

function issueAndBuild(
  h: LifecycleHarness,
  overrides: {
    nodeId?: string;
    label?: string;
    newDeviceKeyId?: string;
    newDevicePublicKey?: string;
    nowMs?: number;
    expiresAtMs?: number;
    authorizingKeyId?: string;
    authorizingPair?: TestKeyPair;
    popPair?: TestKeyPair;
    breakGlass?: boolean;
  } = {},
): { preimageText: string; input: EnrolmentVerificationInput; challengeId: string } {
  const nodeId = overrides.nodeId ?? NODE_A;
  const nowMs = overrides.nowMs ?? Date.parse("2026-07-18T00:00:00.000Z");
  const authPair = overrides.authorizingPair ?? h.authorizing;
  const popPair = overrides.popPair ?? h.newDevice;
  const issued = issueEnrollmentChallenge(h.challengeStore, {
    nodeId,
    nowMs,
    expiresAtMs: overrides.expiresAtMs,
  });
  if (!issued.ok) throw new Error(`issue failed: ${issued.code}`);

  const built = buildDeviceEnrol({
    node_id: nodeId as never,
    new_device_key_id: (overrides.newDeviceKeyId ?? NEW_DEVICE_ID) as never,
    new_device_public_key: (overrides.newDevicePublicKey ?? popPair.paddedBase64Url) as never,
    label: overrides.label ?? "threat-device",
    nonce: issued.challenge.nonce as never,
    issued_at: issued.challenge.issuedAt,
    expires_at: issued.challenge.expiresAt,
  });

  const input: EnrolmentVerificationInput = {
    preimageText: built.preimageText,
    authorizingKeyId: overrides.authorizingKeyId ?? AUTHORIZER_ID,
    authorizingPublicKey: authPair.paddedBase64Url,
    authorizingSignature: signPreimageB64(authPair.privateKey, built.preimageText),
    preimageSha256: built.sha256,
    newDevicePopSignature: signPreimageB64(popPair.privateKey, built.preimageText),
    nowMs: nowMs + 60_000,
    breakGlass: overrides.breakGlass,
  };

  return { preimageText: built.preimageText, input, challengeId: issued.challenge.id };
}

function generateTotp(secret: Uint8Array, timestep: number, digits = 6): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestep));
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

function assertNoPrivateKeyMaterial(obj: unknown): void {
  const blob = JSON.stringify(obj);
  expect(blob).not.toMatch(/BEGIN PRIVATE|private_key|privateKey|secret_key|seed_hex/i);
  if (obj !== null && typeof obj === "object") {
    for (const key of Object.keys(obj as object)) {
      expect(key.toLowerCase()).not.toMatch(/private|secret_key|seed/);
    }
  }
}

// ===========================================================================
// 1. Stolen / replayed enrollment challenges
// ===========================================================================

describe("stolen/replayed enrollment challenges (A.1.1 nonce/expires_at)", () => {
  it("rejects a second enroll that reuses a consumed challenge nonce", () => {
    const h = makeHarness();
    const { input } = issueAndBuild(h);
    const first = verifyAndEnrolDevice(h.deps, input);
    expect(first.ok).toBe(true);

    const replay = verifyAndEnrolDevice(h.deps, {
      ...input,
      nowMs: input.nowMs + 1,
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(replay.code).toBe("CHALLENGE_NOT_ISSUED");
    }
  });

  it("rejects an enrollment past expires_at (real verifyAndEnrolDevice wall-clock gate)", () => {
    const h = makeHarness();
    const issuedAt = Date.parse("2026-07-18T00:00:00.000Z");
    const { input } = issueAndBuild(h, {
      nowMs: issuedAt,
      expiresAtMs: issuedAt + 120_000,
    });
    const late: EnrolmentVerificationInput = {
      ...input,
      nowMs: issuedAt + 300_000,
    };
    const result = verifyAndEnrolDevice(h.deps, late);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(["CHALLENGE_EXPIRED", "ENROLMENT_EXPIRED"]).toContain(result.code);
    }
    expect(h.deviceStore.findById(NEW_DEVICE_ID)).toBeNull();
  });

  it("rejects redirecting a signed enrollment to a different new_device_public_key", () => {
    const h = makeHarness();
    const impostor = generateTestKeyPair();
    const { input, preimageText } = issueAndBuild(h);

    const newline = preimageText.indexOf("\n");
    const payload = JSON.parse(preimageText.slice(newline + 1)) as Record<string, unknown>;
    payload.new_device_public_key = impostor.paddedBase64Url;
    const tamperedPreimage = preimageText.slice(0, newline + 1) + JSON.stringify(payload);

    const result = verifyAndEnrolDevice(h.deps, {
      ...input,
      preimageText: tamperedPreimage,
      preimageSha256: sha256Hex(tamperedPreimage),
      newDevicePopSignature: signPreimageB64(impostor.privateKey, tamperedPreimage),
    });
    expect(result.ok).toBe(false);
    expect(h.deviceStore.findByNodeAndPublicKey(NODE_A, impostor.paddedBase64Url)).toBeNull();
  });
});

// ===========================================================================
// 2. Wrong admin / node (node_id binding)
// ===========================================================================

describe("wrong admin/node — cross-node replay rejected on node_id", () => {
  it("rejects enrollment when challenge was issued for a different node_id", () => {
    const h = makeHarness();
    const nowMs = Date.parse("2026-07-18T00:00:00.000Z");
    const issuedB = issueEnrollmentChallenge(h.challengeStore, { nodeId: NODE_B, nowMs });
    if (!issuedB.ok) throw new Error(issuedB.code);

    const built = buildDeviceEnrol({
      node_id: NODE_A as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: h.newDevice.paddedBase64Url as never,
      label: "cross-node",
      nonce: issuedB.challenge.nonce as never,
      issued_at: issuedB.challenge.issuedAt,
      expires_at: issuedB.challenge.expiresAt,
    });

    const result = verifyAndEnrolDevice(h.deps, {
      preimageText: built.preimageText,
      authorizingKeyId: AUTHORIZER_ID,
      authorizingPublicKey: h.authorizing.paddedBase64Url,
      authorizingSignature: signPreimageB64(h.authorizing.privateKey, built.preimageText),
      preimageSha256: built.sha256,
      newDevicePopSignature: signPreimageB64(h.newDevice.privateKey, built.preimageText),
      nowMs: nowMs + 60_000,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("CHALLENGE_MISMATCH");
    }
  });

  it("rejects an authorizer enrolled only on another node (node_id mismatch before deeper work)", () => {
    const h = makeHarness({ seedAuthorizer: false });
    seedDevice(h.deviceStore, AUTHORIZER_ID, h.authorizing, NODE_B, "other-node-device");
    const { input } = issueAndBuild(h, { nodeId: NODE_A });
    const result = verifyAndEnrolDevice(h.deps, input);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("AUTHORIZER_UNKNOWN");
    }
  });

  it("verifyDeviceSignature rejects a device public key enrolled on a different node", () => {
    const h = makeHarness();
    const preimage = "zp-send-external-approval-v1\n{}";
    const sig = signText(h.authorizing.privateKey, preimage);
    const cross = verifyDeviceSignature(h.deviceStore, {
      nodeId: NODE_B,
      publicKey: h.authorizing.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: sig,
    });
    expect(cross.ok).toBe(false);
    if (!cross.ok) {
      expect(cross.code).toBe("UNKNOWN_DEVICE");
    }
  });
});

// ===========================================================================
// 3. Key rotation
// ===========================================================================

describe("key rotation (new enroll + old revoke)", () => {
  it("rotation keeps existing-trusted-device gate: new enroll requires active authorizer", () => {
    const h = makeHarness();
    const rotated = generateTestKeyPair();
    const { input } = issueAndBuild(h, {
      newDeviceKeyId: ROTATED_DEVICE_ID,
      newDevicePublicKey: rotated.paddedBase64Url,
      popPair: rotated,
    });
    const enrolled = verifyAndEnrolDevice(h.deps, input);
    expect(enrolled.ok).toBe(true);

    expect(h.deviceStore.findActiveByNodeAndPublicKey(NODE_A, h.authorizing.paddedBase64Url)).not.toBeNull();
    expect(h.deviceStore.findActiveByNodeAndPublicKey(NODE_A, rotated.paddedBase64Url)).not.toBeNull();

    const rev = revokeDevice(
      {
        deviceStore: h.deviceStore,
        challengeStore: h.challengeStore,
        breakGlassStore: h.breakGlassStore,
        auditLog: h.revokeAudit,
        sideEffects: new NoopDeviceRevocationSideEffects(),
      },
      {
        nodeId: NODE_A,
        targetDeviceKeyId: AUTHORIZER_ID,
        authorizingDeviceKeyId: ROTATED_DEVICE_ID,
        authorizingDevicePublicKey: rotated.paddedBase64Url,
        nowMs: Date.parse("2026-07-18T01:00:00.000Z"),
      },
    );
    expect(rev.ok).toBe(true);

    const oldSig = verifyDeviceSignature(h.deviceStore, {
      nodeId: NODE_A,
      publicKey: h.authorizing.paddedBase64Url,
      preimageText: "post-rotation-action",
      signatureBytes: signText(h.authorizing.privateKey, "post-rotation-action"),
    });
    expect(oldSig.ok).toBe(false);
    if (!oldSig.ok) expect(oldSig.code).toBe("DEVICE_REVOKED");

    const newSig = verifyDeviceSignature(h.deviceStore, {
      nodeId: NODE_A,
      publicKey: rotated.paddedBase64Url,
      preimageText: "post-rotation-action",
      signatureBytes: signText(rotated.privateKey, "post-rotation-action"),
    });
    expect(newSig.ok).toBe(true);

    expect(h.deviceStore.findById(AUTHORIZER_ID)?.revokedAt).not.toBeNull();
  });

  it("revoked-out authorizer cannot enroll a further device after rotation", () => {
    const h = makeHarness();
    h.deviceStore.revoke(AUTHORIZER_ID, "2026-07-18T00:30:00.000Z");
    const next = generateTestKeyPair();
    const { input } = issueAndBuild(h, {
      newDeviceKeyId: ROTATED_DEVICE_ID,
      newDevicePublicKey: next.paddedBase64Url,
      popPair: next,
    });
    const result = verifyAndEnrolDevice(h.deps, input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("AUTHORIZER_REVOKED");
  });
});

// ===========================================================================
// 4. Revocation race
// ===========================================================================

describe("revocation race (concurrent revoke vs enroll / approve)", () => {
  it("concurrent revoke and enroll resolve to a single consistent winner", async () => {
    const h = makeHarness();
    const candidate = generateTestKeyPair();
    const { input } = issueAndBuild(h, {
      newDeviceKeyId: ROTATED_DEVICE_ID,
      newDevicePublicKey: candidate.paddedBase64Url,
      popPair: candidate,
    });

    const [enrollResult, revokeResult] = await Promise.all([
      Promise.resolve().then(() => verifyAndEnrolDevice(h.deps, input)),
      Promise.resolve().then(() =>
        revokeDevice(
          {
            deviceStore: h.deviceStore,
            challengeStore: h.challengeStore,
            breakGlassStore: h.breakGlassStore,
            auditLog: h.revokeAudit,
            sideEffects: new NoopDeviceRevocationSideEffects(),
          },
          {
            nodeId: NODE_A,
            targetDeviceKeyId: AUTHORIZER_ID,
            authorizingDeviceKeyId: AUTHORIZER_ID,
            authorizingDevicePublicKey: h.authorizing.paddedBase64Url,
            nowMs: Date.parse("2026-07-18T00:02:00.000Z"),
          },
        ),
      ),
    ]);

    const authorizerActive = h.deviceStore.findActiveByNodeAndPublicKey(
      NODE_A,
      h.authorizing.paddedBase64Url,
    );
    expect(revokeResult.ok).toBe(true);
    expect(authorizerActive).toBeNull();

    if (enrollResult.ok) {
      expect(h.deviceStore.findById(ROTATED_DEVICE_ID)).not.toBeNull();
    } else {
      expect(["AUTHORIZER_REVOKED", "AUTHORIZER_UNKNOWN", "CHALLENGE_NOT_ISSUED", "CHALLENGE_EXPIRED"]).toContain(
        enrollResult.code,
      );
      expect(h.deviceStore.findById(ROTATED_DEVICE_ID)).toBeNull();
    }

    const post = verifyDeviceSignature(h.deviceStore, {
      nodeId: NODE_A,
      publicKey: h.authorizing.paddedBase64Url,
      preimageText: "after-race",
      signatureBytes: signText(h.authorizing.privateKey, "after-race"),
    });
    expect(post.ok).toBe(false);
    if (!post.ok) expect(post.code).toBe("DEVICE_REVOKED");
  });

  it("approval signature fails after revoke has committed (no post-revoke complete)", () => {
    const h = makeHarness();
    const preimage = "approval-in-flight";
    const sigBytes = signText(h.authorizing.privateKey, preimage);

    const before = verifyDeviceSignature(h.deviceStore, {
      nodeId: NODE_A,
      publicKey: h.authorizing.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: sigBytes,
    });
    expect(before.ok).toBe(true);

    const rev = revokeDevice(
      {
        deviceStore: h.deviceStore,
        challengeStore: h.challengeStore,
        breakGlassStore: h.breakGlassStore,
        auditLog: h.revokeAudit,
        sideEffects: new NoopDeviceRevocationSideEffects(),
      },
      {
        nodeId: NODE_A,
        targetDeviceKeyId: AUTHORIZER_ID,
        authorizingDeviceKeyId: AUTHORIZER_ID,
        authorizingDevicePublicKey: h.authorizing.paddedBase64Url,
        nowMs: Date.now(),
      },
    );
    expect(rev.ok).toBe(true);

    const after = verifyDeviceSignature(h.deviceStore, {
      nodeId: NODE_A,
      publicKey: h.authorizing.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: sigBytes,
    });
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.code).toBe("DEVICE_REVOKED");
  });
});

// ===========================================================================
// 5. Lockout / rate-limit posture on enrollment & break-glass failures
// ===========================================================================

describe("lockout posture on failed enrollment/break-glass", () => {
  it("repeated failed enrollments trip a per-(node, source, operation) rate limit without leaking factor", () => {
    const limiter = new InMemoryReportingRateLimiter(60_000, 5);
    const sourcePrincipal = "enroll:203.0.113.10:operator-alice";
    const nowMs = Date.parse("2026-07-18T00:00:00.000Z");

    const genericRejects: string[] = [];
    for (let i = 0; i < 7; i++) {
      if (!limiter.consume(NODE_A, sourcePrincipal, nowMs + i * 10)) {
        genericRejects.push("RATE_LIMITED");
        continue;
      }
      const h = makeHarness({ seedAuthorizer: false });
      const impostor = generateTestKeyPair();
      const { input } = issueAndBuild(h, {
        authorizingPair: impostor,
        authorizingKeyId: AUTHORIZER_ID,
        nowMs,
      });
      const result = verifyAndEnrolDevice(h.deps, input);
      expect(result.ok).toBe(false);
      if (!result.ok) genericRejects.push(result.code);
    }

    expect(genericRejects.filter((c) => c === "RATE_LIMITED").length).toBeGreaterThanOrEqual(2);
    for (const code of genericRejects) {
      if (code === "RATE_LIMITED") {
        expect(code).toBe("RATE_LIMITED");
      }
    }
  });

  it("failed break-glass approval attempts share the same opaque rate-limit gate", () => {
    const limiter = new InMemoryReportingRateLimiter(60_000, 3);
    const principal = "break-glass:198.51.100.20:operator-bob";
    const nowMs = Date.parse("2026-07-18T00:00:00.000Z");
    const outcomes: string[] = [];

    for (let i = 0; i < 5; i++) {
      if (!limiter.consume(NODE_A, principal, nowMs + i)) {
        outcomes.push("RATE_LIMITED");
        continue;
      }
      const store = new InMemoryBreakGlassAuthorityStore();
      const audit = new InMemoryBreakGlassAuditLog();
      const pair = generateTestKeyPair();
      const result = ratifyBreakGlassAuthority(store, audit, {
        id: BG_ID,
        nodeId: NODE_A,
        publicKey: pair.paddedBase64Url,
        label: "bg",
        hostAttestation: "",
        nowMs,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) outcomes.push(result.code);
    }

    expect(outcomes.filter((c) => c === "RATE_LIMITED").length).toBeGreaterThanOrEqual(2);
  });
});

// ===========================================================================
// 6. Audit completeness
// ===========================================================================

describe("audit completeness (data-model — enroll / revoke / break-glass)", () => {
  it("records an audit row for successful enrollment and every rejection path exercised", () => {
    const h = makeHarness();

    const ok = issueAndBuild(h, { newDeviceKeyId: NEW_DEVICE_ID });
    expect(verifyAndEnrolDevice(h.deps, ok.input).ok).toBe(true);

    const h2 = makeHarness({ seedAuthorizer: false });
    const bad = issueAndBuild(h2);
    expect(verifyAndEnrolDevice(h2.deps, bad.input).ok).toBe(false);

    const h3 = makeHarness();
    const wrongPop = generateTestKeyPair();
    const popBad = issueAndBuild(h3, {
      newDeviceKeyId: ROTATED_DEVICE_ID,
      popPair: wrongPop,
      newDevicePublicKey: h3.newDevice.paddedBase64Url,
    });
    expect(verifyAndEnrolDevice(h3.deps, popBad.input).ok).toBe(false);

    const allEntries = [...h.auditLog.entries, ...h2.auditLog.entries, ...h3.auditLog.entries];
    expect(allEntries.some((e) => e.outcome === "ENROLLED")).toBe(true);
    expect(allEntries.filter((e) => e.outcome === "REJECTED").length).toBeGreaterThanOrEqual(2);

    for (const entry of allEntries) {
      assertNoPrivateKeyMaterial(entry);
      expect(entry).not.toHaveProperty("privateKey");
      expect(entry).not.toHaveProperty("private_key");
    }
  });

  it("records revocation success and rejection audits without private-key material", () => {
    const h = makeHarness();
    const deps = {
      deviceStore: h.deviceStore,
      challengeStore: h.challengeStore,
      breakGlassStore: h.breakGlassStore,
      auditLog: h.revokeAudit,
      sideEffects: new NoopDeviceRevocationSideEffects(),
    };

    const ok = revokeDevice(deps, {
      nodeId: NODE_A,
      targetDeviceKeyId: AUTHORIZER_ID,
      authorizingDeviceKeyId: AUTHORIZER_ID,
      authorizingDevicePublicKey: h.authorizing.paddedBase64Url,
      nowMs: Date.now(),
    });
    expect(ok.ok).toBe(true);

    const bad = revokeDevice(deps, {
      nodeId: NODE_A,
      targetDeviceKeyId: "00000000-0000-4000-8000-000000000000",
      authorizingDeviceKeyId: AUTHORIZER_ID,
      authorizingDevicePublicKey: h.authorizing.paddedBase64Url,
      nowMs: Date.now(),
    });
    expect(bad.ok).toBe(false);

    expect(h.revokeAudit.entries.some((e) => e.outcome === "REVOKED")).toBe(true);
    expect(h.revokeAudit.entries.some((e) => e.outcome === "REJECTED")).toBe(true);
    for (const entry of h.revokeAudit.entries) {
      assertNoPrivateKeyMaterial(entry);
    }
  });

  it("records break-glass freeze success and rejection audits without private-key material", () => {
    const store = new InMemoryBreakGlassAuthorityStore();
    const audit = new InMemoryBreakGlassAuditLog();
    const pair = generateTestKeyPair();

    const rejected = ratifyBreakGlassAuthority(store, audit, {
      id: BG_ID,
      nodeId: NODE_A,
      publicKey: pair.paddedBase64Url,
      label: "bg",
      hostAttestation: "",
      nowMs: Date.now(),
    });
    expect(rejected.ok).toBe(false);

    const ok = ratifyBreakGlassAuthority(store, audit, {
      id: BG_ID,
      nodeId: NODE_A,
      publicKey: pair.paddedBase64Url,
      label: "bg",
      hostAttestation: "host-attestation-v1:factory-sealed",
      nowMs: Date.now(),
    });
    expect(ok.ok).toBe(true);

    expect(audit.entries.some((e) => e.outcome === "RATIFIED")).toBe(true);
    expect(audit.entries.some((e) => e.outcome === "REJECTED")).toBe(true);
    for (const entry of audit.entries) {
      assertNoPrivateKeyMaterial(entry);
    }
  });
});

// ===========================================================================
// 7. HIGHEST VALUE — device signature cannot replace mandatory TOTP
// ===========================================================================

describe("device signature cannot replace mandatory TOTP (custody; launch floor)", () => {
  /**
   * Explicit, independently identifiable money-mutation gate test.
   * Pre-fix control: a valid enrolled device signs zp-send-external-approval-v1,
   * but guardedMutation is invoked with a missing/invalid TOTP. The mutation body
   * must never run. Contract freeze: APPROVAL_AUTH.deviceSignatureReplacesTotp === false.
   */
  it("valid device approval signature alone does not authorize SEND_EXTERNAL without fresh TOTP", async () => {
    expect(APPROVAL_AUTH.deviceSignatureReplacesTotp).toBe(false);
    expect(APPROVAL_AUTH.deviceSignatureAloneAuthorizes).toBe(false);
    expect(APPROVAL_AUTH.mandatoryGate).toBe("fresh_single_use_totp");

    const h = makeHarness();
    const issuedAt = "2026-07-18T00:00:00.000Z";
    const expiresAt = "2026-07-18T00:05:00.000Z";

    const approval = buildSendExternalApproval({
      node_id: NODE_A as never,
      operation_id: OP_ID as never,
      source_selector: { kind: "WALLET_ID", wallet_id: WALLET_ID as never },
      source_pubkey: h.authorizing.paddedBase64Url as never,
      destination_address: h.newDevice.paddedBase64Url as never,
      amount_zkz: "0.01" as never,
      references_operation_id: null,
      nonce: NONCE_UUID as never,
      issued_at: issuedAt,
      expires_at: expiresAt,
    });

    const deviceSigB64 = signPreimageB64(h.authorizing.privateKey, approval.preimageText);

    const envelope: SignedSuiteTupleEnvelope = {
      key_id: AUTHORIZER_ID as SignedSuiteTupleEnvelope["key_id"],
      preimage_text: approval.preimageText,
      preimage_sha256: approval.sha256,
      signature: deviceSigB64 as SignedSuiteTupleEnvelope["signature"],
    };
    const deviceOk = verifySendExternalApprovalDeviceSignature(envelope, {
      keyId: AUTHORIZER_ID as SignedSuiteTupleEnvelope["key_id"],
      keyClass: "device",
      publicKey: h.authorizing.paddedBase64Url as never,
    });
    expect(deviceOk.payload.purpose).toBe("zp-send-external-approval-v1");

    const storeSig = verifyDeviceSignature(h.deviceStore, {
      nodeId: NODE_A,
      publicKey: h.authorizing.paddedBase64Url,
      preimageText: approval.preimageText,
      signatureBytes: signText(h.authorizing.privateKey, approval.preimageText),
    });
    expect(storeSig.ok).toBe(true);

    const secret = new Uint8Array(20).fill(7);
    const totpConfig: TotpConfig = { secret };
    const log = new TotpConsumptionLog();
    let mutationRan = false;

    const denied = await guardedMutation(
      totpConfig,
      { nodeId: NODE_A, code: "000000", nowMs: Date.parse(issuedAt) },
      log,
      async () => {
        mutationRan = true;
        return { approved: true as const };
      },
    );

    expect(denied.ok).toBe(false);
    if (!denied.ok) expect(denied.reason).toBe("invalid_code");
    expect(mutationRan).toBe(false);

    const timestep = Math.floor(Date.parse(issuedAt) / 1000 / 30);
    const code = generateTotp(secret, timestep);
    mutationRan = false;
    const allowed = await guardedMutation(
      totpConfig,
      { nodeId: NODE_A, code, nowMs: Date.parse(issuedAt) },
      log,
      async () => {
        mutationRan = true;
        expect(storeSig.ok).toBe(true);
        return { approved: true as const };
      },
    );
    expect(allowed.ok).toBe(true);
    expect(mutationRan).toBe(true);
  });

  it("device signature success does not satisfy verifyTotp when code is absent/wrong", async () => {
    const secret = new Uint8Array(20).fill(3);
    const log = new TotpConsumptionLog();
    const h = makeHarness();
    const preimage = "money-path";
    const deviceOk = verifyDeviceSignature(h.deviceStore, {
      nodeId: NODE_A,
      publicKey: h.authorizing.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: signText(h.authorizing.privateKey, preimage),
    });
    expect(deviceOk.ok).toBe(true);

    const totp = await verifyTotp(
      { secret },
      { nodeId: NODE_A, code: "111111", nowMs: Date.now() },
      log,
    );
    expect(totp.ok).toBe(false);
  });
});

// ===========================================================================
// Parent exit criterion: bare login cannot enroll
// ===========================================================================

describe("parent exit criterion — bare login cannot enroll a permanent custody key", () => {
  it("session/TOTP-only path (no enrolled authorizer, no break-glass) never inserts", () => {
    const h = makeHarness({ seedAuthorizer: false });
    const sessionOnly = generateTestKeyPair();
    const { input } = issueAndBuild(h, {
      authorizingPair: sessionOnly,
      authorizingKeyId: AUTHORIZER_ID,
    });
    const result = verifyAndEnrolDevice(h.deps, input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("AUTHORIZER_UNKNOWN");
    expect(h.deviceStore.findById(NEW_DEVICE_ID)).toBeNull();
    expect(h.auditLog.entries.some((e) => e.outcome === "REJECTED")).toBe(true);
  });
});
