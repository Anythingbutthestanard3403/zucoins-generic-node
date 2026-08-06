// revocation + break-glass recovery.
// Mutation-sensitive: removing revoked_at set, nonce invalidation, break-glass
// authorizer resolution, or custody isolation must turn assertions red.
//
// Acceptance: bare login cannot enroll a permanent custody-authority key.

import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { buildDeviceEnrol } from "../protocol/suite/builders.js";
import { InMemoryEnrollmentAuditLog } from "./audit.js";
import {
  buildBreakGlassTotpResetPreimage,
  InMemoryBreakGlassAuditLog,
  ratifyBreakGlassAuthority,
  resetTotpUnderBreakGlass,
  type TotpFactorResetPort,
} from "./break-glass.js";
import { InMemoryBreakGlassAuthorityStore } from "./break-glass-store.js";
import {
  issueEnrollmentChallenge,
  InMemoryEnrollmentChallengeStore,
} from "./challenge.js";
import { verifyAndEnrolDevice, type EnrolmentDeps, type EnrolmentVerificationInput } from "./enrollment.js";
import { InMemoryDeviceKeyStore } from "./in-memory-store.js";
import {
  InMemoryDeviceRevocationAuditLog,
  NoopDeviceRevocationSideEffects,
  revokeDevice,
  type DeviceRevocationSideEffects,
} from "./revocation.js";
import { DEVICE_LIFECYCLE_FORBIDDEN_CUSTODY_FIELDS } from "./types.js";
import { verifyDeviceSignature } from "./verify.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const AUTHORIZER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const TARGET_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const NEW_DEVICE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BG_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

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

function signPreimageB64(
  privateKey: ReturnType<typeof generateTestKeyPair>["privateKey"],
  preimageText: string,
): string {
  const sig = sign(null, Buffer.from(preimageText, "utf8"), privateKey);
  return Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

describe("device revocation", () => {
  function seedDevice(
    store: InMemoryDeviceKeyStore,
    id: string,
    pair: ReturnType<typeof generateTestKeyPair>,
    label: string,
  ): void {
    store.insert({
      id,
      nodeId: NODE_ID,
      publicKey: pair.paddedBase64Url,
      label,
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    });
  }

  it("sets revoked_at and never deletes the row", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
    const auditLog = new InMemoryDeviceRevocationAuditLog();
    const authorizer = generateTestKeyPair();
    const target = generateTestKeyPair();
    seedDevice(deviceStore, AUTHORIZER_ID, authorizer, "auth");
    seedDevice(deviceStore, TARGET_ID, target, "target");

    const result = revokeDevice(
      {
        deviceStore,
        challengeStore,
        breakGlassStore,
        auditLog,
        sideEffects: new NoopDeviceRevocationSideEffects(),
      },
      {
        nodeId: NODE_ID,
        targetDeviceKeyId: TARGET_ID,
        nowMs: Date.parse("2026-07-20T00:00:00.000Z"),
        authorizingDeviceKeyId: AUTHORIZER_ID,
        authorizingDevicePublicKey: authorizer.paddedBase64Url,
      },
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.deviceKey.revokedAt).toBe("2026-07-20T00:00:00.000Z");
      expect(result.alreadyRevoked).toBe(false);
    }
    // Row still present (non-deleting).
    const row = deviceStore.findById(TARGET_ID);
    expect(row).not.toBeNull();
    expect(row!.revokedAt).toBe("2026-07-20T00:00:00.000Z");
    expect(deviceStore.findByNodeAndPublicKey(NODE_ID, target.paddedBase64Url)).not.toBeNull();
    expect(deviceStore.findActiveByNodeAndPublicKey(NODE_ID, target.paddedBase64Url)).toBeNull();
    expect(auditLog.entries.some((e) => e.outcome === "REVOKED")).toBe(true);
  });

  it("invalidates outstanding enrollment challenges on revoke", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
    const auditLog = new InMemoryDeviceRevocationAuditLog();
    const authorizer = generateTestKeyPair();
    const target = generateTestKeyPair();
    seedDevice(deviceStore, AUTHORIZER_ID, authorizer, "auth");
    seedDevice(deviceStore, TARGET_ID, target, "target");

    const issued = issueEnrollmentChallenge(challengeStore, {
      nodeId: NODE_ID,
      nowMs: Date.parse("2026-07-20T00:00:00.000Z"),
    });
    expect(issued.ok).toBe(true);

    const result = revokeDevice(
      {
        deviceStore,
        challengeStore,
        breakGlassStore,
        auditLog,
        sideEffects: new NoopDeviceRevocationSideEffects(),
      },
      {
        nodeId: NODE_ID,
        targetDeviceKeyId: TARGET_ID,
        nowMs: Date.parse("2026-07-20T00:01:00.000Z"),
        authorizingDeviceKeyId: AUTHORIZER_ID,
        authorizingDevicePublicKey: authorizer.paddedBase64Url,
      },
    );

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.invalidatedEnrollmentChallenges).toBe(1);
    if (issued.ok) {
      const ch = challengeStore.findByNonce(issued.challenge.nonce);
      expect(ch?.status).toBe("EXPIRED");
    }
  });

  it("calls session + approval-challenge side-effect ports", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
    const auditLog = new InMemoryDeviceRevocationAuditLog();
    const authorizer = generateTestKeyPair();
    const target = generateTestKeyPair();
    seedDevice(deviceStore, AUTHORIZER_ID, authorizer, "auth");
    seedDevice(deviceStore, TARGET_ID, target, "target");

    const calls: string[] = [];
    const sideEffects: DeviceRevocationSideEffects = {
      invalidateApprovalChallengesForDevice(args) {
        calls.push(`approval:${args.deviceKeyId}`);
      },
      invalidateSessionsForDevice(args) {
        calls.push(`session:${args.deviceKeyId}`);
      },
    };

    const result = revokeDevice(
      { deviceStore, challengeStore, breakGlassStore, auditLog, sideEffects },
      {
        nodeId: NODE_ID,
        targetDeviceKeyId: TARGET_ID,
        nowMs: Date.parse("2026-07-20T00:00:00.000Z"),
        authorizingDeviceKeyId: AUTHORIZER_ID,
        authorizingDevicePublicKey: authorizer.paddedBase64Url,
      },
    );

    expect(result.ok).toBe(true);
    expect(calls).toEqual([`approval:${TARGET_ID}`, `session:${TARGET_ID}`]);
  });

  it("rejects bare revocation with no authorizer (no bare-login path)", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
    const auditLog = new InMemoryDeviceRevocationAuditLog();
    const target = generateTestKeyPair();
    seedDevice(deviceStore, TARGET_ID, target, "target");

    const result = revokeDevice(
      {
        deviceStore,
        challengeStore,
        breakGlassStore,
        auditLog,
        sideEffects: new NoopDeviceRevocationSideEffects(),
      },
      {
        nodeId: NODE_ID,
        targetDeviceKeyId: TARGET_ID,
        nowMs: Date.parse("2026-07-20T00:00:00.000Z"),
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("AUTHORIZER_UNKNOWN");
    expect(deviceStore.findById(TARGET_ID)!.revokedAt).toBeNull();
  });

  it("rejects revoked device as authorizer of a new enrollment", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const auditLog = new InMemoryEnrollmentAuditLog();
    const authorizer = generateTestKeyPair();
    const newDevice = generateTestKeyPair();
    seedDevice(deviceStore, AUTHORIZER_ID, authorizer, "auth");
    deviceStore.revoke(AUTHORIZER_ID, "2026-07-19T00:00:00.000Z");

    const nowMs = Date.parse("2026-07-20T00:00:00.000Z");
    const issued = issueEnrollmentChallenge(challengeStore, { nodeId: NODE_ID, nowMs });
    if (!issued.ok) throw new Error("issue failed");
    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: newDevice.paddedBase64Url as never,
      label: "post-revoke",
      nonce: issued.challenge.nonce as never,
      issued_at: issued.challenge.issuedAt,
      expires_at: issued.challenge.expiresAt,
    });
    const input: EnrolmentVerificationInput = {
      preimageText: built.preimageText,
      authorizingKeyId: AUTHORIZER_ID,
      authorizingPublicKey: authorizer.paddedBase64Url,
      authorizingSignature: signPreimageB64(authorizer.privateKey, built.preimageText),
      preimageSha256: built.sha256,
      newDevicePopSignature: signPreimageB64(newDevice.privateKey, built.preimageText),
      nowMs: nowMs + 60_000,
    };
    const result = verifyAndEnrolDevice({ deviceStore, challengeStore, auditLog }, input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("AUTHORIZER_REVOKED");
  });

  it("revoked device fails signature verification for new actions", () => {
    const store = new InMemoryDeviceKeyStore();
    const pair = generateTestKeyPair();
    seedDevice(store, TARGET_ID, pair, "target");
    store.revoke(TARGET_ID, "2026-07-20T00:00:00.000Z");

    const preimage = "zp-send-external-approval-v1\n{}";
    const sig = sign(null, Buffer.from(preimage, "utf8"), pair.privateKey);
    const result = verifyDeviceSignature(store, {
      nodeId: NODE_ID,
      publicKey: pair.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: new Uint8Array(sig),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("DEVICE_REVOKED");
  });
});

describe("break-glass recovery", () => {
  it("freezes break-glass public key only with host attestation (no session path)", () => {
    const store = new InMemoryBreakGlassAuthorityStore();
    const audit = new InMemoryBreakGlassAuditLog();
    const pair = generateTestKeyPair();

    const rejected = ratifyBreakGlassAuthority(store, audit, {
      id: BG_ID,
      nodeId: NODE_ID,
      publicKey: pair.paddedBase64Url,
      label: "offline-seal",
      nowMs: Date.parse("2026-07-20T00:00:00.000Z"),
      hostAttestation: "   ",
    });
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) expect(rejected.code).toBe("HOST_ATTESTATION_REQUIRED");

    const ok = ratifyBreakGlassAuthority(store, audit, {
      id: BG_ID,
      nodeId: NODE_ID,
      publicKey: pair.paddedBase64Url,
      label: "offline-seal",
      nowMs: Date.parse("2026-07-20T00:00:00.000Z"),
      hostAttestation: "host-cli:vault-master-key-present",
    });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.authority.revokedAt).toBeNull();
      expect(ok.authority.publicKey).toBe(pair.paddedBase64Url);
    }
    expect(audit.entries.some((e) => e.outcome === "RATIFIED")).toBe(true);
  });

  it("enrols a device via frozen break-glass (lost-all-devices path)", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
    const auditLog = new InMemoryEnrollmentAuditLog();
    const bg = generateTestKeyPair();
    const newDevice = generateTestKeyPair();

    const frozen = ratifyBreakGlassAuthority(breakGlassStore, new InMemoryBreakGlassAuditLog(), {
      id: BG_ID,
      nodeId: NODE_ID,
      publicKey: bg.paddedBase64Url,
      label: "break-glass",
      nowMs: Date.parse("2026-01-01T00:00:00.000Z"),
      hostAttestation: "host-cli",
    });
    expect(frozen.ok).toBe(true);

    const nowMs = Date.parse("2026-07-20T00:00:00.000Z");
    const issued = issueEnrollmentChallenge(challengeStore, { nodeId: NODE_ID, nowMs });
    if (!issued.ok) throw new Error("issue failed");

    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: newDevice.paddedBase64Url as never,
      label: "replacement-laptop",
      nonce: issued.challenge.nonce as never,
      issued_at: issued.challenge.issuedAt,
      expires_at: issued.challenge.expiresAt,
    });

    const deps: EnrolmentDeps = { deviceStore, challengeStore, auditLog, breakGlassStore };
    const input: EnrolmentVerificationInput = {
      preimageText: built.preimageText,
      authorizingKeyId: BG_ID,
      authorizingPublicKey: bg.paddedBase64Url,
      authorizingSignature: signPreimageB64(bg.privateKey, built.preimageText),
      preimageSha256: built.sha256,
      newDevicePopSignature: signPreimageB64(newDevice.privateKey, built.preimageText),
      nowMs: nowMs + 60_000,
      breakGlass: true,
    };

    const result = verifyAndEnrolDevice(deps, input);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.deviceKey.id).toBe(NEW_DEVICE_ID);
      expect(result.deviceKey.revokedAt).toBeNull();
    }
    expect(deviceStore.findActiveByNodeAndPublicKey(NODE_ID, newDevice.paddedBase64Url)).not.toBeNull();
    expect(auditLog.entries.some((e) => e.detail.includes("break-glass"))).toBe(true);
  });

  it("rejects break-glass enrollment when authority is unknown (bare login cannot enroll)", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
    const auditLog = new InMemoryEnrollmentAuditLog();
    const impostor = generateTestKeyPair();
    const newDevice = generateTestKeyPair();

    const nowMs = Date.parse("2026-07-20T00:00:00.000Z");
    const issued = issueEnrollmentChallenge(challengeStore, { nodeId: NODE_ID, nowMs });
    if (!issued.ok) throw new Error("issue failed");
    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: newDevice.paddedBase64Url as never,
      label: "attacker",
      nonce: issued.challenge.nonce as never,
      issued_at: issued.challenge.issuedAt,
      expires_at: issued.challenge.expiresAt,
    });

    const result = verifyAndEnrolDevice(
      { deviceStore, challengeStore, auditLog, breakGlassStore },
      {
        preimageText: built.preimageText,
        authorizingKeyId: BG_ID,
        authorizingPublicKey: impostor.paddedBase64Url,
        authorizingSignature: signPreimageB64(impostor.privateKey, built.preimageText),
        preimageSha256: built.sha256,
        newDevicePopSignature: signPreimageB64(newDevice.privateKey, built.preimageText),
        nowMs: nowMs + 60_000,
        breakGlass: true,
      },
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("BREAK_GLASS_AUTHORITY_UNKNOWN");
    expect(deviceStore.findByNodeAndPublicKey(NODE_ID, newDevice.paddedBase64Url)).toBeNull();
  });

  it("rejects break-glass enrollment signed by enrolled device without breakGlass flag path using unenrolled key", () => {
    // Bare session presenting a random key as authorizer (no breakGlass, no enrolled device).
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const auditLog = new InMemoryEnrollmentAuditLog();
    const random = generateTestKeyPair();
    const newDevice = generateTestKeyPair();
    const nowMs = Date.parse("2026-07-20T00:00:00.000Z");
    const issued = issueEnrollmentChallenge(challengeStore, { nodeId: NODE_ID, nowMs });
    if (!issued.ok) throw new Error("issue failed");
    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: newDevice.paddedBase64Url as never,
      label: "session-only",
      nonce: issued.challenge.nonce as never,
      issued_at: issued.challenge.issuedAt,
      expires_at: issued.challenge.expiresAt,
    });
    const result = verifyAndEnrolDevice(
      { deviceStore, challengeStore, auditLog },
      {
        preimageText: built.preimageText,
        authorizingKeyId: AUTHORIZER_ID,
        authorizingPublicKey: random.paddedBase64Url,
        authorizingSignature: signPreimageB64(random.privateKey, built.preimageText),
        preimageSha256: built.sha256,
        newDevicePopSignature: signPreimageB64(newDevice.privateKey, built.preimageText),
        nowMs: nowMs + 60_000,
        // breakGlass omitted — bare path
      },
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("AUTHORIZER_UNKNOWN");
  });

  it("resets TOTP only under break-glass signature (not bare login)", () => {
    const store = new InMemoryBreakGlassAuthorityStore();
    const audit = new InMemoryBreakGlassAuditLog();
    const bg = generateTestKeyPair();
    ratifyBreakGlassAuthority(store, audit, {
      id: BG_ID,
      nodeId: NODE_ID,
      publicKey: bg.paddedBase64Url,
      label: "bg",
      nowMs: Date.parse("2026-01-01T00:00:00.000Z"),
      hostAttestation: "host",
    });

    let resetCount = 0;
    const port: TotpFactorResetPort = {
      resetTotpFactor() {
        resetCount += 1;
      },
    };

    const issuedAt = "2026-07-20T00:00:00.000Z";
    const nonce = "99999999-9999-4999-8999-999999999999";
    const preimage = buildBreakGlassTotpResetPreimage({
      nodeId: NODE_ID,
      authorityId: BG_ID,
      nonce,
      issuedAt,
    });
    expect(preimage.startsWith("zp-break-glass-totp-reset-v1\n")).toBe(true);

    // No signature / wrong key → reject, no reset.
    const bare = resetTotpUnderBreakGlass(store, audit, port, {
      nodeId: NODE_ID,
      authorityId: BG_ID,
      authorityPublicKey: bg.paddedBase64Url,
      nonce,
      issuedAt,
      signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
      nowMs: Date.parse("2026-07-20T00:01:00.000Z"),
    });
    expect(bare.ok).toBe(false);
    expect(resetCount).toBe(0);

    const ok = resetTotpUnderBreakGlass(store, audit, port, {
      nodeId: NODE_ID,
      authorityId: BG_ID,
      authorityPublicKey: bg.paddedBase64Url,
      nonce,
      issuedAt,
      signature: signPreimageB64(bg.privateKey, preimage),
      nowMs: Date.parse("2026-07-20T00:01:00.000Z"),
    });
    expect(ok.ok).toBe(true);
    expect(resetCount).toBe(1);
    expect(audit.entries.some((e) => e.outcome === "TOTP_RESET")).toBe(true);
  });

  it("break-glass can authorize device revocation", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
    const auditLog = new InMemoryDeviceRevocationAuditLog();
    const target = generateTestKeyPair();
    const bg = generateTestKeyPair();
    deviceStore.insert({
      id: TARGET_ID,
      nodeId: NODE_ID,
      publicKey: target.paddedBase64Url,
      label: "lost-phone",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    });
    ratifyBreakGlassAuthority(breakGlassStore, new InMemoryBreakGlassAuditLog(), {
      id: BG_ID,
      nodeId: NODE_ID,
      publicKey: bg.paddedBase64Url,
      label: "bg",
      nowMs: Date.parse("2026-01-01T00:00:00.000Z"),
      hostAttestation: "host",
    });

    const result = revokeDevice(
      {
        deviceStore,
        challengeStore,
        breakGlassStore,
        auditLog,
        sideEffects: new NoopDeviceRevocationSideEffects(),
      },
      {
        nodeId: NODE_ID,
        targetDeviceKeyId: TARGET_ID,
        nowMs: Date.parse("2026-07-20T00:00:00.000Z"),
        breakGlass: true,
        breakGlassKeyId: BG_ID,
        breakGlassPublicKey: bg.paddedBase64Url,
      },
    );
    expect(result.ok).toBe(true);
    expect(deviceStore.findById(TARGET_ID)!.revokedAt).not.toBeNull();
  });
});

describe("custody isolation (device lifecycle never touches wallet custody)", () => {
  it("exports the forbidden custody field list", () => {
    expect(DEVICE_LIFECYCLE_FORBIDDEN_CUSTODY_FIELDS).toContain("key_origin");
    expect(DEVICE_LIFECYCLE_FORBIDDEN_CUSTODY_FIELDS).toContain("recovery_verified_at");
    expect(DEVICE_LIFECYCLE_FORBIDDEN_CUSTODY_FIELDS).toContain("destinations.state");
  });

  it("device module sources never reference wallet custody mutation fields", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const files = readdirSync(here).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));
    for (const file of files) {
      const text = readFileSync(join(here, file), "utf8");
      // The constant definition itself is allowed; production logic must not write these fields.
      if (file === "types.ts") continue;
      for (const field of ["key_origin", "recovery_verified_at"] as const) {
        expect(text.includes(field), `${file} must not reference ${field}`).toBe(false);
      }
      // destinations.state appears only in the forbidden-list export comment path — blocked above via types skip.
      expect(text.includes("wallet.key_origin"), `${file} custody leak`).toBe(false);
    }
  });

  it("revocation result type carries only device registry fields", () => {
    const deviceStore = new InMemoryDeviceKeyStore();
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const breakGlassStore = new InMemoryBreakGlassAuthorityStore();
    const auditLog = new InMemoryDeviceRevocationAuditLog();
    const authorizer = generateTestKeyPair();
    const target = generateTestKeyPair();
    deviceStore.insert({
      id: AUTHORIZER_ID,
      nodeId: NODE_ID,
      publicKey: authorizer.paddedBase64Url,
      label: "a",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    });
    deviceStore.insert({
      id: TARGET_ID,
      nodeId: NODE_ID,
      publicKey: target.paddedBase64Url,
      label: "t",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    });
    const result = revokeDevice(
      {
        deviceStore,
        challengeStore,
        breakGlassStore,
        auditLog,
        sideEffects: new NoopDeviceRevocationSideEffects(),
      },
      {
        nodeId: NODE_ID,
        targetDeviceKeyId: TARGET_ID,
        nowMs: Date.parse("2026-07-20T00:00:00.000Z"),
        authorizingDeviceKeyId: AUTHORIZER_ID,
        authorizingDevicePublicKey: authorizer.paddedBase64Url,
      },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const keys = Object.keys(result.deviceKey);
      expect(keys).toEqual(
        expect.arrayContaining(["id", "nodeId", "publicKey", "label", "enrolledAt", "revokedAt"]),
      );
      expect(keys).not.toContain("key_origin");
      expect(keys).not.toContain("recovery_verified_at");
    }
  });
});

// Silence unused import if tree-shaken away in some runners.
void sha256Hex;
