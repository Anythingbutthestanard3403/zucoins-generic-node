// Mutation-aware enrollment tests. Happy path seeds an enrolled authorizer (store
// bootstrap simulating prior break-glass / prior ceremony). Removing the active-
// authorizer lookup, purpose-prefix parse, PoP check, challenge consume, or audit
// append must turn at least one assertion red.

import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import { buildDeviceEnrol } from "../protocol/suite/builders.js";
import { InMemoryEnrollmentAuditLog } from "./audit.js";
import {
  issueEnrollmentChallenge,
  InMemoryEnrollmentChallengeStore,
} from "./challenge.js";
import {
  verifyAndEnrolDevice,
  verifyAndEnrolGenesisDevice,
  type EnrolmentDeps,
  type EnrolmentVerificationInput,
} from "./enrollment.js";
import { InMemoryDeviceKeyStore } from "./in-memory-store.js";
import { validateDeviceLabel } from "./label-validation.js";
import { verifyDeviceSignature } from "./verify.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const AUTHORIZER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const NEW_DEVICE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GOLDEN_DEVICE_ENROL_SHA256 = "64e6a3213325f01253954b27abeb4ace733c6f57d0cbc888e5f3bd438b789dc9";
const GOLDEN_PREIMAGE =
  'zp-device-enrol-v1\n{"purpose":"zp-device-enrol-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","new_device_key_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","new_device_public_key":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=","label":"golden-device","nonce":"99999999-9999-4999-8999-999999999999","issued_at":"2026-07-18T00:00:00.000Z","expires_at":"2026-07-18T00:05:00.000Z"}';

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

function signText(
  privateKey: ReturnType<typeof generateTestKeyPair>["privateKey"],
  text: string,
): Uint8Array {
  return new Uint8Array(sign(null, Buffer.from(text, "utf8"), privateKey));
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

interface Harness {
  deps: EnrolmentDeps;
  authorizing: ReturnType<typeof generateTestKeyPair>;
  newDevice: ReturnType<typeof generateTestKeyPair>;
  deviceStore: InMemoryDeviceKeyStore;
  challengeStore: InMemoryEnrollmentChallengeStore;
  auditLog: InMemoryEnrollmentAuditLog;
}

function seedAuthorizer(store: InMemoryDeviceKeyStore, authorizing: ReturnType<typeof generateTestKeyPair>): void {
  store.insert({
    id: AUTHORIZER_ID,
    nodeId: NODE_ID,
    publicKey: authorizing.paddedBase64Url,
    label: "seed-authorizer",
    enrolledAt: "2026-01-01T00:00:00.000Z",
    revokedAt: null,
  });
}

function makeHarness(opts: { seedAuthorizer?: boolean } = {}): Harness {
  const deviceStore = new InMemoryDeviceKeyStore();
  const challengeStore = new InMemoryEnrollmentChallengeStore();
  const auditLog = new InMemoryEnrollmentAuditLog();
  const authorizing = generateTestKeyPair();
  const newDevice = generateTestKeyPair();
  if (opts.seedAuthorizer !== false) {
    seedAuthorizer(deviceStore, authorizing);
  }
  return {
    deps: { deviceStore, challengeStore, auditLog },
    authorizing,
    newDevice,
    deviceStore,
    challengeStore,
    auditLog,
  };
}

function issueAndBuild(
  h: Harness,
  overrides: {
    label?: string;
    newDeviceKeyId?: string;
    newDevicePublicKey?: string;
    nowMs?: number;
    expiresAtMs?: number;
  } = {},
): { preimageText: string; sha256: string; input: EnrolmentVerificationInput; challengeId: string } {
  const nowMs = overrides.nowMs ?? Date.parse("2026-07-18T00:00:00.000Z");
  const issued = issueEnrollmentChallenge(h.challengeStore, {
    nodeId: NODE_ID,
    nowMs,
    expiresAtMs: overrides.expiresAtMs,
    nonce: undefined,
  });
  if (!issued.ok) throw new Error(`issue failed: ${issued.code}`);

  const built = buildDeviceEnrol({
    node_id: NODE_ID as never,
    new_device_key_id: (overrides.newDeviceKeyId ?? NEW_DEVICE_ID) as never,
    new_device_public_key: (overrides.newDevicePublicKey ?? h.newDevice.paddedBase64Url) as never,
    label: overrides.label ?? "golden-device",
    nonce: issued.challenge.nonce as never,
    issued_at: issued.challenge.issuedAt,
    expires_at: issued.challenge.expiresAt,
  });

  const authorizingSignature = signPreimageB64(h.authorizing.privateKey, built.preimageText);
  const popSignature = signPreimageB64(h.newDevice.privateKey, built.preimageText);

  const input: EnrolmentVerificationInput = {
    preimageText: built.preimageText,
    authorizingKeyId: AUTHORIZER_ID,
    authorizingPublicKey: h.authorizing.paddedBase64Url,
    authorizingSignature,
    preimageSha256: built.sha256,
    newDevicePopSignature: popSignature,
    nowMs: nowMs + 60_000,
  };

  return {
    preimageText: built.preimageText,
    sha256: built.sha256,
    input,
    challengeId: issued.challenge.id,
  };
}

describe("device label validation (A.4.3 local denylist helper)", () => {
  it("accepts a valid label", () => {
    expect(validateDeviceLabel("my-trezor")).toEqual({ ok: true });
  });

  it("rejects empty label", () => {
    const result = validateDeviceLabel("");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("LABEL_EMPTY");
  });

  it("rejects label with C0 control characters", () => {
    const result = validateDeviceLabel("bad\x00label");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("LABEL_CONTROL_CHARS");
  });

  it("rejects label with leading space", () => {
    const result = validateDeviceLabel(" leading");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("LABEL_LEADING_TRAILING_SPACE");
  });
});

describe("A.8 golden preimage parity", () => {
  it("buildDeviceEnrol reproduces A.8 digest 64e6a321…", () => {
    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=" as never,
      label: "golden-device",
      nonce: "99999999-9999-4999-8999-999999999999" as never,
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
    });
    expect(built.preimageText).toBe(GOLDEN_PREIMAGE);
    expect(built.sha256).toBe(GOLDEN_DEVICE_ENROL_SHA256);
    expect(sha256Hex(built.preimageText)).toBe(GOLDEN_DEVICE_ENROL_SHA256);
    // Bare JSON.stringify (the prior FAIL path) must NOT match the golden.
    const bare = JSON.stringify({
      purpose: "zp-device-enrol-v1",
      canonical_version: 1,
      node_id: NODE_ID,
      new_device_key_id: NEW_DEVICE_ID,
      new_device_public_key: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
      label: "golden-device",
      nonce: "99999999-9999-4999-8999-999999999999",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
    });
    expect(sha256Hex(bare)).not.toBe(GOLDEN_DEVICE_ENROL_SHA256);
  });
});

describe("device enrollment — happy path requires enrolled authorizer", () => {
  it("enrols when authorizer is active, challenge consumed, PoP valid, A.1.1 preimage", () => {
    const h = makeHarness();
    const { input, challengeId } = issueAndBuild(h);

    const result = verifyAndEnrolDevice(h.deps, input);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.deviceKey.publicKey).toBe(h.newDevice.paddedBase64Url);
      expect(result.deviceKey.label).toBe("golden-device");
      expect(result.deviceKey.revokedAt).toBeNull();
      expect(result.deviceKey.id).toBe(NEW_DEVICE_ID);
    }
    // Authorizer gate used the store: both keys now present.
    expect(h.deviceStore.findActiveByNodeAndPublicKey(NODE_ID, h.authorizing.paddedBase64Url)).not.toBeNull();
    expect(h.deviceStore.findActiveByNodeAndPublicKey(NODE_ID, h.newDevice.paddedBase64Url)).not.toBeNull();
    // Challenge single-consumed.
    expect(h.challengeStore.findByNonce(
      // re-parse nonce from preimage
      JSON.parse(input.preimageText.slice("zp-device-enrol-v1\n".length)).nonce as string,
    )?.status).toBe("CONSUMED");
    expect(h.challengeStore.findByNonce(
      JSON.parse(input.preimageText.slice("zp-device-enrol-v1\n".length)).nonce as string,
    )?.id).toBe(challengeId);
    // Audit success, no private key fields.
    expect(h.auditLog.entries).toHaveLength(1);
    expect(h.auditLog.entries[0]?.outcome).toBe("ENROLLED");
    expect(h.auditLog.entries[0]?.code).toBe("OK");
    const blob = JSON.stringify(h.auditLog.entries[0]);
    expect(blob).not.toMatch(/BEGIN PRIVATE|privateKey|seed/i);
  });
});

describe("device enrollment — D1 authorizer gate (mutation-sensitive)", () => {
  it("rejects unenrolled authorizer (bare login cannot enroll)", () => {
    const h = makeHarness({ seedAuthorizer: false });
    const { input } = issueAndBuild(h);

    const result = verifyAndEnrolDevice(h.deps, input);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("AUTHORIZER_UNKNOWN");
    expect(h.deviceStore.findByNodeAndPublicKey(NODE_ID, h.newDevice.paddedBase64Url)).toBeNull();
    expect(h.auditLog.entries.some((e) => e.code === "AUTHORIZER_UNKNOWN")).toBe(true);
  });

  it("rejects revoked authorizer", () => {
    const h = makeHarness();
    h.deviceStore.revoke(AUTHORIZER_ID, "2026-06-01T00:00:00.000Z");
    const { input } = issueAndBuild(h);

    const result = verifyAndEnrolDevice(h.deps, input);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("AUTHORIZER_REVOKED");
    expect(h.deviceStore.findByNodeAndPublicKey(NODE_ID, h.newDevice.paddedBase64Url)).toBeNull();
  });

  it("rejects breakGlass when no break-glass store is configured", () => {
    const h = makeHarness();
    const { input } = issueAndBuild(h);
    const result = verifyAndEnrolDevice(h.deps, { ...input, breakGlass: true });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("BREAK_GLASS_AUTHORITY_UNKNOWN");
    expect(h.deviceStore.findByNodeAndPublicKey(NODE_ID, h.newDevice.paddedBase64Url)).toBeNull();
  });
});

describe("device enrollment — D2 A.1.1 preimage / purpose prefix (mutation-sensitive)", () => {
  it("rejects bare JSON.stringify preimage (missing purpose\\n prefix) before signature", () => {
    const h = makeHarness();
    const issued = issueEnrollmentChallenge(h.challengeStore, {
      nodeId: NODE_ID,
      nowMs: Date.parse("2026-07-18T00:00:00.000Z"),
    });
    if (!issued.ok) throw new Error("issue failed");

    // Prior FAIL construction: bare JSON, no purpose\n prefix.
    const bareTuple = {
      purpose: "zp-device-enrol-v1",
      canonical_version: 1,
      node_id: NODE_ID,
      new_device_key_id: NEW_DEVICE_ID,
      new_device_public_key: h.newDevice.paddedBase64Url,
      label: "golden-device",
      nonce: issued.challenge.nonce,
      issued_at: issued.challenge.issuedAt,
      expires_at: issued.challenge.expiresAt,
    };
    const barePreimage = JSON.stringify(bareTuple);
    const input: EnrolmentVerificationInput = {
      preimageText: barePreimage,
      authorizingKeyId: AUTHORIZER_ID,
      authorizingPublicKey: h.authorizing.paddedBase64Url,
      authorizingSignature: signPreimageB64(h.authorizing.privateKey, barePreimage),
      preimageSha256: sha256Hex(barePreimage),
      newDevicePopSignature: signPreimageB64(h.newDevice.privateKey, barePreimage),
      nowMs: Date.parse("2026-07-18T00:01:00.000Z"),
    };

    const result = verifyAndEnrolDevice(h.deps, input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("PURPOSE_PREFIX_MISMATCH");
    expect(h.deviceStore.findByNodeAndPublicKey(NODE_ID, h.newDevice.paddedBase64Url)).toBeNull();
  });

  it("rejects wrong purpose prefix while payload purpose field stays correct", () => {
    const h = makeHarness();
    const { input: good } = issueAndBuild(h);
    // Tamper only the domain-separation prefix; payload field 1 remains zp-device-enrol-v1.
    const tampered = good.preimageText.replace("zp-device-enrol-v1\n", "zp-destination-bless-v1\n");
    const result = verifyAndEnrolDevice(h.deps, {
      ...good,
      preimageText: tampered,
      preimageSha256: sha256Hex(tampered),
      authorizingSignature: signPreimageB64(h.authorizing.privateKey, tampered),
      newDevicePopSignature: signPreimageB64(h.newDevice.privateKey, tampered),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("PURPOSE_PREFIX_MISMATCH");
  });

  it("rejects non-canonical field reorder", () => {
    const h = makeHarness();
    const issued = issueEnrollmentChallenge(h.challengeStore, {
      nodeId: NODE_ID,
      nowMs: Date.parse("2026-07-18T00:00:00.000Z"),
    });
    if (!issued.ok) throw new Error("issue failed");
    // Valid prefix + JSON but wrong key sequence → rebuild mismatch.
    const reordered =
      'zp-device-enrol-v1\n' +
      JSON.stringify({
        label: "golden-device",
        purpose: "zp-device-enrol-v1",
        canonical_version: 1,
        node_id: NODE_ID,
        new_device_key_id: NEW_DEVICE_ID,
        new_device_public_key: h.newDevice.paddedBase64Url,
        nonce: issued.challenge.nonce,
        issued_at: issued.challenge.issuedAt,
        expires_at: issued.challenge.expiresAt,
      });
    const result = verifyAndEnrolDevice(h.deps, {
      preimageText: reordered,
      authorizingKeyId: AUTHORIZER_ID,
      authorizingPublicKey: h.authorizing.paddedBase64Url,
      authorizingSignature: signPreimageB64(h.authorizing.privateKey, reordered),
      preimageSha256: sha256Hex(reordered),
      newDevicePopSignature: signPreimageB64(h.newDevice.privateKey, reordered),
      nowMs: Date.parse("2026-07-18T00:01:00.000Z"),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("NON_CANONICAL_PREIMAGE");
  });
});

describe("device enrollment — D3 new-device PoP (mutation-sensitive)", () => {
  it("rejects wrong PoP key and does not insert", () => {
    const h = makeHarness();
    const { input } = issueAndBuild(h);
    const attacker = generateTestKeyPair();
    const result = verifyAndEnrolDevice(h.deps, {
      ...input,
      newDevicePopSignature: signPreimageB64(attacker.privateKey, input.preimageText),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("POP_INVALID");
    expect(h.deviceStore.findByNodeAndPublicKey(NODE_ID, h.newDevice.paddedBase64Url)).toBeNull();
    expect(h.auditLog.entries.some((e) => e.code === "POP_INVALID")).toBe(true);
  });
});

describe("device enrollment — D4 audit on reject", () => {
  it("audits AUTHORIZER_UNKNOWN with public keys only", () => {
    const h = makeHarness({ seedAuthorizer: false });
    const { input } = issueAndBuild(h);
    verifyAndEnrolDevice(h.deps, input);
    expect(h.auditLog.entries.length).toBeGreaterThanOrEqual(1);
    const entry = h.auditLog.entries[0]!;
    expect(entry.outcome).toBe("REJECTED");
    expect(entry.authorizingPublicKey).toBe(h.authorizing.paddedBase64Url);
    expect(JSON.stringify(entry)).not.toMatch(/BEGIN (RSA |EC |OPENSSH )?PRIVATE/i);
  });
});

describe("device enrollment — D5 challenge issue/consume", () => {
  it("rejects unknown challenge nonce", () => {
    const h = makeHarness();
    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: h.newDevice.paddedBase64Url as never,
      label: "golden-device",
      nonce: "99999999-9999-4999-8999-999999999999" as never,
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
    });
    const result = verifyAndEnrolDevice(h.deps, {
      preimageText: built.preimageText,
      authorizingKeyId: AUTHORIZER_ID,
      authorizingPublicKey: h.authorizing.paddedBase64Url,
      authorizingSignature: signPreimageB64(h.authorizing.privateKey, built.preimageText),
      preimageSha256: built.sha256,
      newDevicePopSignature: signPreimageB64(h.newDevice.privateKey, built.preimageText),
      nowMs: Date.parse("2026-07-18T00:01:00.000Z"),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("CHALLENGE_UNKNOWN");
  });

  it("rejects second consume of the same challenge", () => {
    const h = makeHarness();
    const first = issueAndBuild(h);
    const ok = verifyAndEnrolDevice(h.deps, first.input);
    expect(ok.ok).toBe(true);

    // Fresh new-device key so we don't trip DUPLICATE_KEY before challenge check.
    const secondDevice = generateTestKeyPair();
    // Rebuild with same consumed nonce — challenge store still has CONSUMED status.
    const payload = JSON.parse(first.input.preimageText.slice("zp-device-enrol-v1\n".length)) as {
      nonce: string;
      issued_at: string;
      expires_at: string;
    };
    const rebuilt = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" as never,
      new_device_public_key: secondDevice.paddedBase64Url as never,
      label: "second-try",
      nonce: payload.nonce as never,
      issued_at: payload.issued_at,
      expires_at: payload.expires_at,
    });
    const result = verifyAndEnrolDevice(h.deps, {
      preimageText: rebuilt.preimageText,
      authorizingKeyId: AUTHORIZER_ID,
      authorizingPublicKey: h.authorizing.paddedBase64Url,
      authorizingSignature: signPreimageB64(h.authorizing.privateKey, rebuilt.preimageText),
      preimageSha256: rebuilt.sha256,
      newDevicePopSignature: signPreimageB64(secondDevice.privateKey, rebuilt.preimageText),
      nowMs: Date.parse("2026-07-18T00:01:00.000Z"),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("CHALLENGE_NOT_ISSUED");
  });

  it("issueEnrollmentChallenge supersedes prior ISSUED for same node", () => {
    const store = new InMemoryEnrollmentChallengeStore();
    const a = issueEnrollmentChallenge(store, {
      nodeId: NODE_ID,
      nowMs: Date.parse("2026-07-18T00:00:00.000Z"),
      id: "11111111-1111-4111-8111-111111111101",
      nonce: "11111111-1111-4111-8111-111111111102",
    });
    const b = issueEnrollmentChallenge(store, {
      nodeId: NODE_ID,
      nowMs: Date.parse("2026-07-18T00:00:01.000Z"),
      id: "11111111-1111-4111-8111-111111111103",
      nonce: "11111111-1111-4111-8111-111111111104",
    });
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(store.findByNonce(a.challenge.nonce)?.status).toBe("SUPERSEDED");
      expect(store.findByNonce(a.challenge.nonce)?.supersededBy).toBe(b.challenge.id);
      expect(store.findByNonce(b.challenge.nonce)?.status).toBe("ISSUED");
    }
  });
});

describe("device enrollment — other rejections", () => {
  it("rejects invalid authorizing signature", () => {
    const h = makeHarness();
    const { input } = issueAndBuild(h);
    const result = verifyAndEnrolDevice(h.deps, {
      ...input,
      authorizingSignature: "A".repeat(86) + "==",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("SIGNATURE_INVALID");
  });

  it("rejects duplicate key enrollment", () => {
    const h = makeHarness();
    const first = issueAndBuild(h);
    expect(verifyAndEnrolDevice(h.deps, first.input).ok).toBe(true);

    const second = issueAndBuild({
      ...h,
      // new challenge store would be needed; reuse harness device store but need new challenge
      challengeStore: h.challengeStore,
      deps: h.deps,
    });
    // Force same public key as first enrollment
    const again = issueAndBuild(h, { newDevicePublicKey: h.newDevice.paddedBase64Url, newDeviceKeyId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" });
    // re-sign pop with the original new device (still holds the key)
    const result = verifyAndEnrolDevice(h.deps, again.input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("DUPLICATE_KEY");
    void second;
  });

  it("rejects window exceeding 300s at issue time", () => {
    const store = new InMemoryEnrollmentChallengeStore();
    const issued = issueEnrollmentChallenge(store, {
      nodeId: NODE_ID,
      nowMs: Date.parse("2026-07-18T00:00:00.000Z"),
      expiresAtMs: Date.parse("2026-07-18T00:06:00.000Z"),
    });
    expect(issued.ok).toBe(false);
    if (!issued.ok) expect(issued.code).toBe("WINDOW_TOO_LONG");
  });
});

describe("device signature verification", () => {
  it("verifies a valid signature from an enrolled device", () => {
    const store = new InMemoryDeviceKeyStore();
    const device = generateTestKeyPair();
    store.insert({
      id: "dev-1",
      nodeId: "node-1",
      publicKey: device.paddedBase64Url,
      label: "test-device",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    });

    const preimage = "test-message-to-sign";
    const signature = signText(device.privateKey, preimage);

    const result = verifyDeviceSignature(store, {
      nodeId: "node-1",
      publicKey: device.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: signature,
    });

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.deviceKey.id).toBe("dev-1");
  });

  it("rejects unknown device", () => {
    const store = new InMemoryDeviceKeyStore();
    const device = generateTestKeyPair();
    const preimage = "test-message";
    const signature = signText(device.privateKey, preimage);

    const result = verifyDeviceSignature(store, {
      nodeId: "node-1",
      publicKey: device.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: signature,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("UNKNOWN_DEVICE");
  });

  it("rejects revoked device", () => {
    const store = new InMemoryDeviceKeyStore();
    const device = generateTestKeyPair();
    store.insert({
      id: "dev-1",
      nodeId: "node-1",
      publicKey: device.paddedBase64Url,
      label: "revoked-device",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: "2026-06-01T00:00:00.000Z",
    });

    const preimage = "test-message";
    const signature = signText(device.privateKey, preimage);

    const result = verifyDeviceSignature(store, {
      nodeId: "node-1",
      publicKey: device.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: signature,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("DEVICE_REVOKED");
  });

  it("rejects device key enrolled on a different node", () => {
    const store = new InMemoryDeviceKeyStore();
    const device = generateTestKeyPair();
    store.insert({
      id: "dev-1",
      nodeId: "node-1",
      publicKey: device.paddedBase64Url,
      label: "test-device",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    });

    const preimage = "test-message";
    const signature = signText(device.privateKey, preimage);

    const result = verifyDeviceSignature(store, {
      nodeId: "node-2",
      publicKey: device.paddedBase64Url,
      preimageText: preimage,
      signatureBytes: signature,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("UNKNOWN_DEVICE");
  });
});

describe("device enrollment — construction-site audit (AC4)", () => {
  it("device production modules do not ad-hoc JSON.stringify enrollment tuples for signing", async () => {
    const { readFileSync, readdirSync } = await import("node:fs");
    const { join } = await import("node:path");
    const dir = join(import.meta.dirname);
    const files = readdirSync(dir).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));
    const offenders: string[] = [];
    for (const file of files) {
      const src = readFileSync(join(dir, file), "utf8");
      // Strip block + line comments so docstrings citing A.1.1 do not false-positive.
      const code = src
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/.*$/gm, "");
      if (/JSON\.stringify\s*\(/.test(code)) {
        offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
    const builders = readFileSync(join(dir, "../protocol/suite/builders.ts"), "utf8");
    expect(builders).toMatch(/export function buildDeviceEnrol/);
    const parsers = readFileSync(join(dir, "../protocol/suite/parsers.ts"), "utf8");
    expect(parsers).toMatch(/export function parseDeviceEnrol/);
  });
});

describe("genesis first-device enrolment (empty registry)", () => {
  it("enrols when no active devices exist and new device self-signs", () => {
    const h = makeHarness({ seedAuthorizer: false });
    const nowMs = Date.parse("2026-07-18T00:00:00.000Z");
    const issued = issueEnrollmentChallenge(h.challengeStore, {
      nodeId: NODE_ID,
      nowMs,
    });
    if (!issued.ok) throw new Error(`issue failed: ${issued.code}`);

    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: h.newDevice.paddedBase64Url as never,
      label: "first-phone",
      nonce: issued.challenge.nonce as never,
      issued_at: issued.challenge.issuedAt,
      expires_at: issued.challenge.expiresAt,
    });
    const pop = signPreimageB64(h.newDevice.privateKey, built.preimageText);

    const result = verifyAndEnrolGenesisDevice(h.deps, {
      preimageText: built.preimageText,
      preimageSha256: built.sha256,
      newDevicePopSignature: pop,
      nowMs: nowMs + 30_000,
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.deviceKey.id).toBe(NEW_DEVICE_ID);
      expect(result.deviceKey.label).toBe("first-phone");
      expect(result.deviceKey.revokedAt).toBeNull();
    }
    expect(h.deviceStore.listActiveByNode(NODE_ID)).toHaveLength(1);
    expect(h.auditLog.entries[0]?.detail).toMatch(/genesis/i);
  });

  it("rejects genesis when an active device already exists", () => {
    const h = makeHarness({ seedAuthorizer: true });
    const nowMs = Date.parse("2026-07-18T00:00:00.000Z");
    const issued = issueEnrollmentChallenge(h.challengeStore, {
      nodeId: NODE_ID,
      nowMs,
    });
    if (!issued.ok) throw new Error(`issue failed: ${issued.code}`);

    const built = buildDeviceEnrol({
      node_id: NODE_ID as never,
      new_device_key_id: NEW_DEVICE_ID as never,
      new_device_public_key: h.newDevice.paddedBase64Url as never,
      label: "second-attempt",
      nonce: issued.challenge.nonce as never,
      issued_at: issued.challenge.issuedAt,
      expires_at: issued.challenge.expiresAt,
    });
    const pop = signPreimageB64(h.newDevice.privateKey, built.preimageText);

    const result = verifyAndEnrolGenesisDevice(h.deps, {
      preimageText: built.preimageText,
      preimageSha256: built.sha256,
      newDevicePopSignature: pop,
      nowMs: nowMs + 30_000,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("AUTHORIZER_UNKNOWN");
    expect(h.deviceStore.findById(NEW_DEVICE_ID)).toBeNull();
  });
});
