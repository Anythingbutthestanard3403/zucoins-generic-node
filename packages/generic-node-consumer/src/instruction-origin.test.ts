// Merchant-hosted instruction-origin surface tests.
// Part of the installable SDK (originally packages/consumer-example).
//
// Proves the substitution-threat property end to end against the frozen pin-first reference
// consumer wired through the merchant surface:
//   * a genuine receive artifact, verified against the independently pinned node identity key,
//     presents the node-SIGNED amount (not the relay's) to the payer;
//   * VECTOR A — an attacker-key artifact (correctly signed by a different valid key) is refused
//     by the pin before presentation;
//   * VECTOR B — a genuine-node-key artifact for a DIFFERENT operation is refused by operation
//     binding;
//   * a forged relay amount is unrepresentable through this surface: InstructionOriginInput has
//     no relay-claimed-amount field at all, so VECTOR A / VECTOR B are the actual proof — the
//     only way an attacker can attempt a different amount is inside the artifact itself, which
//     then fails the pin or the operation binding before anything is displayed.
//
// Evidence discipline: the plaintext node private key seed is generated in-test and never
// asserted against anything but the artifact it signed; no wallet private key crosses this
// surface.

import { Buffer } from "node:buffer";
import { createHash, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  buildReceiveExpectedArtifact,
  parseEd25519Signature,
  parsePositiveZkzAmount,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
} from "@zucoins/node-core";
import type { ArtifactEnvelope } from "@zucoins/node-core/verifier/consumer";
import {
  DISCOVERY_PATH,
  identityKeyFingerprint,
  verifyIdentityPin,
  type NodeIdentityKeyRecord,
  type NodeIdentityPin,
} from "@zucoins/generic-node-contracts/instruction-origin";
import type { ArtifactVerificationCrypto } from "@zucoins/generic-node-contracts/artifacts";

import { verifyReceiveInstructionOrigin, type InstructionOriginInput } from "./instruction-origin.js";

const NOW = 1_700_000_000_000;
const NODE_ID = "33333333-3333-4333-8333-333333333333";
const KEY_ID = "33333333-3333-4333-8333-333333333333";
const IMPLEMENTER_ID = "44444444-4444-4444-8444-444444444444";
const GENUINE_AMOUNT = "5.5";
const FORGED_AMOUNT = "0.01";

function ed25519Pair(): { publicKeyB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(12);
  return { publicKeyB64: Buffer.from(raw).toString("base64url") + "=", privateKey };
}

const NODE = ed25519Pair();
const ATTACKER = ed25519Pair();
const RECEIVER = ed25519Pair();
const RECEIVER_PUBKEY = RECEIVER.publicKeyB64;

function signPreimage(preimageBytes: Uint8Array, priv: KeyObject = NODE.privateKey): string {
  return edSign(null, Buffer.from(preimageBytes), priv).toString("base64url") + "==";
}

/** Node-crypto ArtifactVerificationCrypto (sha256 + padded-base64url Ed25519 verify). */
const crypto: ArtifactVerificationCrypto = {
  ready: async () => {},
  digestPreimage: (text: string) => createHash("sha256").update(text, "utf8").digest("hex"),
  verifyPreimageSignature: (input) => {
    // The wallet encodes pubkeys and signatures as PADDED URL-safe base64 (trailing '=').
    // Node's crypto.verify for Ed25519 requires a KeyObject (not raw bytes), so rebuild an
    // SPKI key from the 32 raw bytes: the SPKI prefix wraps the raw point.
    const decode = (s: string) => Buffer.from(s.replace(/=+$/, ""), "base64url");
    const rawPub = decode(input.publicKeyB64Url);
    if (rawPub.length !== 32) return false;
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawPub]);
    const pubKeyObj = createPublicKey({ key: spki, format: "der", type: "spki" });
    const sig = decode(input.signatureB64Url);
    return edVerify(null, Buffer.from(input.preimageText, "utf8"), pubKeyObj, sig);
  },
};

function pin(): NodeIdentityPin {
  return {
    keyId: KEY_ID,
    publicKeyB64: NODE.publicKeyB64,
    fingerprintSha256: identityKeyFingerprint(NODE.publicKeyB64),
    validFromUnixMs: NOW - 60_000,
    validUntilUnixMs: null,
  };
}

function resolvedKey(pubkeyB64 = NODE.publicKeyB64): NodeIdentityKeyRecord {
  return {
    keyId: KEY_ID,
    role: "node_identity",
    publicKeyB64: pubkeyB64,
    status: "ACTIVE",
    validFromUnixMs: NOW - 60_000,
    validUntilUnixMs: null,
  };
}

function receiveArtifact(operationId: string, amountZkz: string, signer: KeyObject = NODE.privateKey): ArtifactEnvelope {
  const preimage = buildReceiveExpectedArtifact({
    node_id: parseUuid(NODE_ID),
    implementer_id: parseUuid(IMPLEMENTER_ID),
    operation_id: parseUuid(operationId),
    receiver_wallet_id: parseUuid("66666666-6666-4666-8666-666666666666"),
    receiver_pubkey: parseWalletPublicKey(RECEIVER_PUBKEY),
    amount_zkz: parsePositiveZkzAmount(amountZkz),
    discriminator: parseUuid("77777777-7777-4777-8777-777777777777"),
    anchor: "zp1-anchor-test",
    receiver_t0_fingerprint: parseSha256Hex("a".repeat(64)),
    expiry_unix_time_secs: null,
    after_landing: { kind: "HOLD", destination_id: null },
    transfer_code_sha256: parseSha256Hex("b".repeat(64)),
  });
  return {
    key_id: parseUuid(KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes, signer)),
  };
}

function originInput(overrides: Partial<InstructionOriginInput> = {}): InstructionOriginInput {
  return {
    operationId: "11111111-1111-4111-8111-111111111111",
    artifact: receiveArtifact("11111111-1111-4111-8111-111111111111", GENUINE_AMOUNT),
    artifactPurpose: "zp-receive-expected-v1",
    nodeIdentityPin: pin(),
    resolvedKey: resolvedKey(),
    originClass: "implementer-controlled-origin",
    nowUnixMs: NOW,
    crypto,
    ...overrides,
  };
}

describe("merchant-hosted instruction-origin surface", () => {
  it("a genuine receive artifact presents the node-SIGNED amount, not the relay's", async () => {
    const result = await verifyReceiveInstructionOrigin(originInput());
    expect(result.presentable).toBe(true);
    if (!result.presentable) return;
    // The displayed amount is the artifact's bound 5.5 — never the relay's.
    expect(result.instruction.amountZkz).toBe(GENUINE_AMOUNT);
    expect(result.instruction.receiverPubkey).toBe(RECEIVER_PUBKEY);
    expect(result.instruction.expiryUnixTimeSecs).toBeNull();
    expect(result.instruction.operationId).toBe("11111111-1111-4111-8111-111111111111");
    expect(result.instruction.artifactDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("VECTOR A: an attacker-key artifact is refused by the pin before presentation", async () => {
    // Correctly signed by the attacker's own perfectly valid ACTIVE key — individually valid.
    const attackerArtifact = receiveArtifact(
      "11111111-1111-4111-8111-111111111111",
      FORGED_AMOUNT,
      ATTACKER.privateKey,
    );
    // But the merchant pinned the GENUINE node key, so the pin refuses.
    const result = await verifyReceiveInstructionOrigin(
      originInput({ artifact: attackerArtifact }),
    );
    expect(result.presentable).toBe(false);
    if (result.presentable) return;
    expect(result.reason).toBe("artifact_not_verified");
    // No instruction escapes to the payer.
  });

  it("VECTOR A: a resolved key whose public key differs from the pin fails the pin check", async () => {
    // The merchant resolved a DIFFERENT key than the pin — substitution ground.
    const result = await verifyReceiveInstructionOrigin(
      originInput({ resolvedKey: resolvedKey(ATTACKER.publicKeyB64) }),
    );
    expect(result.presentable).toBe(false);
    if (result.presentable) return;
    expect(result.reason).toBe("pin_not_verified");
  });

  it("VECTOR B: a genuine-node-key artifact for a DIFFERENT operation is refused by operation binding", async () => {
    // Re-signed by the REAL node identity key (so digest, pin, signature all pass) but for a
    // different operation_id. Only the operation-binding check catches this.
    const otherOpArtifact = receiveArtifact("22222222-2222-4222-8222-222222222222", FORGED_AMOUNT);
    const result = await verifyReceiveInstructionOrigin(
      originInput({ artifact: otherOpArtifact }),
    );
    expect(result.presentable).toBe(false);
    if (result.presentable) return;
    expect(result.reason).toBe("operation_id_unbound");
  });

  it("a platform-hosted origin is never substitution-proof, however the artifact verifies", async () => {
    const result = await verifyReceiveInstructionOrigin(
      originInput({ originClass: "platform-hosted" }),
    );
    expect(result.presentable).toBe(false);
    if (result.presentable) return;
    expect(result.reason).toBe("origin_not_substitution_proof");
  });

  it("binds the frozen DISCOVERY_PATH — no field lets an origin relocate the check", () => {
    // discovery_path_mismatch (consumer-boundary.ts) is unreachable through this surface BY
    // CONSTRUCTION: instruction-origin.ts always sets `discoveryPath: DISCOVERY_PATH` on the
    // handoff it builds and InstructionOriginInput has no field to override it, so a relay can
    // never relocate the pin check onto attacker-chosen ground. Enforced at the type level: if
    // InstructionOriginInput ever grew a `discoveryPath` field, this line fails to typecheck.
    type InputHasNoDiscoveryPathField = "discoveryPath" extends keyof InstructionOriginInput ? false : true;
    const inputCannotOverrideDiscoveryPath: InputHasNoDiscoveryPathField = true;
    expect(inputCannotOverrideDiscoveryPath).toBe(true);
    expect(DISCOVERY_PATH).toBe("/.well-known/zupay-node");
  });

  it("no wallet private key crosses this surface", () => {
    // Type-level guard: InstructionOriginInput has no field that could carry a private key, seed,
    // or signing capability. This fails to typecheck if such a field is ever added — it does not
    // depend on a fixture happening to omit one.
    type ForbiddenKey = Extract<keyof InstructionOriginInput, "privateKey" | "private_key" | "seed" | "signingKey">;
    const hasNoForbiddenKey: ForbiddenKey extends never ? true : false = true;
    expect(hasNoForbiddenKey).toBe(true);

    // Runtime guard over a real fixture, for a human scanning test output: the public material
    // (key record, pin, signed artifact envelope) never serializes anything key-shaped.
    const input = originInput();
    const json = JSON.stringify(input);
    expect(json).not.toContain("private_key");
    expect(json).not.toContain("privateKey");
    expect(json).not.toContain("seed");
  });
});

// Sanity: the underlying pin verifier agrees the genuine key verifies and the attacker does not.
describe("pin sanity (verifyIdentityPin)", () => {
  it("genuine pinned key verifies", () => {
    const v = verifyIdentityPin(pin(), resolvedKey(), NOW);
    expect(v.verified).toBe(true);
  });
  it("attacker key fails the pin", () => {
    const v = verifyIdentityPin(pin(), resolvedKey(ATTACKER.publicKeyB64), NOW);
    expect(v.verified).toBe(false);
  });
});
