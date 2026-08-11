// Verifier negatives for zp-implementer-event-v1 / -checkpoint-v1 / -keyrotation-v1.
// Proves purpose-before-signature, key-class enforcement, byte-exact preimage binding,
// and rejection of wrong purpose / wrong key class / mutated order / whitespace / sig.
import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  buildImplementerCheckpointPreimage,
  buildImplementerEventPreimage,
  buildImplementerKeyRotationPreimage,
  IMPLEMENTER_CHECKPOINT_GOLDEN,
  IMPLEMENTER_CHECKPOINT_PURPOSE,
  IMPLEMENTER_EVENT_GOLDEN_A,
  IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE,
  IMPLEMENTER_EVENT_PURPOSE,
  IMPLEMENTER_KEYROTATION_GOLDEN,
  IMPLEMENTER_KEYROTATION_PURPOSE,
} from "@zucoins/generic-node-contracts/implementer-events";
import {
  IMPLEMENTER_CHECKPOINT_SIGNATURE,
  IMPLEMENTER_EVENT_A_SHA256,
  IMPLEMENTER_EVENT_A_SIGNATURE,
  IMPLEMENTER_KEYROTATION_SIGNATURE,
  NODE_EVENT_KEY_PUBKEY,
} from "@zucoins/generic-node-contracts/implementer-events";

import { parseEd25519Signature, parseSha256Hex, parseUuid, parseWalletPublicKey } from "../scalars.js";
import type { ResolvedSuiteVerificationKey, SignedSuiteTupleEnvelope } from "../suite/verify.js";
import { SuiteVerifyError } from "../suite/verify.js";
import {
  ImplementerParseError,
  keyClassForImplementerPurpose,
  mayKeyClassSignImplementerPurpose,
  verifyImplementerCheckpoint,
  verifyImplementerEvent,
  verifyImplementerKeyRotation,
} from "./verify.js";

function keyFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function b64url(buf: Buffer): string {
  // Match implementer-events freeze digests: base64url alphabet, keep "=" padding (88 chars).
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

const GOLDEN_PRIV = keyFromSeed(0x00);
const GOLDEN_PUB = b64url(
  Buffer.from(createPublicKey(GOLDEN_PRIV).export({ type: "spki", format: "der" }).subarray(-32)),
);
// A.8 seed-00 public key is published padded.
const GOLDEN_PUB_PADDED = GOLDEN_PUB.endsWith("=") ? GOLDEN_PUB : `${GOLDEN_PUB}=`;

const GOLDEN_KEY_ID = "11111111-1111-4111-8111-111111111111";

function nodeEventKey(
  overrides: Partial<ResolvedSuiteVerificationKey<"node_event">> = {},
): ResolvedSuiteVerificationKey<"node_event"> {
  return {
    keyId: parseUuid(GOLDEN_KEY_ID),
    keyClass: "node_event",
    publicKey: parseWalletPublicKey(NODE_EVENT_KEY_PUBKEY),
    ...overrides,
  };
}

function envelopeFrom(
  preimageText: string,
  signature: string,
  keyId: string = GOLDEN_KEY_ID,
): SignedSuiteTupleEnvelope {
  return {
    key_id: parseUuid(keyId),
    preimage_text: preimageText,
    preimage_sha256: parseSha256Hex(createHash("sha256").update(Buffer.from(preimageText, "utf8")).digest("hex")),
    signature: parseEd25519Signature(signature),
  };
}

describe("verifyImplementerEvent — golden accept", () => {
  it("accepts golden A against the A.8 node-event key", () => {
    expect(GOLDEN_PUB_PADDED.replace(/=+$/, "")).toBe(NODE_EVENT_KEY_PUBKEY.replace(/=+$/, ""));
    const env = envelopeFrom(IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE, IMPLEMENTER_EVENT_A_SIGNATURE);
    expect(env.preimage_sha256).toBe(IMPLEMENTER_EVENT_A_SHA256);
    const parsed = verifyImplementerEvent(env, nodeEventKey());
    expect(parsed.payload.event_id).toBe(IMPLEMENTER_EVENT_GOLDEN_A.event_id);
    expect(parsed.payload.purpose).toBe(IMPLEMENTER_EVENT_PURPOSE);
  });
});

describe("verifyImplementerEvent — negatives", () => {
  function validEnvelope(): SignedSuiteTupleEnvelope {
    const preimage = buildImplementerEventPreimage(IMPLEMENTER_EVENT_GOLDEN_A);
    const sig = sign(null, Buffer.from(preimage, "utf8"), GOLDEN_PRIV);
    return envelopeFrom(preimage, b64url(Buffer.from(sig)));
  }

  it("rejects wrong purpose prefix before signature", () => {
    const env = validEnvelope();
    const swapped = {
      ...env,
      preimage_text: env.preimage_text.replace(IMPLEMENTER_EVENT_PURPOSE, "zp-node-event-v1"),
    };
    expect(() => verifyImplementerEvent(swapped, nodeEventKey())).toThrow(ImplementerParseError);
    try {
      verifyImplementerEvent(swapped, nodeEventKey());
    } catch (error) {
      expect((error as ImplementerParseError).reason).toBe("purpose_mismatch");
    }
  });

  it("rejects wrong key class", () => {
    const env = validEnvelope();
    const wrongClass = {
      keyId: parseUuid(GOLDEN_KEY_ID),
      keyClass: "node_identity" as const,
      publicKey: parseWalletPublicKey(NODE_EVENT_KEY_PUBKEY),
    };
    expect(() =>
      verifyImplementerEvent(env, wrongClass as unknown as ResolvedSuiteVerificationKey<"node_event">),
    ).toThrow(SuiteVerifyError);
    try {
      verifyImplementerEvent(env, wrongClass as unknown as ResolvedSuiteVerificationKey<"node_event">);
    } catch (error) {
      expect((error as SuiteVerifyError).reason).toBe("key_class_mismatch");
    }
  });

  it("rejects mutated field order (non-canonical bytes)", () => {
    const { purpose, canonical_version, ...rest } = IMPLEMENTER_EVENT_GOLDEN_A;
    const reordered = `${IMPLEMENTER_EVENT_PURPOSE}\n${JSON.stringify({ canonical_version, purpose, ...rest })}`;
    const sig = sign(null, Buffer.from(reordered, "utf8"), GOLDEN_PRIV);
    const env = envelopeFrom(reordered, b64url(Buffer.from(sig)));
    expect(() => verifyImplementerEvent(env, nodeEventKey())).toThrow(ImplementerParseError);
    try {
      verifyImplementerEvent(env, nodeEventKey());
    } catch (error) {
      expect((error as ImplementerParseError).reason).toBe("non_canonical_bytes");
    }
  });

  it("rejects mutated whitespace", () => {
    const base = buildImplementerEventPreimage(IMPLEMENTER_EVENT_GOLDEN_A);
    const spaced = base.replace("\n{", "\n {");
    const sig = sign(null, Buffer.from(spaced, "utf8"), GOLDEN_PRIV);
    const env = envelopeFrom(spaced, b64url(Buffer.from(sig)));
    expect(() => verifyImplementerEvent(env, nodeEventKey())).toThrow(ImplementerParseError);
  });

  it("rejects wrong signature", () => {
    const env = validEnvelope();
    const { privateKey: attacker } = generateKeyPairSync("ed25519");
    const badSig = sign(null, Buffer.from(env.preimage_text, "utf8"), attacker);
    const forged = envelopeFrom(env.preimage_text, b64url(Buffer.from(badSig)));
    expect(() => verifyImplementerEvent(forged, nodeEventKey())).toThrow(SuiteVerifyError);
    try {
      verifyImplementerEvent(forged, nodeEventKey());
    } catch (error) {
      expect((error as SuiteVerifyError).reason).toBe("signature_invalid");
    }
  });

  it("rejects key_id mismatch", () => {
    const env = validEnvelope();
    const otherKey = nodeEventKey({ keyId: parseUuid("22222222-2222-4222-8222-222222222222") });
    expect(() => verifyImplementerEvent(env, otherKey)).toThrow(SuiteVerifyError);
  });
});

describe("verifyImplementerCheckpoint + keyrotation", () => {
  it("accepts checkpoint golden", () => {
    const preimage = buildImplementerCheckpointPreimage(IMPLEMENTER_CHECKPOINT_GOLDEN);
    const env = envelopeFrom(preimage, IMPLEMENTER_CHECKPOINT_SIGNATURE);
    const parsed = verifyImplementerCheckpoint(env, nodeEventKey());
    expect(parsed.payload.purpose).toBe(IMPLEMENTER_CHECKPOINT_PURPOSE);
  });

  it("accepts keyrotation golden", () => {
    const preimage = buildImplementerKeyRotationPreimage(IMPLEMENTER_KEYROTATION_GOLDEN);
    const env = envelopeFrom(preimage, IMPLEMENTER_KEYROTATION_SIGNATURE);
    const parsed = verifyImplementerKeyRotation(env, nodeEventKey());
    expect(parsed.payload.purpose).toBe(IMPLEMENTER_KEYROTATION_PURPOSE);
  });

  it("checkpoint rejects event purpose prefix", () => {
    const preimage = buildImplementerEventPreimage(IMPLEMENTER_EVENT_GOLDEN_A);
    const sig = sign(null, Buffer.from(preimage, "utf8"), GOLDEN_PRIV);
    const env = envelopeFrom(preimage, b64url(Buffer.from(sig)));
    expect(() => verifyImplementerCheckpoint(env, nodeEventKey())).toThrow(ImplementerParseError);
  });
});

describe("key class helpers", () => {
  it("maps all three purposes to node_event", () => {
    expect(keyClassForImplementerPurpose(IMPLEMENTER_EVENT_PURPOSE)).toBe("node_event");
    expect(keyClassForImplementerPurpose(IMPLEMENTER_CHECKPOINT_PURPOSE)).toBe("node_event");
    expect(keyClassForImplementerPurpose(IMPLEMENTER_KEYROTATION_PURPOSE)).toBe("node_event");
    expect(keyClassForImplementerPurpose("zp-node-event-v1")).toBeUndefined();
  });

  it("mayKeyClassSignImplementerPurpose enforces class", () => {
    expect(mayKeyClassSignImplementerPurpose(IMPLEMENTER_EVENT_PURPOSE, "node_event")).toBe(true);
    expect(mayKeyClassSignImplementerPurpose(IMPLEMENTER_EVENT_PURPOSE, "node_identity")).toBe(false);
    expect(mayKeyClassSignImplementerPurpose("zp-node-event-v1", "node_event")).toBe(false);
  });
});
