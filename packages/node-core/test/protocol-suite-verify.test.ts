// Verifier coverage: key-class binding, key-id binding, digest binding,
// signature verification, A.9 #10 cross-purpose rejection, and the reporting-register PoP path
// (weak-key rejection before signature check, A.5.1). Signatures are derived from the A.8 seed keys
// with node:crypto, identical to own golden test technique, so no fixture here signs
// anything the vectors did not already pin.
//
// The weak-key vectors in the second describe block are ported from @ fd328e897255
// (packages/node-core/src/protocol/suite-tuples/suite-tuples.offbarrel-negatives.test.ts), retargeted
// onto this module's `assertPrimeOrderEd25519PublicKey` (ed25519-point.ts) and `WeakEd25519KeyError`.
import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import { assertPrimeOrderEd25519PublicKey, WeakEd25519KeyError } from "../src/protocol/suite/ed25519-point.js";
import {
  verifyDestinationBless,
  verifyDeviceEnrol,
  verifyMoveInternalExpectedArtifact,
  verifyNodeEvent,
  verifyReceiveExpectedArtifact,
  verifyReportRequest,
  verifyReportingRegisterProof,
  verifySendExternalApprovalDeviceSignature,
  verifySendExternalExpectedArtifact,
  SuiteVerifyError,
  type ResolvedSuiteVerificationKey,
  type SignedSuiteTupleEnvelope,
} from "../src/protocol/suite/verify.js";
import { SUITE_GOLDENS, type SuiteGoldenVector } from "./__vectors__/suite-appendix-a.js";

function privFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}
const b64url = (buf: Buffer): string => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

function golden(id: string): SuiteGoldenVector {
  const found = SUITE_GOLDENS.find((g) => g.id === id);
  if (found === undefined) throw new Error(`missing golden ${id}`);
  return found;
}

function envelopeFor(id: string, keyId: string): SignedSuiteTupleEnvelope {
  const vector = golden(id);
  return {
    key_id: keyId,
    preimage_text: vector.preimageText,
    preimage_sha256: vector.sha256,
    signature: vector.signature as SignedSuiteTupleEnvelope["signature"],
  };
}

const NODE_KEY: ResolvedSuiteVerificationKey<"node_identity"> = {
  keyId: "77777777-7777-4777-8777-777777777777" as ResolvedSuiteVerificationKey["keyId"],
  keyClass: "node_identity",
  publicKey: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=" as ResolvedSuiteVerificationKey["publicKey"],
};
const DEVICE_KEY: ResolvedSuiteVerificationKey<"device"> = {
  keyId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" as ResolvedSuiteVerificationKey["keyId"],
  keyClass: "device",
  publicKey: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=" as ResolvedSuiteVerificationKey["publicKey"],
};
const REPORTING_KEY: ResolvedSuiteVerificationKey<"reporting"> = {
  keyId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" as ResolvedSuiteVerificationKey["keyId"],
  keyClass: "reporting",
  publicKey: "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=" as ResolvedSuiteVerificationKey["publicKey"],
};
const EVENT_KEY: ResolvedSuiteVerificationKey<"node_event"> = {
  keyId: "77777777-7777-4777-8777-777777777777" as ResolvedSuiteVerificationKey["keyId"],
  keyClass: "node_event",
  publicKey: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=" as ResolvedSuiteVerificationKey["publicKey"],
};

describe("verifiers accept a correctly bound envelope", () => {
  it("receive/move/send: node identity key verifies", () => {
    expect(verifyReceiveExpectedArtifact(envelopeFor("receive-expected", NODE_KEY.keyId), NODE_KEY).sha256).toBe(golden("receive-expected").sha256);
    expect(verifyMoveInternalExpectedArtifact(envelopeFor("move-internal-expected", NODE_KEY.keyId), NODE_KEY).sha256).toBe(golden("move-internal-expected").sha256);
    expect(verifySendExternalExpectedArtifact(envelopeFor("send-external-expected", NODE_KEY.keyId), NODE_KEY).sha256).toBe(golden("send-external-expected").sha256);
  });

  it("approval/bless/enrol: device key verifies", () => {
    expect(verifySendExternalApprovalDeviceSignature(envelopeFor("send-external-approval", DEVICE_KEY.keyId), DEVICE_KEY).sha256).toBe(golden("send-external-approval").sha256);
    expect(verifyDestinationBless(envelopeFor("destination-bless", DEVICE_KEY.keyId), DEVICE_KEY).sha256).toBe(golden("destination-bless").sha256);
    expect(verifyDeviceEnrol(envelopeFor("device-enrol", DEVICE_KEY.keyId), DEVICE_KEY).sha256).toBe(golden("device-enrol").sha256);
  });

  it("report-request: reporting key verifies", () => {
    expect(verifyReportRequest(envelopeFor("report-request", REPORTING_KEY.keyId), REPORTING_KEY).sha256).toBe(golden("report-request").sha256);
  });

  it("node-event A and B: node-event key verifies", () => {
    expect(verifyNodeEvent(envelopeFor("node-event-a", EVENT_KEY.keyId), EVENT_KEY).sha256).toBe(golden("node-event-a").sha256);
    expect(verifyNodeEvent(envelopeFor("node-event-b", EVENT_KEY.keyId), EVENT_KEY).sha256).toBe(golden("node-event-b").sha256);
  });

  it("reporting-register: proof-of-possession self-sign verifies without a resolved key", () => {
    const vector = golden("reporting-register");
    const proof = { preimage_text: vector.preimageText, preimage_sha256: vector.sha256, signature: vector.signature as SignedSuiteTupleEnvelope["signature"] };
    expect(verifyReportingRegisterProof(proof).sha256).toBe(vector.sha256);
  });
});

describe("negatives — key class, key id, digest, signature, and A.9 #10 cross-purpose", () => {
  it("rejects a resolved key of the wrong class", () => {
    const wrongClass = { ...NODE_KEY, keyClass: "device" } as unknown as ResolvedSuiteVerificationKey<"node_identity">;
    expect(() => verifyReceiveExpectedArtifact(envelopeFor("receive-expected", NODE_KEY.keyId), wrongClass)).toThrow(SuiteVerifyError);
  });

  it("rejects a mismatched key id", () => {
    const wrongId = { ...NODE_KEY, keyId: "88888888-8888-4888-8888-888888888888" as ResolvedSuiteVerificationKey["keyId"] };
    expect(() => verifyReceiveExpectedArtifact(envelopeFor("receive-expected", NODE_KEY.keyId), wrongId)).toThrow(SuiteVerifyError);
  });

  it("rejects a tampered preimage_sha256", () => {
    const envelope = { ...envelopeFor("receive-expected", NODE_KEY.keyId), preimage_sha256: "0".repeat(64) };
    expect(() => verifyReceiveExpectedArtifact(envelope, NODE_KEY)).toThrow(SuiteVerifyError);
  });

  it("rejects a tampered signature", () => {
    const valid = envelopeFor("receive-expected", NODE_KEY.keyId);
    const tampered = { ...valid, signature: `A${valid.signature.slice(1)}` as SignedSuiteTupleEnvelope["signature"] };
    expect(() => verifyReceiveExpectedArtifact(tampered, NODE_KEY)).toThrow(SuiteVerifyError);
  });

  it("A.9 #10: rejects a cross-purpose preimage under an otherwise class-correct key", () => {
    // move-internal-expected's preimage under receive-expected's verifier — same key class, wrong purpose.
    const cross = envelopeFor("move-internal-expected", NODE_KEY.keyId);
    expect(() => verifyReceiveExpectedArtifact(cross, NODE_KEY)).toThrow();
  });

  it("reporting-register PoP rejects a substituted preimage/digest/signature triple", () => {
    const approval = golden("send-external-approval");
    expect(() =>
      verifyReportingRegisterProof({
        preimage_text: approval.preimageText,
        preimage_sha256: approval.sha256,
        signature: approval.signature as SignedSuiteTupleEnvelope["signature"],
      }),
    ).toThrow();
  });
});

// Ported from the off-barrel negatives file.
describe("Ed25519 point validation (graft: weak-key battery)", () => {
  it("accepts every A.8 role public key", () => {
    for (const key of [
      "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
      "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
      "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
      "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=",
    ] as const) {
      expect(() => assertPrimeOrderEd25519PublicKey(key as never)).not.toThrow();
    }
  });

  it("rejects identity, non-canonical, small-order, and non-main-subgroup encodings", () => {
    const paddedKey = (bytes: Uint8Array): string => `${Buffer.from(bytes).toString("base64url")}=`;
    const weakHex = [
      "00".repeat(32),
      `01${"00".repeat(31)}`,
      `02${"00".repeat(31)}`,
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
      `${"ec"}${"ff".repeat(30)}7f`,
      `${"ed"}${"ff".repeat(30)}7f`,
      `${"ee"}${"ff".repeat(30)}7f`,
    ];
    const encodings = weakHex.map((hex) => paddedKey(Buffer.from(hex, "hex")));
    encodings.push("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=");
    for (const encoding of encodings) {
      expect(() => assertPrimeOrderEd25519PublicKey(encoding as never)).toThrow(WeakEd25519KeyError);
    }
  });

  it("reporting-register PoP rejects an identity candidate key before the signature is considered", () => {
    const register = JSON.parse(golden("reporting-register").preimageText.slice(golden("reporting-register").preimageText.indexOf("\n") + 1)) as Record<string, unknown>;
    register.new_reporting_public_key = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=";
    const text = `zp-reporting-register-v1\n${JSON.stringify(register)}`;
    // The digest gate precedes the point gate, so a placeholder digest would make this pass as
    // `digest_mismatch` without ever reaching the weak-key check it claims to assert.
    expect(() =>
      verifyReportingRegisterProof({
        preimage_text: text,
        preimage_sha256: createHash("sha256").update(text, "utf8").digest("hex"),
        signature: "not-even-consulted" as SignedSuiteTupleEnvelope["signature"],
      }),
    ).toThrow(WeakEd25519KeyError);
  });
});

describe("cross-implementation signature derivation matches the A.8 goldens", () => {
  it("re-derives every signed golden's signature from its seed key with node:crypto and it verifies", () => {
    for (const vector of SUITE_GOLDENS) {
      if (vector.seedByte === null || vector.signature === null) continue;
      const priv = privFromSeed(vector.seedByte);
      const signatureBytes = sign(null, Buffer.from(vector.preimageText, "utf8"), priv);
      expect(b64url(signatureBytes)).toBe(vector.signature);
    }
  });

  it("createPublicKey from the derived private key matches the A.8 role public key", () => {
    const priv = privFromSeed(0x00);
    const pub = b64url(createPublicKey(priv).export({ type: "spki", format: "der" }).subarray(-32));
    expect(pub).toBe("O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=");
  });
});

// remediation (defect B5) — vectors that discriminate the point checks.
//
// The committed battery above is entirely SMALL-ORDER (order 1/2/4/8) or off-curve. Every one of
// those is caught by the cofactor test `[8]P == identity` alone, so the prime-subgroup test
// `[L]P == identity` is never the deciding check and a mutant deleting it survives the whole suite.
// The vector below closes that: a MIXED-ORDER point (order 8L = prime-order point + order-8 torsion)
// passes the cofactor test and is rejected only by the subgroup test.
//
// Derivation (reproducible from the A.8 material, no new secret): take the A.8 node-identity role
// public key — a genuine prime-order point — and add the standard order-8 torsion point
// `c7176a70…ac03fa`. Encoded compressed, the sum is:
//     hex     e76fc4015d5e223a791875e76aec0b853951d81b187fc5e3d046b36b4e70c6a7
//     base64url 52_EAV1eIjp5GHXnauwLhTlR2BsYf8Xj0Eaza05wxqc=
// with [8]M != identity and [L]M != identity.
describe("Ed25519 point validation — mutation-discriminating vectors", () => {
  const MIXED_ORDER_8L = "52_EAV1eIjp5GHXnauwLhTlR2BsYf8Xj0Eaza05wxqc=";

  it("rejects a mixed-order (8L) point that the cofactor check alone would admit", () => {
    expect(() => assertPrimeOrderEd25519PublicKey(MIXED_ORDER_8L as never)).toThrow(
      WeakEd25519KeyError,
    );
  });

  // `verifyReportingRegisterProof` checks the digest BEFORE the point, so a placeholder digest makes
  // the call fail as `digest_mismatch` and never reach the point check at all. The digest is
  // therefore computed here from the mutated preimage, so the point check is genuinely exercised and
  // the assertion cannot pass vacuously.
  it("rejects a mixed-order candidate key in the reporting-register PoP, before the signature", () => {
    const source = golden("reporting-register").preimageText;
    const register = JSON.parse(source.slice(source.indexOf("\n") + 1)) as Record<string, unknown>;
    register.new_reporting_public_key = MIXED_ORDER_8L;
    const text = `zp-reporting-register-v1\n${JSON.stringify(register)}`;

    expect(() =>
      verifyReportingRegisterProof({
        preimage_text: text,
        preimage_sha256: createHash("sha256").update(text, "utf8").digest("hex"),
        signature: "not-even-consulted" as SignedSuiteTupleEnvelope["signature"],
      }),
    ).toThrow(WeakEd25519KeyError);
  });

  // Non-canonical field element: y >= p. The encoding below is y = 3 + p, which reduces mod p to the
  // on-curve point y = 3. `parseWalletPublicKey` cannot see this — it only checks base64url
  // canonicality and length — so the `y >= FIELD` bound in decodePoint is the sole rejecting check.
  //
  // Recorded finding: a non-canonical encoding of a PRIME-ORDER key is not constructible.
  // The non-canonical space is exactly {y + p : y in 0..18}, and an exhaustive walk of those shows
  // every on-curve member has order 1, 4, 2L, 4L, or 8L — never L. So removing the `y >= FIELD`
  // bound cannot smuggle a usable key past the order checks; it is an EQUIVALENT mutant with respect
  // to key acceptance. The bound is retained and pinned here for encoding non-equivocation (one key,
  // one wire encoding), not as a weak-key defence.
  it("rejects a non-canonical y >= p encoding", () => {
    const NON_CANONICAL_Y = "8P_______________________________________38=";
    expect(() => assertPrimeOrderEd25519PublicKey(NON_CANONICAL_Y as never)).toThrow(
      WeakEd25519KeyError,
    );
  });

  it("still accepts the A.8 prime-order role keys (control — no over-rejection)", () => {
    for (const key of [
      "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
      "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
      "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
      "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=",
    ] as const) {
      expect(() => assertPrimeOrderEd25519PublicKey(key as never)).not.toThrow();
    }
  });
});
