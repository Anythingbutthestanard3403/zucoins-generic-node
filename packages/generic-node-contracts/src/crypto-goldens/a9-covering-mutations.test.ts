// Real covering mutation tests for the three A.9 negative
// vectors that previously had only digest-demonstrations or an injected/simulated rejection:
//
//   #9  nfc-substitution        — an NFC/NFD swap in a signed UTF-8 string must fail verification
//   #11 transfer-code-decoded   — the digest MUST bind the exact input string, not decoded/pad-repaired bytes
//   r3  register-pop-wrong-key  — a PoP signed by any key other than the in-tuple key must be rejected
//
// Each test feeds the ACTUAL breaking mutation through a real production function (libsodium
// Ed25519 verify / the production transfer-code hasher / verifyRegisterProofOfPossession) and
// asserts REJECTION — never a bare "the digest changed" demonstration. The a9-coverage-census
// references these by title so no A.9 class is silently uncovered.
//
// Covers A.1.1 (byte-exact preimage, the byte-exact signing rule), A.2 (transfer-code digest),
// A.9 (required negative vectors), A.5.1 (register tuple); reporting-key enrolment.
import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  digestPreimage,
  encodeBase64Url,
  keypairFromSeedByte,
  ready,
  signPreimage,
  verifyDetached,
  verifyPreimageSignature,
} from "../testkit/independentCrypto.ts";
import {
  decodeTransferCode,
  encodeTransferCode,
  transferCodeSha256,
} from "../transfer-code/transfer-code-codec.ts";
import { verifyRegisterProofOfPossession } from "../reporting-auth/verifier.ts";
import {
  REGISTER_GOLDEN_PAYLOAD,
  buildRegisterPreimage,
} from "../reporting-auth/register-tuple.ts";

const sha256HexOfBytes = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("A.9 covering mutations (the fixture-provenance drift gate /)", () => {
  // ---- #9 nfc-substitution ------------------------------------------------
  // A.9 rule 9: the verifier MUST reject an NFC/NFD substitution in any UTF-8 string. The node
  // performs NO normalization (A.4.3 admission gate), so the exact signed bytes verify and a
  // canonically-equivalent NFD substitution — same glyph, different bytes — breaks the signature.
  it("A.9 #9 - an NFC/NFD substitution in a signed UTF-8 string is rejected by Ed25519 verification", async () => {
    await ready();
    const key = keypairFromSeedByte(0x09);

    const nfcLabel = "café"; // NFC: precomposed e-acute U+00E9
    const nfdLabel = "café"; // NFD: e + combining acute U+0301 (canonically equivalent glyph)
    const preimageNfc = `zp-device-enrol-v1\n${JSON.stringify({ purpose: "zp-device-enrol-v1", label: nfcLabel })}`;
    const preimageNfd = `zp-device-enrol-v1\n${JSON.stringify({ purpose: "zp-device-enrol-v1", label: nfdLabel })}`;

    const signature = signPreimage(preimageNfc, key.privateKey);

    // The exact signed bytes verify — the node admits the non-normalized label without transforming it.
    expect(verifyPreimageSignature(preimageNfc, signature, key.publicKey)).toBe(true);

    // The two forms are the same glyph but different bytes and different digests.
    expect(Buffer.from(preimageNfc, "utf8").equals(Buffer.from(preimageNfd, "utf8"))).toBe(false);
    expect(digestPreimage(preimageNfc)).not.toBe(digestPreimage(preimageNfd));

    // A.9 #9: the NFC/NFD substitution is REJECTED — the signature no longer verifies.
    expect(verifyPreimageSignature(preimageNfd, signature, key.publicKey)).toBe(false);
  });

  // ---- #11 transfer-code-decoded -----------------------------------------
  // A.9 rule 11: the transfer-code digest is the SHA-256 of the EXACT input string. Hashing after
  // a base64url decode or a padding repair is a distinct value, so any check binding the digest to
  // the exact string rejects the decoded/pad-repaired variant.
  it("A.9 #11 - hashing the decoded or pad-repaired transfer code is rejected against the exact-string digest", () => {
    const code = encodeTransferCode({
      version: "1",
      wallet: "bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E=",
      amount: "1.5",
      transfer_code_id: "aaaaaaaa-1111-4111-8111-111111111111",
    });
    // Sanity: the production encoder emits an unpadded URL-safe base64 string that round-trips.
    expect(code).not.toContain("=");
    expect(decodeTransferCode(code)).toMatchObject({ version: "1" });

    // The canonical digest per the production hasher — SHA-256 over the exact UTF-8 bytes.
    const exactDigest = transferCodeSha256(code);

    // Attack A: hash the base64url-DECODED bytes instead of the exact string.
    const decodedBytesDigest = sha256HexOfBytes(Uint8Array.from(Buffer.from(code, "base64url")));
    // Attack B: repair the missing padding first, then hash the (now different) string.
    const padRepaired = code + "=".repeat((4 - (code.length % 4)) % 4);
    const padRepairedDigest = transferCodeSha256(padRepaired);

    expect(padRepaired).not.toBe(code);
    expect(decodedBytesDigest).not.toBe(exactDigest);
    expect(padRepairedDigest).not.toBe(exactDigest);

    // A verifier binding transfer_code_sha256 to the exact string ACCEPTS the exact digest and
    // REJECTS either decoded / pad-repaired recomputation.
    const bindsExactString = (encoded: string, claimedDigest: string): boolean =>
      transferCodeSha256(encoded) === claimedDigest;
    expect(bindsExactString(code, exactDigest)).toBe(true);
    expect(bindsExactString(code, decodedBytesDigest)).toBe(false);
    expect(bindsExactString(code, padRepairedDigest)).toBe(false);
  });

  // ---- r3 register-pop-wrong-key -----------------------------------------
  // A.9 register #3: the reporting-register proof-of-possession MUST be signed by the in-tuple
  // new_reporting_public_key. A signature by any other key — even a real, canonical, valid-point
  // Ed25519 key — is rejected. This uses genuine libsodium crypto (not an injected verifyDetached).
  it("A.9 register #3 - a register PoP signed by a foreign key is rejected", async () => {
    await ready();
    const enrolledKey = keypairFromSeedByte(0x41); // the key the tuple enrols
    const foreignKey = keypairFromSeedByte(0x42); // a different, equally valid Ed25519 key

    const preimage = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      new_reporting_public_key: encodeBase64Url(enrolledKey.publicKey),
    });

    const callbacks = {
      validatePublicKeyPoint: (): boolean => true, // the in-tuple key is a real, valid curve point
      // Real detached Ed25519 verification against the IN-TUPLE public key the verifier passes in.
      verifyDetached: (input: {
        readonly publicKey: Uint8Array;
        readonly preimage: Uint8Array;
        readonly signature: Uint8Array;
      }): boolean => verifyDetached(input.signature, input.preimage, input.publicKey),
    };

    // Positive control: a PoP genuinely signed by the enrolled key verifies.
    const goodSignature = signPreimage(preimage, enrolledKey.privateKey);
    const good = verifyRegisterProofOfPossession(preimage, goodSignature, callbacks);
    expect(good.ok).toBe(true);

    // r3: a PoP signed by the foreign key is rejected at proof-of-possession.
    const wrongSignature = signPreimage(preimage, foreignKey.privateKey);
    const wrong = verifyRegisterProofOfPossession(preimage, wrongSignature, callbacks);
    expect(wrong.ok).toBe(false);
    expect(wrong.reason).toBe("proof-of-possession signature verification failed");
  });
});
