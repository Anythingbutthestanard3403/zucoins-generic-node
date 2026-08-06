/**
 * negative test vectors for the hardened expected-artifact verifier. Each test exercises
 * one mutation class that the byte-canonical enforcement must reject. The byte-exact signing rule (byte-exact
 * JSON.stringify signing), A.1.1, A.9 (negative vectors).
 *
 * The golden fixture is the canonical positive case. Every mutation produces a distinct preimage
 * signed with the test keypair — the signature is valid for the mutated bytes, so rejection is
 * from canonical enforcement, not from signature failure.
 */
import { beforeAll, describe, expect, it } from "vitest";

import {
  ready,
  keypairFromSeedByte,
  encodeBase64Url,
  digestPreimage,
  signPreimage,
  type RawKeypair,
} from "../testkit/independentCrypto.ts";
import { readGoldenText } from "../testkit/byteGolden.ts";
import { defaultSuiteVerificationCrypto } from "../testkit/suiteVerificationCrypto.ts";
import { verifyExpectedArtifact, type ArtifactEnvelope } from "./verify.ts";
import { type NodeIdentityKeyRecord } from "./signing-contract.ts";
import { type ExpectedArtifactPurpose } from "./expected-artifacts.contract.ts";

const NODE_IDENTITY_SEED_BYTE = 0x00;

let nodeKeypair: RawKeypair;
let goldenPub: string;

beforeAll(async () => {
  await ready();
  nodeKeypair = keypairFromSeedByte(NODE_IDENTITY_SEED_BYTE);
  goldenPub = readGoldenText("artifacts/node-identity.pub.b64");
  // Sanity: keypair reproduces the golden public key
  expect(encodeBase64Url(nodeKeypair.publicKey)).toBe(goldenPub);
});

const nodeKeyRecord = (keyId = "node-identity-golden"): NodeIdentityKeyRecord => ({
  keyId,
  role: "node_identity",
  publicKeyB64: goldenPub,
  status: "ACTIVE",
  validFromUnixMs: 0,
  validUntilUnixMs: null,
});

const PURPOSE = "zp-receive-expected-v1" as const;

/** Build a valid envelope from a preimage string, computing digest and signature. */
const buildEnvelope = (preimageText: string, keyId = "node-identity-golden"): ArtifactEnvelope => ({
  key_id: keyId,
  preimage_text: preimageText,
  preimage_sha256: digestPreimage(preimageText),
  signature: signPreimage(preimageText, nodeKeypair.privateKey),
});

/** Verify an envelope with standard key/timing, returning the VerifyResult. */
const verify = async (
  envelope: ArtifactEnvelope,
  expectedPurpose: ExpectedArtifactPurpose = PURPOSE,
) =>
  verifyExpectedArtifact({
    envelope,
    key: nodeKeyRecord(),
    signedAtUnixMs: 1_752_796_800_000,
    expectedPurpose,
    pinnedPublicKeyB64: goldenPub,
  }, defaultSuiteVerificationCrypto);

/** Extract the payload JSON portion from a preimage string. */
const extractPayloadJson = (preimage: string): string => preimage.slice(preimage.indexOf("\n") + 1);

/** Build a mutated preimage from a mutated payload JSON, keeping the purpose prefix. */
const mutatedPreimage = (purpose: string, mutatedJson: string): string =>
  `${purpose}\n${mutatedJson}`;

describe("byte-canonical enforcement", () => {
  it("1. valid canonical preimage passes", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const envelope: ArtifactEnvelope = {
      key_id: "node-identity-golden",
      preimage_text: preimage,
      preimage_sha256: readGoldenText(`artifacts/${PURPOSE}.digest.hex`),
      signature: readGoldenText(`artifacts/${PURPOSE}.sig.b64`),
    };
    const result = await verify(envelope);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.purpose).toBe(PURPOSE);
    }
  });

  it("2. extra whitespace in payload is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const payloadJson = extractPayloadJson(preimage);
    // Insert a space after the first comma — non-canonical whitespace
    const firstComma = payloadJson.indexOf(",");
    const mutatedJson =
      payloadJson.slice(0, firstComma + 1) + " " + payloadJson.slice(firstComma + 1);
    const mutated = mutatedPreimage(PURPOSE, mutatedJson);
    const result = await verify(buildEnvelope(mutated));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("noncanonical_payload");
    }
  });

  it("3. \\u0031 escape for digit is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const payloadJson = extractPayloadJson(preimage);
    // Replace canonical_version number 1 with \u0031 (Unicode escape for "1")
    // In the JSON, "canonical_version":1 — replace the bare 1 with \u0031
    const mutatedJson = payloadJson.replace(
      '"canonical_version":1',
      '"canonical_version":\\u0031',
    );
    const mutated = mutatedPreimage(PURPOSE, mutatedJson);
    const result = await verify(buildEnvelope(mutated));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // \u0031 is a string escape, so JSON.parse sees the number 1 but the bytes differ
      expect(["noncanonical_payload", "malformed_preimage", "canonical_version_invalid"]).toContain(
        result.reason,
      );
    }
  });

  it("4. 1.0 instead of integer 1 is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const payloadJson = extractPayloadJson(preimage);
    // Replace canonical_version 1 with 1.0
    const mutatedJson = payloadJson.replace('"canonical_version":1', '"canonical_version":1.0');
    const mutated = mutatedPreimage(PURPOSE, mutatedJson);
    const result = await verify(buildEnvelope(mutated));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // JSON.parse("1.0") === 1, so semantic checks pass but canonical rebuild produces "1"
      expect(result.reason).toBe("noncanonical_payload");
    }
  });

  it("5. duplicate field in payload is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const payloadJson = extractPayloadJson(preimage);
    // Insert a duplicate "amount_zkz" before the closing brace
    const mutatedJson = payloadJson.slice(0, -1) + ',"amount_zkz":"9.99"}';
    const mutated = mutatedPreimage(PURPOSE, mutatedJson);
    const result = await verify(buildEnvelope(mutated));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // JSON.parse takes last value, so the unknown-field check or canonical rebuild catches it
      expect(["field_value_invalid", "field_sequence_mismatch", "noncanonical_payload"]).toContain(
        result.reason,
      );
    }
  });

  it("6. reordered fields are rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const payloadJson = extractPayloadJson(preimage);
    const parsed = JSON.parse(payloadJson) as Record<string, unknown>;
    // Swap the first two fields: canonical_version before purpose
    const reordered: Record<string, unknown> = {};
    const keys = Object.keys(parsed);
    // Put field 2 before field 1
    reordered[keys[1]] = parsed[keys[1]];
    reordered[keys[0]] = parsed[keys[0]];
    for (let i = 2; i < keys.length; i++) {
      reordered[keys[i]] = parsed[keys[i]];
    }
    const mutatedJson = JSON.stringify(reordered);
    const mutated = mutatedPreimage(PURPOSE, mutatedJson);
    const result = await verify(buildEnvelope(mutated));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("field_sequence_mismatch");
    }
  });

  it("7. unknown extra field is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const payloadJson = extractPayloadJson(preimage);
    const parsed = JSON.parse(payloadJson) as Record<string, unknown>;
    parsed["extra_field"] = "sneaky";
    const mutatedJson = JSON.stringify(parsed);
    const mutated = mutatedPreimage(PURPOSE, mutatedJson);
    const result = await verify(buildEnvelope(mutated));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("field_value_invalid");
      expect(result.detail).toContain("unknown field");
    }
  });

  it("8. missing nullable field (omitted instead of null) is rejected", async () => {
    // Use move-internal which has two nullable fields at the end
    const movePurpose = "zp-move-internal-expected-v1" as const;
    const preimage = readGoldenText(`artifacts/${movePurpose}.preimage.txt`);
    const payloadJson = extractPayloadJson(preimage);
    const parsed = JSON.parse(payloadJson) as Record<string, unknown>;
    // Remove the last nullable field: references_operation_id
    delete parsed["references_operation_id"];
    const mutatedJson = JSON.stringify(parsed);
    const mutated = mutatedPreimage(movePurpose, mutatedJson);
    const result = await verify(buildEnvelope(mutated), movePurpose);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Either field_sequence_mismatch (key count differs) or field_value_invalid (undefined)
      expect(["field_value_invalid", "field_sequence_mismatch"]).toContain(result.reason);
    }
  });

  it("9. BOM prefix on preimage is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const bomPreimage = "\uFEFF" + preimage;
    const result = await verify(buildEnvelope(bomPreimage));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("malformed_preimage");
      expect(result.detail).toContain("BOM");
    }
  });

  it("10. cross-purpose signature is rejected (receive verified as move)", async () => {
    // Take the receive golden, sign it, but verify with expectedPurpose = move
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const envelope: ArtifactEnvelope = {
      key_id: "node-identity-golden",
      preimage_text: preimage,
      preimage_sha256: digestPreimage(preimage),
      signature: signPreimage(preimage, nodeKeypair.privateKey),
    };
    // Expect "move" but preimage has "receive" prefix
    const result = await verify(envelope, "zp-move-internal-expected-v1");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("cross_purpose_expected_mismatch");
    }
  });

  // A.9 vector 10: exhaustive cross-purpose rejection (all 6 direction pairs)
  const CROSS_PURPOSE_PAIRS: Array<{
    actualPurpose: ExpectedArtifactPurpose;
    expectedPurpose: ExpectedArtifactPurpose;
  }> = [
    { actualPurpose: "zp-receive-expected-v1", expectedPurpose: "zp-move-internal-expected-v1" },
    { actualPurpose: "zp-receive-expected-v1", expectedPurpose: "zp-send-external-expected-v1" },
    { actualPurpose: "zp-move-internal-expected-v1", expectedPurpose: "zp-receive-expected-v1" },
    { actualPurpose: "zp-move-internal-expected-v1", expectedPurpose: "zp-send-external-expected-v1" },
    { actualPurpose: "zp-send-external-expected-v1", expectedPurpose: "zp-receive-expected-v1" },
    { actualPurpose: "zp-send-external-expected-v1", expectedPurpose: "zp-move-internal-expected-v1" },
  ];

  for (const { actualPurpose, expectedPurpose } of CROSS_PURPOSE_PAIRS) {
    it(`cross-purpose: ${actualPurpose} rejected when expecting ${expectedPurpose}`, async () => {
      const preimage = readGoldenText(`artifacts/${actualPurpose}.preimage.txt`);
      const envelope: ArtifactEnvelope = {
        key_id: "node-identity-golden",
        preimage_text: preimage,
        preimage_sha256: digestPreimage(preimage),
        signature: signPreimage(preimage, nodeKeypair.privateKey),
      };
      const result = await verify(envelope, expectedPurpose);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe("cross_purpose_expected_mismatch");
      }
    });
  }

  it("11. key_id mismatch is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    // Envelope claims key_id="wrong-key-id" but the key record has keyId="node-identity-golden"
    const envelope: ArtifactEnvelope = {
      key_id: "wrong-key-id",
      preimage_text: preimage,
      preimage_sha256: readGoldenText(`artifacts/${PURPOSE}.digest.hex`),
      signature: readGoldenText(`artifacts/${PURPOSE}.sig.b64`),
    };
    const result = await verify(envelope);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("key_id_mismatch");
    }
  });
});

describe("trailing whitespace rejection", () => {
  it("trailing newline on preimage is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const mutated = preimage + "\n";
    const result = await verify(buildEnvelope(mutated));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("malformed_preimage");
      expect(result.detail).toContain("trailing whitespace");
    }
  });

  it("trailing space on preimage is rejected", async () => {
    const preimage = readGoldenText(`artifacts/${PURPOSE}.preimage.txt`);
    const mutated = preimage + " ";
    const result = await verify(buildEnvelope(mutated));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("malformed_preimage");
      expect(result.detail).toContain("trailing whitespace");
    }
  });
});
