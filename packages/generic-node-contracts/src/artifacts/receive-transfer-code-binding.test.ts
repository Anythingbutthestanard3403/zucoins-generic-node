import { createHash } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

import { readGoldenBytes, readGoldenText, sha256OfBytes, sha256OfGolden } from "../testkit/byteGolden.ts";
import { ready, keypairFromSeedByte, verifyPreimageSignature, type RawKeypair } from "../testkit/independentCrypto.ts";

/**
 * cross-fixture binding proof (refinement of the artifacts and transfer-code binding freezes).
 *
 * The artifacts concern freeze bound the `zp-receive-expected-v1` artifact's `transfer_code_sha256`
 * to an ILLUSTRATIVE placeholder — `SHA-256("golden-transfer-code-v1")` — rather than the hash of a
 * real transfer code. This test is the guard that makes that class of defect impossible to reland:
 * the field MUST equal the SHA-256 of the EXACT stored bytes of the receive-golden transfer-code concern encoded receive-code
 * fixture (`goldens/transfer-code/receive-code.v1.b64url.txt`, merged to main), and NO
 * other derivation of those bytes reproduces it (A.9 rules 9 and 11).
 *
 * The receive-golden transfer-code concern fixture and the artifacts concern artifact set live on originally-separate branches; this test is
 * meaningful only in a tree that contains BOTH (the branch merges main into the artifacts concern
 * freeze branch precisely so this cross-fixture assertion is real).
 */

const FIXTURE = "transfer-code/receive-code.v1.b64url.txt";
const JSON_WRAPPER = "transfer-code/receive-code.v1.json.txt";
const RECEIVE_PREIMAGE = "artifacts/zp-receive-expected-v1.preimage.txt";
const RECEIVE_DIGEST = "artifacts/zp-receive-expected-v1.digest.hex";
const RECEIVE_SIG = "artifacts/zp-receive-expected-v1.sig.b64";

// The corrected binding and the derived receive-artifact outputs (A.8.2).
const CORRECT_TRANSFER_CODE_SHA256 = "104eb00c3bda958b82b7ce5a24e582dd9efa3e63d2192838fe26b5b23dcb2bab";
const NEW_ARTIFACT_DIGEST = "f49635f02d8de86c5b4324f13520cc38c094d79ee2c0df5df60547c590ede498";
const NEW_ARTIFACT_SIG =
  "3NKuFfWanImIVOPKDN9RBv2pUSwsZ6tYypaYyEN_c4z4Zl-TCIC9_y4q5GEM8SYaSWMMgJBa15-UpsXh_9dBBQ==";

// Retired values that MUST NOT be accepted for this artifact ever again.
const RETIRED_PLACEHOLDER = "4b3e384d7c1774a450fdf9f74d338d1c6802a1057b2fd49e23c78244912c18f4";
const RETIRED_ARTIFACT_DIGEST = "57253b7569307bddaea4305af9e98540468f45f0db20e2edb28c1c62ab8bde17";
const RETIRED_ARTIFACT_SIG =
  "b-Y0gWgLHvibsUYHF16_SQcTF2aKRGHzO7e2_yHUiSSwyBDsFz8UowduxiZAp4xZgaS_CxnIrP5WWJQfl1clAQ==";

const sha256Hex = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");

/** Parse the receive artifact's payload object out of its `purpose\n{json}` preimage. */
const receivePayload = (): Record<string, unknown> => {
  const text = readGoldenText(RECEIVE_PREIMAGE);
  return JSON.parse(text.slice(text.indexOf("\n") + 1)) as Record<string, unknown>;
};

describe(": zp-receive-expected-v1 transfer_code_sha256 binds the exact the receive-golden transfer-code concern fixture bytes", () => {
  let nodeKeypair: RawKeypair;
  beforeAll(async () => {
    await ready();
    nodeKeypair = keypairFromSeedByte(0x00);
  });

  it("positive: transfer_code_sha256 === SHA-256(exact stored fixture bytes), no transform", () => {
    const fixtureBytes = readGoldenBytes(FIXTURE);
    const bound = receivePayload().transfer_code_sha256;
    expect(sha256OfBytes(fixtureBytes)).toBe(CORRECT_TRANSFER_CODE_SHA256);
    expect(bound).toBe(CORRECT_TRANSFER_CODE_SHA256);
    // fixture is exactly the 494 stored bytes, no trailing newline
    expect(fixtureBytes.length).toBe(494);
    expect(fixtureBytes[fixtureBytes.length - 1]).not.toBe(0x0a);
  });

  it("negative: hashing the JSON wrapper (.json.txt) does not reproduce the binding", () => {
    expect(sha256OfBytes(readGoldenBytes(JSON_WRAPPER))).not.toBe(CORRECT_TRANSFER_CODE_SHA256);
  });

  it("negative: hashing the base64url-DECODED bytes does not reproduce the binding (A.9 rule 11)", () => {
    const decoded = Buffer.from(readGoldenText(FIXTURE), "base64url");
    expect(sha256Hex(decoded)).not.toBe(CORRECT_TRANSFER_CODE_SHA256);
  });

  it("negative: padding-repairing the fixture before hashing does not reproduce the binding (A.9 rule 11)", () => {
    const raw = readGoldenText(FIXTURE);
    const pad = (4 - (raw.length % 4)) % 4;
    const repaired = raw + "=".repeat(pad);
    expect(repaired).not.toBe(raw); // the stored fixture is unpadded (494 chars)
    expect(sha256Hex(Buffer.from(repaired, "utf8"))).not.toBe(CORRECT_TRANSFER_CODE_SHA256);
  });

  it("negative: NFC/NFD normalization cannot masquerade as the raw-byte binding (A.9 rule 9)", () => {
    const raw = readGoldenText(FIXTURE);
    // The encoded fixture (base64url of percent-encoded JSON) is ASCII-only, so NFC/NFD are no-ops
    // on it: the binding is normalization-stable by construction, not by luck.
    // eslint-disable-next-line no-control-regex
    expect(/^[\x00-\x7f]*$/.test(raw)).toBe(true);
    expect(raw.normalize("NFC")).toBe(raw);
    expect(raw.normalize("NFD")).toBe(raw);
    expect(sha256Hex(Buffer.from(raw.normalize("NFC"), "utf8"))).toBe(CORRECT_TRANSFER_CODE_SHA256);
    // Probe: SHA-256 is normalization-sensitive in general. NFC U+00E9 and NFD U+0065 U+0301 are
    // the same abstract character but distinct byte strings, so a normalizer inserted anywhere in
    // the binding path would diverge from the raw-byte hash for any normalizable codepoint.
    const composedE = "\u00e9"; // NFC: single codepoint U+00E9
    const decomposedE = "e\u0301"; // NFD: U+0065 + combining acute U+0301
    expect(composedE).not.toBe(decomposedE);
    expect(composedE.normalize("NFC")).toBe(decomposedE.normalize("NFC"));
    expect(sha256Hex(Buffer.from(composedE, "utf8"))).not.toBe(sha256Hex(Buffer.from(decomposedE, "utf8")));
  });

  it("negative: the retired placeholder is SHA-256 of the illustrative string, and is NOT the binding", () => {
    expect(sha256Hex(Buffer.from("golden-transfer-code-v1", "utf8"))).toBe(RETIRED_PLACEHOLDER);
    expect(receivePayload().transfer_code_sha256).not.toBe(RETIRED_PLACEHOLDER);
    expect(CORRECT_TRANSFER_CODE_SHA256).not.toBe(RETIRED_PLACEHOLDER);
  });

  it("negative: the retired artifact digest/signature no longer describe the receive golden", () => {
    expect(sha256OfGolden(RECEIVE_PREIMAGE)).toBe(NEW_ARTIFACT_DIGEST);
    expect(sha256OfGolden(RECEIVE_PREIMAGE)).not.toBe(RETIRED_ARTIFACT_DIGEST);
    expect(readGoldenText(RECEIVE_DIGEST)).toBe(NEW_ARTIFACT_DIGEST);
    expect(readGoldenText(RECEIVE_DIGEST)).not.toBe(RETIRED_ARTIFACT_DIGEST);
    expect(readGoldenText(RECEIVE_SIG)).toBe(NEW_ARTIFACT_SIG);
    expect(readGoldenText(RECEIVE_SIG)).not.toBe(RETIRED_ARTIFACT_SIG);
  });

  it("negative: mixed old/new tuples fail Ed25519 verification against the node identity key", () => {
    const preimage = readGoldenText(RECEIVE_PREIMAGE);
    // the current (corrected) signature verifies over the current preimage
    expect(verifyPreimageSignature(preimage, NEW_ARTIFACT_SIG, nodeKeypair.publicKey)).toBe(true);
    // the retired signature does NOT verify over the corrected preimage
    expect(verifyPreimageSignature(preimage, RETIRED_ARTIFACT_SIG, nodeKeypair.publicKey)).toBe(false);
  });
});
