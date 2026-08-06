import { describe, expect, it } from "vitest";

import { ready, keypairFromSeedByte, digestPreimage, signPreimage } from "../testkit/independentCrypto.ts";
import { readGoldenText, sha256OfGolden } from "../testkit/byteGolden.ts";
import { APPROVAL_CONCERN_MANIFEST, APPROVAL_GOLDEN } from "./manifest.ts";

/**
 * Golden ANCHOR census (the approval concern). Defends against the "regen-stays-green" defect class: goldens that
 * are byte-perfect but not mechanically anchored, so mutating the content and regenerating every
 * derived artifact (digest.hex, sig.b64, meta.json, the gen snapshot, and the manifest goldenRefs)
 * leaves the whole suite green.
 *
 * The defence: the appendix A.8 values live here as IMMOVABLE inline string literals — never read
 * from meta.json, the manifest, or any regenerable artifact at runtime. Every on-disk file, the
 * ConcernManifest, the manifest export, and meta.json are asserted EQUAL to these literals, and a
 * permanent negative proves a content mutation cannot reproduce them. Editing a golden's content
 * without also editing this file's literals turns the suite red.
 */

const PURPOSE = "zp-send-external-approval-v1";

// --- appendix A.8 values, transcribed as immovable inline literals (the anchor). ---
const A8_ARTIFACT_DIGEST = "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146";
const A8_DEVICE_SIGNATURE =
  "HLd6EN7uw2KHCgRAryuyEh6ljmHsjgvCJ6Ke1Gq3fb0PDV1Vsn3QCzuo51o0VnH9LCbDI3c_s6AFK3NO013ZCA==";
const A8_DEVICE_PUBKEY = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";

// Raw byte-golden file digests (sha256 of each on-disk file's exact bytes), pinned inline. The
// preimage's own digest is the artifact digest by construction (A.8 invariant).
const FILE_SHA256_PREIMAGE = "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146";
const FILE_SHA256_DIGEST_HEX = "b8a162f4b807402a1c74443fdc113b874b517be527f726714cae883ea3d34e3b";
const FILE_SHA256_SIG_B64 = "a112a12ce9b9187eb9e75e7404c76ee4da67eb5e24a9ae6adfe43a3f082c86e3";

const baseName = (path: string): string => path.split("/").pop() ?? path;

describe("the approval concern golden anchor census — inline A.8 literals (regen-stays-green defence)", () => {
  it("each on-disk golden file's sha256 equals its inline-pinned digest", () => {
    expect(sha256OfGolden(`approval/${PURPOSE}.preimage.txt`)).toBe(FILE_SHA256_PREIMAGE);
    expect(sha256OfGolden(`approval/${PURPOSE}.digest.hex`)).toBe(FILE_SHA256_DIGEST_HEX);
    expect(sha256OfGolden(`approval/${PURPOSE}.sig.b64`)).toBe(FILE_SHA256_SIG_B64);
  });

  it("each golden file's CONTENT equals its inline A.8 value", () => {
    // The preimage bytes' own sha256 is the artifact digest (A.8 invariant).
    expect(sha256OfGolden(`approval/${PURPOSE}.preimage.txt`)).toBe(A8_ARTIFACT_DIGEST);
    expect(readGoldenText(`approval/${PURPOSE}.digest.hex`)).toBe(A8_ARTIFACT_DIGEST);
    expect(readGoldenText(`approval/${PURPOSE}.sig.b64`)).toBe(A8_DEVICE_SIGNATURE);
  });

  it("the ConcernManifest goldenRefs equal the inline literals (manifest cannot drift from A.8)", () => {
    const byBase = new Map(APPROVAL_CONCERN_MANIFEST.goldenRefs.map((r) => [baseName(r.path), r.sha256]));
    expect(byBase.get(`${PURPOSE}.preimage.txt`)).toBe(FILE_SHA256_PREIMAGE);
    expect(byBase.get(`${PURPOSE}.digest.hex`)).toBe(FILE_SHA256_DIGEST_HEX);
    expect(byBase.get(`${PURPOSE}.sig.b64`)).toBe(FILE_SHA256_SIG_B64);
  });

  it("the APPROVAL_GOLDEN manifest export equals the inline A.8 values", () => {
    expect(APPROVAL_GOLDEN.artifactDigestSha256).toBe(A8_ARTIFACT_DIGEST);
    expect(APPROVAL_GOLDEN.deviceSignatureB64).toBe(A8_DEVICE_SIGNATURE);
    expect(APPROVAL_GOLDEN.devicePublicKeyB64).toBe(A8_DEVICE_PUBKEY);
  });

  it("the meta.json provenance equals the inline literals (meta cannot drift from A.8)", () => {
    const meta = JSON.parse(readGoldenText(`approval/${PURPOSE}.meta.json`)) as {
      artifact_digest_sha256: string;
      verification_pubkey_b64: string;
      files: Record<string, { sha256: string }>;
    };
    expect(meta.artifact_digest_sha256).toBe(A8_ARTIFACT_DIGEST);
    expect(meta.verification_pubkey_b64).toBe(A8_DEVICE_PUBKEY);
    expect(meta.files[`${PURPOSE}.preimage.txt`].sha256).toBe(FILE_SHA256_PREIMAGE);
    expect(meta.files[`${PURPOSE}.digest.hex`].sha256).toBe(FILE_SHA256_DIGEST_HEX);
    expect(meta.files[`${PURPOSE}.sig.b64`].sha256).toBe(FILE_SHA256_SIG_B64);
  });

  it("PERMANENT NEGATIVE: mutating the content (amount 2.25 -> 9.99) cannot reproduce the pinned digest or signature", async () => {
    await ready();
    const pre = readGoldenText(`approval/${PURPOSE}.preimage.txt`);
    const payload = JSON.parse(pre.slice(pre.indexOf("\n") + 1)) as Record<string, unknown>;
    expect(payload.amount_zkz).toBe("2.25"); // guard: the fixture itself is unmutated

    // Object spread keeps amount_zkz in its original position, changing only its value, so the
    // mutated preimage differs from the golden ONLY in the economic amount.
    const mutated = `${PURPOSE}\n${JSON.stringify({ ...payload, amount_zkz: "9.99" })}`;

    // Recomputing every derived artifact from the mutated content still cannot move the inline A.8
    // literals: the digest and the deterministic device signature both change and no longer match.
    expect(digestPreimage(mutated)).not.toBe(A8_ARTIFACT_DIGEST);
    expect(signPreimage(mutated, keypairFromSeedByte(0x01).privateKey)).not.toBe(A8_DEVICE_SIGNATURE);
  });
});
