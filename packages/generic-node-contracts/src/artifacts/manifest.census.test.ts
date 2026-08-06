import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { ARTIFACTS_CONCERN_MANIFEST } from "./manifest.ts";
import { readGoldenText, sha256OfGolden } from "../testkit/byteGolden.ts";

/**
 * Remediation of a review finding: `ARTIFACTS_CONCERN_MANIFEST.goldenRefs` carried
 * the A.8 literals but nothing consumed them — mutating a golden's amount
 * (`2.25` -> `22.5`) and regenerating its digest/sig/meta.json together stayed green across every
 * existing artifact test, because every prior check compared the goldens against EACH OTHER
 * (meta.json vs bytes, manifest vs bytes) rather than against a fixed, independent source.
 *
 * Every hex/base64 literal below is copied by hand from the pinned tables in
 * the canonical-fields appendix A.8 (cited per
 * group) — never read back from a golden file or from `ARTIFACTS_CONCERN_MANIFEST` itself — so a
 * golden and its manifest entry regenerated together in lockstep can no longer pass silently.
 */

// A.8 "Expected machine-generated outputs" table, SHA-256 column: sha256 of each artifact's
// exact preimage.txt bytes. Equal, by the A.8 invariant, to the artifact's .digest.hex file text.
const PINNED_ARTIFACT_DIGEST: Readonly<Record<string, string>> = {
  "zp-receive-expected-v1": "f49635f02d8de86c5b4324f13520cc38c094d79ee2c0df5df60547c590ede498",
  "zp-move-internal-expected-v1": "ad964723e07ca2aef3356f1e02990e07b90be49b5387a7095091398a10944a14",
  "zp-send-external-expected-v1": "f094f981f833c908fae1fa661cb6d9f6c3cdf29bab792f2660b866c588f22cb5",
};

// Same A.8 table, Signature/key column: the exact padded base64url Ed25519 signature over each
// preimage, signed by the node identity key.
const PINNED_ARTIFACT_SIGNATURE: Readonly<Record<string, string>> = {
  "zp-receive-expected-v1":
    "3NKuFfWanImIVOPKDN9RBv2pUSwsZ6tYypaYyEN_c4z4Zl-TCIC9_y4q5GEM8SYaSWMMgJBa15-UpsXh_9dBBQ==",
  "zp-move-internal-expected-v1":
    "LBOpWe9v6yQXGYeerr0oIoW6gm3kF-nga7FrHkANO7jEw3XjkKjqqPYeCshORWQnXMU9kkKV_0-eE_FLmNUpDA==",
  "zp-send-external-expected-v1":
    "TKbgi1fVDCnik1TscotEf0i8eFp3NuQ3JlSsPMJgy6imF-Nct9KniWMkPv5bUAtDNp7fFXG89YLI5qme6MyWDA==",
};

// A.8 deterministic golden fixture table, seed byte `00` row (node identity/event).
const PINNED_NODE_IDENTITY_PUBKEY = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

const GOLDEN_DIR = "goldens/artifacts";

const sha256OfLiteral = (text: string): string => createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");

/**
 * sha256 of each raw golden FILE's bytes, keyed by path relative to `goldens/`. Every value here
 * is derived in-test from the A.8 literals above — never read from disk and never read from
 * `ARTIFACTS_CONCERN_MANIFEST` — so it anchors both the on-disk bytes and the manifest's own
 * `goldenRefs` pins independently of each other.
 */
const EXPECTED_FILE_SHA256: Readonly<Record<string, string>> = {
  "artifacts/zp-receive-expected-v1.preimage.txt": PINNED_ARTIFACT_DIGEST["zp-receive-expected-v1"],
  "artifacts/zp-receive-expected-v1.digest.hex": sha256OfLiteral(PINNED_ARTIFACT_DIGEST["zp-receive-expected-v1"]),
  "artifacts/zp-receive-expected-v1.sig.b64": sha256OfLiteral(PINNED_ARTIFACT_SIGNATURE["zp-receive-expected-v1"]),
  "artifacts/zp-move-internal-expected-v1.preimage.txt": PINNED_ARTIFACT_DIGEST["zp-move-internal-expected-v1"],
  "artifacts/zp-move-internal-expected-v1.digest.hex":
    sha256OfLiteral(PINNED_ARTIFACT_DIGEST["zp-move-internal-expected-v1"]),
  "artifacts/zp-move-internal-expected-v1.sig.b64":
    sha256OfLiteral(PINNED_ARTIFACT_SIGNATURE["zp-move-internal-expected-v1"]),
  "artifacts/zp-send-external-expected-v1.preimage.txt": PINNED_ARTIFACT_DIGEST["zp-send-external-expected-v1"],
  "artifacts/zp-send-external-expected-v1.digest.hex":
    sha256OfLiteral(PINNED_ARTIFACT_DIGEST["zp-send-external-expected-v1"]),
  "artifacts/zp-send-external-expected-v1.sig.b64":
    sha256OfLiteral(PINNED_ARTIFACT_SIGNATURE["zp-send-external-expected-v1"]),
  "artifacts/node-identity.pub.b64": sha256OfLiteral(PINNED_NODE_IDENTITY_PUBKEY),
};

describe("ARTIFACTS_CONCERN_MANIFEST golden census (A.8 anchors)", () => {
  it("declares the artifacts concern and its frozen decision ref", () => {
    expect(ARTIFACTS_CONCERN_MANIFEST.concernId).toBe("artifacts");
    expect(ARTIFACTS_CONCERN_MANIFEST.decisionRefs).toContain("artifacts-freeze");
  });

  it("has exactly the 10 goldenRefs this fixture set expects (no silently added/removed entry)", () => {
    expect(ARTIFACTS_CONCERN_MANIFEST.goldenRefs).toHaveLength(10);
    expect(new Set(ARTIFACTS_CONCERN_MANIFEST.goldenRefs.map((ref) => ref.path)).size).toBe(10);
  });

  for (const [relPath, expectedSha] of Object.entries(EXPECTED_FILE_SHA256)) {
    const fileName = relPath.split("/")[1];

    it(`goldens/${relPath} bytes hash to the A.8-derived literal, independent of the manifest`, () => {
      expect(sha256OfGolden(relPath)).toBe(expectedSha);
    });

    it(`ARTIFACTS_CONCERN_MANIFEST.goldenRefs pins ${fileName} to the same A.8-derived literal (manifest-drift guard)`, () => {
      const ref = ARTIFACTS_CONCERN_MANIFEST.goldenRefs.find((r) => r.path === `${GOLDEN_DIR}/${fileName}`);
      expect(ref).toBeDefined();
      // Editing the manifest's pin alone (without touching the golden file) must redden here
      // exactly as loudly as editing the golden file alone reddens the assertion above.
      expect(ref?.sha256).toBe(expectedSha);
    });
  }

  it("each artifact's .digest.hex file text is exactly the pinned A.8 digest literal", () => {
    for (const [purpose, digest] of Object.entries(PINNED_ARTIFACT_DIGEST)) {
      expect(readGoldenText(`artifacts/${purpose}.digest.hex`)).toBe(digest);
    }
  });

  it("each artifact's .sig.b64 file text is exactly the pinned A.8 signature literal", () => {
    for (const [purpose, sig] of Object.entries(PINNED_ARTIFACT_SIGNATURE)) {
      expect(readGoldenText(`artifacts/${purpose}.sig.b64`)).toBe(sig);
    }
  });

  it("the node-identity pubkey golden file text is exactly the pinned A.8 fixture literal", () => {
    expect(readGoldenText("artifacts/node-identity.pub.b64")).toBe(PINNED_NODE_IDENTITY_PUBKEY);
  });

  describe("negative proof: a mutated-and-regenerated golden cannot pass this anchor (bypass repro, 2.25 -> 22.5)", () => {
    const MUTATION_TARGET = '"amount_zkz":"2.25"';
    const MUTATION_REPLACEMENT = '"amount_zkz":"22.5"';

    for (const purpose of Object.keys(PINNED_ARTIFACT_DIGEST)) {
      it(`mutating ${purpose}'s amount_zkz and recomputing its digest no longer matches the pinned literal`, () => {
        const original = readGoldenText(`artifacts/${purpose}.preimage.txt`);
        const occurrences = original.split(MUTATION_TARGET).length - 1;
        expect(occurrences).toBe(1); // sanity: the mutation must land on exactly one field

        const mutated = original.replaceAll(MUTATION_TARGET, MUTATION_REPLACEMENT);
        expect(mutated).not.toBe(original);

        const mutatedDigest = sha256OfLiteral(mutated);
        // This is the demonstrated bypass: regenerate digest/sig/meta.json from the mutated
        // bytes and every existing (self-referential) check stays internally consistent. The
        // pinned literal above never moves when the on-disk golden moves, so this anchor still
        // catches the mutation even though a from-scratch regeneration of every derived file
        // would not.
        expect(mutatedDigest).not.toBe(PINNED_ARTIFACT_DIGEST[purpose]);
      });
    }
  });
});
