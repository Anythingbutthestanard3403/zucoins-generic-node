// Drift anchor for the transcribed suite vectors.
//
// `test/__vectors__/suite-appendix-a.ts` is a HAND-TRANSCRIBED capture of canonical fields. Because
// the serializer is checked against that transcription, a stale value there is invisible: the code
// reproduces the wrong bytes and the suite still goes green. That is exactly how the-VOIDED
// `zp-receive-expected-v1` triple (`4b3e384d…` / `57253b75…` / `b-Y0gWgL…`) survived in this branch
// after canon had already moved.
//
// This file removes the transcription's authority by binding it to the committed golden byte-files in
// `@zucoins/generic-node-contracts`, which are the artifacts actually corrected. A future
// canon change that is not mirrored into the vectors now reddens here instead of merging silently.
//
// Canon under test (all on `origin/main`):
//   packages/generic-node-contracts/goldens/artifacts/<purpose>.{preimage.txt,digest.hex,sig.b64}
//   packages/generic-node-contracts/goldens/transfer-code/receive-code.v1.b64url.txt

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { SUITE_GOLDENS } from "./__vectors__/suite-appendix-a.js";

const CONTRACTS_GOLDENS = fileURLToPath(
  new URL("../../generic-node-contracts/goldens/", import.meta.url),
);

const readCanon = (relativePath: string): string =>
  readFileSync(`${CONTRACTS_GOLDENS}${relativePath}`, "utf8");

function vector(id: string) {
  const found = SUITE_GOLDENS.find((entry) => entry.id === id);
  if (found === undefined) throw new Error(`missing golden vector: ${id}`);
  return found;
}

// Every A.8.2 purpose that has committed artifact byte-files to anchor against.
const ANCHORED = [
  { id: "receive-expected", purpose: "zp-receive-expected-v1" },
  { id: "move-internal-expected", purpose: "zp-move-internal-expected-v1" },
  { id: "send-external-expected", purpose: "zp-send-external-expected-v1" },
] as const;

describe("B1 — transcribed A.8.2 vectors are anchored to committed contract goldens", () => {
  for (const { id, purpose } of ANCHORED) {
    describe(purpose, () => {
      const local = vector(id);

      it("preimage text matches the committed artifact byte-for-byte", () => {
        expect(local.preimageText).toBe(readCanon(`artifacts/${purpose}.preimage.txt`));
      });

      it("digest matches the committed digest, and re-derives from the preimage", () => {
        const committedDigest = readCanon(`artifacts/${purpose}.digest.hex`).trim();
        expect(local.sha256).toBe(committedDigest);
        expect(createHash("sha256").update(local.preimageText, "utf8").digest("hex")).toBe(
          committedDigest,
        );
      });

      it("signature matches the committed signature", () => {
        expect(local.signature).toBe(readCanon(`artifacts/${purpose}.sig.b64`).trim());
      });
    });
  }

  // Substantive rule: the receive artifact's `transfer_code_sha256` is the SHA-256 of the
  // encoded receive-code fixture's exact stored bytes — no decode, padding repair, newline
  // insertion, normalization, JSON wrapper, or reserialization (A.9 rules 9 and 11).
  it("receive `transfer_code_sha256` is the hash of the fixture's exact stored bytes", () => {
    const fixtureBytes = readFileSync(`${CONTRACTS_GOLDENS}transfer-code/receive-code.v1.b64url.txt`);
    const expected = createHash("sha256").update(fixtureBytes).digest("hex");

    expect(vector("receive-expected").values.transfer_code_sha256).toBe(expected);
    expect(vector("receive-expected").preimageText).toContain(`"transfer_code_sha256":"${expected}"`);
  });

  // The retired values must never reappear in the transcription. A.8.1's SplitChain golden keeps its
  // own illustrative `4b3e384d…` line, so this is scoped to the vectors file, not the whole repo.
  it("no-voided value survives in the vectors", () => {
    const voided = [
      "4b3e384d7c1774a450fdf9f74d338d1c6802a1057b2fd49e23c78244912c18f4",
      "57253b7569307bddaea4305af9e98540468f45f0db20e2edb28c1c62ab8bde17",
      "b-Y0gWgLHvibsUYHF16_SQcTF2aKRGHzO7e2_yHUiSSwyBDsFz8UowduxiZAp4xZgaS_CxnIrP5WWJQfl1clAQ==",
    ];
    const serialized = JSON.stringify(SUITE_GOLDENS);
    for (const value of voided) expect(serialized).not.toContain(value);
  });
});
