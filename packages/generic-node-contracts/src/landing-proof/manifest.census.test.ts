import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { LANDING_PROOF_CONCERN_MANIFEST } from "./manifest.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "landing-proof.json");

describe("LANDING_PROOF_CONCERN_MANIFEST (the landing-proof concern; the concern-manifest registry leave-behind)", () => {
  it("declares the landing-proof concern and its canonical decision ref", () => {
    expect(LANDING_PROOF_CONCERN_MANIFEST.concernId).toBe("landing-proof");
    expect(LANDING_PROOF_CONCERN_MANIFEST.decisionRefs).toContain("complete-path-adjudication");
  });

  it("carries the scan rules and the landing-proof source citation", () => {
    expect(LANDING_PROOF_CONCERN_MANIFEST.scanRules).toContain(
      "forbidden-terms:packages/generic-node-contracts/src",
    );
    expect(LANDING_PROOF_CONCERN_MANIFEST.sourceDocCitations).toContain(
      "complete-path-adjudication: any-depth complete-path landing proof anchored at a fresh head",
    );
  });

  it("goldenRef sha256 pins the committed gen/landing-proof.json exactly", () => {
    const golden = LANDING_PROOF_CONCERN_MANIFEST.goldenRefs.find(
      (ref) => ref.path === "gen/landing-proof.json",
    );
    expect(golden).toBeDefined();
    const actual = createHash("sha256").update(readFileSync(genPath)).digest("hex");
    expect(golden?.sha256).toBe(actual);
  });
});
