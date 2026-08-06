import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { OBSERVATION_CONCERN_MANIFEST } from "./manifest.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "observation.json");

describe("OBSERVATION_CONCERN_MANIFEST (the observation concern; the concern-manifest registry leave-behind)", () => {
  it("declares the observation concern and its frozen decision refs", () => {
    expect(OBSERVATION_CONCERN_MANIFEST.concernId).toBe("observation");
    expect(OBSERVATION_CONCERN_MANIFEST.decisionRefs).toContain("observation-dedup");
  });

  it("carries the scan rules and the observation-dedup rule source citation", () => {
    expect(OBSERVATION_CONCERN_MANIFEST.scanRules).toContain(
      "forbidden-terms:packages/generic-node-contracts/src",
    );
    expect(OBSERVATION_CONCERN_MANIFEST.sourceDocCitations).toContain("decision: observation-dedup");
  });

  it("goldenRef sha256 pins the committed gen/observation.json exactly", () => {
    const golden = OBSERVATION_CONCERN_MANIFEST.goldenRefs.find(
      (ref) => ref.path === "gen/observation.json",
    );
    expect(golden).toBeDefined();
    const actual = createHash("sha256").update(readFileSync(genPath)).digest("hex");
    expect(golden?.sha256).toBe(actual);
  });
});
