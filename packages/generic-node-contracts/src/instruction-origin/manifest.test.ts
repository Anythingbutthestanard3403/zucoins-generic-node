// the presentation-scope concern-manifest freeze: registration shape only (the concern-manifest registry assembles the registry).
import { describe, expect, it } from "vitest";

import { INSTRUCTION_ORIGIN_CONCERN_MANIFEST } from "./manifest.ts";

describe("the presentation-scope concern ConcernManifest registration", () => {
  it("concernId is exactly the presentation-scope concern", () => {
    expect(INSTRUCTION_ORIGIN_CONCERN_MANIFEST.concernId).toBe("instruction-origin");
  });

  it("decisionRefs cites the instruction-origin identity rule", () => {
    expect(INSTRUCTION_ORIGIN_CONCERN_MANIFEST.decisionRefs).toContain("instruction-origin-identity");
  });

  it("carries no golden byte refs (data + pure predicates only)", () => {
    expect(INSTRUCTION_ORIGIN_CONCERN_MANIFEST.goldenRefs).toEqual([]);
  });

  it("frozenValues includes every sub-freeze (.1, .2, .3)", () => {
    const keys = Object.keys(INSTRUCTION_ORIGIN_CONCERN_MANIFEST.frozenValues);
    for (const expected of [
      "ORIGIN_CLASSES",
      "PIN_REJECT_REASONS",
      "CAPABILITY_IDS",
      "PRESENTATION_HANDOFF_FIELDS",
      "SUBSTITUTION_THREAT_TABLE",
    ]) {
      expect(keys).toContain(expected);
    }
  });
});
