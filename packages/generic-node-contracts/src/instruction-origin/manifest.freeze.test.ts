import { describe, expect, it } from "vitest";

import golden from "./gen/instruction-origin.json" with { type: "json" };
import { INSTRUCTION_ORIGIN_CONCERN_MANIFEST } from "./manifest.ts";

describe("the presentation-scope concern manifest freeze", () => {
  it("the frozen instruction-origin values match the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(INSTRUCTION_ORIGIN_CONCERN_MANIFEST.frozenValues))).toEqual(golden);
  });

  it("the ConcernManifest self-registers the presentation-scope concern with its canonical decisions", () => {
    expect(INSTRUCTION_ORIGIN_CONCERN_MANIFEST.concernId).toBe("instruction-origin");
    expect(INSTRUCTION_ORIGIN_CONCERN_MANIFEST.decisionRefs).toContain("instruction-origin-identity");
  });

  it("declares no tier-3 golden refs yet (no byte artifact pinned for this concern)", () => {
    expect(INSTRUCTION_ORIGIN_CONCERN_MANIFEST.goldenRefs).toEqual([]);
  });
});
