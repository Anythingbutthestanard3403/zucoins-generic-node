import { describe, expect, it } from "vitest";

import golden from "./gen/compat-literals.json" with { type: "json" };
import { COMPAT_LITERALS_CONCERN_MANIFEST } from "./manifest.ts";

describe("compat-literals concern manifest freeze", () => {
  it("the frozen compat-literals values match the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(COMPAT_LITERALS_CONCERN_MANIFEST.frozenValues))).toEqual(golden);
  });

  it("the ConcernManifest self-registers the compat-literals concern with its canonical decisions", () => {
    expect(COMPAT_LITERALS_CONCERN_MANIFEST.concernId).toBe("compat-literals");
    expect(COMPAT_LITERALS_CONCERN_MANIFEST.decisionRefs).toContain("compat-literal-preservation");
  });

  it("declares no tier-3 golden refs yet (no byte artifact pinned for this concern)", () => {
    expect(COMPAT_LITERALS_CONCERN_MANIFEST.goldenRefs).toEqual([]);
  });
});
