import { describe, expect, it } from "vitest";

import golden from "./gen/readiness.json" with { type: "json" };
import { READINESS_CONCERN_MANIFEST } from "./manifest.ts";

describe("the named concern manifest freeze", () => {
  it("the frozen readiness values match the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(READINESS_CONCERN_MANIFEST.frozenValues))).toEqual(golden);
  });

  it("the ConcernManifest self-registers the named concern with its canonical decisions", () => {
    expect(READINESS_CONCERN_MANIFEST.concernId).toBe("readiness");
    expect(READINESS_CONCERN_MANIFEST.decisionRefs).toContain("startup-sequence");
    expect(READINESS_CONCERN_MANIFEST.goldenRefs.length).toBeGreaterThan(0);
  });
});
