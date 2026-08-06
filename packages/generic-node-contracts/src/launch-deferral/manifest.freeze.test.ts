import { describe, expect, it } from "vitest";

import golden from "./gen/launch-deferral.json" with { type: "json" };
import { LAUNCH_DEFERRAL_CONCERN_MANIFEST } from "./manifest.ts";

describe("launch-deferral concern manifest freeze", () => {
  it("the frozen launch-deferral values match the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(LAUNCH_DEFERRAL_CONCERN_MANIFEST.frozenValues))).toEqual(golden);
  });

  it("the ConcernManifest self-registers the launch-deferral concern with its canonical decisions", () => {
    expect(LAUNCH_DEFERRAL_CONCERN_MANIFEST.concernId).toBe("launch-deferral");
    expect(LAUNCH_DEFERRAL_CONCERN_MANIFEST.decisionRefs).toContain("launch-capability-deferral");
  });

  it("declares no tier-3 golden refs yet (no byte artifact pinned for this concern)", () => {
    expect(LAUNCH_DEFERRAL_CONCERN_MANIFEST.goldenRefs).toEqual([]);
  });
});
