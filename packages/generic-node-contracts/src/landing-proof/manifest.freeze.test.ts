import { describe, expect, it } from "vitest";

import golden from "./gen/landing-proof.json" with { type: "json" };
import { LANDING_PROOF_CONCERN_MANIFEST } from "./manifest.ts";

describe("the landing-proof concern manifest freeze", () => {
  it("the frozen landing-proof values match the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(LANDING_PROOF_CONCERN_MANIFEST.frozenValues))).toEqual(golden);
  });

  it("the ConcernManifest self-registers the landing-proof concern with its canonical decisions", () => {
    expect(LANDING_PROOF_CONCERN_MANIFEST.concernId).toBe("landing-proof");
    expect(LANDING_PROOF_CONCERN_MANIFEST.decisionRefs.length).toBeGreaterThan(0);
    expect(LANDING_PROOF_CONCERN_MANIFEST.goldenRefs.length).toBeGreaterThan(0);
  });
});
