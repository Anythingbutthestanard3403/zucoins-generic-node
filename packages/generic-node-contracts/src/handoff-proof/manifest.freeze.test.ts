import { describe, expect, it } from "vitest";

import golden from "./gen/handoff-proof.json" with { type: "json" };
import { HANDOFF_PROOF_CONCERN_MANIFEST } from "./manifest.ts";

describe("handoff-proof concern manifest freeze", () => {
  it("the frozen handoff-proof values match the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(HANDOFF_PROOF_CONCERN_MANIFEST.frozenValues))).toEqual(golden);
  });

  it("the ConcernManifest self-registers the handoff-proof concern with its canonical decisions", () => {
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.concernId).toBe("handoff-proof");
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.decisionRefs).toContain("two-instance-handoff-backstop");
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.goldenRefs.length).toBeGreaterThan(0);
  });
});
