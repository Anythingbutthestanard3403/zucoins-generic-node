import { describe, expect, it } from "vitest";

import golden from "./gen/engine-startup.json" with { type: "json" };
import { ENGINE_STARTUP_CONCERN_MANIFEST } from "./manifest.ts";

describe("the named concern manifest freeze", () => {
  it("the frozen engine-startup values match the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(ENGINE_STARTUP_CONCERN_MANIFEST.frozenValues))).toEqual(golden);
  });

  it("the ConcernManifest self-registers the named concern with its canonical decisions", () => {
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.concernId).toBe("engine-startup");
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.decisionRefs).toContain("startup-sequence");
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.decisionRefs).toContain("vault-storage-model");
    // The tier-2 gen/engine-startup.json goldenRef digest is verified by manifest.census.test.ts.
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.goldenRefs.length).toBeGreaterThan(0);
  });
});
