import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { ENGINE_STARTUP_CONCERN_MANIFEST } from "./manifest.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "engine-startup.json");

describe("ENGINE_STARTUP_CONCERN_MANIFEST (the named concern; the concern-manifest registry leave-behind)", () => {
  it("declares the engine-startup concern and the startup-sequence / vault-storage-model authority", () => {
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.concernId).toBe("engine-startup");
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.decisionRefs).toContain("startup-sequence");
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.decisionRefs).toContain("vault-storage-model");
  });

  it("carries the scan rules and the runtime-component / boot-recovery source citations", () => {
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.scanRules).toContain(
      "forbidden-terms:packages/generic-node-contracts/src",
    );
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.sourceDocCitations).toContain("node-core: runtime components");
    expect(ENGINE_STARTUP_CONCERN_MANIFEST.sourceDocCitations).toContain("decision: startup-sequence");
  });

  it("goldenRef sha256 pins the committed gen/engine-startup.json exactly", () => {
    const golden = ENGINE_STARTUP_CONCERN_MANIFEST.goldenRefs.find(
      (ref) => ref.path === "gen/engine-startup.json",
    );
    expect(golden).toBeDefined();
    const actual = createHash("sha256").update(readFileSync(genPath)).digest("hex");
    expect(golden?.sha256).toBe(actual);
  });
});
