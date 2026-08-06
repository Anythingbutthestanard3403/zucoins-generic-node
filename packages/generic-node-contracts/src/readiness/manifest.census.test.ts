import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { READINESS_CONCERN_MANIFEST } from "./manifest.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "readiness.json");

describe("READINESS_CONCERN_MANIFEST (the readiness concern)", () => {
  it("declares the readiness concern and its governing rules", () => {
    expect(READINESS_CONCERN_MANIFEST.concernId).toBe("readiness");
    expect(READINESS_CONCERN_MANIFEST.decisionRefs).toContain("startup-sequence");
    expect(READINESS_CONCERN_MANIFEST.decisionRefs).toContain("vault-storage-model");
  });

  it("carries the scan rules and the governing source citations", () => {
    expect(READINESS_CONCERN_MANIFEST.scanRules).toContain(
      "forbidden-terms:packages/generic-node-contracts/src",
    );
    expect(READINESS_CONCERN_MANIFEST.sourceDocCitations).toContain(
      "node-core: runtime components and the readiness sentence",
    );
    expect(READINESS_CONCERN_MANIFEST.sourceDocCitations).toContain(
      "operations-recovery: boot recovery and degraded operation",
    );
    expect(READINESS_CONCERN_MANIFEST.sourceDocCitations).toContain(
      "startup-sequence: readiness is decoupled from signer-lock ownership",
    );
  });

  it("goldenRef sha256 pins the committed gen/readiness.json exactly", () => {
    const golden = READINESS_CONCERN_MANIFEST.goldenRefs.find(
      (ref) => ref.path === "gen/readiness.json",
    );
    expect(golden).toBeDefined();
    const actual = createHash("sha256").update(readFileSync(genPath)).digest("hex");
    expect(golden?.sha256).toBe(actual);
  });
});
