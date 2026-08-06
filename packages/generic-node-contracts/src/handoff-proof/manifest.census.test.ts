import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { HANDOFF_PROOF_CONCERN_MANIFEST } from "./manifest.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "handoff-proof.json");

describe("HANDOFF_PROOF_CONCERN_MANIFEST (concern-manifest registry leave-behind)", () => {
  it("declares the handoff-proof concern and its canonical decision refs", () => {
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.concernId).toBe("handoff-proof");
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.decisionRefs).toContain("two-instance-handoff-backstop");
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.decisionRefs).toContain("vault-storage-envelope");
  });

  it("carries the scan rules and the leadership-lock / boot-recovery source citations", () => {
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.scanRules).toContain(
      "forbidden-terms:packages/generic-node-contracts/src",
    );
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.sourceDocCitations).toContain("node-core leadership lock");
    expect(HANDOFF_PROOF_CONCERN_MANIFEST.sourceDocCitations).toContain("two-instance-handoff-backstop");
  });

  it("goldenRef sha256 pins the committed gen/handoff-proof.json exactly", () => {
    const golden = HANDOFF_PROOF_CONCERN_MANIFEST.goldenRefs.find(
      (ref) => ref.path === "gen/handoff-proof.json",
    );
    expect(golden).toBeDefined();
    const actual = createHash("sha256").update(readFileSync(genPath)).digest("hex");
    expect(golden?.sha256).toBe(actual);
  });
});
