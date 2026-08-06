import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { VAULT_CONCERN_MANIFEST } from "./manifest.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "vault.json");

describe("VAULT_CONCERN_MANIFEST (the vault concern; the concern-manifest registry leave-behind)", () => {
  it("declares the vault concern and the vault-storage-model authority", () => {
    expect(VAULT_CONCERN_MANIFEST.concernId).toBe("vault");
    expect(VAULT_CONCERN_MANIFEST.decisionRefs).toContain("vault-storage-model");
    expect(VAULT_CONCERN_MANIFEST.decisionRefs).toContain("single-blob-vault-precursor");
  });

  it("carries the scan rules and the vault-storage-model source citations", () => {
    expect(VAULT_CONCERN_MANIFEST.scanRules).toContain(
      "forbidden-terms:packages/generic-node-contracts/src",
    );
    expect(VAULT_CONCERN_MANIFEST.sourceDocCitations).toContain("decision: vault-storage-model");
    expect(VAULT_CONCERN_MANIFEST.sourceDocCitations).toContain("signing-custody: vault");
  });

  it("goldenRef sha256 pins the committed gen/vault.json exactly", () => {
    const golden = VAULT_CONCERN_MANIFEST.goldenRefs.find((ref) => ref.path === "gen/vault.json");
    expect(golden).toBeDefined();
    const actual = createHash("sha256").update(readFileSync(genPath)).digest("hex");
    expect(golden?.sha256).toBe(actual);
  });
});
