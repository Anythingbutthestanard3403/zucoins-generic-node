import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { walletStateAlignmentContract } from "./alignment-manifest.js";

const snapshotPath = fileURLToPath(
  new URL("../../gen/wallet-state-alignment.json", import.meta.url),
);

describe("wallet-state alignment manifest — snapshot sync (3-tier)", () => {
  it("gen/wallet-state-alignment.json equals walletStateAlignmentContract", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(walletStateAlignmentContract);
  });
});

describe("wallet-state alignment manifest — census", () => {
  it("aggregates selectors, projection-bound set, dispositions, and contradiction classes", () => {
    expect(Object.keys(walletStateAlignmentContract).sort()).toEqual([
      "bootAuditContradictionClasses",
      "bootAuditDispositions",
      "projectionBoundSelectors",
      "selectors",
    ]);
    expect(walletStateAlignmentContract.projectionBoundSelectors).toHaveLength(5);
    expect(Object.keys(walletStateAlignmentContract.bootAuditContradictionClasses)).toContain(
      "overstated_restriction_to_available",
    );
  });
});
