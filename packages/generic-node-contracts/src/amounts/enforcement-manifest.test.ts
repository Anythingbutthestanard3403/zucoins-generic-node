import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { amountEnforcementContract } from "./enforcement-manifest.js";

const snapshotPath = fileURLToPath(
  new URL("../../gen/amount-enforcement.json", import.meta.url),
);

describe("amount enforcement manifest — snapshot sync (3-tier)", () => {
  it("gen/amount-enforcement.json equals the as-const amountEnforcementContract", () => {
    const snapshot = JSON.parse(readFileSync(snapshotPath, "utf8"));
    expect(snapshot).toEqual(amountEnforcementContract);
  });
});

describe("amount enforcement manifest — census", () => {
  it("aggregates the three frozen maps", () => {
    expect(Object.keys(amountEnforcementContract).sort()).toEqual([
      "dbCheckDomainByRole",
      "fieldRoles",
      "writeViolationPolicy",
    ]);
  });
  it("carries all 11 field roles and the write-violation policy", () => {
    expect(Object.keys(amountEnforcementContract.fieldRoles)).toHaveLength(11);
    expect(amountEnforcementContract.writeViolationPolicy.sqlstate).toBe("23514");
  });
});
