import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  amountsContract,
  amountsConcernManifest,
  AMOUNT_REJECTION_REASONS,
  ZKZ_AMOUNT_CHECK_DOMAINS,
} from "./manifest.js";

// gen/amounts.json is the committed snapshot of the as-const manifest. This sync test fails
// if the two drift; regenerate per CONTRACT.md.
const snapshotPath = fileURLToPath(
  new URL("../../gen/amounts.json", import.meta.url),
);

describe("amounts manifest — snapshot sync (3-tier)", () => {
  it("gen/amounts.json equals the as-const amountsContract", () => {
    const snapshot = JSON.parse(readFileSync(snapshotPath, "utf8"));
    expect(snapshot).toEqual(amountsContract);
  });
});

describe("amounts manifest — frozen-fact census", () => {
  it("freezes the bound, precision, rounding, and exponent config", () => {
    expect(amountsContract.upperBoundExclusive).toBe("100000000");
    expect(amountsContract.maxDecimalPlaces).toBe(32);
    expect(amountsContract.rounding).toBe("ROUND_DOWN");
    expect(amountsContract.exponentialAt).toEqual([-33, 33]);
  });
  it("greatest legal value is 99999999. + 32 nines", () => {
    expect(amountsContract.greatestLegalValue).toBe(`99999999.${"9".repeat(32)}`);
  });
  it("freezes the exact canonical grammar pattern", () => {
    expect(amountsContract.canonicalDecimalPattern).toBe(
      "^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$",
    );
  });
  it("freezes the layer split (balance inclusive-zero, operation exclusive-zero)", () => {
    expect(amountsContract.layers.balance.lowerBoundInclusive).toBe(true);
    expect(amountsContract.layers.operation.lowerBoundInclusive).toBe(false);
    expect(amountsContract.layers.balance.upperBoundExclusive).toBe("100000000");
    expect(amountsContract.layers.operation.upperBoundExclusive).toBe("100000000");
  });
  it("freezes the four rejection reason codes", () => {
    expect(AMOUNT_REJECTION_REASONS).toEqual({
      grammar: "amount_grammar_violation",
      nonCanonical: "amount_not_canonical",
      notPositive: "amount_not_positive",
      outOfRange: "amount_out_of_range",
    });
  });
});

describe("amounts manifest — DB CHECK domains (SQL text as data, no schema here)", () => {
  it("balance domain is the grammar regex", () => {
    expect(ZKZ_AMOUNT_CHECK_DOMAINS.zkz_balance_text).toBe(
      "VALUE ~ '^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$'",
    );
  });
  it("positive domain uses NUMERIC positivity, not a string `<> '0'`", () => {
    const positive = ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text;
    expect(positive).toContain("VALUE::numeric > 0");
    expect(positive).not.toContain("<> '0'");
  });
});

describe("amounts concern manifest — provisional shape", () => {
  it("wraps the frozen contract under its concern id", () => {
    expect(amountsConcernManifest.concern).toBe("amounts");
    expect(amountsConcernManifest.frozenBy).toBe("zkz-amount-grammar");
    expect(amountsConcernManifest.contract).toBe(amountsContract);
  });
});
