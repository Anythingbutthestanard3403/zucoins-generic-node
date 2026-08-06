import { describe, expect, it } from "vitest";

import {
  amountWithinTolerance,
  compareAmounts,
  signedDelta,
  subtractAmounts,
} from "./types.js";

describe("compareAmounts", () => {
  it("orders integer amounts numerically, not lexicographically", () => {
    expect(compareAmounts("2", "10")).toBe(-1);
    expect(compareAmounts("10", "2")).toBe(1);
    expect(compareAmounts("10", "10")).toBe(0);
  });

  it("compares fractional amounts by value", () => {
    expect(compareAmounts("0.000001", "0.01")).toBe(-1);
    expect(compareAmounts("0.01", "0.000001")).toBe(1);
    expect(compareAmounts("0.10", "0.1")).toBe(0);
  });

  it("rejects malformed amounts", () => {
    expect(() => compareAmounts("abc", "1")).toThrow(/malformed amount/);
  });
});

describe("subtractAmounts / signedDelta", () => {
  it("subtracts fractional dust", () => {
    expect(subtractAmounts("1.000001", "0.000001")).toBe("1");
    expect(signedDelta("1", "0.999999")).toBe("-0.000001");
    expect(signedDelta("1", "1.000001")).toBe("0.000001");
  });

  it("amountWithinTolerance respects the bound", () => {
    expect(amountWithinTolerance("0.000001", "0.000001", "0")).toBe(true);
    expect(amountWithinTolerance("0.000001", "0.01", "0")).toBe(false);
  });
});
