import { describe, it, expect } from "vitest";
import { BigNumber } from "bignumber.js";
import {
  emitAmount,
  addAmounts,
  subtractAmounts,
  compareAmounts,
  isNumericallyPositive,
  isWithinBalanceMagnitude,
  isWithinOperationMagnitude,
  numericDecimalPlaces,
  isFiniteAmount,
} from "./emitter.js";

const NINES_32 = "9".repeat(32);
const SIXES_32 = "6".repeat(32);
const THREES_32 = "3".repeat(32);
const ZEROS_31 = "0".repeat(31);

describe("emitAmount — canonical wire form (.toFixed() no-arg)", () => {
  it("trims trailing zeros", () => {
    expect(emitAmount("2.50")).toBe("2.5");
    expect(emitAmount("2.000")).toBe("2");
    expect(emitAmount("0.250000")).toBe("0.25");
    expect(emitAmount("5.0")).toBe("5");
  });
  it("emits sub-1e-6 amounts in plain (non-exponential) notation", () => {
    expect(emitAmount("0.0000001")).toBe("0.0000001");
    expect(emitAmount("0.00000000000000000001")).toBe("0.00000000000000000001");
    expect(emitAmount(`0.${ZEROS_31}1`)).toBe(`0.${ZEROS_31}1`);
    expect(emitAmount("0.0000001")).not.toContain("e");
  });
  it("keeps a large in-bounds amount non-exponential", () => {
    expect(emitAmount("99999999.5")).toBe("99999999.5");
    expect(emitAmount(`99999999.${NINES_32}`)).toBe(`99999999.${NINES_32}`);
  });
});

describe("ROUND_DOWN config guard (parity with splitchain Amount)", () => {
  // emitAmount / addAmounts / subtractAmounts never round: `.toFixed()` no-arg and
  // plus/minus are exact, so a >32 dp value is emitted in full (and rejected upstream by the
  // grammar / magnitude predicates, never truncated at emission — identical to splitchain's
  // toAmountString, which relies on assertAmountWithinBounds for the >32 dp rejection). The
  // frozen `{ DECIMAL_PLACES: 32, ROUND_DOWN }` config is the value any rounding operation
  // inherits; prove its behaviour through a division on an identically-configured clone,
  // exactly as packages/splitchain/src/amount.test.ts does.
  const Mirror = BigNumber.clone({ DECIMAL_PLACES: 32, ROUNDING_MODE: BigNumber.ROUND_DOWN });
  it("2/3 truncates DOWN at 32 dp (…6, never …7)", () => {
    expect(new Mirror(2).dividedBy(3).toFixed()).toBe(`0.${SIXES_32}`);
  });
  it("1/3 truncates DOWN at 32 dp", () => {
    expect(new Mirror(1).dividedBy(3).toFixed()).toBe(`0.${THREES_32}`);
  });
  it("emitAmount preserves a full 32-dp value without corrupting it", () => {
    expect(emitAmount(`0.${SIXES_32}`)).toBe(`0.${SIXES_32}`);
    expect(emitAmount(`0.${NINES_32}`)).toBe(`0.${NINES_32}`);
  });
});

describe("arithmetic — exact BigNumber, never IEEE-754", () => {
  it("adds and subtracts absolute balances exactly", () => {
    expect(subtractAmounts("10", "2.5")).toBe("7.5");
    expect(addAmounts("3", "2.5")).toBe("5.5");
    expect(addAmounts("0", "2.5")).toBe("2.5");
  });
  it("0.1 + 0.2 === 0.3 and 0.3 - 0.1 === 0.2 (float would drift)", () => {
    expect(addAmounts("0.1", "0.2")).toBe("0.3");
    expect(subtractAmounts("0.3", "0.1")).toBe("0.2");
    expect(0.1 + 0.2).not.toBe(0.3);
  });
  it("keeps positivity and magnitude policy out of generic arithmetic", () => {
    expect(subtractAmounts("0", "1")).toBe("-1");
    expect(addAmounts("99999999", "2")).toBe("100000001");
  });
});

describe("string-only public money boundary", () => {
  it("rejects every representative non-string before BigNumber can coerce it", () => {
    const hostileObject = { toString: () => "2.5" };
    const nonStrings: unknown[] = [
      0.1 + 0.2,
      Number.MAX_SAFE_INTEGER + 2,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      new BigNumber("2.5"),
      new String("2.5"),
      2n,
      ["2.5"],
      hostileObject,
      null,
      undefined,
    ];

    for (const value of nonStrings) {
      expect(() => Reflect.apply(emitAmount, undefined, [value])).toThrow(TypeError);
      for (const fn of [addAmounts, subtractAmounts, compareAmounts]) {
        expect(() => Reflect.apply(fn, undefined, [value, "1"])).toThrow(TypeError);
        expect(() => Reflect.apply(fn, undefined, ["1", value])).toThrow(TypeError);
      }
    }
  });

  it("freezes primitive-string inputs at compile time", () => {
    // Never invoked — exists solely so tsc exercises the @ts-expect-error
    // assertions below at compile time. See no-constant-condition.
    const _compileTimeNegativeAssertions = (): void => {
      // @ts-expect-error JavaScript numbers are forbidden on the amount emitter boundary.
      emitAmount(0.1 + 0.2);
      // @ts-expect-error BigNumber objects are forbidden on the amount emitter boundary.
      emitAmount(new BigNumber("2.5"));
      // @ts-expect-error JavaScript numbers are forbidden in the first operand.
      addAmounts(1, "2");
      // @ts-expect-error JavaScript numbers are forbidden in the second operand.
      addAmounts("1", 2);
      // @ts-expect-error JavaScript numbers are forbidden in the first operand.
      subtractAmounts(1, "2");
      // @ts-expect-error JavaScript numbers are forbidden in the second operand.
      subtractAmounts("1", 2);
      // @ts-expect-error JavaScript numbers are forbidden in the first operand.
      compareAmounts(1, "2");
      // @ts-expect-error JavaScript numbers are forbidden in the second operand.
      compareAmounts("1", 2);
    };
    void _compileTimeNegativeAssertions;
    expect(true).toBe(true);
  });
});

describe("compareAmounts — numeric three-way compare", () => {
  it("compares by value, not by string", () => {
    expect(compareAmounts("2", "10")).toBe(-1); // "2" > "10" as strings
    expect(compareAmounts("10", "2")).toBe(1);
    expect(compareAmounts("2.50", "2.5")).toBe(0); // equal despite different bytes
  });
  it("throws on a non-numeric operand", () => {
    expect(() => compareAmounts("abc", "1")).toThrow();
  });
});

describe("numeric predicates — positivity is numeric, not string", () => {
  it("rejects every zero form as not-positive", () => {
    expect(isNumericallyPositive("0")).toBe(false);
    expect(isNumericallyPositive("0.0")).toBe(false);
    expect(isNumericallyPositive("0.00")).toBe(false);
    expect(isNumericallyPositive(`0.${"0".repeat(32)}`)).toBe(false);
  });
  it("accepts the smallest positive unit", () => {
    expect(isNumericallyPositive(`0.${ZEROS_31}1`)).toBe(true);
  });
  it("balance magnitude admits 0, operation magnitude does not", () => {
    expect(isWithinBalanceMagnitude("0")).toBe(true);
    expect(isWithinOperationMagnitude("0")).toBe(false);
    expect(isWithinBalanceMagnitude(`99999999.${NINES_32}`)).toBe(true);
    expect(isWithinOperationMagnitude(`99999999.${NINES_32}`)).toBe(true);
  });
  it("both magnitudes reject the exact bound and above", () => {
    expect(isWithinBalanceMagnitude("100000000")).toBe(false);
    expect(isWithinOperationMagnitude("100000000")).toBe(false);
    expect(isWithinBalanceMagnitude("100000000.1")).toBe(false);
  });
  it("both magnitudes reject >32 dp and non-finite", () => {
    expect(isWithinBalanceMagnitude(`0.${"1".repeat(33)}`)).toBe(false);
    expect(isWithinOperationMagnitude(`0.${"1".repeat(33)}`)).toBe(false);
    expect(isFiniteAmount("not-a-number")).toBe(false);
    expect(numericDecimalPlaces("2.5")).toBe(1);
  });
});
