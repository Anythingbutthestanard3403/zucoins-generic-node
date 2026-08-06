import { describe, it, expect } from "vitest";
import { CANONICAL_DECIMAL_PATTERN, matchesCanonicalGrammar } from "./grammar.js";

const NINES_32 = "9".repeat(32);
const ONES_32 = "1".repeat(32);
const ZEROS_31 = "0".repeat(31);
const ZEROS_32 = "0".repeat(32);

describe("canonical grammar — accepts (census of legal shapes)", () => {
  const legal = [
    "0",
    "1",
    "99999999", // greatest legal integer (8 digits)
    "0.5",
    "2.5",
    "0.25",
    "99999999.5",
    `0.${ONES_32}`, // 32 decimal places
    `0.${ZEROS_31}1`, // smallest DP32 unit (10^-32)
    `99999999.${NINES_32}`, // greatest legal value below the bound
  ];
  for (const value of legal) {
    it(`accepts ${JSON.stringify(value)}`, () => {
      expect(matchesCanonicalGrammar(value)).toBe(true);
    });
  }
});

describe("canonical grammar — rejects (adversarial self-check)", () => {
  const illegal: Array<[string, string]> = [
    ["", "empty string"],
    ["100000000", "exact upper bound 1e8 (9-digit integer)"],
    ["100000000.1", "above the bound"],
    ["100000001", "above the bound integer"],
    ["999999999", "'9' x 9 — nine-digit integer >= 1e8"],
    [`0.${ONES_32}1`, "33 decimal places"],
    [`1.${NINES_32}9`, "33 decimal places on a non-zero integer"],
    ["1e5", "exponent lowercase"],
    ["1E5", "exponent uppercase"],
    ["1.5e3", "exponent with fraction"],
    ["1e-7", "negative exponent"],
    ["+1", "leading plus"],
    ["-1", "leading minus"],
    ["-0", "negative zero"],
    ["-0.5", "negative fraction"],
    ["00", "leading-zero integer"],
    ["01", "leading-zero integer"],
    ["00.1", "leading-zero integer with fraction"],
    ["1.", "trailing dot"],
    [".5", "no integer part"],
    ["1..5", "double dot"],
    ["1.5.5", "two dots"],
    ["1,000", "thousands separator"],
    ["1_000", "underscore separator"],
    [" 1", "leading space"],
    ["1 ", "trailing space"],
    ["5\n", "trailing newline"],
    ["\n5", "leading newline"],
    ["Infinity", "infinity keyword"],
    ["NaN", "nan keyword"],
    ["0x1F", "hex literal"],
    ["1.0x", "trailing garbage"],
    ["１", "fullwidth digit one (U+FF11)"],
    ["١", "arabic-indic digit one (U+0661)"],
    ["1．5", "fullwidth full stop as decimal point"],
  ];
  for (const [value, why] of illegal) {
    it(`rejects ${JSON.stringify(value)} — ${why}`, () => {
      expect(matchesCanonicalGrammar(value)).toBe(false);
    });
  }
});

describe("canonical grammar — frozen pattern text", () => {
  it("is the exact the amounts-grammar freeze pattern", () => {
    expect(CANONICAL_DECIMAL_PATTERN).toBe("^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$");
  });
  it(`greatest legal value is 99999999.${NINES_32}`, () => {
    expect(matchesCanonicalGrammar(`99999999.${NINES_32}`)).toBe(true);
    // Nothing one unit larger is representable: adding a 33rd place or a 9th integer digit
    // both leave the grammar.
    expect(matchesCanonicalGrammar(`99999999.${NINES_32}9`)).toBe(false);
    expect(matchesCanonicalGrammar(`100000000.${ZEROS_32}`)).toBe(false);
  });
});
