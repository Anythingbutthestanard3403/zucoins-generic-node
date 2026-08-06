import { describe, it, expect } from "vitest";
import { BigNumber } from "bignumber.js";
import { emitAmount } from "./emitter.js";

// These tests do NOT exercise the sanctioned emitter's misuse (emitAmount only ever calls
// `.toFixed()` with no argument). They pin WHY the two forbidden forms are byte defects, so a
// future refactor that reaches for `.toFixed(dp)` or `.toString()` has a red test explaining
// the loss. The demo clones below mirror the pinned emitter's rounding; only the emission
// method under test differs.
const RoundDownClone = BigNumber.clone({
  DECIMAL_PLACES: 32,
  ROUNDING_MODE: BigNumber.ROUND_DOWN,
});

describe("emitter misuse — .toFixed(dp) zero-pads (byte defect)", () => {
  it("toFixed(32) pads trailing zeros that the canonical emitter trims", () => {
    const misused = new RoundDownClone("2.5").toFixed(32);
    expect(misused).toBe(`2.5${"0".repeat(31)}`);
    expect(emitAmount("2.5")).toBe("2.5");
    expect(misused).not.toBe(emitAmount("2.5"));
  });
});

describe("emitter misuse — .toString() can emit exponent notation (byte defect)", () => {
  it("toString consults EXPONENTIAL_AT and exponents small values; toFixed never does", () => {
    // A deliberately exponent-prone config makes the defect deterministic and independent of
    // the library's default EXPONENTIAL_AT. The pinned emitter is immune because it uses
    // .toFixed(), which never consults EXPONENTIAL_AT.
    const ExponentProne = BigNumber.clone({ EXPONENTIAL_AT: [-1, 1] });
    const misused = new ExponentProne("0.01").toString();
    expect(misused).toContain("e");
    expect(emitAmount("0.01")).toBe("0.01");
    expect(emitAmount("0.01")).not.toContain("e");
  });
});
