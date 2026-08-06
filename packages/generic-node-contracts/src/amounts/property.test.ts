import { describe, it, expect } from "vitest";
import {
  emitAmount,
  addAmounts,
  subtractAmounts,
  numericDecimalPlaces,
  isWithinBalanceMagnitude,
} from "./emitter.js";
import { isCanonicalAmount, validateOperationAmount } from "./validators.js";
import { matchesCanonicalGrammar } from "./grammar.js";

// Deterministic seeded PRNG (mulberry32) — reproducible, CI-stable, zero new dependencies.
function mulberry32(seed: number): () => number {
  let s = seed;
  return () => {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = mulberry32(0x5f3759df);
const randInt = (max: number): number => Math.floor(rng() * max);

// Generates a canonical amount by construction: no leading zero, no trailing zero, <=32 dp,
// integer part <= `intDigits` digits (so < 1e8). Can yield "0".
function genCanonical(intDigits: number): string {
  let intPart: string;
  if (rng() < 0.2) {
    intPart = "0";
  } else {
    const digits = 1 + randInt(intDigits);
    let s = String(1 + randInt(9));
    for (let i = 1; i < digits; i += 1) s += String(randInt(10));
    intPart = s;
  }
  let frac = "";
  if (rng() < 0.8) {
    const fdigits = 1 + randInt(32);
    for (let i = 0; i < fdigits; i += 1) frac += String(randInt(10));
    frac = frac.replace(/0+$/, "");
  }
  return frac ? `${intPart}.${frac}` : intPart;
}

const maxDp = (a: string, b: string): number =>
  Math.max(numericDecimalPlaces(a) ?? 0, numericDecimalPlaces(b) ?? 0);

describe("property — emit/parse canonicality (idempotence)", () => {
  it("every generated canonical value round-trips through the emitter unchanged", () => {
    for (let i = 0; i < 500; i += 1) {
      const a = genCanonical(8);
      expect(isCanonicalAmount(a)).toBe(true);
      expect(emitAmount(a)).toBe(a);
    }
  });
  it("appending a trailing zero always breaks canonicality (negative)", () => {
    for (let i = 0; i < 300; i += 1) {
      const a = genCanonical(8);
      if (!a.includes(".")) continue;
      expect(isCanonicalAmount(`${a}0`)).toBe(false);
    }
  });
});

describe("property — arithmetic round-trips and no-rounding invariants", () => {
  it("(a + b) - b === a for canonical in-range operands", () => {
    for (let i = 0; i < 500; i += 1) {
      const a = genCanonical(7);
      const b = genCanonical(7);
      const sum = addAmounts(a, b);
      if (!isWithinBalanceMagnitude(sum)) continue; // skip overflow past the bound
      expect(subtractAmounts(sum, b)).toBe(a);
    }
  });
  it("addition is commutative", () => {
    for (let i = 0; i < 300; i += 1) {
      const a = genCanonical(7);
      const b = genCanonical(7);
      expect(addAmounts(a, b)).toBe(addAmounts(b, a));
    }
  });
  it("add/subtract never introduce precision beyond the operands (no rounding, <=32 dp)", () => {
    for (let i = 0; i < 500; i += 1) {
      const a = genCanonical(7);
      const b = genCanonical(7);
      const sum = addAmounts(a, b);
      const bound = maxDp(a, b);
      expect(numericDecimalPlaces(sum) ?? 0).toBeLessThanOrEqual(bound);
      expect(numericDecimalPlaces(sum) ?? 0).toBeLessThanOrEqual(32);
    }
  });
});

describe("property — operation positivity and precision rejection", () => {
  it("every non-zero generated canonical is a valid operation amount", () => {
    for (let i = 0; i < 400; i += 1) {
      const a = genCanonical(8);
      if (a === "0") continue;
      expect(validateOperationAmount(a)).toEqual({ ok: true, canonical: a });
    }
  });
  it("extending any fraction to 33 places is always grammar-rejected (negative)", () => {
    for (let i = 0; i < 300; i += 1) {
      const a = genCanonical(8);
      const base = a.includes(".") ? a : `${a}.`;
      const overPrecise = `${base}${"1".repeat(33)}`;
      expect(matchesCanonicalGrammar(overPrecise)).toBe(false);
    }
  });
});
