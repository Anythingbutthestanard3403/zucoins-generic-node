import { describe, it, expect } from "vitest";
import {
  isCanonicalAmount,
  validateBalanceAmount,
  validateOperationAmount,
} from "./validators.js";
import { AMOUNT_REJECTION_REASONS } from "./manifest.js";

const NINES_32 = "9".repeat(32);
const ZEROS_31 = "0".repeat(31);

describe("isCanonicalAmount — canonical-equality predicate", () => {
  it("accepts canonical forms", () => {
    expect(isCanonicalAmount("0")).toBe(true);
    expect(isCanonicalAmount("2.5")).toBe(true);
    expect(isCanonicalAmount("0.25")).toBe(true);
    expect(isCanonicalAmount(`99999999.${NINES_32}`)).toBe(true);
  });
  it("rejects grammar-legal but non-canonical trailing-zero forms", () => {
    expect(isCanonicalAmount("2.50")).toBe(false);
    expect(isCanonicalAmount("2.000")).toBe(false);
    expect(isCanonicalAmount("0.250000")).toBe(false);
    expect(isCanonicalAmount("5.0")).toBe(false);
    expect(isCanonicalAmount("0.0")).toBe(false);
  });
  it("rejects grammar violations outright", () => {
    expect(isCanonicalAmount("1e5")).toBe(false);
    expect(isCanonicalAmount("-1")).toBe(false);
    expect(isCanonicalAmount("100000000")).toBe(false);
  });
});

describe("layer split — balance admits zero, operation requires strictly positive", () => {
  it("balance accepts a swept-payer / genesis '0'", () => {
    expect(validateBalanceAmount("0")).toEqual({ ok: true, canonical: "0" });
  });
  it("operation rejects '0' as not-positive", () => {
    expect(validateOperationAmount("0")).toEqual({
      ok: false,
      reason: AMOUNT_REJECTION_REASONS.notPositive,
    });
  });
  it("both accept a normal positive amount", () => {
    expect(validateBalanceAmount("2.5")).toEqual({ ok: true, canonical: "2.5" });
    expect(validateOperationAmount("2.5")).toEqual({ ok: true, canonical: "2.5" });
  });
  it("both accept the greatest legal value", () => {
    const greatest = `99999999.${NINES_32}`;
    expect(validateBalanceAmount(greatest)).toEqual({ ok: true, canonical: greatest });
    expect(validateOperationAmount(greatest)).toEqual({ ok: true, canonical: greatest });
  });
  it("operation accepts the smallest positive unit", () => {
    const unit = `0.${ZEROS_31}1`;
    expect(validateOperationAmount(unit)).toEqual({ ok: true, canonical: unit });
  });
});

describe("zero-as-operation-amount regression — closes the string-check bypass", () => {
  // the amounts-grammar freeze hardening addendum clause 1: '0.0', '0.00', '0.'+32 zeros all match the regex and
  // are `<> '0'` as strings, yet are mathematically zero. NUMERIC positivity rejects them.
  const zeroForms = ["0", "0.0", "0.00", `0.${"0".repeat(32)}`];
  for (const value of zeroForms) {
    it(`rejects ${JSON.stringify(value)} as an operation amount`, () => {
      expect(validateOperationAmount(value).ok).toBe(false);
    });
  }
  it("the non-canonical zero forms fail canonical-equality too (defence in depth)", () => {
    expect(validateOperationAmount("0.0")).toEqual({
      ok: false,
      reason: AMOUNT_REJECTION_REASONS.nonCanonical,
    });
    expect(validateOperationAmount("0.00")).toEqual({
      ok: false,
      reason: AMOUNT_REJECTION_REASONS.nonCanonical,
    });
    // Canonical "0" gets past the canonical gate and is stopped only by NUMERIC positivity —
    // this is the exact case a string `<> '0'` DB check would have let through.
    expect(validateOperationAmount("0")).toEqual({
      ok: false,
      reason: AMOUNT_REJECTION_REASONS.notPositive,
    });
  });
});

describe("validators — reason taxonomy for rejections", () => {
  it("maps each failure class to its reason", () => {
    expect(validateOperationAmount("1e5")).toEqual({
      ok: false,
      reason: AMOUNT_REJECTION_REASONS.grammar,
    });
    expect(validateBalanceAmount("2.50")).toEqual({
      ok: false,
      reason: AMOUNT_REJECTION_REASONS.nonCanonical,
    });
    expect(validateBalanceAmount("100000000")).toEqual({
      ok: false,
      reason: AMOUNT_REJECTION_REASONS.grammar, // 9-digit integer never reaches the range check
    });
  });
});
