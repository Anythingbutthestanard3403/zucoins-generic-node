import { BigNumber } from "bignumber.js";
import { assertPrimitiveAmountString } from "./string-boundary.js";

// The only module in this concern that touches bignumber.js. All byte-authority arithmetic
// and every numeric predicate are confined here so the rest of the contract stays a pure,
// dependency-free structural surface.
//
// Isolated, pinned clone — never global BigNumber.config — so a distant caller's config can
// never mutate rounding out from under signed emission. Byte-parity with
// packages/splitchain/src/amount.ts (`Amount`): DECIMAL_PLACES 32, ROUND_DOWN,
// EXPONENTIAL_AT [-33, 33]. Kept module-private (stricter than splitchain, which exports its
// clone) so no downstream caller can reach `.config()`; the pure functions below are the
// entire surface.
const Amount = BigNumber.clone({
  DECIMAL_PLACES: 32,
  ROUNDING_MODE: BigNumber.ROUND_DOWN,
  EXPONENTIAL_AT: [-33, 33],
});

const ZERO = new Amount("0");
const UPPER_BOUND_EXCLUSIVE = new Amount("100000000");
const MAX_DECIMAL_PLACES = 32;

// Canonical wire emission: `.toFixed()` with NO argument. `.toFixed(dp)` zero-pads and
// `.toString()` / template coercion can emit exponent notation — both are byte defects on
// the signed money path, so this is the single sanctioned emitter.
export function emitAmount(value: string): string {
  assertPrimitiveAmountString(value);
  return new Amount(value).toFixed();
}

export function addAmounts(a: string, b: string): string {
  assertPrimitiveAmountString(a);
  assertPrimitiveAmountString(b);
  return new Amount(a).plus(b).toFixed();
}

export function subtractAmounts(a: string, b: string): string {
  assertPrimitiveAmountString(a);
  assertPrimitiveAmountString(b);
  return new Amount(a).minus(b).toFixed();
}

export function compareAmounts(a: string, b: string): -1 | 0 | 1 {
  assertPrimitiveAmountString(a);
  assertPrimitiveAmountString(b);
  const result = new Amount(a).comparedTo(b);
  if (result === null) {
    throw new Error("compareAmounts received a non-numeric operand");
  }
  if (result < 0) return -1;
  if (result > 0) return 1;
  return 0;
}

export function isFiniteAmount(input: unknown): boolean {
  assertPrimitiveAmountString(input);
  return new Amount(input).isFinite();
}

export function numericDecimalPlaces(input: unknown): number | null {
  assertPrimitiveAmountString(input);
  return new Amount(input).decimalPlaces();
}

// Positivity is a NUMERIC predicate, never a string comparison:
// `'0.0'`, `'0.00'`, and `'0.' + 32 zeros` are mathematically zero and must be
// rejected here even though a string `<> '0'` test would pass them.
export function isNumericallyPositive(input: unknown): boolean {
  assertPrimitiveAmountString(input);
  const v = new Amount(input);
  return v.isFinite() && v.gt(ZERO);
}

// Balance / post-state / head magnitude: `0 <= amount < 1e8`, <=32 dp. A swept-payer
// balance, genesis, and a landed payer partial are legitimately "0" (the balance-layer boundary).
export function isWithinBalanceMagnitude(input: unknown): boolean {
  assertPrimitiveAmountString(input);
  const v = new Amount(input);
  if (!v.isFinite()) return false;
  const dp = v.decimalPlaces();
  if (dp === null || dp > MAX_DECIMAL_PLACES) return false;
  return v.gte(ZERO) && v.lt(UPPER_BOUND_EXCLUSIVE);
}

// Operation / expected-artifact / approval magnitude: `0 < amount < 1e8`, <=32 dp
// (strictly positive — the stricter-of-two layer).
export function isWithinOperationMagnitude(input: unknown): boolean {
  assertPrimitiveAmountString(input);
  const v = new Amount(input);
  if (!v.isFinite()) return false;
  const dp = v.decimalPlaces();
  if (dp === null || dp > MAX_DECIMAL_PLACES) return false;
  return v.gt(ZERO) && v.lt(UPPER_BOUND_EXCLUSIVE);
}
