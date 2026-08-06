import { assertPrimitiveAmountString } from "./string-boundary.js";

// Canonical ZKZ decimal-text grammar — frozen contract data under the amounts-grammar
// freeze. This is a purely structural gate: it
// rejects sign, exponent, thousands/decimal separators, leading zeros, a trailing dot,
// `-0`, and more than 32 decimal places. By capping the integer part at eight digits it
// also structurally forbids any value at or above 1e8 (a nine-digit integer never matches),
// so the exclusive upper bound is enforced by the grammar itself, not a separate check.
export const CANONICAL_DECIMAL_PATTERN = "^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$";

// Constructed once. Without the `m` flag `$` matches only end-of-input (never before a
// trailing newline), and `[0-9]` matches ASCII digits only (Unicode digit forms reject).
const CANONICAL_DECIMAL_REGEXP = new RegExp(CANONICAL_DECIMAL_PATTERN);

export function matchesCanonicalGrammar(input: unknown): boolean {
  assertPrimitiveAmountString(input);
  return CANONICAL_DECIMAL_REGEXP.test(input);
}
