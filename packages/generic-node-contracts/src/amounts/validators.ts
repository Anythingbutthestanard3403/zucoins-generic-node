import { matchesCanonicalGrammar } from "./grammar.js";
import {
  emitAmount,
  isNumericallyPositive,
  isWithinBalanceMagnitude,
  isWithinOperationMagnitude,
} from "./emitter.js";
import { AMOUNT_REJECTION_REASONS, type AmountRejectionReason } from "./manifest.js";
import { assertPrimitiveAmountString } from "./string-boundary.js";

export type AmountCheck =
  | { readonly ok: true; readonly canonical: string }
  | { readonly ok: false; readonly reason: AmountRejectionReason };

// Canonical-equality: an input is canonical iff it matches the grammar AND re-emitting its
// parsed value reproduces it byte-for-byte (the amounts-grammar freeze). This is what rejects grammar-legal but
// non-canonical forms such as "2.50", "0.0", or "05" (grammar catches the last).
export function isCanonicalAmount(input: unknown): boolean {
  assertPrimitiveAmountString(input);
  if (!matchesCanonicalGrammar(input)) return false;
  return emitAmount(input) === input;
}

function canonicalFailure(input: string): AmountRejectionReason | null {
  if (!matchesCanonicalGrammar(input)) return AMOUNT_REJECTION_REASONS.grammar;
  if (emitAmount(input) !== input) return AMOUNT_REJECTION_REASONS.nonCanonical;
  return null;
}

// Balance / post-state / head amount (0 <= amount < 1e8). Zero is legitimate here.
export function validateBalanceAmount(input: unknown): AmountCheck {
  assertPrimitiveAmountString(input);
  const failure = canonicalFailure(input);
  if (failure) return { ok: false, reason: failure };
  if (!isWithinBalanceMagnitude(input)) {
    return { ok: false, reason: AMOUNT_REJECTION_REASONS.outOfRange };
  }
  return { ok: true, canonical: input };
}

// Operation / expected-artifact / approval amount (0 < amount < 1e8). Zero is rejected as a
// NUMERIC predicate, so canonical "0" and non-canonical zero forms both fail as not-positive.
export function validateOperationAmount(input: unknown): AmountCheck {
  assertPrimitiveAmountString(input);
  const failure = canonicalFailure(input);
  if (failure) return { ok: false, reason: failure };
  if (!isNumericallyPositive(input)) {
    return { ok: false, reason: AMOUNT_REJECTION_REASONS.notPositive };
  }
  if (!isWithinOperationMagnitude(input)) {
    return { ok: false, reason: AMOUNT_REJECTION_REASONS.outOfRange };
  }
  return { ok: true, canonical: input };
}
