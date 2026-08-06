import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { CANONICAL_DECIMAL_PATTERN } from "./grammar.js";

// Reason taxonomy for a rejected node-authored amount. Frozen here as a stable vocabulary
// the amounts API/DB enforcement builds its single typed API/DB error contract on; this
// module does not mint that API error envelope.
export const AMOUNT_REJECTION_REASONS = {
  grammar: "amount_grammar_violation",
  nonCanonical: "amount_not_canonical",
  notPositive: "amount_not_positive",
  outOfRange: "amount_out_of_range",
} as const;

export type AmountRejectionReason =
  (typeof AMOUNT_REJECTION_REASONS)[keyof typeof AMOUNT_REJECTION_REASONS];

// The two DB CHECK-domain predicates for the DB-domains concern (DB work), recorded here as SQL text DATA
// only — no schema is created here. `zkz_amount_positive_text` uses NUMERIC
// positivity (`VALUE::numeric > 0`), NOT the string form `VALUE <> '0'`:
// `'0.0'`, `'0.00'`, `'0.' + 32 zeros` match the regex and are `<> '0'`
// as strings while being mathematically zero.
export const ZKZ_AMOUNT_CHECK_DOMAINS = {
  zkz_balance_text: "VALUE ~ '^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$'",
  zkz_amount_positive_text:
    "VALUE ~ '^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$' AND VALUE::numeric > 0",
} as const;

export const amountsContract = {
  upperBoundExclusive: "100000000",
  greatestLegalValue: "99999999.99999999999999999999999999999999",
  maxDecimalPlaces: 32,
  rounding: "ROUND_DOWN",
  exponentialAt: [-33, 33],
  canonicalDecimalPattern: CANONICAL_DECIMAL_PATTERN,
  layers: {
    balance: {
      lowerBound: "0",
      lowerBoundInclusive: true,
      upperBoundExclusive: "100000000",
    },
    operation: {
      lowerBound: "0",
      lowerBoundInclusive: false,
      upperBoundExclusive: "100000000",
    },
  },
  dbCheckDomains: ZKZ_AMOUNT_CHECK_DOMAINS,
  rejectionReasons: AMOUNT_REJECTION_REASONS,
} as const;

// Provisional concern manifest — the operations census owns the shared ConcernManifest type; this
// conforms to that shape (concern id + frozen contract) and is superseded on merge.
export const amountsConcernManifest = {
  concern: "amounts",
  frozenBy: "zkz-amount-grammar",
  contract: amountsContract,
} as const;

/**
 * the amounts scalar/arithmetic's self-registered ConcernManifest. Wraps `amountsContract`
 * byte-identically under the canonical shape; `amountsConcernManifest` above is the
 * provisional form it supersedes. Registration export only — the concern-manifest registry
 * assembles `src/registry.ts`.
 */
export const AMOUNTS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "amounts",
  decisionRefs: [
    "zkz-amount-grammar",
    "amount-bounds-authority-split",
    "amount-column-precision-widening",
  ],
  frozenValues: { amountsContract },
  goldenRefs: [{ path: "gen/amounts.json", sha256: "c5acaa06b6e55e0cb3ec08ad6fe9c54d243ac36dc89ebbe5dfd5a71e1d9ea32e" }],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "zkz-amount-grammar: canonical ZKZ decimal-text grammar, exclusive < 1e8 bound, 32 dp, ROUND_DOWN",
    "amount-bounds-authority-split: protocol bound 0 <= amount < 1e8 enforced at the protocol layer only",
    "amount-column-precision-widening: ledger amount columns carry numeric(40,32) matching the protocol bound",
  ],
});
