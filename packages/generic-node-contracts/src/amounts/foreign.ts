import { matchesCanonicalGrammar } from "./grammar.js";
import { assertPrimitiveAmountString } from "./string-boundary.js";

export type ForeignAmountInspection = {
  // The EXACT original bytes, returned verbatim — never canonicalized or round-tripped.
  readonly bytes: string;
  readonly wellFormed: boolean;
  // Reason code when malformed; this is recorded evidence, never a rewrite or an INSERT drop.
  readonly anomaly: string | null;
};

// The byte-exact signing rule carve-out. Canonicalization applies ONLY to node-authored amounts. Every
// foreign signed amount — payer step-1, recipient step-2, an observed on-chain
// step_*_state.amount — is verified over its EXACT original bytes and MUST NOT be reformatted
// or re-serialized. Well-formedness is the structural grammar (NOT canonical-equality) so a
// legitimately non-canonical foreign form such as "2.50" is not falsely flagged; the grammar
// alone guarantees a finite decimal in `0 <= v < 1e8` with <=32 dp. A malformed foreign
// amount is recorded as an anomaly, never rejected in a way that drops evidence.
export function inspectForeignAmount(rawBytes: unknown): ForeignAmountInspection {
  assertPrimitiveAmountString(rawBytes);
  if (!matchesCanonicalGrammar(rawBytes)) {
    return { bytes: rawBytes, wellFormed: false, anomaly: "foreign_amount_grammar_violation" };
  }
  return { bytes: rawBytes, wellFormed: true, anomaly: null };
}
