/**
 * SOURCE: the observation-verification spec (the complete-path ancestry walk, retention,
 * threats), the data model (the head-row body fields), and the complete-path landing-proof rule
 * (canonical). the landing-proof index/walk — the exact-body signature ancestry index.
 *
 * The index consumes the observation concern's frozen `gateway_observations` head rows and re-freezes none of them;
 * the observation concern wins on any conflict. This file freezes the index KEY and ENTRY field shape, and the rule
 * for which observed records are indexable as chain entries.
 */

import { type FieldSpec } from "../observation/record-fields.contract.ts";

/**
 * The ancestry-index KEY. A verified full body is indexed by (wallet public key, step-2 signature).
 * The key is role-relative: one MOVE transaction is indexed under BOTH the sender and the receiver
 * wallet keys as two distinct entries that share the same step-2 signature.
 */
export const ANCESTRY_INDEX_KEY_FIELDS = [
  {
    name: "wallet_public_key",
    type: "padded_base64url_pubkey",
    nullable: false,
    note: "the role-view wallet stream; a MOVE indexes under both the sender and receiver keys",
  },
  {
    name: "step_2_signature",
    type: "padded_base64url_signature",
    nullable: false,
    note: "the completing (second) transaction signature; the body's identity within a wallet role-view",
  },
] as const satisfies readonly FieldSpec[];

/**
 * The ancestry-index ENTRY. It preserves the exact body verbatim, its recomputable digest, and the
 * role-relative predecessor pointer (`p_signature`) plus the current-state signature (`s_signature`)
 * a successor's predecessor resolves to. Genesis is a walk terminal, never an entry, so `wallet_role`
 * here is only sender or receiver.
 */
export const ANCESTRY_INDEX_ENTRY_FIELDS = [
  { name: "wallet_public_key", type: "padded_base64url_pubkey", nullable: false, note: "key part; the role-view wallet stream" },
  { name: "step_2_signature", type: "padded_base64url_signature", nullable: false, note: "key part; the body identity" },
  { name: "wallet_role", type: "wallet_observation_role", nullable: false, note: "sender | receiver; the role-relative view (genesis is a terminal, never an entry)" },
  { name: "completed_transaction_text", type: "text", nullable: false, note: "the EXACT signed body, byte-for-byte as observed; never normalized or reformatted (the byte-exact signing rule)" },
  { name: "completed_transaction_sha256", type: "sha256_hex", nullable: false, note: "SHA-256 of completed_transaction_text; recomputed and byte-compared on ingest" },
  { name: "s_signature", type: "padded_base64url_signature", nullable: false, note: "this role-view's current state signature; the target a successor's predecessor pointer resolves to" },
  { name: "p_signature", type: "text", nullable: false, note: "role-relative PREDECESSOR: the previous state signature; empty string iff the predecessor is genesis (walk root)" },
  { name: "step_1_signature", type: "padded_base64url_signature", nullable: false, note: "the initiating (first) transaction signature" },
  { name: "source_observation_id", type: "uuid", nullable: false, note: "provenance: the gateway_observations row this entry was populated from" },
] as const satisfies readonly FieldSpec[];

/**
 * Which observed records are indexable as full-body chain entries. Only a completely-verified HEAD
 * row carrying a full completed transaction body is a chain entry: genesis is a terminal (it has no
 * completed body), and every non-verified or non-head disposition is never an entry. A record that
 * fails the observation concern's `verifyGatewayObservationRecord` (any invariant violation) is not indexable.
 */
export const INDEXABILITY_RULE = {
  requiredParseResult: "VERIFIED_HEAD",
  requiresEmptyRecordViolations: true,
  requiresCompletedTransactionText: true,
  requiresStepTwoSignature: true,
  genesisIsTerminalNotEntry: true,
  nonVerifiedNeverIndexed: true,
} as const;
