import { ZKZ_AMOUNT_CHECK_DOMAINS } from "./manifest.js";
import { type AmountFieldRole } from "./field-roles.js";

// CHECK-domain application map for the DB-domains concern (DB work). Data only — no schema here. Each
// persisted amount role is bound to one of .1's frozen CHECK domains, or to the foreign
// posture. the DB-domains concern attaches the named domain to the column that stores each role. Per the amounts-grammar freeze:
// balance/step/head columns -> zkz_balance_text; operations.amount_zkz + artifact/approval
// amounts -> zkz_amount_positive_text.
export const FOREIGN_NO_REJECT = "foreign_no_reject" as const;

type CheckDomainName = keyof typeof ZKZ_AMOUNT_CHECK_DOMAINS | typeof FOREIGN_NO_REJECT;

export const ZKZ_CHECK_DOMAIN_BY_ROLE = {
  operation_amount_zkz: "zkz_amount_positive_text",
  expected_artifact_amount: "zkz_amount_positive_text",
  approval_amount: "zkz_amount_positive_text",
  node_post_transfer_state: "zkz_balance_text",
  derived_balance: "zkz_balance_text",
  node_head_amount: "zkz_balance_text",
  genesis_amount: "zkz_balance_text",
  // Foreign / observation columns: NO rejecting CHECK — a malformed foreign amount is stored
  // as evidence and flagged as an anomaly, never dropped at INSERT (the amounts-grammar freeze addendum clause 2).
  payer_signed_step_amount: FOREIGN_NO_REJECT,
  recipient_signed_step_amount: FOREIGN_NO_REJECT,
  observed_onchain_step_state: FOREIGN_NO_REJECT,
} as const satisfies Partial<Record<AmountFieldRole, CheckDomainName>>;

// Write-time bound-violation posture on a node-authored positive/balance column. Under the amounts-grammar freeze
// the CHECK domain replaces v1's NUMERIC(40,32) width, so an out-of-domain write now raises
// SQLSTATE 23514 (check_violation), NOT 22003 (numeric overflow, the DB amount-domain enforcement rule). It is routed to an
// operator hold / quarantine — never a crash-loop, and never a resubmit (the never-blind-retry rule).
export const AMOUNT_WRITE_VIOLATION_POLICY = {
  sqlstate: "23514",
  disposition: "operator_hold_quarantine",
  neverCrashLoop: true,
  neverResubmit: true,
} as const;
