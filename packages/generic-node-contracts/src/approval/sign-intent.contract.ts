/**
 * The sign-intent formation CONTRACT_FREEZE (approval-tuple freeze; two-timer
 * separation). This freezes the state machine that turns ONE consumed approval into
 * AT MOST ONE persisted sign intent, ONE deterministic step-1 signature, and ONE persisted
 * partial. It fixes: the formation-state sequence and its guarded transitions; the inputs a sign
 * intent binds before the signer runs; the immutability of those bytes once the intent exists;
 * approval consumption with burn-on-failure; redelivery restricted to the identical persisted
 * bytes; and that expiry or any changed signed byte forces a NEW operation under a FRESH approval,
 * never a second partial under the old one. DATA ONLY; the pure decision functions live in
 * `verify.ts` and `crash-recovery.contract.ts`.
 */

import { APPROVAL_PURPOSE } from "./approval-tuple.contract.ts";

/**
 * Frozen formation-state sequence. `APPROVED_UNSIGNED` is the post-approval entry;
 * `SIGNING_CLAIMED` is reached by compare-and-swap only after the sign intent is persisted;
 * `PARTIAL_PERSISTED` follows the deterministic signature + code commit; delivery makes the code
 * externally observable and moves to `PARTIAL_DELIVERED` / `AWAITING_REDEMPTION`.
 */
export const FORMATION_STATES = [
  "APPROVED_UNSIGNED",
  "SIGNING_CLAIMED",
  "PARTIAL_PERSISTED",
  "PARTIAL_DELIVERED",
  "AWAITING_REDEMPTION",
] as const;
export type FormationState = (typeof FORMATION_STATES)[number];

/**
 * The single legal forward path. Each transition names the guard that MUST hold. There
 * is exactly one successor per state: linearity freezes phase sequencing. The no-second-partial
 * guarantee is NOT a consequence of linearity itself — it is carried by the structural fences:
 * the `APPROVAL_CONSUMED_NO_SIGN_INTENT` guard fact and `INVARIANT_BREACH_PREDICATE`
 * (`crash-recovery.contract.ts`), `STRUCTURAL_UNIQUENESS`'s per-`operation_id` uniqueness above,
 * and the compare-and-swap transition guard on `persist_sign_intent_before_signer`/
 * `persist_partial_before_delivery`. Those fences are what make same-preimage recovery (never
 * re-formation) the only option, not the mere absence of a fork in this table.
 */
export const FORMATION_TRANSITIONS = [
  { from: "APPROVED_UNSIGNED", to: "SIGNING_CLAIMED", guard: "persist_sign_intent_before_signer_then_compare_and_swap" },
  { from: "SIGNING_CLAIMED", to: "PARTIAL_PERSISTED", guard: "sign_exact_persisted_preimage_then_persist_partial_before_delivery" },
  { from: "PARTIAL_PERSISTED", to: "PARTIAL_DELIVERED", guard: "make_persisted_code_externally_observable" },
  { from: "PARTIAL_DELIVERED", to: "AWAITING_REDEMPTION", guard: "await_external_cosign_and_settlement_observation" },
] as const;

/**
 * The one-approval cardinality invariant. One consumed approval maps to
 * AT MOST ONE of each downstream artifact. `maxPerApproval: 1` everywhere — never a second.
 */
export const APPROVAL_CARDINALITY = {
  signIntent: { maxPerApproval: 1 },
  stepOneSignature: { maxPerApproval: 1 },
  persistedPartial: { maxPerApproval: 1 },
  externallyObservableCode: { maxPerApproval: 1 },
} as const;

/**
 * The exact inputs a sign intent binds and persists BEFORE the signer runs.
 * These are captured once, from fresh accepted observations at a specific lease epoch, and then
 * frozen. `inner_preimage_text` is the exact bytes the signer signs; nothing rebuilds it later.
 */
export const SIGN_INTENT_BOUND_INPUTS = [
  "consumed_approval_id",
  "source_observation_id",
  "destination_observation_id",
  "lease_group",
  "lease_epoch",
  "inner_preimage_text",
  "inner_digest",
] as const;
export type SignIntentBoundInput = (typeof SIGN_INTENT_BOUND_INPUTS)[number];

/**
 * Immutability rule. Once a sign intent exists, none of its bound bytes —
 * the chain link, the time, the expiry, the destination, the amount, or any other signed byte —
 * may be re-formed. Recovery revalidates and completes the SAME preimage; it never mints a new
 * one. These are exactly the fields frozen once the intent exists.
 */
export const SIGN_INTENT_FROZEN_AFTER_EXISTS = [
  "inner_preimage_text",
  "inner_digest",
  "chain_link",
  "redemption_time",
  "redemption_expiry",
  "destination_address",
  "amount_zkz",
] as const;

/**
 * Approval consumption + burn-on-failure. The mandatory fresh
 * TOTP is consumed (its `(node_id,timestep)` reserved globally single-use) BEFORE the mutation,
 * and is NEVER restored if signing, persistence, or delivery later fails — a burnt approval is
 * spent, forcing a fresh approval for any retry. There is no restoration after downstream failure.
 */
export const APPROVAL_CONSUMPTION = {
  consumedBeforeMutation: true,
  burnOnSignerFailure: true,
  burnOnPersistenceFailure: true,
  burnOnDeliveryFailure: true,
  burnOnGatewayFailure: true,
  restoredAfterDownstreamFailure: false,
} as const;

/**
 * Redelivery rule. After a partial is persisted, recovery may
 * only re-emit the IDENTICAL persisted bytes — it never re-signs, re-forms, or mints a variant.
 */
export const REDELIVERY_RULE = "byte_identical_persisted_partial_only" as const;

/**
 * Replacement rule. Expiry, or a change to any signed economic or
 * chain byte, requires SAFE RESOLUTION of the existing operation and then a NEW operation carrying
 * a FRESH approval (and a fresh TOTP, and a fresh device signature where configured). It NEVER
 * permits a second partial under the old approval, and the old approval's expiry is never refreshed.
 */
export const REPLACEMENT_RULE = {
  triggeredBy: ["expiry", "changed_chain_link", "changed_time", "changed_expiry", "changed_destination", "changed_amount", "changed_signed_byte"],
  requires: ["safe_resolution_of_existing_operation", "new_operation", "fresh_approval"],
  permitsSecondPartialUnderOldApproval: false,
  refreshesExpiryUnderOldApproval: false,
} as const;

/**
 * Two-timer separation. Two DISTINCT time bounds exist and are never
 * conflated:
 *  - T1 approval-challenge freshness = the approval tuple's `expires_at` (A.4.1). Refreshable
 *    while the operation is still in the approval-challenge (pre-consumption) phase, FROZEN at
 *    consumption; it is a pre-formation gate on the challenge, never the redemption deadline, and
 *    is never surfaced or signed as one.
 *  - T2 redemption expiry = the signed SplitChain inner's expiry, materialized ONCE at sign-intent
 *    formation and byte-frozen thereafter (no re-form of time/expiry after the sign intent
 *    exists). It is the single immutable redemption deadline; the approval `expires_at`
 *    is not it.
 */
export const TIMER_SEPARATION = {
  t1ApprovalChallengeFreshness: {
    source: "approval_tuple.expires_at",
    refreshableWhilePreConsumption: true,
    frozenAtConsumption: true,
    isRedemptionDeadline: false,
  },
  t2RedemptionExpiry: {
    source: "signed_splitchain_inner.expiry",
    materializedAt: "sign_intent_formation",
    byteFrozenAfterFormation: true,
    isSingleImmutableRedemptionDeadline: true,
  },
} as const;

/** The approval purpose this state machine consumes, re-exported for one-import ergonomics. */
export const CONSUMED_APPROVAL_PURPOSE = APPROVAL_PURPOSE;

/**
 * Structural uniqueness + lease-epoch preservation. Contract-level facts only —
 * NO DDL; the CONTRACT_FREEZE gate forbids a schema/DB
 * seam here. A sign intent is unique per `operation_id`, NOT per `lease_epoch`: a lease can be
 * re-acquired at a new epoch across a crash without that ever authorizing a second sign intent
 * for the same operation. A step-1 partial is unique per `operation_id` for the identical reason.
 * Recovery always completes the SAME in-flight formation under the `lease_epoch` originally bound
 * at sign-intent formation (`SIGN_INTENT_BOUND_INPUTS.lease_epoch`), never a re-minted epoch. Boot
 * reconciliation (lease epoch is monotonic; boot never re-forms an external partial)
 * adopts whatever lease it finds for an in-flight formation at that lease's existing epoch; it
 * never mints a fresh epoch underneath one.
 */
export const STRUCTURAL_UNIQUENESS = {
  signIntentUniqueBy: "operation_id",
  stepOnePartialUniqueBy: "operation_id",
  uniquePerLeaseEpoch: false,
  recoveryCompletesUnderOriginallyBoundLeaseEpoch: true,
  bootReconciliationMintsNewEpochForInFlightFormation: false,
  bootReconciliationAdoptsExistingLeaseAtExistingEpoch: true,
} as const;

export const SOURCE = "sign-intent formation state machine; approval-tuple freeze; two-timer separation" as const;
