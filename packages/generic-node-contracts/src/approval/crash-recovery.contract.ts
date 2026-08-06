/**
 * The approval crash-recovery CONTRACT_FREEZE (approval-tuple freeze; crash matrix,
 * threat controls, mandatory tests). This freezes the crash/replay decision table as data: for
 * every durable state a process can die in, the single allowed recovery action and the single
 * forbidden action. Recovery may only FINISH the identical persisted formation or RE-EMIT the
 * identical persisted bytes; no crash path may create a second sign intent or a second partial.
 * DATA ONLY; the `recoveryActionFor` lookup is a pure function in `verify.ts`.
 */

/**
 * The durable states a crash can leave behind, in the exact sequence of the frozen crash table.
 * The sequence walks the formation timeline from pre-consumption to a terminal expired partial.
 */
export const CRASH_DURABLE_STATES = [
  "APPROVAL_PENDING_NO_SIGN_INTENT",
  "APPROVAL_CONSUMED_NO_SIGN_INTENT",
  "SIGNING_CLAIMED_NO_PARTIAL",
  "PARTIAL_COMMITTED_UNDELIVERED",
  "PARTIAL_DELIVERED_HEAD_UNCHANGED",
  "PARTIAL_DELIVERED_EXPECTED_AT_HEAD",
  "PARTIAL_DELIVERED_HEAD_ANOMALOUS",
  "PARTIAL_EXPIRED",
] as const;
export type CrashDurableState = (typeof CRASH_DURABLE_STATES)[number];

/** Closed set of allowed recovery actions (the crash table's middle column). */
export const RECOVERY_ACTIONS = [
  "AWAIT_APPROVAL_OR_REJECT_SAFELY",
  "ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT",
  "REVALIDATE_SAME_PREIMAGE_COMPLETE_FIRST_FORMATION",
  "DELIVER_EXACT_PERSISTED_CODE",
  "REDELIVER_EXACT_PERSISTED_CODE",
  "MARK_LANDED_FROM_VERIFIED_OBSERVATION",
  "NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE",
  "TERMINALIZE_ON_POSITIVE_EXPIRY_OR_NON_LANDING",
] as const;
export type RecoveryAction = (typeof RECOVERY_ACTIONS)[number];

/** Closed set of forbidden actions (the crash table's right column). */
export const FORBIDDEN_RECOVERY_ACTIONS = [
  "ACQUIRE_OR_SIGN",
  "CREATE_SECOND_SIGN_INTENT",
  "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
  "RE_SIGN_OR_RE_FORM",
  "MINT_REPLACEMENT_PARTIAL",
  "SUBMIT_OR_DELIVER_NEW_CODE",
  "INFER_NON_LANDING_OR_RETRY",
  "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
] as const;
export type ForbiddenRecoveryAction = (typeof FORBIDDEN_RECOVERY_ACTIONS)[number];

export interface CrashMatrixRow {
  readonly durableState: CrashDurableState;
  readonly recovery: RecoveryAction;
  readonly forbidden: ForbiddenRecoveryAction;
  readonly note: string;
}

/**
 * The frozen crash matrix — one row per durable state, in table sequence. Each row's
 * `recovery` is the ONLY permitted action and `forbidden` is the named counter-action that would
 * violate one approval → one partial.
 */
export const CRASH_MATRIX = [
  {
    durableState: "APPROVAL_PENDING_NO_SIGN_INTENT",
    recovery: "AWAIT_APPROVAL_OR_REJECT_SAFELY",
    forbidden: "ACQUIRE_OR_SIGN",
    note: "no approval consumed yet; keep awaiting the guarded mutation or reject safely",
  },
  {
    durableState: "APPROVAL_CONSUMED_NO_SIGN_INTENT",
    recovery: "ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT",
    forbidden: "CREATE_SECOND_SIGN_INTENT",
    note: "acquire the source lease, read fresh source/destination, persist the first sign intent only",
  },
  {
    durableState: "SIGNING_CLAIMED_NO_PARTIAL",
    recovery: "REVALIDATE_SAME_PREIMAGE_COMPLETE_FIRST_FORMATION",
    forbidden: "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
    note: "prove no delivery path ran, revalidate the same preimage/head, complete the first persisted formation",
  },
  {
    durableState: "PARTIAL_COMMITTED_UNDELIVERED",
    recovery: "DELIVER_EXACT_PERSISTED_CODE",
    forbidden: "RE_SIGN_OR_RE_FORM",
    note: "a partial is committed but was never delivered; deliver the exact persisted code",
  },
  {
    durableState: "PARTIAL_DELIVERED_HEAD_UNCHANGED",
    recovery: "REDELIVER_EXACT_PERSISTED_CODE",
    forbidden: "MINT_REPLACEMENT_PARTIAL",
    note: "delivered and the source head is unchanged; redeliver the exact persisted code only under delivery policy",
  },
  {
    durableState: "PARTIAL_DELIVERED_EXPECTED_AT_HEAD",
    recovery: "MARK_LANDED_FROM_VERIFIED_OBSERVATION",
    forbidden: "SUBMIT_OR_DELIVER_NEW_CODE",
    note: "the expected transaction is at the head; mark landed from the verified observation",
  },
  {
    durableState: "PARTIAL_DELIVERED_HEAD_ANOMALOUS",
    recovery: "NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE",
    forbidden: "INFER_NON_LANDING_OR_RETRY",
    note: "unrelated/regressed/unverifiable head; escalate to needs-attention and preserve the lease and evidence",
  },
  {
    durableState: "PARTIAL_EXPIRED",
    recovery: "TERMINALIZE_ON_POSITIVE_EXPIRY_OR_NON_LANDING",
    forbidden: "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
    note: "terminalize the operation under positive expiry/non-landing rules; a replacement is a new operation with a fresh approval",
  },
] as const satisfies readonly CrashMatrixRow[];

/**
 * The four crash points, each mapped to the durable states it can
 * leave behind. This is the frozen bridge between "where a process died" and the matrix rows.
 */
export const CRASH_POINTS = [
  { point: "BEFORE_SIGN_INTENT_PERSIST", states: ["APPROVAL_PENDING_NO_SIGN_INTENT", "APPROVAL_CONSUMED_NO_SIGN_INTENT"] },
  { point: "AFTER_SIGN_INTENT_BEFORE_SIGN", states: ["SIGNING_CLAIMED_NO_PARTIAL"] },
  { point: "AFTER_SIGN_BEFORE_DELIVERY", states: ["PARTIAL_COMMITTED_UNDELIVERED"] },
  {
    point: "AFTER_DELIVERY",
    states: [
      "PARTIAL_DELIVERED_HEAD_UNCHANGED",
      "PARTIAL_DELIVERED_EXPECTED_AT_HEAD",
      "PARTIAL_DELIVERED_HEAD_ANOMALOUS",
      "PARTIAL_EXPIRED",
    ],
  },
] as const;
export type CrashPoint = (typeof CRASH_POINTS)[number]["point"];

/**
 * Before a durable sign intent exists, first formation may start only after confirming the signer
 * was never called; if the exact preimage or phase boundary is unavailable or contradictory, the
 * outcome is NEEDS_ATTENTION. Recovery classification is a six-member closed set —
 * `LANDED_VERIFIED`, `PROVEN_NOT_STARTED`, `PROVEN_NOT_LANDED`, `WAITING`, `INDETERMINATE`,
 * `INVARIANT_BREACH`. If the database says the sign intent is absent but signer audit indicates a
 * call, or any expected exact preimage is unavailable, classification is INVARIANT_BREACH, not
 * PROVEN_NOT_STARTED.
 *
 * `INVARIANT_BREACH` is one of the six top-level recovery classifications — a DIFFERENT axis
 * from the `CRASH_DURABLE_STATES` table above, which stays the verbatim eight-member crash
 * table and is never extended. This is the frozen predicate that reclassifies the
 * `APPROVAL_CONSUMED_NO_SIGN_INTENT` durable state (and, symmetrically, any durable state whose
 * persisted preimage record is unavailable or contradictory) away from its ordinary table
 * recovery action and onto `NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE`. Once breached: never first
 * formation, never re-sign, never lease release.
 */
export const INVARIANT_BREACH_PREDICATE = {
  classification: "INVARIANT_BREACH",
  action: "NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE",
  triggeredBy: [
    "no_persisted_sign_intent_row_but_signer_audit_shows_a_signing_call",
    "persisted_preimage_record_unavailable_or_contradictory",
  ],
  permitsFirstFormation: false,
  permitsReSign: false,
  permitsLeaseRelease: false,
} as const;

/**
 * Guard fact for the `APPROVAL_CONSUMED_NO_SIGN_INTENT` row: first formation
 * is permitted ONLY after recovery proves the signer was never called for this operation. When
 * that proof fails — a signer-audit call exists with no persisted sign-intent row, or the
 * persisted preimage record is unavailable/contradictory — this row's ordinary recovery action
 * (`ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT`) is replaced by `INVARIANT_BREACH_PREDICATE`.
 */
export const APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD = {
  row: "APPROVAL_CONSUMED_NO_SIGN_INTENT",
  guard: "first_formation_permitted_only_after_proving_signer_never_called",
} as const;

/**
 * Signer determinism — a REQUIREMENT the step-1 signer must satisfy (RFC 8032), not
 * merely an observed fact about Ed25519. The step-1 signer MUST be pure deterministic Ed25519 per
 * RFC 8032: the signature is a pure function of the private key and the exact message bytes, with
 * no per-call randomness. A hedged or randomized Ed25519 variant is FORBIDDEN on this path; using
 * one is a violation that MUST fail closed — never silently accepted, never treated as
 * byte-compatible with the deterministic scheme this concern freezes.
 *
 * This requirement is what makes same-preimage recovery possible: because signing is deterministic
 * for a fixed key and message, a crash after computing the signature but before persistence
 * recovers by re-signing the SAME frozen preimage and obtaining the SAME signature — completion of
 * the first durable formation, never authorization to create a new partial.
 *
 * Frozen fact: the recovery re-sign branch byte-compares its freshly computed signature against
 * any PRIOR signer-audit signature for the same operation BEFORE delivery. A mismatch — which can
 * only arise from a requirement violation above (a non-deterministic signer, a different key, or
 * different signed bytes) — is `INVARIANT_BREACH_PREDICATE`'s classification; a mismatched
 * signature is never delivered.
 */
export const DETERMINISTIC_RESIGN = {
  stepOneSignerMustBeDeterministicEd25519Rfc8032: true,
  hedgedOrRandomizedEd25519Forbidden: true,
  signerRequirementViolationFailsClosed: true,
  ed25519DeterministicForFixedKeyAndMessage: true,
  recoveryReSignsSamePreimage: true,
  recoveryYieldsSameSignature: true,
  isCompletionNotNewAuthorization: true,
  recoveryByteComparesAgainstPriorSignerAuditSignatureBeforeDelivery: true,
  mismatchClassification: INVARIANT_BREACH_PREDICATE.classification,
} as const;

export const SOURCE = "crash/replay decision table; recovery classification closed set; approval-tuple freeze" as const;
