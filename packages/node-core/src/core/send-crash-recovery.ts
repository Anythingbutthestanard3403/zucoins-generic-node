// SEND_EXTERNAL exact redelivery + formation crash recovery.
// Exact partial only: no rebuild, no second sign intent, no fresh transfer code.
//
// This module produces no new signed-byte surface. It classifies recovery at the durable
// formation boundaries left by and serves only identical persisted transfer-
// code bytes. It never submits (the never-blind-retry rule — the node never submits SEND_EXTERNAL),
// never rebuilds an inner, never refreshes a chain link or expiry, and never mints a second
// sign intent or partial under the same approval.
//
// Boundary: core → protocol|data|gateway|verifier only. Composition root wires ports to
// claim-and-observe / form-and-sign / material-store. This file imports neither send/ nor any
// submit surface.

import type { SqlQueryFn } from "./sql-query-fn.js";
import {
  recordInMemoryPartialDelivery,
  type InMemoryFormAndSignState,
} from "./send-form-and-sign.js";
import { recordPartialDelivery } from "./transaction-material-store.js";
import { hashTransferCodeText } from "../protocol/send-transfer-code.js";

// ── Closed vocabularies ───────────────────────────────────────────────────────

/** Recovery actions this classifier may emit. */
export const SEND_CRASH_RECOVERY_ACTIONS = [
  "AWAIT_APPROVAL_OR_REJECT_SAFE",
  "ACQUIRE_LEASE_AND_FIRST_FORMATION",
  "FIRST_FORMATION_FROM_HELD_LEASE",
  "SIGN_IDENTICAL_PERSISTED_PREIMAGE",
  "RESTORE_AWAITING_REDEMPTION_AND_DELIVER_EXACT",
  "REDELIVER_EXACT_PERSISTED_CODE",
  "MARK_LANDED_FROM_VERIFIED_OBSERVATION",
  "NEEDS_ATTENTION_PRESERVE_LEASE",
  "TERMINALIZE_UNDER_POSITIVE_EXPIRY_NON_LANDING",
  "INVARIANT_BREACH",
] as const;
export type SendCrashRecoveryActionKind =
  (typeof SEND_CRASH_RECOVERY_ACTIONS)[number];

/**
 * Forbidden actions named by the crash matrix. Every classification returns the set of
 * forbidden actions that MUST NOT fire for that row — tests assert both the recovery action
 * and the absence of each forbidden action (not merely "no error").
 */
export const SEND_CRASH_FORBIDDEN_ACTIONS = [
  "ACQUIRE_OR_SIGN",
  "CREATE_SECOND_SIGN_INTENT",
  "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
  "RESIGN_OR_REFORM",
  "MINT_REPLACEMENT_PARTIAL",
  "SUBMIT_OR_DELIVER_NEW_CODE",
  "INFER_NON_LANDING_OR_RETRY",
  "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
  "BLIND_SUBMIT",
  "SILENT_REFORM_WHEN_AUDIT_CONTRADICTS",
] as const;
export type SendCrashForbiddenAction =
  (typeof SEND_CRASH_FORBIDDEN_ACTIONS)[number];

/** Operator recovery action — not the expiry-driven CLOSE. */
export const CLOSE_NEVER_STARTED_EXTERNAL_SEND =
  "CLOSE_NEVER_STARTED_EXTERNAL_SEND" as const;

// ── Evidence ──────────────────────────────────────────────────────────────────

/**
 * Durable formation evidence for recovery classification. All fields are facts already
 * committed (or proven absent) — never inferred from gateway silence alone.
 */
export interface SendFormationCrashEvidence {
  readonly operationId: string;
  readonly sourceWalletId: string;
  /** Public status: CREATED | APPROVED | AWAITING_REDEMPTION | NEEDS_ATTENTION | … */
  readonly status: string;
  /** Formation CAS cell when status is still pre-partial (APPROVED_*). */
  readonly formationState: string | null;
  readonly sourceLeaseHeld: boolean;
  readonly signIntentPersisted: boolean;
  /** True when inner_preimage_text is readable for the durable sign-intent row. */
  readonly exactPreimageAvailable: boolean;
  readonly step1SignaturePersisted: boolean;
  readonly partialPersisted: boolean;
  readonly partialFirstDelivered: boolean;
  readonly signerAuditIndicatesCall: boolean;
  /** Present only when a partial row is durable — the exact SHA-256 of transfer_code_text. */
  readonly transferCodeSha256: string | null;
  /**
   * Post-delivery observation class used by crash-matrix rows 5–8. Absent for pre-delivery
   * classification. Landing verification itself is; this classifier only names the
   * recovery action and forbids the forbidden ones.
   */
  readonly postDeliveryObservation?:
    | "SOURCE_HEAD_UNCHANGED"
    | "EXPECTED_TX_AT_HEAD"
    | "UNRELATED_OR_REGRESSED_OR_UNVERIFIABLE"
    | "PARTIAL_EXPIRED_PENDING_NON_LANDING";
}

export interface SendCrashRecoveryClassification {
  readonly action: SendCrashRecoveryActionKind;
  /** Crash-matrix forbidden column — every entry must remain unexercised by recovery. */
  readonly forbidden: readonly SendCrashForbiddenAction[];
  readonly operationId: string;
  readonly sourceWalletId: string;
  /** Present on EXACT redelivery / deliver rows — identity of the only legal bytes. */
  readonly transferCodeSha256: string | null;
  /** True when the operator must be paged (INVARIANT_BREACH). */
  readonly pageOperator: boolean;
  /** Human-readable reason for breach / attention (stable for tests + audit). */
  readonly reason: string | null;
}

// ── Recovery / crash-matrix classifier ───────────────────────────────────────────

const FORBIDDEN_ALWAYS_NO_SUBMIT: readonly SendCrashForbiddenAction[] = [
  "BLIND_SUBMIT",
  "SUBMIT_OR_DELIVER_NEW_CODE",
];

/**
 * Classify recovery for one SEND_EXTERNAL operation from durable evidence.
 *
 * Ordering is deliberate and fail-closed:
 * 1. INVARIANT_BREACH when DB says no intent but signer audit says called.
 * 2. Partial-row evidence first (exact redelivery / post-partial). Preimage is NOT
 * required once a partial is durable (recovery row 4 / step 5).
 * Contradictory partial flags (no step1, no intent) breach — never SIGN_IDENTICAL.
 * 3. Missing exact preimage only on the pre-partial SIGN_IDENTICAL path.
 * 4. Crash-matrix row 1 — approval still pending.
 * 5. The four formation boundaries (with lease held vs not).
 * 6. Crash-matrix post-partial rows (deliver / redeliver / landed / attention / expiry).
 */
export function classifySendCrashRecovery(
  evidence: SendFormationCrashEvidence,
): SendCrashRecoveryClassification {
  const base = {
    operationId: evidence.operationId,
    sourceWalletId: evidence.sourceWalletId,
    transferCodeSha256: evidence.transferCodeSha256,
  };

  // ── Degenerate: signer audit without durable intent ──
  if (!evidence.signIntentPersisted && evidence.signerAuditIndicatesCall) {
    return {
      ...base,
      action: "INVARIANT_BREACH",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "SILENT_REFORM_WHEN_AUDIT_CONTRADICTS",
        "ACQUIRE_OR_SIGN",
        "CREATE_SECOND_SIGN_INTENT",
        "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
      ],
      pageOperator: true,
      reason: "SIGNER_AUDIT_WITHOUT_SIGN_INTENT",
    };
  }

  // ── Partial evidence first (never fall through to SIGN_IDENTICAL) ──
  // Partial without sign intent cannot arise under the contract.
  if (evidence.partialPersisted && !evidence.signIntentPersisted) {
    return {
      ...base,
      action: "INVARIANT_BREACH",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "SILENT_REFORM_WHEN_AUDIT_CONTRADICTS",
        "MINT_REPLACEMENT_PARTIAL",
        "RESIGN_OR_REFORM",
      ],
      pageOperator: true,
      reason: "PARTIAL_WITHOUT_SIGN_INTENT",
    };
  }

  // Partial row without step-1 flag is contradictory (step_1_signature NOT NULL on
  // partial). Never re-enter SIGN_IDENTICAL when any partial exists.
  if (evidence.partialPersisted && !evidence.step1SignaturePersisted) {
    return {
      ...base,
      action: "INVARIANT_BREACH",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "SILENT_REFORM_WHEN_AUDIT_CONTRADICTS",
        "MINT_REPLACEMENT_PARTIAL",
        "RESIGN_OR_REFORM",
        "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
        "CREATE_SECOND_SIGN_INTENT",
      ],
      pageOperator: true,
      reason: "PARTIAL_WITHOUT_STEP1_FLAG",
    };
  }

  // ── Signature/partial durable (recovery row 4 + crash-matrix rows 4–8) ──
  // Preimage availability is irrelevant once the partial commits — redeliver identical bytes.
  if (evidence.partialPersisted && evidence.step1SignaturePersisted) {
    return classifyPostPartialRecovery(evidence, base);
  }

  // ── Pre-partial: missing expected preimage blocks SIGN_IDENTICAL only ──
  if (
    evidence.signIntentPersisted &&
    !evidence.exactPreimageAvailable &&
    !evidence.partialPersisted
  ) {
    return {
      ...base,
      action: "INVARIANT_BREACH",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "SILENT_REFORM_WHEN_AUDIT_CONTRADICTS",
        "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
        "RESIGN_OR_REFORM",
      ],
      pageOperator: true,
      reason: "EXPECTED_EXACT_PREIMAGE_UNAVAILABLE",
    };
  }

  // ── Crash-matrix row 1: approval pending, no sign intent ──
  if (
    evidence.status === "CREATED" &&
    !evidence.signIntentPersisted &&
    !evidence.partialPersisted
  ) {
    return {
      ...base,
      action: "AWAIT_APPROVAL_OR_REJECT_SAFE",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "ACQUIRE_OR_SIGN",
        "CREATE_SECOND_SIGN_INTENT",
      ],
      pageOperator: false,
      reason: null,
    };
  }

  // Signature claimed without partial is the SIGNING_CLAIMED crash row (crash-matrix row 3
  // / recovery row 3). Sign the identical preimage only. Never reached when partial exists.
  if (evidence.signIntentPersisted && !evidence.step1SignaturePersisted) {
    return {
      ...base,
      action: "SIGN_IDENTICAL_PERSISTED_PREIMAGE",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
        "CREATE_SECOND_SIGN_INTENT",
        "RESIGN_OR_REFORM",
        "MINT_REPLACEMENT_PARTIAL",
        "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
      ],
      pageOperator: false,
      reason: null,
    };
  }

  // ── Recovery rows 1–2: APPROVED, no sign intent, no signer audit ──
  if (
    evidence.status === "APPROVED" &&
    !evidence.signIntentPersisted &&
    !evidence.signerAuditIndicatesCall &&
    !evidence.partialPersisted
  ) {
    if (evidence.sourceLeaseHeld) {
      return {
        ...base,
        action: "FIRST_FORMATION_FROM_HELD_LEASE",
        forbidden: [
          ...FORBIDDEN_ALWAYS_NO_SUBMIT,
          "CREATE_SECOND_SIGN_INTENT",
          "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
        ],
        pageOperator: false,
        reason: null,
      };
    }
    return {
      ...base,
      action: "ACQUIRE_LEASE_AND_FIRST_FORMATION",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "CREATE_SECOND_SIGN_INTENT",
        "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
      ],
      pageOperator: false,
      reason: null,
    };
  }

  // Anything else at the formation boundary is unclassifiable → fail closed.
  return {
    ...base,
    action: "INVARIANT_BREACH",
    forbidden: [
      ...FORBIDDEN_ALWAYS_NO_SUBMIT,
      "SILENT_REFORM_WHEN_AUDIT_CONTRADICTS",
      "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
    ],
    pageOperator: true,
    reason: "UNCLASSIFIABLE_FORMATION_EVIDENCE",
  };
}

function classifyPostPartialRecovery(
  evidence: SendFormationCrashEvidence,
  base: {
    readonly operationId: string;
    readonly sourceWalletId: string;
    readonly transferCodeSha256: string | null;
  },
): SendCrashRecoveryClassification {
  const post = evidence.postDeliveryObservation;

  // Crash-matrix row 8 — partial expired (positive expiry / non-landing rules;
  // this ticket only names the action and forbids expiry refresh under the old approval).
  if (post === "PARTIAL_EXPIRED_PENDING_NON_LANDING") {
    return {
      ...base,
      action: "TERMINALIZE_UNDER_POSITIVE_EXPIRY_NON_LANDING",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
        "MINT_REPLACEMENT_PARTIAL",
        "RESIGN_OR_REFORM",
        "INFER_NON_LANDING_OR_RETRY",
      ],
      pageOperator: false,
      reason: "PARTIAL_EXPIRED",
    };
  }

  // Crash-matrix row 7 — unrelated / regressed / unverifiable head.
  if (post === "UNRELATED_OR_REGRESSED_OR_UNVERIFIABLE") {
    return {
      ...base,
      action: "NEEDS_ATTENTION_PRESERVE_LEASE",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "INFER_NON_LANDING_OR_RETRY",
        "MINT_REPLACEMENT_PARTIAL",
        "RESIGN_OR_REFORM",
        "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
      ],
      pageOperator: true,
      reason: "HEAD_UNRELATED_OR_UNVERIFIABLE",
    };
  }

  // Crash-matrix row 6 — expected tx at head → mark landed (owns the verify write).
  if (post === "EXPECTED_TX_AT_HEAD") {
    return {
      ...base,
      action: "MARK_LANDED_FROM_VERIFIED_OBSERVATION",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "MINT_REPLACEMENT_PARTIAL",
        "RESIGN_OR_REFORM",
      ],
      pageOperator: false,
      reason: null,
    };
  }

  // Crash-matrix row 5 — partial delivered, source head unchanged → exact redelivery only.
  if (evidence.partialFirstDelivered || post === "SOURCE_HEAD_UNCHANGED") {
    return {
      ...base,
      action: "REDELIVER_EXACT_PERSISTED_CODE",
      forbidden: [
        ...FORBIDDEN_ALWAYS_NO_SUBMIT,
        "MINT_REPLACEMENT_PARTIAL",
        "RESIGN_OR_REFORM",
        "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
        "CREATE_SECOND_SIGN_INTENT",
        "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
      ],
      pageOperator: false,
      reason: null,
    };
  }

  // Crash-matrix row 4 — partial committed, never delivered → first deliver of exact bytes.
  // Also recovery row 4: restore AWAITING_REDEMPTION if needed.
  return {
    ...base,
    action: "RESTORE_AWAITING_REDEMPTION_AND_DELIVER_EXACT",
    forbidden: [
      ...FORBIDDEN_ALWAYS_NO_SUBMIT,
      "RESIGN_OR_REFORM",
      "CONSTRUCT_DIFFERENT_INNER_OR_CODE",
      "CREATE_SECOND_SIGN_INTENT",
      "MINT_REPLACEMENT_PARTIAL",
      "REFRESH_EXPIRY_UNDER_OLD_APPROVAL",
    ],
    pageOperator: false,
    reason: null,
  };
}

// ── Exact redelivery (step 5) ────────────────────────

/**
 * Byte-frozen partial payload returned by redelivery. The only mutable fields on the
 * underlying row are delivery counters — never these strings.
 */
export interface ExactPersistedPartial {
  readonly operationId: string;
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  readonly step1Signature: string;
  readonly innerSha256: string;
  readonly firstDeliveredAt: string | null;
  readonly lastRedeliveredAt: string | null;
  readonly redeliveryCount: number;
}

export interface RedeliveryResult {
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  readonly redeliveryCount: number;
  readonly firstDeliveredAt: string;
  /** SHA-256 of the three immutable byte columns before the delivery stamp — for tests. */
  readonly immutableBytesFingerprintBefore: string;
  readonly immutableBytesFingerprintAfter: string;
}

/**
 * Fingerprint of the signed/immutable partial columns.
 * Content-binds `transferCodeText` (full string), not merely its length — same-length
 * mutations must change the fingerprint.
 */
export function fingerprintImmutablePartialBytes(partial: {
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  readonly step1Signature: string;
  readonly innerSha256?: string;
}): string {
  // Not a signing digest — a test/audit binding over the immutable columns only.
  return [
    partial.transferCodeSha256,
    partial.step1Signature,
    partial.transferCodeText,
    partial.innerSha256 ?? "",
  ].join("|");
}

/**
 * Handout integrity: every redelivery path must prove
 * `sha256(transfer_code_text) === transfer_code_sha256` before serving bytes
 * (mirrors form-and-sign persist gate; step 5).
 */
export function assertTransferCodeTextMatchesSha256(partial: {
  readonly operationId: string;
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
}): void {
  const recomputed = hashTransferCodeText(partial.transferCodeText);
  if (recomputed !== partial.transferCodeSha256) {
    throw new Error(
      `redelivery transfer_code_text does not match transfer_code_sha256 for operation ${partial.operationId}`,
    );
  }
}

function snapshotExactPartial(partial: ExactPersistedPartial): ExactPersistedPartial {
  return {
    operationId: partial.operationId,
    transferCodeText: partial.transferCodeText,
    transferCodeSha256: partial.transferCodeSha256,
    step1Signature: partial.step1Signature,
    innerSha256: partial.innerSha256,
    firstDeliveredAt: partial.firstDeliveredAt,
    lastRedeliveredAt: partial.lastRedeliveredAt,
    redeliveryCount: partial.redeliveryCount,
  };
}

function immutablePartialFieldsEqual(
  a: ExactPersistedPartial,
  b: ExactPersistedPartial,
): boolean {
  return (
    a.transferCodeText === b.transferCodeText &&
    a.transferCodeSha256 === b.transferCodeSha256 &&
    a.step1Signature === b.step1Signature &&
    a.innerSha256 === b.innerSha256
  );
}

/**
 * Serve the exact persisted transfer code and stamp delivery counters only.
 *
 * Contract (step 5):
 * - returns the identical transfer_code_text / transfer_code_sha256 bytes
 * - never rebuilds, re-signs, refreshes links, or changes expiry
 * - the only write is the delivery-counter UPDATE (first_delivered_at /
 * last_redelivered_at / redelivery_count)
 * - handout always re-proves sha256(text) === transfer_code_sha256
 */
export function redeliverExactPersistedPartial(
  partial: ExactPersistedPartial,
  deliveredAt: string,
  stamp: (operationId: string, at: string) => number,
): RedeliveryResult {
  // Snapshot by value so a stamp that mutates the caller's object by alias cannot
  // rewrite the bytes we fingerprint / hand out.
  const snapshot = snapshotExactPartial(partial);
  assertTransferCodeTextMatchesSha256(snapshot);
  const before = fingerprintImmutablePartialBytes(snapshot);
  const redeliveryCount = stamp(snapshot.operationId, deliveredAt);
  assertTransferCodeTextMatchesSha256(snapshot);
  const after = fingerprintImmutablePartialBytes(snapshot);
  if (before !== after) {
    // Defensive: stamp ports must not touch immutable columns. Fail closed rather than
    // hand out bytes that may have been rewritten under us.
    throw new Error(
      `redelivery mutated immutable partial bytes for operation ${snapshot.operationId}`,
    );
  }
  return {
    transferCodeText: snapshot.transferCodeText,
    transferCodeSha256: snapshot.transferCodeSha256,
    redeliveryCount,
    firstDeliveredAt:
      snapshot.firstDeliveredAt === null ? deliveredAt : snapshot.firstDeliveredAt,
    immutableBytesFingerprintBefore: before,
    immutableBytesFingerprintAfter: after,
  };
}

/**
 * In-memory redelivery against the form-and-sign state adapter. Composition
 * roots use {@link redeliverExactPersistedPartial} with {@link recordPartialDelivery}.
 * Re-loads the partial row after the delivery stamp and re-proves content binding.
 */
export function redeliverFromInMemoryPartial(
  state: InMemoryFormAndSignState,
  operationId: string,
  deliveredAt: string,
): RedeliveryResult {
  const row = state.partials.get(operationId);
  if (row === undefined) {
    throw new Error(
      `no persisted partial for operation ${operationId}: redelivery is forbidden until the partial row commits`,
    );
  }
  const beforeSnapshot: ExactPersistedPartial = {
    operationId: row.operationId,
    transferCodeText: row.transferCodeText,
    transferCodeSha256: row.transferCodeSha256,
    step1Signature: row.step1Signature,
    // In-memory adapter does not store innerSha256 on the partial map; bind empty.
    innerSha256: "",
    firstDeliveredAt: row.firstDeliveredAt,
    lastRedeliveredAt: null,
    redeliveryCount: row.redeliveryCount,
  };
  assertTransferCodeTextMatchesSha256(beforeSnapshot);
  const before = fingerprintImmutablePartialBytes(beforeSnapshot);
  const redeliveryCount = recordInMemoryPartialDelivery(state, operationId, deliveredAt);
  const afterRow = state.partials.get(operationId);
  if (afterRow === undefined) {
    throw new Error(
      `partial row disappeared during redelivery stamp for operation ${operationId}`,
    );
  }
  const afterSnapshot: ExactPersistedPartial = {
    operationId: afterRow.operationId,
    transferCodeText: afterRow.transferCodeText,
    transferCodeSha256: afterRow.transferCodeSha256,
    step1Signature: afterRow.step1Signature,
    innerSha256: "",
    firstDeliveredAt: afterRow.firstDeliveredAt,
    lastRedeliveredAt: null,
    redeliveryCount: afterRow.redeliveryCount,
  };
  assertTransferCodeTextMatchesSha256(afterSnapshot);
  if (!immutablePartialFieldsEqual(beforeSnapshot, afterSnapshot)) {
    throw new Error(
      `redelivery mutated immutable partial bytes for operation ${operationId}`,
    );
  }
  const after = fingerprintImmutablePartialBytes(afterSnapshot);
  if (before !== after) {
    throw new Error(
      `redelivery mutated immutable partial bytes for operation ${operationId}`,
    );
  }
  return {
    transferCodeText: afterSnapshot.transferCodeText,
    transferCodeSha256: afterSnapshot.transferCodeSha256,
    redeliveryCount,
    firstDeliveredAt:
      beforeSnapshot.firstDeliveredAt === null
        ? deliveredAt
        : beforeSnapshot.firstDeliveredAt,
    immutableBytesFingerprintBefore: before,
    immutableBytesFingerprintAfter: after,
  };
}

/** SQL catalogue — read-only selects + the one status-restore CAS. */
export const SEND_CRASH_RECOVERY_SQL = {
  /**
   * Exact partial bytes for redelivery. SELECT-only — no write path to
   * transfer_code_text / step_1_signature / transfer_code_sha256.
   */
  LOAD_PARTIAL_BYTES:
    "SELECT operation_id, transfer_code_text, transfer_code_sha256, " +
    "step_1_signature, inner_sha256, first_delivered_at, last_redelivered_at, " +
    "redelivery_count FROM external_send_partials WHERE operation_id = $1",

  /**
   * Load the durable sign-intent preimage for crash-resume signing (row 3).
   * SELECT-only — external_send_sign_intents is insert-only.
   */
  LOAD_SIGN_INTENT_PREIMAGE:
    "SELECT operation_id, approval_id, source_wallet_id, " +
    "source_t0_observation_id, destination_t0_observation_id, " +
    "lease_group_id, lease_epoch, inner_preimage_text, inner_sha256, " +
    "redemption_expiry_at, prepared_at " +
    "FROM external_send_sign_intents WHERE operation_id = $1",

  /**
   * Recovery row 4 — restore AWAITING_REDEMPTION when the partial is durable but the
   * public status drifted (e.g. crash between partial insert visibility and status CAS
   * replay). Allowlist only pre-await formation statuses — never demote NEEDS_ATTENTION
   * (row 7) or terminal landed/rejected rows. Never touches signed bytes.
   */
  RESTORE_AWAITING_REDEMPTION_WHEN_PARTIAL:
    "UPDATE send_operations SET status = 'AWAITING_REDEMPTION', " +
    "formation_state = 'PARTIAL_PERSISTED', " +
    "row_version = row_version + 1 " +
    "WHERE operation_id = $1 " +
    "AND status = 'APPROVED' " +
    "AND EXISTS (SELECT 1 FROM external_send_partials p WHERE p.operation_id = $1) " +
    "RETURNING operation_id, status, formation_state, row_version",

  /**
   * CLOSE_NEVER_STARTED_EXTERNAL_SEND — APPROVED→REJECTED only when every negative is
   * re-proven under the same lock. Consumed approval evidence is not touched.
   */
  CLOSE_NEVER_STARTED_CAS:
    "UPDATE send_operations SET status = 'REJECTED', " +
    "row_version = row_version + 1 " +
    "WHERE operation_id = $1 AND status = 'APPROVED' " +
    "AND row_version = $2 " +
    "AND NOT EXISTS (SELECT 1 FROM external_send_sign_intents s WHERE s.operation_id = $1) " +
    "AND NOT EXISTS (SELECT 1 FROM external_send_partials p WHERE p.operation_id = $1) " +
    "AND NOT EXISTS (SELECT 1 FROM signer_audit a WHERE a.operation_id = $1) " +
    "RETURNING operation_id, status, row_version",
} as const;

export async function loadExactPersistedPartial(
  query: SqlQueryFn,
  operationId: string,
): Promise<ExactPersistedPartial | null> {
  const rows = await query(SEND_CRASH_RECOVERY_SQL.LOAD_PARTIAL_BYTES, [operationId]);
  const row = rows[0];
  if (row === undefined) return null;
  return {
    operationId: String(row.operation_id),
    transferCodeText: String(row.transfer_code_text),
    transferCodeSha256: String(row.transfer_code_sha256),
    step1Signature: String(row.step_1_signature),
    innerSha256: String(row.inner_sha256),
    firstDeliveredAt:
      row.first_delivered_at === null || row.first_delivered_at === undefined
        ? null
        : String(row.first_delivered_at),
    lastRedeliveredAt:
      row.last_redelivered_at === null || row.last_redelivered_at === undefined
        ? null
        : String(row.last_redelivered_at),
    redeliveryCount: Number(row.redelivery_count),
  };
}

export async function redeliverExactPersistedPartialAsync(
  partial: ExactPersistedPartial,
  deliveredAt: string,
  stamp: (operationId: string, at: string) => Promise<number>,
): Promise<RedeliveryResult> {
  const snapshot = snapshotExactPartial(partial);
  assertTransferCodeTextMatchesSha256(snapshot);
  const before = fingerprintImmutablePartialBytes(snapshot);
  const redeliveryCount = await stamp(snapshot.operationId, deliveredAt);
  assertTransferCodeTextMatchesSha256(snapshot);
  const after = fingerprintImmutablePartialBytes(snapshot);
  if (before !== after) {
    throw new Error(
      `redelivery mutated immutable partial bytes for operation ${snapshot.operationId}`,
    );
  }
  return {
    transferCodeText: snapshot.transferCodeText,
    transferCodeSha256: snapshot.transferCodeSha256,
    redeliveryCount,
    firstDeliveredAt:
      snapshot.firstDeliveredAt === null ? deliveredAt : snapshot.firstDeliveredAt,
    immutableBytesFingerprintBefore: before,
    immutableBytesFingerprintAfter: after,
  };
}

/**
 * Redelivery over SQL: SELECT exact bytes, stamp delivery counters via the
 * sole partial UPDATE, re-SELECT and re-prove content binding, return identical text.
 * Zero write access to signed columns.
 */
export async function redeliverExactPartialViaSql(
  query: SqlQueryFn,
  operationId: string,
  deliveredAt: string,
): Promise<RedeliveryResult> {
  const partial = await loadExactPersistedPartial(query, operationId);
  if (partial === null) {
    throw new Error(
      `no persisted partial for operation ${operationId}: redelivery is forbidden until the partial row commits`,
    );
  }
  assertTransferCodeTextMatchesSha256(partial);
  const before = fingerprintImmutablePartialBytes(partial);
  const redeliveryCount = await recordPartialDelivery(query, operationId, deliveredAt);
  const afterLoad = await loadExactPersistedPartial(query, operationId);
  if (afterLoad === null) {
    throw new Error(
      `partial row disappeared during redelivery stamp for operation ${operationId}`,
    );
  }
  assertTransferCodeTextMatchesSha256(afterLoad);
  if (!immutablePartialFieldsEqual(partial, afterLoad)) {
    throw new Error(
      `redelivery mutated immutable partial bytes for operation ${operationId}`,
    );
  }
  const after = fingerprintImmutablePartialBytes(afterLoad);
  if (before !== after) {
    throw new Error(
      `redelivery mutated immutable partial bytes for operation ${operationId}`,
    );
  }
  return {
    transferCodeText: afterLoad.transferCodeText,
    transferCodeSha256: afterLoad.transferCodeSha256,
    redeliveryCount,
    firstDeliveredAt:
      partial.firstDeliveredAt === null ? deliveredAt : partial.firstDeliveredAt,
    immutableBytesFingerprintBefore: before,
    immutableBytesFingerprintAfter: after,
  };
}

// ── CLOSE_NEVER_STARTED_EXTERNAL_SEND ───────────────────────

export type CloseNeverStartedGateResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly blockingEvidence:
        | "SIGN_INTENT"
        | "SIGNER_CALL"
        | "SIGNATURE"
        | "PARTIAL"
        | "DELIVERY"
        | "NOT_APPROVED"
        | "INVARIANT_BREACH_CLASSIFICATION";
      readonly detail: string;
    };

/**
 * Fail-closed gate for CLOSE_NEVER_STARTED_EXTERNAL_SEND. Every one of the five durable
 * negatives (sign intent, signer call, signature, partial, delivery) must be re-proven
 * absent. A prior INVARIANT_BREACH classification also blocks the close.
 */
export function evaluateCloseNeverStartedExternalSend(
  evidence: SendFormationCrashEvidence,
): CloseNeverStartedGateResult {
  if (evidence.status !== "APPROVED") {
    return {
      ok: false,
      blockingEvidence: "NOT_APPROVED",
      detail: `status is ${evidence.status}, not APPROVED`,
    };
  }
  if (evidence.signIntentPersisted) {
    return {
      ok: false,
      blockingEvidence: "SIGN_INTENT",
      detail: "external_send_sign_intents row exists",
    };
  }
  if (evidence.signerAuditIndicatesCall) {
    return {
      ok: false,
      blockingEvidence: "SIGNER_CALL",
      detail: "signer_audit indicates a call for this operation",
    };
  }
  if (evidence.step1SignaturePersisted) {
    return {
      ok: false,
      blockingEvidence: "SIGNATURE",
      detail: "step-1 signature is persisted",
    };
  }
  if (evidence.partialPersisted) {
    return {
      ok: false,
      blockingEvidence: "PARTIAL",
      detail: "external_send_partials row exists",
    };
  }
  if (evidence.partialFirstDelivered) {
    return {
      ok: false,
      blockingEvidence: "DELIVERY",
      detail: "partial first_delivered_at is set",
    };
  }

  // Re-run classification: only PROVEN-style first-formation rows may close.
  const classification = classifySendCrashRecovery(evidence);
  if (classification.action === "INVARIANT_BREACH") {
    return {
      ok: false,
      blockingEvidence: "INVARIANT_BREACH_CLASSIFICATION",
      detail: classification.reason ?? "INVARIANT_BREACH",
    };
  }
  if (
    classification.action !== "ACQUIRE_LEASE_AND_FIRST_FORMATION" &&
    classification.action !== "FIRST_FORMATION_FROM_HELD_LEASE"
  ) {
    return {
      ok: false,
      blockingEvidence: "INVARIANT_BREACH_CLASSIFICATION",
      detail: `classification ${classification.action} is not PROVEN_NOT_STARTED`,
    };
  }
  return { ok: true };
}

export interface CloseNeverStartedPort {
  /**
   * Under one DB-TX: re-check the five negatives, CAS APPROVED→REJECTED, release source
   * lease if held. Must refuse (return ok:false) if any evidence appeared between the gate
   * and the lock. Must NOT touch operation_approvals (consumed approval remains permanent).
   */
  commitCloseNeverStarted(input: {
    readonly operationId: string;
    readonly expectedRowVersion: number;
    readonly releaseSourceLease: boolean;
  }): Promise<
    | { readonly ok: true; readonly status: "REJECTED"; readonly rowVersion: number }
    | { readonly ok: false; readonly reason: string }
  >;
}

export async function applyCloseNeverStartedExternalSend(input: {
  readonly evidence: SendFormationCrashEvidence;
  readonly expectedRowVersion: number;
  readonly port: CloseNeverStartedPort;
}): Promise<
  | { readonly ok: true; readonly status: "REJECTED"; readonly rowVersion: number }
  | { readonly ok: false; readonly reason: string; readonly gate: CloseNeverStartedGateResult }
> {
  const gate = evaluateCloseNeverStartedExternalSend(input.evidence);
  if (!gate.ok) {
    return {
      ok: false,
      reason: `close_blocked:${gate.blockingEvidence}`,
      gate,
    };
  }
  const committed = await input.port.commitCloseNeverStarted({
    operationId: input.evidence.operationId,
    expectedRowVersion: input.expectedRowVersion,
    releaseSourceLease: input.evidence.sourceLeaseHeld,
  });
  if (!committed.ok) {
    return {
      ok: false,
      reason: committed.reason,
      gate,
    };
  }
  return {
    ok: true,
    status: "REJECTED",
    rowVersion: committed.rowVersion,
  };
}

/**
 * In-memory close port for unit tests. Mirrors the SQL negatives: any intent/partial/audit
 * appearance between gate and commit fails closed.
 */
export function createInMemoryCloseNeverStartedPort(state: {
  status: string;
  rowVersion: number;
  signIntent: boolean;
  partial: boolean;
  signerAudit: boolean;
  leaseHeld: boolean;
  approvals: Array<{ id: string; consumed: boolean }>;
  releasedLeases: string[];
}): CloseNeverStartedPort {
  return {
    async commitCloseNeverStarted(input) {
      if (state.status !== "APPROVED") {
        return { ok: false, reason: "not_approved" };
      }
      if (state.rowVersion !== input.expectedRowVersion) {
        return { ok: false, reason: "row_version_conflict" };
      }
      if (state.signIntent || state.partial || state.signerAudit) {
        return { ok: false, reason: "evidence_appeared_under_lock" };
      }
      state.status = "REJECTED";
      state.rowVersion += 1;
      if (input.releaseSourceLease && state.leaseHeld) {
        state.leaseHeld = false;
        state.releasedLeases.push(input.operationId);
      }
      // Approvals are intentionally not mutated — consumed evidence stays permanent.
      return { ok: true, status: "REJECTED", rowVersion: state.rowVersion };
    },
  };
}

// ── Crash-matrix named-row helpers (test surface) ────────────────────────────────

/** The eight crash-matrix row ids — one named test per row. */
export const SEC_10_3_CRASH_MATRIX_ROWS = [
  "APPROVAL_PENDING_NO_SIGN_INTENT",
  "APPROVAL_CONSUMED_NO_SIGN_INTENT",
  "SIGNING_CLAIMED_NO_PARTIAL",
  "PARTIAL_COMMITTED_NEVER_DELIVERED",
  "PARTIAL_DELIVERED_SOURCE_HEAD_UNCHANGED",
  "PARTIAL_DELIVERED_EXPECTED_TX_AT_HEAD",
  "PARTIAL_DELIVERED_UNRELATED_OR_UNVERIFIABLE_HEAD",
  "PARTIAL_EXPIRED",
] as const;
export type Sec103CrashMatrixRowId = (typeof SEC_10_3_CRASH_MATRIX_ROWS)[number];

/** Build the evidence fixture that corresponds to one crash-matrix row. */
export function evidenceForSec103Row(
  row: Sec103CrashMatrixRowId,
  ids: { readonly operationId: string; readonly sourceWalletId: string },
): SendFormationCrashEvidence {
  const base = {
    operationId: ids.operationId,
    sourceWalletId: ids.sourceWalletId,
    exactPreimageAvailable: true,
    signerAuditIndicatesCall: false,
    transferCodeSha256: null as string | null,
  };

  switch (row) {
    case "APPROVAL_PENDING_NO_SIGN_INTENT":
      return {
        ...base,
        status: "CREATED",
        formationState: null,
        sourceLeaseHeld: false,
        signIntentPersisted: false,
        step1SignaturePersisted: false,
        partialPersisted: false,
        partialFirstDelivered: false,
      };
    case "APPROVAL_CONSUMED_NO_SIGN_INTENT":
      return {
        ...base,
        status: "APPROVED",
        formationState: "APPROVED_UNSIGNED",
        sourceLeaseHeld: false,
        signIntentPersisted: false,
        step1SignaturePersisted: false,
        partialPersisted: false,
        partialFirstDelivered: false,
      };
    case "SIGNING_CLAIMED_NO_PARTIAL":
      return {
        ...base,
        status: "APPROVED",
        formationState: "SIGNING_CLAIMED",
        sourceLeaseHeld: true,
        signIntentPersisted: true,
        step1SignaturePersisted: false,
        partialPersisted: false,
        partialFirstDelivered: false,
      };
    case "PARTIAL_COMMITTED_NEVER_DELIVERED":
      return {
        ...base,
        status: "AWAITING_REDEMPTION",
        formationState: "PARTIAL_PERSISTED",
        sourceLeaseHeld: true,
        signIntentPersisted: true,
        step1SignaturePersisted: true,
        partialPersisted: true,
        partialFirstDelivered: false,
        transferCodeSha256: "aa".repeat(32),
      };
    case "PARTIAL_DELIVERED_SOURCE_HEAD_UNCHANGED":
      return {
        ...base,
        status: "AWAITING_REDEMPTION",
        formationState: "PARTIAL_PERSISTED",
        sourceLeaseHeld: true,
        signIntentPersisted: true,
        step1SignaturePersisted: true,
        partialPersisted: true,
        partialFirstDelivered: true,
        transferCodeSha256: "bb".repeat(32),
        postDeliveryObservation: "SOURCE_HEAD_UNCHANGED",
      };
    case "PARTIAL_DELIVERED_EXPECTED_TX_AT_HEAD":
      return {
        ...base,
        status: "AWAITING_REDEMPTION",
        formationState: "PARTIAL_PERSISTED",
        sourceLeaseHeld: true,
        signIntentPersisted: true,
        step1SignaturePersisted: true,
        partialPersisted: true,
        partialFirstDelivered: true,
        transferCodeSha256: "cc".repeat(32),
        postDeliveryObservation: "EXPECTED_TX_AT_HEAD",
      };
    case "PARTIAL_DELIVERED_UNRELATED_OR_UNVERIFIABLE_HEAD":
      return {
        ...base,
        status: "AWAITING_REDEMPTION",
        formationState: "PARTIAL_PERSISTED",
        sourceLeaseHeld: true,
        signIntentPersisted: true,
        step1SignaturePersisted: true,
        partialPersisted: true,
        partialFirstDelivered: true,
        transferCodeSha256: "dd".repeat(32),
        postDeliveryObservation: "UNRELATED_OR_REGRESSED_OR_UNVERIFIABLE",
      };
    case "PARTIAL_EXPIRED":
      return {
        ...base,
        status: "NEEDS_ATTENTION",
        formationState: "PARTIAL_PERSISTED",
        sourceLeaseHeld: true,
        signIntentPersisted: true,
        step1SignaturePersisted: true,
        partialPersisted: true,
        partialFirstDelivered: true,
        transferCodeSha256: "ee".repeat(32),
        postDeliveryObservation: "PARTIAL_EXPIRED_PENDING_NON_LANDING",
      };
    default: {
      const _exhaustive: never = row;
      throw new Error(`unknown crash-matrix row: ${String(_exhaustive)}`);
    }
  }
}

/** Expected (action, forbidden-subset) pairs for the eight crash-matrix rows. */
export const SEC_10_3_EXPECTED: Readonly<
  Record<
    Sec103CrashMatrixRowId,
    {
      readonly action: SendCrashRecoveryActionKind;
      readonly mustForbid: readonly SendCrashForbiddenAction[];
    }
  >
> = {
  APPROVAL_PENDING_NO_SIGN_INTENT: {
    action: "AWAIT_APPROVAL_OR_REJECT_SAFE",
    mustForbid: ["ACQUIRE_OR_SIGN", "BLIND_SUBMIT"],
  },
  APPROVAL_CONSUMED_NO_SIGN_INTENT: {
    action: "ACQUIRE_LEASE_AND_FIRST_FORMATION",
    mustForbid: ["CREATE_SECOND_SIGN_INTENT", "BLIND_SUBMIT"],
  },
  SIGNING_CLAIMED_NO_PARTIAL: {
    action: "SIGN_IDENTICAL_PERSISTED_PREIMAGE",
    mustForbid: ["CONSTRUCT_DIFFERENT_INNER_OR_CODE", "CREATE_SECOND_SIGN_INTENT"],
  },
  PARTIAL_COMMITTED_NEVER_DELIVERED: {
    action: "RESTORE_AWAITING_REDEMPTION_AND_DELIVER_EXACT",
    mustForbid: ["RESIGN_OR_REFORM", "MINT_REPLACEMENT_PARTIAL"],
  },
  PARTIAL_DELIVERED_SOURCE_HEAD_UNCHANGED: {
    action: "REDELIVER_EXACT_PERSISTED_CODE",
    mustForbid: ["MINT_REPLACEMENT_PARTIAL", "RESIGN_OR_REFORM"],
  },
  PARTIAL_DELIVERED_EXPECTED_TX_AT_HEAD: {
    action: "MARK_LANDED_FROM_VERIFIED_OBSERVATION",
    mustForbid: ["SUBMIT_OR_DELIVER_NEW_CODE", "MINT_REPLACEMENT_PARTIAL"],
  },
  PARTIAL_DELIVERED_UNRELATED_OR_UNVERIFIABLE_HEAD: {
    action: "NEEDS_ATTENTION_PRESERVE_LEASE",
    mustForbid: ["INFER_NON_LANDING_OR_RETRY", "MINT_REPLACEMENT_PARTIAL"],
  },
  PARTIAL_EXPIRED: {
    action: "TERMINALIZE_UNDER_POSITIVE_EXPIRY_NON_LANDING",
    mustForbid: ["REFRESH_EXPIRY_UNDER_OLD_APPROVAL", "MINT_REPLACEMENT_PARTIAL"],
  },
};
