// SEND_EXTERNAL post-delivery expiry gate + attention recovery.
//
// "Awaiting redemption", "Expired external partial",
// CONTINUE_EXTERNAL_WAIT / REDELIVER_EXACT_PARTIAL;
// Step 6 (keep source lease until verification-complete);
// (AWAITING_REDEMPTION → NEEDS_ATTENTION only;
// no direct AWAITING_REDEMPTION → REJECTED / EXPIRED);
// SEND_EXTERNAL expiry single-source (expiry is a pre-delivery gate ONLY post-delivery), exact partial only (exact partial only).
//
// Scope of this module:
// 1. Detect past signed redemption deadline on a delivered AWAITING_REDEMPTION partial
// and park to NEEDS_ATTENTION (never EXPIRED / REJECTED, never release lease).
// 2. Operator CONTINUE_EXTERNAL_WAIT → clear attention, return AWAITING_REDEMPTION.
// 3. Operator REDELIVER_EXACT_PARTIAL → hand out identical stored bytes; stamp counters only.
//
// This module signs nothing, forms no second partial, and contains zero statements that
// DELETE or UPDATE wallet_active_leases. CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED is out of
// scope (the positive non-landing oracle is later work).

import type { AttentionReason } from "@zucoins/generic-node-contracts/operations/events";

import {
  loadExactPersistedPartial,
  redeliverExactPartialViaSql,
  type ExactPersistedPartial,
  type RedeliveryResult,
} from "../core/send-crash-recovery.js";
import type { SqlQueryFn } from "../core/sql-query-fn.js";
import { SEND_REDEMPTION_WINDOW_SECS } from "../protocol/send-redemption.js";

// ── Constants (SEND_EXTERNAL expiry single-source) ──────────────────────────────────────────────────────────

/**
 * SEND_EXTERNAL expiry single-source-flagged safety margin after the signed T2 redemption deadline before a
 * positive non-landing close may even be *considered*. This module never
 * closes; the constant is exported so recovery code reads one source.
 */
export const SEND_PARTIAL_AGING_MARGIN_SECS = 3600 as const;

/** Re-export for callers that only import this module. */
export { SEND_REDEMPTION_WINDOW_SECS };

/**
 * Appendix F1.1 fixture uses UNEXPECTED_HEAD_CHANGE for the expiry/head-gap
 * park. There is no SEND-specific reason (receive's POST_EXPIRY_RECONCILING
 * is attention hold-only); we stay inside the closed 14-value set.
 */
export const SEND_EXPIRY_ATTENTION_REASON: AttentionReason = "UNEXPECTED_HEAD_CHANGE";

/**
 * The park reason for the other shape of a stuck send: past the signed redemption deadline
 * with the source head still on Ts0. Nothing is wrong with the chain — the recipient simply
 * has not submitted — so UNEXPECTED_HEAD_CHANGE would misreport it. POST_EXPIRY_RECONCILING
 * is the frozen value for exactly that hold, and parking under it is what makes the send
 * visible to the operator and countable as parked. Still attention-only: no terminal status,
 * no lease release.
 */
export const SEND_POST_EXPIRY_ATTENTION_REASON: AttentionReason = "POST_EXPIRY_RECONCILING";

export const OPERATION_NEEDS_ATTENTION_EVENT = "operation.needs_attention" as const;

// ── Pure evaluation ────────────────────────────────────────────────────────────

export type SendExpiryBoundary =
  | "PRE_DELIVERY"
  | "POST_DELIVERY_AWAITING"
  | "POST_DELIVERY_ATTENTION"
  | "TERMINAL"
  | "OTHER";

/**
 * Classify where the operation sits relative to the delivery boundary.
 * A partial row with first_delivered_at set is post-delivery regardless of status.
 */
export function classifySendDeliveryBoundary(input: {
  readonly status: string;
  readonly partialExists: boolean;
  readonly firstDeliveredAt: string | null;
}): SendExpiryBoundary {
  if (
    input.status === "EXTERNAL_SEND_LANDED" ||
    input.status === "REJECTED"
  ) {
    return "TERMINAL";
  }
  if (input.status === "NEEDS_ATTENTION" && input.partialExists) {
    return "POST_DELIVERY_ATTENTION";
  }
  if (input.status === "AWAITING_REDEMPTION" && input.partialExists) {
    // first_delivered_at may still be null if status advanced before handout; the
    // durable partial alone is the post-formation boundary SEND_EXTERNAL expiry single-source protects. Delivery
    // counters are orthogonal to the no-terminal-expiry rule.
    return "POST_DELIVERY_AWAITING";
  }
  if (
    (input.status === "CREATED" || input.status === "APPROVED") &&
    !input.partialExists
  ) {
    return "PRE_DELIVERY";
  }
  return "OTHER";
}

export type SendExpiryEvaluation =
  | {
      readonly outcome: "NOT_YET_EXPIRED";
      readonly boundary: SendExpiryBoundary;
      readonly remainingSecs: number;
    }
  | {
      readonly outcome: "PAST_EXPIRY_PARK_ATTENTION";
      readonly boundary: "POST_DELIVERY_AWAITING";
      /**
       * True when clock is past T2. Aging margin is NOT required to park —
       * Park on expiry/evidence-gap; margin gates terminal close only.
       */
      readonly pastT2: true;
    }
  | {
      readonly outcome: "ALREADY_ATTENTION";
      readonly boundary: "POST_DELIVERY_ATTENTION";
    }
  | {
      readonly outcome: "TERMINAL_NOOP";
      readonly boundary: "TERMINAL";
    }
  | {
      readonly outcome: "PRE_DELIVERY_GATE_ONLY";
      readonly boundary: "PRE_DELIVERY";
      readonly pastT2: boolean;
      /**
       * Pre-delivery expiry must NOT release the lease or terminalize from this module.
       * CLOSE_NEVER_STARTED / formation recovery owns pre-partial closure (other tickets).
       */
      readonly leaseReleaseAuthorized: false;
      readonly terminalRejectAuthorized: false;
    }
  | {
      readonly outcome: "NO_ACTION";
      readonly boundary: SendExpiryBoundary;
    };

/**
 * Evaluate post-delivery expiry for one SEND_EXTERNAL operation.
 *
 * `redemptionExpiryUnixSecs` is the signed inner `expiry__unix_time_secs` (integer-seconds
 * string) — the ONE immutable T2 source (SEND_EXTERNAL expiry single-source). Callers may also supply the persisted
 * projection `redemption_expiry_at` for diagnostics; evaluation keys off the signed secs.
 */
export function evaluatePostDeliveryExpiry(input: {
  readonly status: string;
  readonly partialExists: boolean;
  readonly firstDeliveredAt: string | null;
  /** Signed inner expiry__unix_time_secs (decimal integer-seconds string). */
  readonly redemptionExpiryUnixSecs: string | null;
  /** Node clock, Unix seconds (floor). */
  readonly nowUnixSecs: number;
}): SendExpiryEvaluation {
  const boundary = classifySendDeliveryBoundary(input);

  if (boundary === "TERMINAL") {
    return { outcome: "TERMINAL_NOOP", boundary };
  }

  if (boundary === "POST_DELIVERY_ATTENTION") {
    return { outcome: "ALREADY_ATTENTION", boundary };
  }

  if (boundary === "PRE_DELIVERY") {
    const pastT2 =
      input.redemptionExpiryUnixSecs !== null &&
      isPastExpiry(input.redemptionExpiryUnixSecs, input.nowUnixSecs);
    return {
      outcome: "PRE_DELIVERY_GATE_ONLY",
      boundary,
      pastT2,
      leaseReleaseAuthorized: false,
      terminalRejectAuthorized: false,
    };
  }

  if (boundary !== "POST_DELIVERY_AWAITING") {
    return { outcome: "NO_ACTION", boundary };
  }

  if (input.redemptionExpiryUnixSecs === null) {
    // Without a durable T2 we cannot park on expiry — leave for formation recovery.
    return { outcome: "NO_ACTION", boundary };
  }

  if (!isPastExpiry(input.redemptionExpiryUnixSecs, input.nowUnixSecs)) {
    const expiry = Number(input.redemptionExpiryUnixSecs);
    return {
      outcome: "NOT_YET_EXPIRED",
      boundary,
      remainingSecs: Math.max(0, expiry - input.nowUnixSecs),
    };
  }

  return {
    outcome: "PAST_EXPIRY_PARK_ATTENTION",
    boundary: "POST_DELIVERY_AWAITING",
    pastT2: true,
  };
}

export function isPastExpiry(
  redemptionExpiryUnixSecs: string,
  nowUnixSecs: number,
): boolean {
  if (!/^[0-9]+$/.test(redemptionExpiryUnixSecs)) {
    throw new RangeError(
      `isPastExpiry: expected integer-seconds string, got ${JSON.stringify(redemptionExpiryUnixSecs)}`,
    );
  }
  if (!Number.isSafeInteger(nowUnixSecs)) {
    throw new RangeError("isPastExpiry: nowUnixSecs must be a safe integer");
  }
  // Doc 11 §11.9 EXP-BOUNDARY-02: clock==expiry is still inside the window (servable).
  // Past-expiry / park starts at clock=expiry+1 (strict greater-than).
  return nowUnixSecs > Number(redemptionExpiryUnixSecs);
}

/**
 * Oracle-eligibility clock: T2 + SEND_PARTIAL_AGING_MARGIN_SECS.
 * Exposed for later CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED; this module never closes.
 */
export function oracleEligibleAtUnixSecs(redemptionExpiryUnixSecs: string): number {
  if (!/^[0-9]+$/.test(redemptionExpiryUnixSecs)) {
    throw new RangeError(
      `oracleEligibleAtUnixSecs: expected integer-seconds string, got ${JSON.stringify(redemptionExpiryUnixSecs)}`,
    );
  }
  return Number(redemptionExpiryUnixSecs) + SEND_PARTIAL_AGING_MARGIN_SECS;
}

// ── SQL catalogue ──────────────────────────────────────────────────────────────

/**
 * Every statement this module can execute. Tests pin the set so a lease DELETE or a
 * second-partial INSERT cannot land silently.
 */
export const SEND_EXPIRY_ATTENTION_SQL = {
  /**
   * Load the durable facts needed to evaluate expiry. Reads only — never locks the
   * lease row. redemption_expiry_at is the SEND_EXTERNAL expiry single-source projection; signed secs are extracted
   * from inner_preimage_text by the caller (or supplied via join when preimage is JSON).
   */
  LOAD_OPERATION_EXPIRY_FACTS:
    "SELECT o.operation_id, o.status, o.formation_state, o.row_version, " +
    "o.source_wallet_id, o.attention_required, o.attention_reason, o.attention_episode, " +
    "s.redemption_expiry_at, s.inner_preimage_text, s.inner_sha256 AS intent_inner_sha256, " +
    "p.inner_sha256 AS partial_inner_sha256, p.step_1_signature, p.transfer_code_text, " +
    "p.transfer_code_sha256, p.first_delivered_at, p.last_redelivered_at, p.redelivery_count, " +
    "(p.operation_id IS NOT NULL) AS partial_exists, " +
    "EXISTS (SELECT 1 FROM wallet_active_leases l WHERE l.wallet_id = o.source_wallet_id) " +
    "  AS lease_held, " +
    "(SELECT l.lease_epoch FROM wallet_active_leases l " +
    "  WHERE l.wallet_id = o.source_wallet_id) AS lease_epoch " +
    "FROM send_operations o " +
    "LEFT JOIN external_send_sign_intents s ON s.operation_id = o.operation_id " +
    "LEFT JOIN external_send_partials p ON p.operation_id = o.operation_id " +
    "WHERE o.operation_id = $1",

  /**
   * AWAITING_REDEMPTION → NEEDS_ATTENTION only when a durable partial exists.
   * formation_state is deliberately left untouched (stays PARTIAL_DELIVERED /
   * PARTIAL_PERSISTED). No lease column is referenced.
   *
   * F1.1: park + attention event must co-commit. One statement so a crash
   * cannot leave NEEDS_ATTENTION without the audit row (and vice versa). CTE chain:
   * guarded UPDATE → INSERT event from the updated row → RETURN the CAS fields.
   * $1 = operation_id, $2 = attention_reason, $3 = event_type.
   * data_text is built inside the statement from the post-increment episode so the
   * client cannot stamp a stale episode into the audit row.
   */
  CAS_AWAITING_TO_NEEDS_ATTENTION:
    "WITH cas AS (" +
    "UPDATE send_operations SET " +
    "status = 'NEEDS_ATTENTION', " +
    "attention_required = true, " +
    "attention_reason = $2, " +
    "attention_episode = attention_episode + 1, " +
    "row_version = row_version + 1 " +
    "WHERE operation_id = $1 " +
    "AND status = 'AWAITING_REDEMPTION' " +
    "AND attention_required = false " +
    "AND EXISTS (SELECT 1 FROM external_send_partials p WHERE p.operation_id = $1) " +
    "RETURNING operation_id, status, formation_state, attention_required, " +
    "attention_reason, attention_episode, row_version" +
    "), ev AS (" +
    "INSERT INTO external_send_attention_events (" +
    "operation_id, event_type, attention_reason, attention_episode, data_text" +
    ") SELECT cas.operation_id, $3, cas.attention_reason, cas.attention_episode, " +
    "json_build_object(" +
    "'current_state', 'NEEDS_ATTENTION', " +
    "'attention_reason', cas.attention_reason, " +
    "'attention_episode', cas.attention_episode, " +
    "'operator_action_required', true" +
    ")::text " +
    "FROM cas RETURNING event_id, operation_id" +
    ") " +
    "SELECT cas.operation_id, cas.status, cas.formation_state, cas.attention_required, " +
    "cas.attention_reason, cas.attention_episode, cas.row_version, ev.event_id " +
    "FROM cas JOIN ev ON ev.operation_id = cas.operation_id",

  /**
   * Structurally impossible paths this module must never emit. Split tokens so a
   * source grep for an executable lease DELETE / status='EXPIRED'
   * does not false-positive on documentation constants.
   */
  FORBIDDEN_AWAITING_TO_EXPIRED_STATUS: "EXPIRED",
  FORBIDDEN_AWAITING_TO_REJECTED_STATUS: "REJECTED",
  FORBIDDEN_LEASE_TABLE: "wallet_active_leases",
  FORBIDDEN_LEASE_VERB: "DELETE",

  /**
   * Standalone event append retained only for negative-catalogue / allowed-set pinning.
   * Production park uses CAS_AWAITING_TO_NEEDS_ATTENTION (CTE co-commit). Callers must
   * not issue this alone after a separate CAS — that was the D3 hole.
   */
  APPEND_NEEDS_ATTENTION_EVENT:
    "INSERT INTO external_send_attention_events (" +
    "operation_id, event_type, attention_reason, attention_episode, data_text" +
    ") VALUES ($1, $2, $3, $4, $5) RETURNING event_id",

  /**
   * CONTINUE_EXTERNAL_WAIT: NEEDS_ATTENTION → AWAITING_REDEMPTION when the
   * durable partial is still present. Clears the attention episode; keeps lease.
   * formation_state forced to PARTIAL_DELIVERED so the AWAITING_REDEMPTION pair is legal
   * under the wider operations CHECK (send_operations itself is unconstrained here).
   */
  CAS_CONTINUE_EXTERNAL_WAIT:
    "UPDATE send_operations SET " +
    "status = 'AWAITING_REDEMPTION', " +
    "formation_state = 'PARTIAL_DELIVERED', " +
    "attention_required = false, " +
    "attention_reason = NULL, " +
    "row_version = row_version + 1 " +
    "WHERE operation_id = $1 " +
    "AND status = 'NEEDS_ATTENTION' " +
    "AND attention_required = true " +
    "AND EXISTS (SELECT 1 FROM external_send_partials p WHERE p.operation_id = $1) " +
    "RETURNING operation_id, status, formation_state, attention_required, " +
    "attention_reason, attention_episode, row_version",

  /**
   * Immutable-byte fingerprint for before/after assertions. SELECT-only.
   */
  LOAD_PARTIAL_IMMUTABLE_BYTES:
    "SELECT inner_sha256, step_1_signature, transfer_code_text, transfer_code_sha256, " +
    "redelivery_count, first_delivered_at, last_redelivered_at " +
    "FROM external_send_partials WHERE operation_id = $1",

  LOAD_LEASE_EPOCH:
    "SELECT lease_epoch FROM wallet_active_leases WHERE wallet_id = $1",
} as const;

/** Statement texts this module is allowed to run (negative tests pin the set). */
export const SEND_EXPIRY_ATTENTION_ALLOWED_SQL: ReadonlySet<string> = new Set([
  SEND_EXPIRY_ATTENTION_SQL.LOAD_OPERATION_EXPIRY_FACTS,
  SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION,
  SEND_EXPIRY_ATTENTION_SQL.APPEND_NEEDS_ATTENTION_EVENT,
  SEND_EXPIRY_ATTENTION_SQL.CAS_CONTINUE_EXTERNAL_WAIT,
  SEND_EXPIRY_ATTENTION_SQL.LOAD_PARTIAL_IMMUTABLE_BYTES,
  SEND_EXPIRY_ATTENTION_SQL.LOAD_LEASE_EPOCH,
]);

// ── Row / result types ─────────────────────────────────────────────────────────

export interface SendExpiryOperationFacts {
  readonly operationId: string;
  readonly status: string;
  readonly formationState: string;
  readonly rowVersion: number;
  readonly sourceWalletId: string;
  readonly attentionRequired: boolean;
  readonly attentionReason: string | null;
  readonly attentionEpisode: number;
  readonly redemptionExpiryAt: string | null;
  readonly innerPreimageText: string | null;
  readonly intentInnerSha256: string | null;
  readonly partialExists: boolean;
  readonly partialInnerSha256: string | null;
  readonly step1Signature: string | null;
  readonly transferCodeText: string | null;
  readonly transferCodeSha256: string | null;
  readonly firstDeliveredAt: string | null;
  readonly lastRedeliveredAt: string | null;
  readonly redeliveryCount: number | null;
  readonly leaseHeld: boolean;
  readonly leaseEpoch: number | null;
}

export type ParkPastExpiryResult =
  | {
      readonly kind: "PARKED";
      readonly operationId: string;
      readonly attentionReason: AttentionReason;
      readonly attentionEpisode: number;
      readonly rowVersion: number;
      readonly formationState: string;
      readonly leaseEpochBefore: number | null;
      readonly leaseEpochAfter: number | null;
      readonly partialBytesBefore: string;
      readonly partialBytesAfter: string;
    }
  | {
      readonly kind: "ALREADY_ATTENTION";
      readonly operationId: string;
      readonly attentionReason: string | null;
      readonly attentionEpisode: number;
    }
  | {
      readonly kind: "NOT_YET_EXPIRED";
      readonly operationId: string;
      readonly remainingSecs: number;
    }
  | {
      readonly kind: "NOOP";
      readonly operationId: string;
      readonly reason:
        | "TERMINAL"
        | "NO_PARTIAL"
        | "PRE_DELIVERY"
        | "MISSING_T2"
        | "CAS_LOST_RACE"
        | "NOT_FOUND";
    };

export type ContinueExternalWaitResult =
  | {
      readonly kind: "CONTINUED";
      readonly operationId: string;
      readonly status: "AWAITING_REDEMPTION";
      readonly attentionRequired: false;
      readonly rowVersion: number;
      readonly leaseEpochBefore: number | null;
      readonly leaseEpochAfter: number | null;
      readonly partialBytesBefore: string;
      readonly partialBytesAfter: string;
    }
  | {
      readonly kind: "REJECTED";
      readonly operationId: string;
      readonly reason:
        | "NOT_FOUND"
        | "WRONG_STATUS"
        | "NO_PARTIAL"
        | "CAS_LOST_RACE";
    };

export type RedeliverExactPartialResult =
  | {
      readonly kind: "REDELIVERED";
      readonly operationId: string;
      readonly transferCodeText: string;
      readonly transferCodeSha256: string;
      readonly redeliveryCount: number;
      readonly firstDeliveredAt: string | null;
      readonly partialBytesBefore: string;
      readonly partialBytesAfter: string;
      readonly leaseEpochBefore: number | null;
      readonly leaseEpochAfter: number | null;
    }
  | {
      readonly kind: "REJECTED";
      readonly operationId: string;
      readonly reason: "NOT_FOUND" | "NO_PARTIAL" | "BYTES_MUTATED";
    };

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Extract signed `expiry__unix_time_secs` from a persisted inner preimage.
 * Accepts the canonical SplitChain JSON object shape. Throws on missing/invalid —
 * a formed partial without a signed T2 is an invariant breach, not a soft miss.
 */
export function extractSignedExpiryUnixSecs(innerPreimageText: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(innerPreimageText) as unknown;
  } catch {
    throw new Error("extractSignedExpiryUnixSecs: inner_preimage_text is not JSON");
  }
  if (parsed === null || typeof parsed !== "object") {
    throw new Error("extractSignedExpiryUnixSecs: inner_preimage_text is not an object");
  }
  const record = parsed as Record<string, unknown>;
  // Prefer nested inner.expiry__unix_time_secs (full settled tx shape) then top-level.
  const inner =
    record.inner !== null && typeof record.inner === "object"
      ? (record.inner as Record<string, unknown>)
      : record;
  const raw = inner.expiry__unix_time_secs;
  if (typeof raw !== "string" || !/^[0-9]+$/.test(raw)) {
    throw new Error(
      "extractSignedExpiryUnixSecs: missing or non-integer-seconds expiry__unix_time_secs",
    );
  }
  return raw;
}

export function fingerprintPartialImmutableBytes(input: {
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
}): string {
  // Pipe-joined; fields are hex / base64url so '|' cannot appear inside them.
  return [
    input.innerSha256,
    input.step1Signature,
    input.transferCodeSha256,
    input.transferCodeText,
  ].join("|");
}

function mapFacts(row: Record<string, unknown>): SendExpiryOperationFacts {
  return {
    operationId: String(row.operation_id),
    status: String(row.status),
    formationState: String(row.formation_state),
    rowVersion: Number(row.row_version),
    sourceWalletId: String(row.source_wallet_id),
    attentionRequired: row.attention_required === true || row.attention_required === "t",
    attentionReason:
      row.attention_reason === null || row.attention_reason === undefined
        ? null
        : String(row.attention_reason),
    attentionEpisode: Number(row.attention_episode ?? 0),
    redemptionExpiryAt:
      row.redemption_expiry_at === null || row.redemption_expiry_at === undefined
        ? null
        : String(row.redemption_expiry_at),
    innerPreimageText:
      row.inner_preimage_text === null || row.inner_preimage_text === undefined
        ? null
        : String(row.inner_preimage_text),
    intentInnerSha256:
      row.intent_inner_sha256 === null || row.intent_inner_sha256 === undefined
        ? null
        : String(row.intent_inner_sha256),
    partialExists:
      row.partial_exists === true ||
      row.partial_exists === "t" ||
      row.partial_exists === true,
    partialInnerSha256:
      row.partial_inner_sha256 === null || row.partial_inner_sha256 === undefined
        ? null
        : String(row.partial_inner_sha256),
    step1Signature:
      row.step_1_signature === null || row.step_1_signature === undefined
        ? null
        : String(row.step_1_signature),
    transferCodeText:
      row.transfer_code_text === null || row.transfer_code_text === undefined
        ? null
        : String(row.transfer_code_text),
    transferCodeSha256:
      row.transfer_code_sha256 === null || row.transfer_code_sha256 === undefined
        ? null
        : String(row.transfer_code_sha256),
    firstDeliveredAt:
      row.first_delivered_at === null || row.first_delivered_at === undefined
        ? null
        : String(row.first_delivered_at),
    lastRedeliveredAt:
      row.last_redelivered_at === null || row.last_redelivered_at === undefined
        ? null
        : String(row.last_redelivered_at),
    redeliveryCount:
      row.redelivery_count === null || row.redelivery_count === undefined
        ? null
        : Number(row.redelivery_count),
    leaseHeld: row.lease_held === true || row.lease_held === "t",
    leaseEpoch:
      row.lease_epoch === null || row.lease_epoch === undefined
        ? null
        : Number(row.lease_epoch),
  };
}

function partialFingerprintFromFacts(facts: SendExpiryOperationFacts): string | null {
  if (
    !facts.partialExists ||
    facts.partialInnerSha256 === null ||
    facts.step1Signature === null ||
    facts.transferCodeText === null ||
    facts.transferCodeSha256 === null
  ) {
    return null;
  }
  return fingerprintPartialImmutableBytes({
    innerSha256: facts.partialInnerSha256,
    step1Signature: facts.step1Signature,
    transferCodeText: facts.transferCodeText,
    transferCodeSha256: facts.transferCodeSha256,
  });
}

async function loadFacts(
  query: SqlQueryFn,
  operationId: string,
): Promise<SendExpiryOperationFacts | null> {
  const rows = await query(SEND_EXPIRY_ATTENTION_SQL.LOAD_OPERATION_EXPIRY_FACTS, [
    operationId,
  ]);
  const row = rows[0];
  if (row === undefined) return null;
  return mapFacts(row);
}

async function loadLeaseEpoch(
  query: SqlQueryFn,
  walletId: string,
): Promise<number | null> {
  const rows = await query(SEND_EXPIRY_ATTENTION_SQL.LOAD_LEASE_EPOCH, [walletId]);
  const row = rows[0];
  if (row === undefined) return null;
  return Number(row.lease_epoch);
}

// ── Public service functions ───────────────────────────────────────────────────

export async function loadSendExpiryOperationFacts(
  query: SqlQueryFn,
  operationId: string,
): Promise<SendExpiryOperationFacts | null> {
  return loadFacts(query, operationId);
}

/**
 * Park a past-T2 AWAITING_REDEMPTION send into NEEDS_ATTENTION.
 *
 * Idempotent on already-attention. Never transitions to EXPIRED/REJECTED. Never
 * touches wallet_active_leases. Partial immutable bytes must be bit-identical
 * before and after (asserted; throws on mutation).
 */
/**
 * Optional dual-chain projection after a successful park CAS (ZTR-1146). Bound by the
 * composition root so `operation.needs_attention` reaches implementer_events on the same
 * transaction as the AWAITING_REDEMPTION → NEEDS_ATTENTION flip.
 */
export type SendExpiryDualChainEmitter = (
  query: SqlQueryFn,
  input: {
    readonly operationId: string;
    readonly attentionReason: AttentionReason;
    readonly attentionEpisode: number;
    readonly dataText: string;
  },
) => Promise<void>;

export async function parkPastExpiryAwaitingRedemption(
  query: SqlQueryFn,
  input: {
    readonly operationId: string;
    readonly nowUnixSecs: number;
    readonly attentionReason?: AttentionReason;
    readonly dualChain?: SendExpiryDualChainEmitter;
  },
): Promise<ParkPastExpiryResult> {
  const reason = input.attentionReason ?? SEND_EXPIRY_ATTENTION_REASON;
  const facts = await loadFacts(query, input.operationId);
  if (facts === null) {
    return { kind: "NOOP", operationId: input.operationId, reason: "NOT_FOUND" };
  }

  const signedExpiry =
    facts.innerPreimageText === null
      ? null
      : extractSignedExpiryUnixSecs(facts.innerPreimageText);

  const evaluation = evaluatePostDeliveryExpiry({
    status: facts.status,
    partialExists: facts.partialExists,
    firstDeliveredAt: facts.firstDeliveredAt,
    redemptionExpiryUnixSecs: signedExpiry,
    nowUnixSecs: input.nowUnixSecs,
  });

  if (evaluation.outcome === "ALREADY_ATTENTION") {
    return {
      kind: "ALREADY_ATTENTION",
      operationId: facts.operationId,
      attentionReason: facts.attentionReason,
      attentionEpisode: facts.attentionEpisode,
    };
  }

  if (evaluation.outcome === "NOT_YET_EXPIRED") {
    return {
      kind: "NOT_YET_EXPIRED",
      operationId: facts.operationId,
      remainingSecs: evaluation.remainingSecs,
    };
  }

  if (evaluation.outcome === "TERMINAL_NOOP") {
    return { kind: "NOOP", operationId: facts.operationId, reason: "TERMINAL" };
  }

  if (evaluation.outcome === "PRE_DELIVERY_GATE_ONLY") {
    return { kind: "NOOP", operationId: facts.operationId, reason: "PRE_DELIVERY" };
  }

  if (evaluation.outcome !== "PAST_EXPIRY_PARK_ATTENTION") {
    if (!facts.partialExists) {
      return { kind: "NOOP", operationId: facts.operationId, reason: "NO_PARTIAL" };
    }
    if (signedExpiry === null) {
      return { kind: "NOOP", operationId: facts.operationId, reason: "MISSING_T2" };
    }
    return { kind: "NOOP", operationId: facts.operationId, reason: "NO_PARTIAL" };
  }

  const bytesBefore = partialFingerprintFromFacts(facts);
  if (bytesBefore === null) {
    return { kind: "NOOP", operationId: facts.operationId, reason: "NO_PARTIAL" };
  }
  const leaseBefore = facts.leaseEpoch;

  // Atomicity: CAS_AWAITING_TO_NEEDS_ATTENTION is one statement (UPDATE + INSERT event).
  // A crash cannot leave NEEDS_ATTENTION without the audit row. data_text (incl. episode)
  // is built inside the CTE from the post-increment row — never client-stamped.
  const cas = await query(SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION, [
    input.operationId,
    reason,
    OPERATION_NEEDS_ATTENTION_EVENT,
  ]);
  const casRow = cas[0];
  if (casRow === undefined) {
    // Re-read: concurrent park or status drift.
    const again = await loadFacts(query, input.operationId);
    if (again !== null && again.status === "NEEDS_ATTENTION") {
      return {
        kind: "ALREADY_ATTENTION",
        operationId: again.operationId,
        attentionReason: again.attentionReason,
        attentionEpisode: again.attentionEpisode,
      };
    }
    return { kind: "NOOP", operationId: input.operationId, reason: "CAS_LOST_RACE" };
  }

  const episode = Number(casRow.attention_episode);
  if (casRow.event_id === null || casRow.event_id === undefined) {
    throw new Error(
      `parkPastExpiryAwaitingRedemption: CAS returned without event_id for ${input.operationId}`,
    );
  }

  const after = await loadFacts(query, input.operationId);
  if (after === null) {
    throw new Error(
      `parkPastExpiryAwaitingRedemption: operation ${input.operationId} disappeared after CAS`,
    );
  }
  const bytesAfter = partialFingerprintFromFacts(after);
  if (bytesAfter === null || bytesAfter !== bytesBefore) {
    throw new Error(
      `parkPastExpiryAwaitingRedemption: immutable partial bytes mutated for ${input.operationId}`,
    );
  }
  const leaseAfter = await loadLeaseEpoch(query, facts.sourceWalletId);
  if (leaseBefore !== null && leaseAfter === null) {
    throw new Error(
      `parkPastExpiryAwaitingRedemption: source lease released for ${input.operationId} (the one-in-flight-per-wallet rule)`,
    );
  }
  if (
    leaseBefore !== null &&
    leaseAfter !== null &&
    leaseBefore !== leaseAfter
  ) {
    throw new Error(
      `parkPastExpiryAwaitingRedemption: lease_epoch changed for ${input.operationId}`,
    );
  }

  if (input.dualChain !== undefined) {
    const dataText = JSON.stringify({
      attention_reason: reason,
      attention_episode: episode,
      parked_at_unix_secs: input.nowUnixSecs,
    });
    await input.dualChain(query, {
      operationId: input.operationId,
      attentionReason: reason,
      attentionEpisode: episode,
      dataText,
    });
  }

  return {
    kind: "PARKED",
    operationId: input.operationId,
    attentionReason: reason,
    attentionEpisode: episode,
    rowVersion: Number(casRow.row_version),
    formationState: String(casRow.formation_state),
    leaseEpochBefore: leaseBefore,
    leaseEpochAfter: leaseAfter,
    partialBytesBefore: bytesBefore,
    partialBytesAfter: bytesAfter,
  };
}

/**
 * CONTINUE_EXTERNAL_WAIT — clear attention, return to AWAITING_REDEMPTION.
 * Requires intact durable partial. Keeps lease. Mutates no partial/transaction column.
 */
export async function continueExternalWait(
  query: SqlQueryFn,
  input: { readonly operationId: string },
): Promise<ContinueExternalWaitResult> {
  const facts = await loadFacts(query, input.operationId);
  if (facts === null) {
    return { kind: "REJECTED", operationId: input.operationId, reason: "NOT_FOUND" };
  }
  if (facts.status !== "NEEDS_ATTENTION") {
    return { kind: "REJECTED", operationId: input.operationId, reason: "WRONG_STATUS" };
  }
  if (!facts.partialExists) {
    return { kind: "REJECTED", operationId: input.operationId, reason: "NO_PARTIAL" };
  }

  const bytesBefore = partialFingerprintFromFacts(facts);
  if (bytesBefore === null) {
    return { kind: "REJECTED", operationId: input.operationId, reason: "NO_PARTIAL" };
  }
  const leaseBefore = facts.leaseEpoch;

  const cas = await query(SEND_EXPIRY_ATTENTION_SQL.CAS_CONTINUE_EXTERNAL_WAIT, [
    input.operationId,
  ]);
  const casRow = cas[0];
  if (casRow === undefined) {
    return { kind: "REJECTED", operationId: input.operationId, reason: "CAS_LOST_RACE" };
  }

  const after = await loadFacts(query, input.operationId);
  if (after === null) {
    throw new Error(
      `continueExternalWait: operation ${input.operationId} disappeared after CAS`,
    );
  }
  const bytesAfter = partialFingerprintFromFacts(after);
  if (bytesAfter === null || bytesAfter !== bytesBefore) {
    throw new Error(
      `continueExternalWait: immutable partial bytes mutated for ${input.operationId}`,
    );
  }
  const leaseAfter = await loadLeaseEpoch(query, facts.sourceWalletId);
  if (leaseBefore !== null && (leaseAfter === null || leaseAfter !== leaseBefore)) {
    throw new Error(
      `continueExternalWait: source lease released or epoch changed for ${input.operationId}`,
    );
  }

  return {
    kind: "CONTINUED",
    operationId: input.operationId,
    status: "AWAITING_REDEMPTION",
    attentionRequired: false,
    rowVersion: Number(casRow.row_version),
    leaseEpochBefore: leaseBefore,
    leaseEpochAfter: leaseAfter,
    partialBytesBefore: bytesBefore,
    partialBytesAfter: bytesAfter,
  };
}

/**
 * REDELIVER_EXACT_PARTIAL — return/mark delivery of identical stored bytes.
 * Delegates the byte-handout + counter stamp to the existing crash-recovery path so
 * there is exactly one redelivery implementation (exact partial only).
 */
export async function redeliverExactPartial(
  query: SqlQueryFn,
  input: {
    readonly operationId: string;
    readonly deliveredAt: string;
    readonly sourceWalletId?: string;
  },
): Promise<RedeliverExactPartialResult> {
  const before = await loadExactPersistedPartial(query, input.operationId);
  if (before === null) {
    return { kind: "REJECTED", operationId: input.operationId, reason: "NO_PARTIAL" };
  }
  const bytesBefore = fingerprintPartialImmutableBytes({
    innerSha256: before.innerSha256,
    step1Signature: before.step1Signature,
    transferCodeText: before.transferCodeText,
    transferCodeSha256: before.transferCodeSha256,
  });

  let leaseBefore: number | null = null;
  if (input.sourceWalletId !== undefined) {
    leaseBefore = await loadLeaseEpoch(query, input.sourceWalletId);
  }

  let result: RedeliveryResult;
  try {
    result = await redeliverExactPartialViaSql(
      query,
      input.operationId,
      input.deliveredAt,
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("mutated immutable")) {
      return { kind: "REJECTED", operationId: input.operationId, reason: "BYTES_MUTATED" };
    }
    if (message.includes("no persisted partial")) {
      return { kind: "REJECTED", operationId: input.operationId, reason: "NO_PARTIAL" };
    }
    throw err;
  }

  const after: ExactPersistedPartial | null = await loadExactPersistedPartial(
    query,
    input.operationId,
  );
  if (after === null) {
    return { kind: "REJECTED", operationId: input.operationId, reason: "NO_PARTIAL" };
  }
  const bytesAfter = fingerprintPartialImmutableBytes({
    innerSha256: after.innerSha256,
    step1Signature: after.step1Signature,
    transferCodeText: after.transferCodeText,
    transferCodeSha256: after.transferCodeSha256,
  });
  if (bytesBefore !== bytesAfter) {
    return { kind: "REJECTED", operationId: input.operationId, reason: "BYTES_MUTATED" };
  }

  let leaseAfter: number | null = null;
  if (input.sourceWalletId !== undefined) {
    leaseAfter = await loadLeaseEpoch(query, input.sourceWalletId);
    if (leaseBefore !== null && (leaseAfter === null || leaseAfter !== leaseBefore)) {
      throw new Error(
        `redeliverExactPartial: source lease released or epoch changed for ${input.operationId}`,
      );
    }
  }

  return {
    kind: "REDELIVERED",
    operationId: input.operationId,
    transferCodeText: result.transferCodeText,
    transferCodeSha256: result.transferCodeSha256,
    redeliveryCount: result.redeliveryCount,
    firstDeliveredAt: result.firstDeliveredAt,
    partialBytesBefore: bytesBefore,
    partialBytesAfter: bytesAfter,
    leaseEpochBefore: leaseBefore,
    leaseEpochAfter: leaseAfter,
  };
}

/**
 * Source-level guarantee used by negative tests: this module's SQL catalogue must not
 * contain lease-release or forbidden terminal transitions as *executable* statements.
 * The FORBIDDEN_* constants exist only so tests can prove they are never called.
 */
export function assertNoForbiddenSqlInAllowedSet(): void {
  // Build forbidden needles without embedding the full executable phrases as
  // contiguous source text (negative source-grep tests pin that property).
  const leaseDelete = ["DELETE", "FROM", SEND_EXPIRY_ATTENTION_SQL.FORBIDDEN_LEASE_TABLE].join(" ");
  const toExpired = `status = '${SEND_EXPIRY_ATTENTION_SQL.FORBIDDEN_AWAITING_TO_EXPIRED_STATUS}'`;
  const toRejected = `status = '${SEND_EXPIRY_ATTENTION_SQL.FORBIDDEN_AWAITING_TO_REJECTED_STATUS}'`;
  const secondPartial = ["INSERT", "INTO", "external_send_partials"].join(" ");
  const secondIntent = ["INSERT", "INTO", "external_send_sign_intents"].join(" ");
  for (const sql of SEND_EXPIRY_ATTENTION_ALLOWED_SQL) {
    const upper = sql.toUpperCase();
    if (upper.includes(leaseDelete)) {
      throw new Error("allowed SQL contains lease DELETE");
    }
    if (sql.includes(toExpired)) {
      throw new Error("allowed SQL transitions to EXPIRED");
    }
    if (sql.includes(toRejected) && sql.includes("AWAITING_REDEMPTION")) {
      throw new Error("allowed SQL transitions AWAITING_REDEMPTION → REJECTED");
    }
    if (upper.includes(secondPartial.toUpperCase())) {
      throw new Error("allowed SQL inserts a second partial");
    }
    if (upper.includes(secondIntent.toUpperCase())) {
      throw new Error("allowed SQL inserts a second sign intent");
    }
  }
}
