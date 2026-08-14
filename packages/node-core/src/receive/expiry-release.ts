// receive expiry, attention, and expired-unpaid release.
//
// Governing rules:
// * attention hold (a durable candidate can never terminally expire)
// * receive_release_proofs parent (receive_release_proofs parent is operations(id); kinds triple +
// biconditionals; EXPIRED_PROVEN_NOT_STARTED for lease+no-T0/code/artifact/signer)
// * walletless-receive expiry (wallet identity comes from lease + operation_wallets, never the
// nullable operations.receiver_wallet_id projection)
//
// The SQL implementation is deliberately transaction-factory based. The composition
// root must provide a SERIALIZABLE transaction. Every predicate is re-derived from
// durable rows while the operation and active lease are locked. Success delegates the
// destructive half to the sole guarded lease repository.

import { createHash, randomUUID } from "node:crypto";

import {
  completeGroupOperation,
  mintReleaseProof,
  releaseLease,
} from "../leases/repository.js";
import type {
  ActiveLeaseRow,
  CompleteGroupOperationParams,
  MintReleaseProofParams,
  ReleaseLeaseParams,
  SqlExecutor,
} from "../leases/types.js";
import { createSqlAcknowledgementStore } from "../verification/acknowledgement-sql.js";
import { evaluateGroupRelease } from "../verification/predicates.js";

// The contracts package deliberately does not publish pool-policy/receive-expiry
// subpaths. Keep these byte-exact twins next to the runtime that consumes them;
// parity is covered by the expiry-release contract tests.
export const RECEIVE_QUEUE_MAX_WAIT_MS = 30_000 as const;
export const POST_EXPIRY_RECONCILING = "POST_EXPIRY_RECONCILING" as const;
export const SAFE_TERMINAL_RELEASE_STATUS = "RELEASED_T0_UNCHANGED" as const;
export const RECEIVE_PROVEN_NOT_STARTED_RELEASE_STATUS =
  "RELEASED_PROVEN_NOT_STARTED" as const;
export const RECEIVE_EXPIRY_SAFETY_MARGIN_SECS = 30 as const;
export const RECEIVE_EXPIRED_EVENT = "operation.expired" as const;
export const RECEIVE_NEEDS_ATTENTION_EVENT = "operation.needs_attention" as const;
export const RECEIVE_EXPIRED_RELEASE_KIND = "EXPIRED_T0_UNCHANGED" as const;
export const RECEIVE_PROVEN_NOT_STARTED_RELEASE_KIND =
  "EXPIRED_PROVEN_NOT_STARTED" as const;
export const RECEIVE_EXPIRED_LEASE_PROOF_KIND = "RECEIVE_EXPIRED_T0" as const;
export const RECEIVE_EXPIRED_RELEASE_STATUS = SAFE_TERMINAL_RELEASE_STATUS;

export type ReceiveExpiryReleaseStatus =
  | typeof RECEIVE_EXPIRED_RELEASE_STATUS
  | typeof RECEIVE_PROVEN_NOT_STARTED_RELEASE_STATUS;

export type ReceiveExpiryReleaseKind =
  | typeof RECEIVE_EXPIRED_RELEASE_KIND
  | typeof RECEIVE_PROVEN_NOT_STARTED_RELEASE_KIND;

function isSafeTerminalReleaseStatus(
  value: string | null,
): value is ReceiveExpiryReleaseStatus {
  return (
    value === RECEIVE_EXPIRED_RELEASE_STATUS ||
    value === RECEIVE_PROVEN_NOT_STARTED_RELEASE_STATUS
  );
}

export type ReceiveExpiryAttentionReason =
  | typeof POST_EXPIRY_RECONCILING
  | "T0_RELEASE_MISMATCH"
  | "LEASE_INVARIANT_VIOLATION"
  | "EXACT_BYTES_UNAVAILABLE";

export interface ReceiveExpiryTxFactory {
  /**
   * Must run `fn` in a SERIALIZABLE database transaction and roll it back on throw.
   * The isolation requirement closes a lease-insert phantom around the walletless
   * expiry predicate.
   */
  withTransaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T>;
}

/**
 * Dual-chain projection for receive expiry events (ZTR-1146). Bound by the composition
 * root to `appendDurableDualChainEvent`. Runs on the same `tx` as the slice-local insert
 * so a failed append rolls back the EXPIRED / NEEDS_ATTENTION transition.
 */
export type ReceiveExpiryDualChainEmitter = (
  tx: SqlExecutor,
  input: {
    readonly operationId: string;
    readonly eventType: typeof RECEIVE_EXPIRED_EVENT | typeof RECEIVE_NEEDS_ATTENTION_EVENT;
    readonly dataText: string;
  },
) => Promise<void>;

/**
 * Outcome of the pre-transaction confirm-read that produced (or failed to produce)
 * `freshObservationId`. Threaded into attention_detail so operators can tell
 * "gateway unreadable" / "exact repeat" / "read never attempted" apart (ZTR-1279).
 */
export type FreshReadOutcome =
  | {
      readonly kind: "appended";
      readonly observationId: string;
      readonly relationship?: string;
    }
  | {
      readonly kind: "exact_repeat";
      readonly observationId: string;
    }
  | {
      readonly kind: "failed";
      readonly reason: string;
    }
  | {
      readonly kind: "skipped";
      readonly reason: string;
    }
  | {
      readonly kind: "not_attempted";
      readonly reason: string;
    };

/** Compact wire form for logs and attention_detail JSON. */
export function serializeFreshReadOutcome(
  outcome: FreshReadOutcome | null | undefined,
): string {
  if (outcome === undefined || outcome === null) return "unknown";
  switch (outcome.kind) {
    case "appended":
      return outcome.relationship !== undefined
        ? `appended:${outcome.relationship}:${outcome.observationId}`
        : `appended:${outcome.observationId}`;
    case "exact_repeat":
      return `exact-repeat:${outcome.observationId}`;
    case "failed":
      return `failed:${outcome.reason}`;
    case "skipped":
      return `skipped:${outcome.reason}`;
    case "not_attempted":
      return `not_attempted:${outcome.reason}`;
  }
}

export interface ExpireReceiveInput {
  readonly operationId: string;
  /** Fresh, already-persisted gateway observation produced for this expiry pass. */
  readonly freshObservationId: string | null;
  /**
   * How the confirm-read that produced `freshObservationId` resolved. Optional for
   * callers that only have an id (e.g. recovery action reusing a prior read); when
   * omitted, attention_detail still names failed predicates without a fresh-read clause.
   */
  readonly freshReadOutcome?: FreshReadOutcome | null;
  readonly nowMs?: number;
  readonly queueMaxWaitMs?: number;
  readonly safetyMarginSecs?: number;
  /** Test seam for deterministic proof IDs; production defaults to randomUUID. */
  readonly newId?: () => string;
}

export type ExpireReceiveOutcome =
  | { readonly kind: "NOT_FOUND" }
  | {
      readonly kind: "NOT_EXPIRED";
      readonly status: "CREATED" | "READY" | "EXPIRED";
      readonly expiresAtMs: number;
    }
  | { readonly kind: "LANDED"; readonly status: "RECEIVE_LANDED" }
  | {
      readonly kind: "CONFLICT";
      readonly status: string;
      readonly reason: "STATUS_OR_ROW_VERSION_CHANGED";
    }
  | {
      readonly kind: "EXPIRED_UNASSIGNED";
      readonly status: "EXPIRED";
      readonly eventAppended: boolean;
    }
  | {
      readonly kind: "NEEDS_ATTENTION";
      readonly status: "CREATED" | "READY" | "EXPIRED";
      readonly attentionReason: ReceiveExpiryAttentionReason;
      readonly attentionEpisode: number;
      readonly eventAppended: boolean;
      readonly failedPredicates: readonly ReceiveReleasePredicateName[];
      /** JSON written to operations.attention_detail (predicates + causes + fresh-read). */
      readonly attentionDetail: string;
      readonly walletStillPinned: true;
    }
  | {
      readonly kind: "INVARIANT_BREACH";
      readonly status: "CREATED" | "READY" | "EXPIRED";
      readonly attentionReason: "EXACT_BYTES_UNAVAILABLE";
      readonly attentionEpisode: number;
      readonly eventAppended: boolean;
      readonly failedPredicates: readonly ReceiveReleasePredicateName[];
      readonly attentionDetail: string;
      readonly walletId: string;
      readonly walletState: "QUARANTINED";
      readonly activeLeasePreserved: true;
    }
  | {
      readonly kind: "RELEASED";
      readonly status: "EXPIRED";
      readonly releaseStatus: ReceiveExpiryReleaseStatus;
      readonly releaseProofId: string;
      readonly receiveReleaseProofId: string;
      readonly walletId: string;
      readonly walletState: "AVAILABLE";
    }
  | {
      readonly kind: "ALREADY_RELEASED";
      readonly status: "EXPIRED";
      readonly releaseStatus: ReceiveExpiryReleaseStatus;
    };

export type ReceiveReleasePredicateName =
  | "EXPIRY_PLUS_SAFETY_MARGIN"
  | "NO_LANDED_PROOF"
  | "FRESH_VERIFIED_T0_EXACT"
  | "NO_ANOMALY_LINEAGE_OR_SUBMIT"
  | "CHILD_ABSENT_OR_SAFE_TERMINAL"
  | "PRE_CODE_FORMATION_PROVEN_SAFE";

export interface ReceiveReleasePredicates {
  readonly expiryPlusSafetyMargin: boolean;
  readonly noLandedProof: boolean;
  readonly freshVerifiedT0Exact: boolean;
  readonly noAnomalyLineageOrSubmit: boolean;
  readonly childAbsentOrSafeTerminal: boolean;
  readonly preCodeFormationProvenSafe: boolean;
}

export function failedReceiveReleasePredicates(
  predicates: ReceiveReleasePredicates,
): ReceiveReleasePredicateName[] {
  const failed: ReceiveReleasePredicateName[] = [];
  if (!predicates.expiryPlusSafetyMargin) failed.push("EXPIRY_PLUS_SAFETY_MARGIN");
  if (!predicates.noLandedProof) failed.push("NO_LANDED_PROOF");
  if (!predicates.freshVerifiedT0Exact) failed.push("FRESH_VERIFIED_T0_EXACT");
  if (!predicates.noAnomalyLineageOrSubmit) {
    failed.push("NO_ANOMALY_LINEAGE_OR_SUBMIT");
  }
  if (!predicates.childAbsentOrSafeTerminal) {
    failed.push("CHILD_ABSENT_OR_SAFE_TERMINAL");
  }
  if (!predicates.preCodeFormationProvenSafe) {
    failed.push("PRE_CODE_FORMATION_PROVEN_SAFE");
  }
  return failed;
}

export function allReceiveReleasePredicatesHold(
  predicates: ReceiveReleasePredicates,
): boolean {
  return failedReceiveReleasePredicates(predicates).length === 0;
}

/**
 * Base operator-language cause for each release predicate. Frozen safe vocabulary
 * (no drift-gate terms). Enriched further when a fresh-read outcome is known.
 */
export const RECEIVE_RELEASE_PREDICATE_CAUSES: Readonly<
  Record<ReceiveReleasePredicateName, string>
> = {
  EXPIRY_PLUS_SAFETY_MARGIN:
    "expiry plus safety margin not yet satisfied, or expiry bytes on the operation and code do not match",
  NO_LANDED_PROOF: "a landed proof row already exists for this receive",
  FRESH_VERIFIED_T0_EXACT:
    "fresh verified head does not match T0 exactly within the post-expiry window",
  NO_ANOMALY_LINEAGE_OR_SUBMIT:
    "anomaly, lineage gap, candidate, or submit evidence blocks terminal release",
  CHILD_ABSENT_OR_SAFE_TERMINAL:
    "a child operation is present and not in a safe terminal state",
  PRE_CODE_FORMATION_PROVEN_SAFE:
    "pre-code formation evidence is incomplete or inconsistent with a safe release",
};

function humanFreshReadClause(outcome: FreshReadOutcome | null | undefined): string | null {
  if (outcome === undefined || outcome === null) return null;
  switch (outcome.kind) {
    case "exact_repeat":
      return (
        "post-expiry confirm-read recorded as an exact repeat of the prior head " +
        `(observation ${outcome.observationId}); no distinct post-expiry head change was observed`
      );
    case "appended":
      return (
        `post-expiry confirm-read appended observation ${outcome.observationId}` +
        (outcome.relationship !== undefined ? ` (${outcome.relationship})` : "")
      );
    case "failed":
      return `post-expiry confirm-read failed: ${outcome.reason}`;
    case "skipped":
      return `post-expiry confirm-read was skipped: ${outcome.reason}`;
    case "not_attempted":
      return `post-expiry confirm-read was not attempted: ${outcome.reason}`;
  }
}

/**
 * Build the durable attention_detail JSON for a parked expiry release.
 * Includes bare predicate ids (backward compatible) plus per-predicate human causes
 * and the fresh-read outcome (ZTR-1279).
 */
export function buildReceiveExpiryAttentionDetail(
  failed: readonly ReceiveReleasePredicateName[],
  freshReadOutcome?: FreshReadOutcome | null,
  freshObservationId?: string | null,
): string {
  const freshClause = humanFreshReadClause(freshReadOutcome);
  const predicate_causes = failed.map((predicate) => {
    let cause = RECEIVE_RELEASE_PREDICATE_CAUSES[predicate];
    if (predicate === "FRESH_VERIFIED_T0_EXACT") {
      if (freshClause !== null) {
        cause = `${cause}; ${freshClause}`;
      } else if (freshObservationId === null || freshObservationId === undefined) {
        cause =
          `${cause}; no fresh observation id was supplied (confirm-read missing or null)`;
      }
    }
    return { predicate, cause };
  });
  const body: {
    failed_predicates: readonly ReceiveReleasePredicateName[];
    predicate_causes: readonly { predicate: string; cause: string }[];
    fresh_read?: {
      kind: string;
      observation_id?: string;
      relationship?: string;
      reason?: string;
      summary: string;
    };
  } = {
    failed_predicates: failed,
    predicate_causes,
  };
  if (freshReadOutcome !== undefined && freshReadOutcome !== null) {
    const summary = serializeFreshReadOutcome(freshReadOutcome);
    switch (freshReadOutcome.kind) {
      case "appended":
        body.fresh_read = {
          kind: "appended",
          observation_id: freshReadOutcome.observationId,
          ...(freshReadOutcome.relationship !== undefined
            ? { relationship: freshReadOutcome.relationship }
            : {}),
          summary,
        };
        break;
      case "exact_repeat":
        body.fresh_read = {
          kind: "exact-repeat",
          observation_id: freshReadOutcome.observationId,
          summary,
        };
        break;
      case "failed":
        body.fresh_read = {
          kind: "failed",
          reason: freshReadOutcome.reason,
          summary,
        };
        break;
      case "skipped":
        body.fresh_read = {
          kind: "skipped",
          reason: freshReadOutcome.reason,
          summary,
        };
        break;
      case "not_attempted":
        body.fresh_read = {
          kind: "not_attempted",
          reason: freshReadOutcome.reason,
          summary,
        };
        break;
    }
  }
  return JSON.stringify(body);
}

export const RECEIVE_EXPIRY_RELEASE_STATEMENTS = {
  LOCK_OPERATION: `
SELECT id::text AS id, status::text AS status, row_version::text AS row_version,
       receiver_wallet_id::text AS receiver_wallet_id,
       expiry_unix_time_secs, t0_observation_id::text AS t0_observation_id,
       attention_required, attention_reason,
       attention_episode::text AS attention_episode,
       receive_release_status, created_at::text AS created_at
  FROM operations
 WHERE id = $1::uuid
   AND kind = 'RECEIVE_EXTERNAL'
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  LOCK_RECEIVER_LEASE: `
SELECT l.wallet_id::text AS wallet_id,
       l.membership_id::text AS membership_id,
       l.lease_group_id::text AS lease_group_id,
       l.root_operation_id::text AS root_operation_id,
       l.operation_id::text AS operation_id,
       l.lease_role, l.lease_epoch::text AS lease_epoch,
       l.acquired_at::text AS acquired_at,
       l.heartbeat_at::text AS heartbeat_at,
       l.owner_instance_id::text AS owner_instance_id,
       l.release_not_before::text AS release_not_before
  FROM wallet_active_leases l
 WHERE l.operation_id = $1::uuid
   AND l.lease_role = 'RECEIVE_WINDOW'
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  LOAD_RECEIVER_BINDING: `
SELECT wallet_id::text AS wallet_id,
       t0_observation_id::text AS t0_observation_id
  FROM operation_wallets
 WHERE operation_id = $1::uuid
   AND operation_role = 'RECEIVER'`.replace(/\s+/g, " ").trim(),

  LOAD_MATERIAL_FACTS: `
SELECT
  (EXISTS (SELECT 1 FROM receive_codes c WHERE c.operation_id = $1::uuid)) AS code_exists,
  (SELECT c.code_status FROM receive_codes c WHERE c.operation_id = $1::uuid) AS code_status,
  (SELECT c.expiry_unix_time_secs FROM receive_codes c WHERE c.operation_id = $1::uuid)
    AS code_expiry_unix_time_secs,
  EXISTS (SELECT 1 FROM receive_arms a WHERE a.operation_id = $1::uuid) AS arm_exists,
  EXISTS (SELECT 1 FROM operation_expected_artifacts a
           WHERE a.operation_id = $1::uuid) AS artifact_exists,
  EXISTS (SELECT 1 FROM signer_audit a WHERE a.operation_id = $1::uuid) AS signer_audit_exists,
  EXISTS (SELECT 1 FROM operation_transactions t
           WHERE t.operation_id = $1::uuid) AS candidate_exists,
  EXISTS (SELECT 1 FROM gateway_submit_attempts a
           WHERE a.operation_id = $1::uuid) AS submit_exists,
  EXISTS (SELECT 1 FROM receive_landing_proofs p
           WHERE p.operation_id = $1::uuid) AS landed_proof_exists`.replace(/\s+/g, " ").trim(),

  LOAD_OBSERVATIONS: `
SELECT t0.id::text AS t0_id,
       t0.wallet_id::text AS t0_wallet_id,
       t0.wallet_public_key AS t0_wallet_public_key,
       t0_observer.domain::text AS t0_observer_domain,
       t0.s_signature AS t0_s, t0.p_signature AS t0_p, t0.b_amount AS t0_b,
       fresh.id::text AS fresh_id,
       fresh.wallet_id::text AS fresh_wallet_id,
       fresh.wallet_public_key AS fresh_wallet_public_key,
       fresh_observer.domain::text AS fresh_observer_domain,
       expected.public_key AS expected_wallet_public_key,
       fresh.s_signature AS fresh_s, fresh.p_signature AS fresh_p,
       fresh.b_amount AS fresh_b,
       fresh.parse_result::text AS fresh_parse_result,
       fresh.relationship::text AS fresh_relationship,
       fresh.observed_at::text AS fresh_observed_at,
       EXISTS (
         SELECT 1
           FROM observation_anomalies oa
           JOIN gateway_observations anomalous ON anomalous.id = oa.observation_id
          WHERE anomalous.wallet_id = $3::uuid
            AND anomalous.observed_at >= t0.observed_at
       ) AS anomaly_exists
  FROM gateway_observations t0
  JOIN gateway_observations fresh ON fresh.id = $2::uuid
  JOIN observers t0_observer ON t0_observer.id = t0.observer_id
  JOIN observers fresh_observer ON fresh_observer.id = fresh.observer_id
  JOIN wallets expected ON expected.id = $3::uuid
 WHERE t0.id = $1::uuid`.replace(/\s+/g, " ").trim(),

  CAS_TO_EXPIRED: `
UPDATE operations
   SET status = 'EXPIRED',
       row_version = row_version + 1,
       terminal_at = COALESCE(terminal_at, now()),
       updated_at = now()
 WHERE id = $1::uuid
   AND kind = 'RECEIVE_EXTERNAL'
   AND status = $2::operation_status
   AND row_version = $3::bigint
   AND NOT EXISTS (
         SELECT 1 FROM operation_transactions t WHERE t.operation_id = $1::uuid
       )
   AND NOT EXISTS (
         SELECT 1 FROM gateway_submit_attempts a WHERE a.operation_id = $1::uuid
       )
   AND NOT EXISTS (
         SELECT 1 FROM receive_landing_proofs p WHERE p.operation_id = $1::uuid
       )
 RETURNING status::text AS status, row_version::text AS row_version`.replace(/\s+/g, " ").trim(),

  CAS_UNASSIGNED_TO_EXPIRED: `
UPDATE operations
   SET status = 'EXPIRED',
       row_version = row_version + 1,
       terminal_at = COALESCE(terminal_at, now()),
       updated_at = now()
 WHERE id = $1::uuid
   AND kind = 'RECEIVE_EXTERNAL'
   AND status = 'CREATED'
   AND row_version = $2::bigint
   AND receiver_wallet_id IS NULL
   AND NOT EXISTS (
         SELECT 1 FROM operation_wallets ow
          WHERE ow.operation_id = $1::uuid AND ow.operation_role = 'RECEIVER'
       )
   AND NOT EXISTS (
         SELECT 1 FROM wallet_active_leases l
          WHERE l.operation_id = $1::uuid AND l.lease_role = 'RECEIVE_WINDOW'
       )
   AND NOT EXISTS (
         SELECT 1 FROM operation_transactions t WHERE t.operation_id = $1::uuid
       )
   AND NOT EXISTS (
         SELECT 1 FROM gateway_submit_attempts a WHERE a.operation_id = $1::uuid
       )
   AND NOT EXISTS (
         SELECT 1 FROM receive_landing_proofs p WHERE p.operation_id = $1::uuid
       )
 RETURNING status::text AS status`.replace(/\s+/g, " ").trim(),

  REVOKE_CODE: `
UPDATE receive_codes
   SET code_status = 'EXPIRED',
       released_at = COALESCE(released_at, now())
 WHERE operation_id = $1::uuid
   AND code_status IN ('AWAITING_ARM','RELEASED')
 RETURNING operation_id::text AS operation_id`.replace(/\s+/g, " ").trim(),

  APPEND_EXPIRED_EVENT: `
INSERT INTO receive_expiry_events (operation_id, event_type, data_text)
VALUES ($1::uuid, $2, $3)
ON CONFLICT (operation_id) DO NOTHING
RETURNING event_id`.replace(/\s+/g, " ").trim(),

  OPEN_ATTENTION_EPISODE: `
WITH opened AS (
  UPDATE operations
     SET attention_required = true,
         attention_reason = $2,
         attention_detail = $3,
         attention_episode = attention_episode + 1,
         row_version = row_version + 1,
         updated_at = now()
   WHERE id = $1::uuid
     AND attention_required = false
  RETURNING id, status, attention_episode, attention_reason
), event AS (
  INSERT INTO receive_expiry_attention_events (
    operation_id, event_type, attention_reason, attention_episode, data_text
  )
  SELECT id, $4, attention_reason, attention_episode,
         jsonb_build_object(
           'current_state', status::text,
           'attention_reason', attention_reason,
           'attention_episode', attention_episode,
           'operator_action_required', true,
           'failed_predicates', $5::jsonb
         )::text
    FROM opened
  RETURNING event_id, operation_id
)
SELECT opened.status::text AS status,
       opened.attention_episode::text AS attention_episode,
       event.event_id::text AS event_id
  FROM opened JOIN event ON event.operation_id = opened.id`.replace(/\s+/g, " ").trim(),

  LOAD_ATTENTION: `
SELECT status::text AS status, attention_required,
       attention_reason, attention_episode::text AS attention_episode,
       attention_detail
  FROM operations
 WHERE id = $1::uuid`.replace(/\s+/g, " ").trim(),

  ESCALATE_ATTENTION_TO_RECONCILING: `
UPDATE operations
   SET attention_reason = $2,
       attention_detail = $3,
       row_version = row_version + 1,
       updated_at = now()
 WHERE id = $1::uuid
   AND attention_required = true
   AND attention_reason IS DISTINCT FROM $2
 RETURNING status::text AS status, attention_reason,
           attention_episode::text AS attention_episode`.replace(/\s+/g, " ").trim(),

  INSERT_RECEIVE_RELEASE_PROOF: `
INSERT INTO receive_release_proofs (
  id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
  verification_acknowledgement_id, proof_manifest_text, proof_manifest_sha256, released_at
) VALUES (
  $1::uuid, $2::uuid, $3, $4::uuid, $5::uuid,
  NULL, $6, $7, to_timestamp($8 / 1000.0)
)
RETURNING id::text AS id`.replace(/\s+/g, " ").trim(),

  SET_RELEASE_STATUS: `
UPDATE operations
   SET receive_release_status = $2,
       attention_required = false,
       attention_reason = NULL,
       attention_detail = NULL,
       row_version = row_version + 1,
       updated_at = now()
 WHERE id = $1::uuid
   AND status = 'EXPIRED'
   AND receive_release_status IS NULL
 RETURNING receive_release_status`.replace(/\s+/g, " ").trim(),

  LOAD_CURRENT_STATUS: `
SELECT status::text AS status, row_version::text AS row_version,
       receive_release_status
  FROM operations
 WHERE id = $1::uuid`.replace(/\s+/g, " ").trim(),

  QUARANTINE_WALLET: `
UPDATE wallets
   SET state = 'QUARANTINED',
       quarantine_reason = COALESCE(
         quarantine_reason,
         'RECEIVE_INVARIANT_BREACH:EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT'
       )
 WHERE id = $1::uuid
   AND state IN ('PINNED','QUARANTINED')
 RETURNING state::text AS state`.replace(/\s+/g, " ").trim(),
} as const;

interface OperationRow {
  readonly id: string;
  readonly status: "CREATED" | "READY" | "RECEIVE_LANDED" | "EXPIRED";
  readonly row_version: string;
  readonly receiver_wallet_id: string | null;
  readonly expiry_unix_time_secs: string | null;
  readonly t0_observation_id: string | null;
  readonly attention_required: boolean;
  readonly attention_reason: string | null;
  readonly attention_episode: string;
  readonly receive_release_status: string | null;
  readonly created_at: string;
}

interface ReceiverBindingRow {
  readonly wallet_id: string;
  readonly t0_observation_id: string | null;
}

interface MaterialFactsRow {
  readonly code_exists: boolean;
  readonly code_status: string | null;
  readonly code_expiry_unix_time_secs: string | null;
  readonly arm_exists: boolean;
  readonly artifact_exists: boolean;
  readonly signer_audit_exists: boolean;
  readonly candidate_exists: boolean;
  readonly submit_exists: boolean;
  readonly landed_proof_exists: boolean;
}

interface ObservationFactsRow {
  readonly t0_id: string;
  readonly t0_wallet_id: string | null;
  readonly t0_wallet_public_key: string;
  readonly t0_observer_domain: string;
  readonly t0_s: string | null;
  readonly t0_p: string | null;
  readonly t0_b: string | null;
  readonly fresh_id: string;
  readonly fresh_wallet_id: string | null;
  readonly fresh_wallet_public_key: string;
  readonly fresh_observer_domain: string;
  readonly expected_wallet_public_key: string;
  readonly fresh_s: string | null;
  readonly fresh_p: string | null;
  readonly fresh_b: string | null;
  readonly fresh_parse_result: string;
  readonly fresh_relationship: string;
  readonly fresh_observed_at: string;
  readonly anomaly_exists: boolean;
}

function firstRow<R>(result: { readonly rows: readonly R[] }): R | undefined {
  return result.rows[0];
}

function asBool(value: unknown): boolean {
  return value === true || value === "t";
}

function unixSecondsToMs(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`receive expiry is not an integer-seconds string: ${JSON.stringify(value)}`);
  }
  const ms = Number(value) * 1000;
  if (!Number.isSafeInteger(ms)) {
    throw new RangeError("receive expiry is outside the safe millisecond range");
  }
  return ms;
}

function exactProjection(observations: ObservationFactsRow): boolean {
  return (
    observations.t0_s === observations.fresh_s &&
    observations.t0_p === observations.fresh_p &&
    observations.t0_b === observations.fresh_b
  );
}

function verifiedObservation(observations: ObservationFactsRow): boolean {
  return (
    observations.fresh_parse_result === "VERIFIED_GENESIS" ||
    observations.fresh_parse_result === "VERIFIED_HEAD"
  );
}

function safeUnchangedRelationship(observations: ObservationFactsRow): boolean {
  return (
    observations.fresh_relationship === "DUPLICATE" ||
    observations.fresh_relationship === "EQUIVALENT_STATE_DIFFERENT_ENVELOPE"
  );
}

function expiryTimeMs(
  operation: OperationRow,
  material: MaterialFactsRow,
  queueMaxWaitMs: number,
): number {
  if (operation.expiry_unix_time_secs !== null) {
    return unixSecondsToMs(operation.expiry_unix_time_secs);
  }
  return Date.parse(operation.created_at) + queueMaxWaitMs;
}

function expiryBytesMatch(operation: OperationRow, material: MaterialFactsRow): boolean {
  if (!material.code_exists) {
    return material.code_expiry_unix_time_secs === null;
  }
  return (
    operation.expiry_unix_time_secs !== null &&
    material.code_expiry_unix_time_secs !== null &&
    operation.expiry_unix_time_secs === material.code_expiry_unix_time_secs
  );
}

function attentionReasonFor(
  failed: readonly ReceiveReleasePredicateName[],
  material: MaterialFactsRow,
  lease: ActiveLeaseRow | undefined,
  binding: ReceiverBindingRow | undefined,
): ReceiveExpiryAttentionReason {
  if (
    material.candidate_exists ||
    material.submit_exists ||
    material.landed_proof_exists
  ) {
    return POST_EXPIRY_RECONCILING;
  }
  if (
    lease === undefined ||
    binding === undefined ||
    lease.wallet_id !== binding.wallet_id ||
    failed.includes("CHILD_ABSENT_OR_SAFE_TERMINAL") ||
    failed.includes("PRE_CODE_FORMATION_PROVEN_SAFE")
  ) {
    return "LEASE_INVARIANT_VIOLATION";
  }
  return "T0_RELEASE_MISMATCH";
}

function buildEventData(input: {
  readonly previousState: "CREATED" | "READY";
  readonly expiredAt: string;
  readonly walletAssigned: boolean;
  readonly releaseStatus: ReceiveExpiryReleaseStatus | null;
}): string {
  return JSON.stringify({
    previous_state: input.previousState,
    expired_at: input.expiredAt,
    wallet_assigned: input.walletAssigned,
    release_status: input.releaseStatus,
  });
}

async function appendExpiredEvent(
  tx: SqlExecutor,
  operationId: string,
  input: {
    readonly previousState: "CREATED" | "READY";
    readonly expiredAt: string;
    readonly walletAssigned: boolean;
    readonly releaseStatus: ReceiveExpiryReleaseStatus | null;
  },
  dualChain?: ReceiveExpiryDualChainEmitter,
): Promise<boolean> {
  const dataText = buildEventData(input);
  const inserted = await tx.query<{ event_id: string }>(
    RECEIVE_EXPIRY_RELEASE_STATEMENTS.APPEND_EXPIRED_EVENT,
    [
      operationId,
      RECEIVE_EXPIRED_EVENT,
      dataText,
    ],
  );
  if (inserted.rows.length === 1 && dualChain !== undefined) {
    await dualChain(tx, {
      operationId,
      eventType: RECEIVE_EXPIRED_EVENT,
      dataText,
    });
  }
  return inserted.rows.length === 1;
}

async function openAttention(
  tx: SqlExecutor,
  operationId: string,
  reason: ReceiveExpiryAttentionReason,
  failed: readonly ReceiveReleasePredicateName[],
  dualChain: ReceiveExpiryDualChainEmitter | undefined,
  freshReadOutcome: FreshReadOutcome | null | undefined,
  freshObservationId: string | null | undefined,
): Promise<Extract<ExpireReceiveOutcome, { kind: "NEEDS_ATTENTION" }>> {
  const detail = buildReceiveExpiryAttentionDetail(
    failed,
    freshReadOutcome,
    freshObservationId,
  );
  const opened = await tx.query<{
    status: "CREATED" | "READY" | "EXPIRED";
    attention_episode: string;
    event_id: string;
  }>(RECEIVE_EXPIRY_RELEASE_STATEMENTS.OPEN_ATTENTION_EPISODE, [
    operationId,
    reason,
    detail,
    RECEIVE_NEEDS_ATTENTION_EVENT,
    JSON.stringify(failed),
  ]);
  const row = opened.rows[0];
  if (row !== undefined) {
    if (dualChain !== undefined) {
      await dualChain(tx, {
        operationId,
        eventType: RECEIVE_NEEDS_ATTENTION_EVENT,
        dataText: detail,
      });
    }
    return {
      kind: "NEEDS_ATTENTION",
      status: row.status,
      attentionReason: reason,
      attentionEpisode: Number(row.attention_episode),
      eventAppended: true,
      failedPredicates: failed,
      attentionDetail: detail,
      walletStillPinned: true,
    };
  }
  const existing = firstRow(
    await tx.query<{
      status: "CREATED" | "READY" | "EXPIRED";
      attention_required: boolean;
      attention_reason: string | null;
      attention_episode: string;
      attention_detail: string | null;
    }>(RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOAD_ATTENTION, [operationId]),
  );
  if (existing === undefined || !asBool(existing.attention_required)) {
    throw new Error(`receive attention CAS lost without an open episode: ${operationId}`);
  }
  if (
    reason === POST_EXPIRY_RECONCILING &&
    existing.attention_reason !== POST_EXPIRY_RECONCILING
  ) {
    const escalated = firstRow(
      await tx.query<{
        status: "CREATED" | "READY" | "EXPIRED";
        attention_reason: typeof POST_EXPIRY_RECONCILING;
        attention_episode: string;
      }>(RECEIVE_EXPIRY_RELEASE_STATEMENTS.ESCALATE_ATTENTION_TO_RECONCILING, [
        operationId,
        POST_EXPIRY_RECONCILING,
        detail,
      ]),
    );
    if (escalated !== undefined) {
      return {
        kind: "NEEDS_ATTENTION",
        status: escalated.status,
        attentionReason: escalated.attention_reason,
        attentionEpisode: Number(escalated.attention_episode),
        eventAppended: false,
        failedPredicates: failed,
        attentionDetail: detail,
        walletStillPinned: true,
      };
    }
  }
  return {
    kind: "NEEDS_ATTENTION",
    status: existing.status,
    attentionReason:
      existing.attention_reason === POST_EXPIRY_RECONCILING ||
      existing.attention_reason === "T0_RELEASE_MISMATCH" ||
      existing.attention_reason === "LEASE_INVARIANT_VIOLATION" ||
      existing.attention_reason === "EXACT_BYTES_UNAVAILABLE"
        ? existing.attention_reason
        : reason,
    attentionEpisode: Number(existing.attention_episode),
    eventAppended: false,
    failedPredicates: failed,
    // In-process detail from this tick's predicate re-eval. Not written to
    // operations.attention_detail on the held path (only OPEN / ESCALATE write).
    // Legacy parked rows therefore keep open-time detail until escalation or
    // operator recovery — see docs/operations/attention-triage.md (ZTR-1285).
    attentionDetail: detail,
    walletStillPinned: true,
  };
}

function releaseProofManifest(input: {
  readonly releaseKind: ReceiveExpiryReleaseKind;
  readonly releaseStatus: ReceiveExpiryReleaseStatus;
  readonly operationId: string;
  readonly walletId: string;
  readonly expiryUnixTimeSecs: string | null;
  readonly t0ObservationId: string | null;
  readonly freshObservationId: string | null;
  readonly freshObservedAt: string | null;
  readonly safetyMarginSecs: number;
  readonly predicates: ReceiveReleasePredicates;
}): string {
  // Fixed insertion sequence: this digest is durable proof evidence.
  return JSON.stringify({
    release_kind: input.releaseKind,
    release_status: input.releaseStatus,
    operation_id: input.operationId,
    wallet_id: input.walletId,
    expiry_unix_time_secs: input.expiryUnixTimeSecs,
    t0_observation_id: input.t0ObservationId,
    fresh_observation_id: input.freshObservationId,
    fresh_observed_at: input.freshObservedAt,
    safety_margin_secs: input.safetyMarginSecs,
    predicates: {
      expiry_plus_safety_margin: input.predicates.expiryPlusSafetyMargin,
      no_landed_proof: input.predicates.noLandedProof,
      fresh_verified_t0_exact: input.predicates.freshVerifiedT0Exact,
      no_anomaly_lineage_or_submit: input.predicates.noAnomalyLineageOrSubmit,
      child_absent_or_safe_terminal: input.predicates.childAbsentOrSafeTerminal,
      pre_code_formation_proven_safe: input.predicates.preCodeFormationProvenSafe,
    },
  });
}

export interface ReceiveExpiryLeaseRepository {
  completeGroupOperation(
    tx: SqlExecutor,
    params: CompleteGroupOperationParams,
  ): Promise<void>;
  mintReleaseProof(
    tx: SqlExecutor,
    params: MintReleaseProofParams,
  ): Promise<void>;
  releaseLease(
    tx: SqlExecutor,
    params: ReleaseLeaseParams,
  ): Promise<unknown>;
}

const CANONICAL_RECEIVE_EXPIRY_LEASE_REPOSITORY: ReceiveExpiryLeaseRepository = {
  completeGroupOperation,
  mintReleaseProof,
  releaseLease,
};

export class SqlReceiveExpiryReleaseService {
  private readonly dualChain: ReceiveExpiryDualChainEmitter | undefined;

  constructor(
    txFactory: ReceiveExpiryTxFactory,
    leaseRepositoryOrDualChain?:
      | ReceiveExpiryLeaseRepository
      | ReceiveExpiryDualChainEmitter,
    dualChainMaybe?: ReceiveExpiryDualChainEmitter,
  ) {
    // Back-compat: (txFactory) | (txFactory, leaseRepo) | (txFactory, dualChain) |
    // (txFactory, leaseRepo, dualChain). A dual-chain emitter is detected by arity 2.
    this.txFactory = txFactory;
    if (
      leaseRepositoryOrDualChain !== undefined &&
      typeof leaseRepositoryOrDualChain === "function"
    ) {
      this.leaseRepository = CANONICAL_RECEIVE_EXPIRY_LEASE_REPOSITORY;
      this.dualChain = leaseRepositoryOrDualChain;
    } else {
      this.leaseRepository =
        (leaseRepositoryOrDualChain as ReceiveExpiryLeaseRepository | undefined) ??
        CANONICAL_RECEIVE_EXPIRY_LEASE_REPOSITORY;
      this.dualChain = dualChainMaybe;
    }
  }

  private readonly txFactory: ReceiveExpiryTxFactory;
  private readonly leaseRepository: ReceiveExpiryLeaseRepository;

  async expire(input: ExpireReceiveInput): Promise<ExpireReceiveOutcome> {
    const nowMs = input.nowMs ?? Date.now();
    const queueMaxWaitMs = input.queueMaxWaitMs ?? RECEIVE_QUEUE_MAX_WAIT_MS;
    const safetyMarginSecs =
      input.safetyMarginSecs ?? RECEIVE_EXPIRY_SAFETY_MARGIN_SECS;
    const safetyMarginMs = safetyMarginSecs * 1000;
    const newId = input.newId ?? randomUUID;
    const dualChain = this.dualChain;

    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new RangeError("expire receive nowMs must be a non-negative safe integer");
    }
    if (!Number.isSafeInteger(queueMaxWaitMs) || queueMaxWaitMs <= 0) {
      throw new RangeError("queueMaxWaitMs must be a positive safe integer");
    }
    if (!Number.isSafeInteger(safetyMarginSecs) || safetyMarginSecs <= 0) {
      throw new RangeError("safetyMarginSecs must be a positive safe integer");
    }

    return this.txFactory.withTransaction(async (tx) => {
      const operation = firstRow(
        await tx.query<OperationRow>(
          RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOCK_OPERATION,
          [input.operationId],
        ),
      );
      if (operation === undefined) return { kind: "NOT_FOUND" };
      if (operation.status === "RECEIVE_LANDED") {
        return { kind: "LANDED", status: "RECEIVE_LANDED" };
      }
      if (isSafeTerminalReleaseStatus(operation.receive_release_status)) {
        return {
          kind: "ALREADY_RELEASED",
          status: "EXPIRED",
          releaseStatus: operation.receive_release_status,
        };
      }

      const lease = firstRow(
        await tx.query<ActiveLeaseRow>(
          RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOCK_RECEIVER_LEASE,
          [input.operationId],
        ),
      );
      const binding = firstRow(
        await tx.query<ReceiverBindingRow>(
          RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOAD_RECEIVER_BINDING,
          [input.operationId],
        ),
      );
      const material = firstRow(
        await tx.query<MaterialFactsRow>(
          RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOAD_MATERIAL_FACTS,
          [input.operationId],
        ),
      );
      if (material === undefined) {
        throw new Error(`receive material query returned no row: ${input.operationId}`);
      }

      const expiresAtMs = expiryTimeMs(operation, material, queueMaxWaitMs);
      if (nowMs < expiresAtMs) {
        return { kind: "NOT_EXPIRED", status: operation.status, expiresAtMs };
      }

      // boundary is the durable candidate/submit/landing evidence itself, not the
      // presence of a projection or lease row. Check it before the unassigned branch so a
      // damaged operation can never use missing wallet linkage to terminally expire.
      if (
        material.candidate_exists ||
        material.submit_exists ||
        material.landed_proof_exists
      ) {
        if (material.code_exists) {
          await tx.query(RECEIVE_EXPIRY_RELEASE_STATEMENTS.REVOKE_CODE, [
            input.operationId,
          ]);
        }
        const failed: ReceiveReleasePredicateName[] = [
          ...(material.landed_proof_exists ? ["NO_LANDED_PROOF" as const] : []),
          ...((material.candidate_exists || material.submit_exists)
            ? ["NO_ANOMALY_LINEAGE_OR_SUBMIT" as const]
            : []),
        ];
        return openAttention(
          tx,
          input.operationId,
          POST_EXPIRY_RECONCILING,
          failed,
          dualChain,
          input.freshReadOutcome,
          input.freshObservationId,
        );
      }

      const unassigned = lease === undefined && binding === undefined;
      if (unassigned) {
        if (operation.status === "EXPIRED") {
          const appended = await appendExpiredEvent(tx, input.operationId, {
            previousState: "CREATED",
            expiredAt: new Date(nowMs).toISOString(),
            walletAssigned: false,
            releaseStatus: null,
          }, dualChain);
          return {
            kind: "EXPIRED_UNASSIGNED",
            status: "EXPIRED",
            eventAppended: appended,
          };
        }
        if (operation.status !== "CREATED") {
          return openAttention(
            tx,
            input.operationId,
            "LEASE_INVARIANT_VIOLATION",
            ["PRE_CODE_FORMATION_PROVEN_SAFE"],
            dualChain,
            input.freshReadOutcome,
            input.freshObservationId,
          );
        }
        const updated = await tx.query<{ status: "EXPIRED" }>(
          RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED,
          [input.operationId, operation.row_version],
        );
        if (updated.rows.length === 0) {
          const current = firstRow(
            await tx.query<{
              status: string;
              row_version: string;
              receive_release_status: string | null;
            }>(RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOAD_CURRENT_STATUS, [
              input.operationId,
            ]),
          );
          if (current?.status === "RECEIVE_LANDED") {
            return { kind: "LANDED", status: "RECEIVE_LANDED" };
          }
          return {
            kind: "CONFLICT",
            status: current?.status ?? "MISSING",
            reason: "STATUS_OR_ROW_VERSION_CHANGED",
          };
        }
        return {
          kind: "EXPIRED_UNASSIGNED",
          status: "EXPIRED",
          eventAppended: await appendExpiredEvent(tx, input.operationId, {
            previousState: "CREATED",
            expiredAt: new Date(nowMs).toISOString(),
            walletAssigned: false,
            releaseStatus: null,
          }, dualChain),
        };
      }

      // anti-stranding: a nullable operation projection is never wallet identity.
      if (
        lease === undefined ||
        binding === undefined ||
        lease.wallet_id !== binding.wallet_id
      ) {
        return openAttention(
          tx,
          input.operationId,
          "LEASE_INVARIANT_VIOLATION",
          ["PRE_CODE_FORMATION_PROVEN_SAFE"],
          dualChain,
          input.freshReadOutcome,
          input.freshObservationId,
        );
      }

      // Signer use without the expected exact code/artifact record can
      // never be classified as "not formed". Quarantine in the same transaction
      // and preserve the active lease.
      if (
        material.signer_audit_exists &&
        (!material.code_exists || !material.artifact_exists)
      ) {
        const quarantined = await tx.query<{ state: "QUARANTINED" }>(
          RECEIVE_EXPIRY_RELEASE_STATEMENTS.QUARANTINE_WALLET,
          [lease.wallet_id],
        );
        if (quarantined.rows.length !== 1) {
          throw new Error(
            `receive invariant-breach quarantine failed: ${lease.wallet_id}`,
          );
        }
        const attention = await openAttention(
          tx,
          input.operationId,
          "EXACT_BYTES_UNAVAILABLE",
          ["PRE_CODE_FORMATION_PROVEN_SAFE"],
          dualChain,
          input.freshReadOutcome,
          input.freshObservationId,
        );
        return {
          kind: "INVARIANT_BREACH",
          status: attention.status,
          attentionReason: "EXACT_BYTES_UNAVAILABLE",
          attentionEpisode: attention.attentionEpisode,
          eventAppended: attention.eventAppended,
          failedPredicates: attention.failedPredicates,
          attentionDetail: attention.attentionDetail,
          walletId: lease.wallet_id,
          walletState: "QUARANTINED",
          activeLeasePreserved: true,
        };
      }

      if (!expiryBytesMatch(operation, material)) {
        return openAttention(
          tx,
          input.operationId,
          "T0_RELEASE_MISMATCH",
          ["EXPIRY_PLUS_SAFETY_MARGIN"],
          dualChain,
          input.freshReadOutcome,
          input.freshObservationId,
        );
      }

      // Pre-boundary READY/CREATED expiry. The CAS is the arbiter against the
      // RECEIVE_LANDED DB-TX and rechecks absence of candidate/submit/landing rows.
      const previousState =
        operation.status === "EXPIRED"
          ? material.code_exists
            ? "READY"
            : "CREATED"
          : operation.status;
      if (operation.status !== "EXPIRED") {
        const updated = await tx.query<{ status: "EXPIRED"; row_version: string }>(
          RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_TO_EXPIRED,
          [input.operationId, operation.status, operation.row_version],
        );
        if (updated.rows.length === 0) {
          const current = firstRow(
            await tx.query<{
              status: string;
              row_version: string;
              receive_release_status: string | null;
            }>(RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOAD_CURRENT_STATUS, [
              input.operationId,
            ]),
          );
          if (current?.status === "RECEIVE_LANDED") {
            return { kind: "LANDED", status: "RECEIVE_LANDED" };
          }
          return {
            kind: "CONFLICT",
            status: current?.status ?? "MISSING",
            reason: "STATUS_OR_ROW_VERSION_CHANGED",
          };
        }
      }
      if (material.code_exists) {
        await tx.query(RECEIVE_EXPIRY_RELEASE_STATEMENTS.REVOKE_CODE, [
          input.operationId,
        ]);
      }

      const t0ObservationId =
        binding.t0_observation_id ?? operation.t0_observation_id;
      const groupFacts = await createSqlAcknowledgementStore().readGroupReleaseFacts(
        tx,
        lease.lease_group_id,
      );
      const childFacts = {
        childDisposition: groupFacts.childDisposition,
        operations: groupFacts.operations.filter(
          (fact) => fact.operationId !== input.operationId,
        ),
      };
      const noFormationEvidence =
        !material.code_exists &&
        !material.arm_exists &&
        !material.artifact_exists &&
        !material.signer_audit_exists;
      const childSafe =
        childFacts.operations.length === 0 &&
        childFacts.childDisposition === "NONE"
          ? true
          : evaluateGroupRelease(childFacts).status === "RELEASED";
      const expiryPlusSafetyMargin = nowMs >= expiresAtMs + safetyMarginMs;

      // PROVEN_NOT_STARTED: lease held, never T0/code/artifact/signer, never
      // candidate/submit/landing. Distinct from EXPIRED_T0_UNCHANGED (requires snapshots).
      if (
        t0ObservationId === null &&
        input.freshObservationId === null &&
        noFormationEvidence &&
        !material.candidate_exists &&
        !material.submit_exists &&
        !material.landed_proof_exists &&
        childSafe &&
        expiryPlusSafetyMargin
      ) {
        const predicates: ReceiveReleasePredicates = {
          expiryPlusSafetyMargin: true,
          noLandedProof: true,
          freshVerifiedT0Exact: true,
          noAnomalyLineageOrSubmit: true,
          childAbsentOrSafeTerminal: true,
          preCodeFormationProvenSafe: true,
        };
        return commitRelease(tx, this.leaseRepository, {
          operationId: input.operationId,
          previousState,
          nowMs,
          safetyMarginSecs,
          lease,
          expiryUnixTimeSecs: operation.expiry_unix_time_secs,
          releaseKind: RECEIVE_PROVEN_NOT_STARTED_RELEASE_KIND,
          releaseStatus: RECEIVE_PROVEN_NOT_STARTED_RELEASE_STATUS,
          t0ObservationId: null,
          freshObservationId: null,
          freshObservedAt: null,
          predicates,
          newId,
          dualChain,
        });
      }

      const observations =
        t0ObservationId === null || input.freshObservationId === null
          ? undefined
          : firstRow(
              await tx.query<ObservationFactsRow>(
                RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOAD_OBSERVATIONS,
                [t0ObservationId, input.freshObservationId, lease.wallet_id],
              ),
            );

      const freshObservedAtMs =
        observations === undefined ? Number.NaN : Date.parse(observations.fresh_observed_at);
      const freshWithinWindow =
        observations !== undefined &&
        freshObservedAtMs >= expiresAtMs + safetyMarginMs &&
        freshObservedAtMs <= nowMs &&
        nowMs - freshObservedAtMs <= safetyMarginMs;
      const freshExact =
        observations !== undefined &&
        observations.t0_wallet_id === lease.wallet_id &&
        observations.fresh_wallet_id === lease.wallet_id &&
        observations.t0_wallet_public_key ===
          observations.expected_wallet_public_key &&
        observations.fresh_wallet_public_key ===
          observations.expected_wallet_public_key &&
        observations.t0_observer_domain === "NODE" &&
        observations.fresh_observer_domain === "NODE" &&
        verifiedObservation(observations) &&
        exactProjection(observations) &&
        freshWithinWindow;
      const anomalyOrLineage =
        observations === undefined ||
        asBool(observations.anomaly_exists) ||
        !safeUnchangedRelationship(observations);

      const completeCodeAndArtifact =
        material.code_exists && material.artifact_exists;
      const preCodeFormationProvenSafe =
        (noFormationEvidence || completeCodeAndArtifact) &&
        !material.candidate_exists &&
        !material.submit_exists;
      const predicates: ReceiveReleasePredicates = {
        expiryPlusSafetyMargin,
        noLandedProof: !material.landed_proof_exists,
        freshVerifiedT0Exact: freshExact,
        noAnomalyLineageOrSubmit:
          !anomalyOrLineage && !material.candidate_exists && !material.submit_exists,
        childAbsentOrSafeTerminal: childSafe,
        preCodeFormationProvenSafe,
      };
      const failed = failedReceiveReleasePredicates(predicates);
      if (failed.length > 0 || observations === undefined || t0ObservationId === null) {
        return openAttention(
          tx,
          input.operationId,
          attentionReasonFor(failed, material, lease, binding),
          failed,
          dualChain,
          input.freshReadOutcome,
          input.freshObservationId,
        );
      }

      return commitRelease(tx, this.leaseRepository, {
        operationId: input.operationId,
        previousState,
        nowMs,
        safetyMarginSecs,
        lease,
        expiryUnixTimeSecs:
          operation.expiry_unix_time_secs ?? material.code_expiry_unix_time_secs,
        releaseKind: RECEIVE_EXPIRED_RELEASE_KIND,
        releaseStatus: RECEIVE_EXPIRED_RELEASE_STATUS,
        t0ObservationId,
        freshObservationId: observations.fresh_id,
        freshObservedAt: observations.fresh_observed_at,
        predicates,
        newId,
        dualChain,
      });
    });
  }
}

async function commitRelease(
  tx: SqlExecutor,
  leaseRepository: ReceiveExpiryLeaseRepository,
  input: {
    readonly operationId: string;
    readonly previousState: "CREATED" | "READY";
    readonly nowMs: number;
    readonly safetyMarginSecs: number;
    readonly lease: ActiveLeaseRow;
    readonly expiryUnixTimeSecs: string | null;
    readonly releaseKind: ReceiveExpiryReleaseKind;
    readonly releaseStatus: ReceiveExpiryReleaseStatus;
    readonly t0ObservationId: string | null;
    readonly freshObservationId: string | null;
    readonly freshObservedAt: string | null;
    readonly predicates: ReceiveReleasePredicates;
    readonly newId: () => string;
    readonly dualChain?: ReceiveExpiryDualChainEmitter;
  },
): Promise<Extract<ExpireReceiveOutcome, { kind: "RELEASED" }>> {
  const leaseProofId = input.newId();
  const receiveProofId = input.newId();
  const manifest = releaseProofManifest({
    releaseKind: input.releaseKind,
    releaseStatus: input.releaseStatus,
    operationId: input.operationId,
    walletId: input.lease.wallet_id,
    expiryUnixTimeSecs: input.expiryUnixTimeSecs,
    t0ObservationId: input.t0ObservationId,
    freshObservationId: input.freshObservationId,
    freshObservedAt: input.freshObservedAt,
    safetyMarginSecs: input.safetyMarginSecs,
    predicates: input.predicates,
  });
  const manifestSha = createHash("sha256").update(manifest, "utf8").digest("hex");

  await tx.query(RECEIVE_EXPIRY_RELEASE_STATEMENTS.INSERT_RECEIVE_RELEASE_PROOF, [
    receiveProofId,
    input.operationId,
    input.releaseKind,
    input.t0ObservationId,
    input.freshObservationId,
    manifest,
    manifestSha,
    input.nowMs,
  ]);

  await leaseRepository.completeGroupOperation(tx, {
    leaseGroupId: input.lease.lease_group_id,
    operationId: input.operationId,
  });
  await leaseRepository.mintReleaseProof(tx, {
    proofId: leaseProofId,
    walletId: input.lease.wallet_id,
    operationId: input.operationId,
    membershipId: input.lease.membership_id,
    leaseGroupId: input.lease.lease_group_id,
    leaseEpoch: BigInt(input.lease.lease_epoch),
    proofKind: RECEIVE_EXPIRED_LEASE_PROOF_KIND,
    proofDigest: manifestSha,
  });
  await leaseRepository.releaseLease(tx, {
    walletId: input.lease.wallet_id,
    ownerInstanceId: input.lease.owner_instance_id,
    operationId: input.operationId,
    membershipId: input.lease.membership_id,
    leaseGroupId: input.lease.lease_group_id,
    leaseEpoch: BigInt(input.lease.lease_epoch),
    releaseProofId: leaseProofId,
    releaseReason: input.releaseKind,
  });
  const released = await tx.query<{ receive_release_status: string }>(
    RECEIVE_EXPIRY_RELEASE_STATEMENTS.SET_RELEASE_STATUS,
    [input.operationId, input.releaseStatus],
  );
  if (released.rows.length !== 1) {
    throw new Error(`receive release status CAS failed: ${input.operationId}`);
  }
  await appendExpiredEvent(tx, input.operationId, {
    previousState: input.previousState,
    expiredAt: new Date(input.nowMs).toISOString(),
    walletAssigned: true,
    releaseStatus: input.releaseStatus,
  }, input.dualChain);

  return {
    kind: "RELEASED",
    status: "EXPIRED",
    releaseStatus: input.releaseStatus,
    releaseProofId: leaseProofId,
    receiveReleaseProofId: receiveProofId,
    walletId: input.lease.wallet_id,
    walletState: "AVAILABLE",
  };
}

// ── — worker-level scan for expired receives ──────────────────────
//
// The money worker tick calls this to discover operations the expiry-release
// service should process. The query is deliberately generous: it selects any
// RECEIVE_EXTERNAL that might need expiry work (status CREATED/READY/EXPIRED,
// no release yet, past expiry + safety margin). Walletless EXPIRED rows that
// already carry terminal_at are fully done (queue-age path stamps both in one
// UPDATE) — re-selecting them only re-appends receive_expiry_events forever
// (ZTR-1249). EXPIRED + receiver still assigned stays in the scan so lease
// release can finish. Attention-parked rows (`attention_required = true`) are
// excluded (ZTR-1277): each candidate may cost a live gateway fresh-head read,
// and parked rows cannot progress until operator RELEASE_EXPIRED_RECEIVE
// (when the five predicates hold), quarantine, or attention retraction —
// RETRY_OBSERVATION is deliberately not offered on EXPIRED attention-parked
// receives (ZTR-1283; row_version-only no-op). Re-scanning parked rows only
// hammers the gateway and bloats gateway_observations. After retraction the
// flag clears and the row naturally rejoins. The service itself re-derives
// every predicate under SERIALIZABLE isolation; this scan is selection only.

export const LOAD_EXPIRED_RECEIVE_CANDIDATES = `
SELECT o.id::text AS operation_id,
       o.status::text AS status,
       o.expiry_unix_time_secs,
       o.created_at::text AS created_at,
       o.t0_observation_id::text AS t0_observation_id,
       o.receiver_wallet_id::text AS receiver_wallet_id
  FROM operations o
 WHERE o.kind = 'RECEIVE_EXTERNAL'
   AND o.status IN ('CREATED','READY','EXPIRED')
   AND o.receive_release_status IS NULL
   AND o.attention_required = false
   AND NOT (
         o.status = 'EXPIRED'
         AND o.terminal_at IS NOT NULL
         AND o.receiver_wallet_id IS NULL
       )
   AND (
         (o.expiry_unix_time_secs IS NOT NULL AND
          o.expiry_unix_time_secs::numeric < EXTRACT(EPOCH FROM (now() - interval '30 seconds')))
         OR
         (o.expiry_unix_time_secs IS NULL AND
          o.created_at < now() - make_interval(secs => 60))
       )
 ORDER BY o.created_at ASC, o.id ASC /* contract-allow:order:frozen-sql-text */
 LIMIT 25`.replace(/\s+/g, " ").trim();

export interface ExpiredReceiveCandidate {
  readonly operationId: string;
  readonly status: "CREATED" | "READY" | "EXPIRED";
  readonly expiryUnixTimeSecs: string | null;
  readonly createdAt: string;
  readonly t0ObservationId: string | null;
  readonly receiverWalletId: string | null;
}

export async function loadExpiredReceiveCandidates(
  db: SqlExecutor,
): Promise<readonly ExpiredReceiveCandidate[]> {
  // The scan SQL is frozen text and projects snake_case column names; map them
  // to the typed candidate shape here so callers never receive undefined ids.
  const result = await db.query<{
    readonly operation_id: string;
    readonly status: "CREATED" | "READY" | "EXPIRED";
    readonly expiry_unix_time_secs: string | null;
    readonly created_at: string;
    readonly t0_observation_id: string | null;
    readonly receiver_wallet_id: string | null;
  }>(LOAD_EXPIRED_RECEIVE_CANDIDATES);
  return result.rows.map((row) => ({
    operationId: row.operation_id,
    status: row.status,
    expiryUnixTimeSecs: row.expiry_unix_time_secs,
    createdAt: row.created_at,
    t0ObservationId: row.t0_observation_id,
    receiverWalletId: row.receiver_wallet_id,
  }));
}
