// Reporting restore-hold evaluation and release.

import {
  compareContinuityMarkers,
  hashHoldReleaseEvidence,
  type ContinuityMarkers,
  type LocalContinuitySnapshot,
} from "./markers.js";
import {
  DISCOVER_RESTORE_NODE_IDS_SQL,
  runFailClosedPerNodeHold,
  withConnectedPgClient,
  type HoldDbClient,
} from "./hold-db-orchestration.js";

export type RestoreHoldRejectReason =
  | "missing_trusted_source"
  | "missing_local_snapshot"
  | "local_marker_incomplete"
  | "trusted_marker_incomplete"
  | "lifecycle_epoch_mismatch"
  | "nonce_burn_high_water_mismatch"
  | "terminal_event_hash_mismatch"
  | "local_event_hash_malformed"
  | "regression_lifecycle_epoch"
  | "regression_nonce_burn_high_water"
  | "explicit_evidence_required";

export type RestoreHoldDecision =
  | {
      readonly release: true;
      readonly holdReleaseEvidenceSha256: string;
      readonly trusted: ContinuityMarkers;
      readonly local: LocalContinuitySnapshot;
    }
  | {
      readonly release: false;
      readonly reason: RestoreHoldRejectReason;
      readonly detail?: string;
    };

export interface RestoreHoldEvaluationInput {
  readonly trusted: ContinuityMarkers | null;
  readonly local: LocalContinuitySnapshot | null;
  readonly priorTrusted?: {
    readonly lifecycleEpoch: bigint;
    readonly nonceBurnHighWater: bigint;
  };
}

export function evaluateRestoreHoldRelease(
  input: RestoreHoldEvaluationInput,
): RestoreHoldDecision {
  if (input.trusted === null) {
    return { release: false, reason: "missing_trusted_source" };
  }
  if (input.local === null) {
    return { release: false, reason: "missing_local_snapshot" };
  }

  const local = input.local;
  const trusted = input.trusted;

  if (!local.terminalEventHash) {
    return { release: false, reason: "local_marker_incomplete" };
  }

  if (input.priorTrusted !== undefined) {
    if (local.lifecycleEpoch < input.priorTrusted.lifecycleEpoch) {
      return { release: false, reason: "regression_lifecycle_epoch" };
    }
    if (local.nonceBurnHighWater < input.priorTrusted.nonceBurnHighWater) {
      return { release: false, reason: "regression_nonce_burn_high_water" };
    }
  }

  const comparison = compareContinuityMarkers(local, trusted);
  if (!comparison.equal) {
    return {
      release: false,
      reason: comparison.reason as RestoreHoldRejectReason,
      detail: comparison.reason,
    };
  }

  return {
    release: true,
    holdReleaseEvidenceSha256: hashHoldReleaseEvidence(trusted),
    trusted,
    local,
  };
}

export function buildRestoreHoldReleaseUpdate(input: {
  readonly nodeId: string;
  readonly decision: Extract<RestoreHoldDecision, { release: true }>;
  readonly now: Date;
}): { readonly sql: string; readonly params: readonly unknown[] } {
  const { decision, nodeId, now } = input;
  return {
    sql: `
      UPDATE reporting_restore_state
         SET restore_hold = false,
             local_lifecycle_epoch = $2,
             local_nonce_burn_high_water = $3,
             local_event_hash = $4,
             trusted_lifecycle_epoch = $5,
             trusted_nonce_burn_high_water = $6,
             trusted_event_hash = $7,
             trusted_source_id = $8,
             trusted_source_observed_at = $9::timestamptz,
             hold_release_evidence_sha256 = $10,
             hold_released_at = $11::timestamptz,
             updated_at = $11::timestamptz
       WHERE node_id = $1::uuid
         AND restore_hold = true
    `,
    params: [
      nodeId,
      decision.local.lifecycleEpoch.toString(),
      decision.local.nonceBurnHighWater.toString(),
      decision.local.terminalEventHash,
      decision.trusted.lifecycleEpoch,
      decision.trusted.nonceBurnHighWater,
      decision.trusted.terminalEventHash,
      decision.trusted.trustedSourceId,
      decision.trusted.trustedSourceObservedAt,
      decision.holdReleaseEvidenceSha256,
      now.toISOString(),
    ],
  };
}

/**
 * Post-restore fail-closed upsert.
 * A production ZBKP may encode restore_hold=false with release evidence columns
 * populated. ON CONFLICT DO NOTHING would leave that released row intact and
 * admission would treat the restored DB as not held. Always force hold=true and
 * null the release evidence so the CHECK allows hold=true again.
 */
export function buildForceRestoreHoldUpsert(input: {
  readonly nodeId: string;
  readonly now: Date;
}): { readonly sql: string; readonly params: readonly unknown[] } {
  return {
    sql: `
      INSERT INTO reporting_restore_state (
        node_id, restore_hold, created_at, updated_at
      ) VALUES ($1::uuid, true, $2::timestamptz, $2::timestamptz)
      ON CONFLICT (node_id) DO UPDATE
        SET restore_hold = true,
            local_lifecycle_epoch = NULL,
            local_nonce_burn_high_water = NULL,
            local_event_hash = NULL,
            trusted_lifecycle_epoch = NULL,
            trusted_nonce_burn_high_water = NULL,
            trusted_event_hash = NULL,
            trusted_source_id = NULL,
            trusted_source_observed_at = NULL,
            hold_release_evidence_sha256 = NULL,
            hold_released_at = NULL,
            updated_at = EXCLUDED.updated_at
    `,
    params: [input.nodeId, input.now.toISOString()],
  };
}

/** @deprecated alias — prefer buildForceRestoreHoldUpsert (forces hold on conflict). */
export function buildEnsureRestoreHoldInsert(input: {
  readonly nodeId: string;
  readonly now: Date;
}): { readonly sql: string; readonly params: readonly unknown[] } {
  return buildForceRestoreHoldUpsert(input);
}

export const REPORTING_RESTORE_STATE_EXISTS_SQL = `
  SELECT 1
    FROM information_schema.tables
   WHERE table_schema = 'public'
     AND table_name = 'reporting_restore_state'
   LIMIT 1
`;

/**
 * Connected-client body of restore_hold force. Shared by the URL wrapper and
 * dual-gate (same connection / transaction). Auth event-chain mutation stays
 * in auth-hold.ts — only restore-state SQL is applied here.
 */
export async function forceRestoreHoldOnClient(
  client: HoldDbClient,
  options: { readonly nodeId?: string; readonly now?: Date } = {},
): Promise<{ readonly applied: boolean; readonly nodeIds: readonly string[] }> {
  const now = options.now ?? new Date();
  // Prefer rows already present in the dump; fall back to nodes.id so a
  // greenfield dump without a restore-state row still gets held.
  return runFailClosedPerNodeHold(client, {
    tableExistsSql: REPORTING_RESTORE_STATE_EXISTS_SQL,
    explicitNodeId: options.nodeId,
    discoverNodeIdsSql: DISCOVER_RESTORE_NODE_IDS_SQL,
    applyPerNode: async (c, nodeId) => {
      const { sql, params } = buildForceRestoreHoldUpsert({ nodeId, now });
      await c.query(sql, params as unknown[]);
    },
  });
}

/**
 * After a successful psql apply, force reporting_restore_state.restore_hold=true
 * for every restored node (or a single explicit nodeId). No-ops when the
 * reporting schema is absent (e.g. destroy/restore drill DBs without the reporting DDL).
 * Fail-closed: any error while the table exists propagates to the caller.
 */
export async function applyForceRestoreHoldAfterRestore(
  databaseUrl: string,
  options: { readonly nodeId?: string; readonly now?: Date } = {},
): Promise<{ readonly applied: boolean; readonly nodeIds: readonly string[] }> {
  return withConnectedPgClient(databaseUrl, (client) =>
    forceRestoreHoldOnClient(client, options),
  );
}
