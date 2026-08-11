/**
 * Per-scrape operational metrics snapshot collectors.
 *
 * DB-truth gauges: bounded COUNT/GROUP BY queries only. No money-path writes.
 * Process stamps (halt, leadership, storage pressure, readiness, worker health)
 * are supplied by the composition root — this module never imports receive/
 * operator/workers (core boundary: protocol/data/gateway/verifier only).
 */

import {
  emptyOperationalSnapshot,
  type MetricLeaseRole,
  type MetricOperationStatus,
  type MetricWalletState,
  type MetricWorkerName,
  type OperationalMetricsSnapshot,
  METRIC_LEASE_ROLES,
  METRIC_OPERATION_STATUSES,
  METRIC_WALLET_STATES,
  METRIC_WORKER_NAMES,
} from "./metrics.js";

/** Narrow node-postgres-shaped surface (local — core does not import receive/leases). */
export interface MetricsSqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ readonly rows: R[]; readonly rowCount?: number | null }>;
}

/**
 * Quarantine reasons that mean "unexpected head movement".
 * Closed pair — never free-text matched beyond these two relationship kinds.
 */
export const UNEXPECTED_HEAD_QUARANTINE_REASONS = [
  "GENESIS_AFTER_HISTORY",
  "REGRESSION",
] as const;

export const METRICS_SNAPSHOT_STATEMENTS = {
  COUNT_WALLETS_BY_STATE: `
SELECT state::text AS state, count(*)::int AS wallets
  FROM wallets
 GROUP BY state`
    .replace(/\s+/g, " ")
    .trim(),

  COUNT_AVAILABLE_WALLETS: `
SELECT count(*)::int AS available_count
  FROM wallets w
 WHERE w.key_origin = 'node_generated'
   AND w.recovery_verified_at IS NOT NULL
   AND w.state = 'AVAILABLE'
   AND NOT EXISTS (
         SELECT 1
           FROM receive_release_proofs rrp
           JOIN operation_wallets ow
             ON ow.operation_id = rrp.operation_id
            AND ow.operation_role = 'RECEIVER'
          WHERE ow.wallet_id = w.id)
   AND NOT EXISTS (
         SELECT 1
           FROM lease_release_proofs lrp
          WHERE lrp.wallet_id = w.id
            AND lrp.proof_kind = 'RECEIVE_EXPIRED_T0')`
    .replace(/\s+/g, " ")
    .trim(),

  COUNT_ACTIVE_LEASES_BY_ROLE: `
SELECT lease_role::text AS lease_role,
       count(*)::int AS leases,
       COALESCE(EXTRACT(EPOCH FROM (now() - min(acquired_at)))::int, 0) AS oldest_age_secs
  FROM wallet_active_leases
 GROUP BY lease_role`
    .replace(/\s+/g, " ")
    .trim(),

  QUEUE_DEPTH_AND_OLDEST_AGE: `
SELECT count(*)::int AS depth,
       COALESCE(EXTRACT(EPOCH FROM (now() - min(o.created_at)))::int, 0) AS oldest_age_secs
  FROM operations o
 WHERE o.kind = 'RECEIVE_EXTERNAL'
   AND o.status = 'CREATED'
   AND o.receiver_wallet_id IS NULL
   AND NOT EXISTS (
         SELECT 1
           FROM operation_wallets ow
          WHERE ow.operation_id = o.id
            AND ow.operation_role = 'RECEIVER')`
    .replace(/\s+/g, " ")
    .trim(),

  COUNT_QUARANTINED_UNEXPECTED_HEAD: `
SELECT count(*)::int AS wallets
  FROM wallets
 WHERE state = 'QUARANTINED'
   AND quarantine_reason IN ('GENESIS_AFTER_HISTORY', 'REGRESSION')`
    .replace(/\s+/g, " ")
    .trim(),

  // Only the post-delivery park counts. A NEEDS_ATTENTION send that never reached a
  // delivered partial (a formation failure) holds no source-wallet lease, so counting it
  // would overstate what is held against the wallet cap — the one thing this gauge is read
  // for. The two reasons are the two the completion lander parks under (F1.1's post-expiry
  // hold and B4's head anomaly); both are non-terminal and both keep the lease.
  COUNT_PARKED_EXTERNAL_SENDS: `
SELECT count(*)::int AS parked
  FROM send_operations s
 WHERE s.status = 'NEEDS_ATTENTION'
   AND s.attention_reason IN ('POST_EXPIRY_RECONCILING', 'UNEXPECTED_HEAD_CHANGE')
   AND EXISTS (SELECT 1 FROM external_send_partials p
                WHERE p.operation_id = s.operation_id
                  AND p.first_delivered_at IS NOT NULL)`
    .replace(/\s+/g, " ")
    .trim(),

  COUNT_ATTENTION_REQUIRED_OPS: `
SELECT count(*)::int AS attention
  FROM operations
 WHERE attention_required = true`
    .replace(/\s+/g, " ")
    .trim(),

  COUNT_OPERATIONS_BY_STATUS: `
SELECT status::text AS status,
       count(*)::int AS ops,
       COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at)))::int, 0) AS oldest_age_secs
  FROM operations
 GROUP BY status`
    .replace(/\s+/g, " ")
    .trim(),
} as const;

/** Process-local stamps the composition root already owns (readiness / halt / workers). */
export interface MetricsProcessStamps {
  readonly storagePressure: boolean;
  readonly signerLeadershipHeld: boolean;
  readonly haltEngaged: boolean;
  readonly readinessReady: boolean;
  readonly observationDegraded: boolean;
  readonly workerHealth?: Readonly<Partial<Record<MetricWorkerName, 0 | 1>>>;
  readonly poolCapTotal: number;
  /**
   * 1 when tracked in-flight signing work exists while leadership is absent.
   * Process stamp; composition root supplies from the shutdown registry.
   */
  readonly signerInFlightAmbiguous?: boolean;
}

function isWalletState(value: string): value is MetricWalletState {
  return (METRIC_WALLET_STATES as readonly string[]).includes(value);
}

function isLeaseRole(value: string): value is MetricLeaseRole {
  return (METRIC_LEASE_ROLES as readonly string[]).includes(value);
}

function isOperationStatus(value: string): value is MetricOperationStatus {
  return (METRIC_OPERATION_STATUSES as readonly string[]).includes(value);
}

/**
 * Collect the full per-scrape operational snapshot from DB + process stamps.
 * Safe to call on every scrape: read-only, bounded GROUP BY / COUNT scans.
 */
export async function collectOperationalMetricsSnapshot(
  db: MetricsSqlExecutor,
  stamps: MetricsProcessStamps,
): Promise<OperationalMetricsSnapshot> {
  const poolCapTotal = stamps.poolCapTotal;
  if (!Number.isInteger(poolCapTotal) || poolCapTotal < 1) {
    throw new RangeError(
      "collectOperationalMetricsSnapshot: poolCapTotal must be an integer >= 1",
    );
  }

  const [
    byStateRows,
    availableRows,
    leaseRows,
    queueRows,
    quarantineRows,
    opRows,
    parkedSendRows,
    attentionRows,
  ] =
    await Promise.all([
      db.query<{ state: string; wallets: number }>(
        METRICS_SNAPSHOT_STATEMENTS.COUNT_WALLETS_BY_STATE,
      ),
      db.query<{ available_count: number }>(METRICS_SNAPSHOT_STATEMENTS.COUNT_AVAILABLE_WALLETS),
      db.query<{ lease_role: string; leases: number; oldest_age_secs: number }>(
        METRICS_SNAPSHOT_STATEMENTS.COUNT_ACTIVE_LEASES_BY_ROLE,
      ),
      db.query<{ depth: number; oldest_age_secs: number }>(
        METRICS_SNAPSHOT_STATEMENTS.QUEUE_DEPTH_AND_OLDEST_AGE,
      ),
      db.query<{ wallets: number }>(
        METRICS_SNAPSHOT_STATEMENTS.COUNT_QUARANTINED_UNEXPECTED_HEAD,
      ),
      db.query<{ status: string; ops: number; oldest_age_secs: number }>(
        METRICS_SNAPSHOT_STATEMENTS.COUNT_OPERATIONS_BY_STATUS,
      ),
      db.query<{ parked: number }>(METRICS_SNAPSHOT_STATEMENTS.COUNT_PARKED_EXTERNAL_SENDS),
      db.query<{ attention: number }>(METRICS_SNAPSHOT_STATEMENTS.COUNT_ATTENTION_REQUIRED_OPS),
    ]);

  const walletsByState: Partial<Record<MetricWalletState, number>> = {};
  let totalWallets = 0;
  for (const row of byStateRows.rows) {
    const n = Number(row.wallets);
    totalWallets += n;
    if (isWalletState(row.state)) walletsByState[row.state] = n;
  }

  const activeLeasesByRole: Partial<Record<MetricLeaseRole, number>> = {};
  let oldestLeaseAgeSecs = 0;
  for (const row of leaseRows.rows) {
    const n = Number(row.leases);
    const age = Number(row.oldest_age_secs);
    if (isLeaseRole(row.lease_role)) activeLeasesByRole[row.lease_role] = n;
    if (age > oldestLeaseAgeSecs) oldestLeaseAgeSecs = age;
  }

  const operationsByStatus: Partial<Record<MetricOperationStatus, number>> = {};
  const operationsOldestAgeSecsByStatus: Partial<Record<MetricOperationStatus, number>> = {};
  for (const row of opRows.rows) {
    if (!isOperationStatus(row.status)) continue;
    operationsByStatus[row.status] = Number(row.ops);
    operationsOldestAgeSecsByStatus[row.status] = Number(row.oldest_age_secs);
  }

  const queue = queueRows.rows[0];
  const workerHealth: Partial<Record<MetricWorkerName, 0 | 1>> = {};
  for (const name of METRIC_WORKER_NAMES) {
    workerHealth[name] = stamps.workerHealth?.[name] ?? 0;
  }

  const base = emptyOperationalSnapshot();
  return {
    ...base,
    availableWallets: Number(availableRows.rows[0]?.available_count ?? 0),
    totalWallets,
    walletsByState,
    activeLeasesByRole,
    pinnedWallets: walletsByState.PINNED ?? 0,
    queueDepth: Number(queue?.depth ?? 0),
    queueOldestAgeSecs: Number(queue?.oldest_age_secs ?? 0),
    capUtilizationPercent: Math.floor((totalWallets * 100) / poolCapTotal),
    poolCapTotal,
    oldestLeaseAgeSecs,
    quarantinedUnexpectedHead: Number(quarantineRows.rows[0]?.wallets ?? 0),
    parkedExternalSends: Number(parkedSendRows.rows[0]?.parked ?? 0),
    attentionRequiredOps: Number(attentionRows.rows[0]?.attention ?? 0),
    signerInFlightAmbiguous: stamps.signerInFlightAmbiguous ? 1 : 0,
    operationsByStatus,
    operationsOldestAgeSecsByStatus,
    storagePressure: stamps.storagePressure ? 1 : 0,
    signerLeadershipHeld: stamps.signerLeadershipHeld ? 1 : 0,
    haltEngaged: stamps.haltEngaged ? 1 : 0,
    readinessReady: stamps.readinessReady ? 1 : 0,
    observationDegraded: stamps.observationDegraded ? 1 : 0,
    workerHealth,
  };
}

/**
 * Build a snapshot from already-computed pool pressure + process stamps when
 * the composition root already called collectPoolPressureMetrics (no second
 * wallet census). Lease-by-role and ops-by-status still need their own queries
 * unless the caller supplies them.
 */
export function snapshotFromPoolPressure(
  pressure: {
    readonly availableWalletCount: number;
    readonly capCount: number;
    readonly capUtilizationPercent: number;
    readonly poolCapTotal: number;
    readonly pinnedWalletCount: number;
    readonly queueDepth: number;
    readonly oldestQueuedAgeSecs: number;
    readonly oldestReceiveLeaseAgeSecs: number;
  },
  stamps: MetricsProcessStamps,
  extras?: {
    readonly activeLeasesByRole?: Readonly<Partial<Record<MetricLeaseRole, number>>>;
    readonly oldestLeaseAgeSecs?: number;
    readonly quarantinedUnexpectedHead?: number;
    readonly parkedExternalSends?: number;
    readonly attentionRequiredOps?: number;
    readonly operationsByStatus?: Readonly<Partial<Record<MetricOperationStatus, number>>>;
    readonly operationsOldestAgeSecsByStatus?: Readonly<
      Partial<Record<MetricOperationStatus, number>>
    >;
    readonly walletsByState?: Readonly<Partial<Record<MetricWalletState, number>>>;
  },
): OperationalMetricsSnapshot {
  const workerHealth: Partial<Record<MetricWorkerName, 0 | 1>> = {};
  for (const name of METRIC_WORKER_NAMES) {
    workerHealth[name] = stamps.workerHealth?.[name] ?? 0;
  }
  return {
    availableWallets: pressure.availableWalletCount,
    totalWallets: pressure.capCount,
    walletsByState: {
      AVAILABLE: pressure.availableWalletCount,
      PINNED: pressure.pinnedWalletCount,
      ...(extras?.walletsByState ?? {}),
    },
    activeLeasesByRole: extras?.activeLeasesByRole ?? {},
    pinnedWallets: pressure.pinnedWalletCount,
    queueDepth: pressure.queueDepth,
    queueOldestAgeSecs: pressure.oldestQueuedAgeSecs,
    capUtilizationPercent: pressure.capUtilizationPercent,
    poolCapTotal: pressure.poolCapTotal,
    oldestLeaseAgeSecs: extras?.oldestLeaseAgeSecs ?? pressure.oldestReceiveLeaseAgeSecs,
    quarantinedUnexpectedHead: extras?.quarantinedUnexpectedHead ?? 0,
    parkedExternalSends: extras?.parkedExternalSends ?? 0,
    attentionRequiredOps: extras?.attentionRequiredOps ?? 0,
    signerInFlightAmbiguous: stamps.signerInFlightAmbiguous ? 1 : 0,
    operationsByStatus: extras?.operationsByStatus ?? {},
    operationsOldestAgeSecsByStatus: extras?.operationsOldestAgeSecsByStatus ?? {},
    storagePressure: stamps.storagePressure ? 1 : 0,
    signerLeadershipHeld: stamps.signerLeadershipHeld ? 1 : 0,
    haltEngaged: stamps.haltEngaged ? 1 : 0,
    readinessReady: stamps.readinessReady ? 1 : 0,
    observationDegraded: stamps.observationDegraded ? 1 : 0,
    workerHealth,
  };
}
