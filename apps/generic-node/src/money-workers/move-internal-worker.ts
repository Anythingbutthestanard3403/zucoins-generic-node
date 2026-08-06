// generic-node shell binding for MOVE_INTERNAL money workers.
// Composes node-core pipeline under the custody money tick.
// Production default: lease + durable progress only; unbound baseline/form/sign/
// submit/land ports WAIT each tick (not green CREATED→LANDED). Full pipeline is
// offline composition (injected ports) or Wave-4 live path (≤0.01).

import type { Pool } from "pg";

import {
  acquireMoveLeases,
  createSqlMoveWorkerProgressLoader,
  runMoveInternalMoneyWorker,
  type MetricsHooks,
  type MoveInternalMoneyWorkerPorts,
  type MoveLeaseTxFn,
  type MoveMoneyWorkerAdvance,
  type MoneyPathSignerGates,
} from "@zucoins/node-core";

export interface MoveInternalWorkerLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface PendingMoveRow {
  readonly operationId: string;
  readonly implementerId: string;
  readonly nodeId: string;
  readonly sourceWalletId: string;
  readonly destinationId: string;
  readonly destinationWalletId: string;
  readonly sourcePublicKey: string;
  readonly destinationPublicKey: string;
  readonly amountZkz: string;
  readonly leaseGroupId: string;
  readonly spawnedFromOperationId: string | null;
  readonly rowVersion: number;
  readonly status: string;
}

export const LOAD_PENDING_MOVES_SQL = `
SELECT
  o.id::text AS operation_id,
  o.implementer_id::text AS implementer_id,
  o.node_id::text AS node_id,
  o.source_wallet_id::text AS source_wallet_id,
  o.destination_id::text AS destination_id,
  d.wallet_id::text AS destination_wallet_id,
  sw.public_key AS source_public_key,
  dw.public_key AS destination_public_key,
  o.amount_zkz::text AS amount_zkz,
  lgo.lease_group_id::text AS lease_group_id,
  o.spawned_from_operation_id::text AS spawned_from_operation_id,
  o.row_version::int AS row_version,
  o.status::text AS status
FROM operations o
JOIN destinations d ON d.id = o.destination_id
JOIN wallets sw ON sw.id = o.source_wallet_id
JOIN wallets dw ON dw.id = d.wallet_id
JOIN lease_group_operations lgo ON lgo.operation_id = o.id
WHERE o.kind = 'MOVE_INTERNAL'
  AND o.status IN ('CREATED', 'NEEDS_ATTENTION')
ORDER BY o.created_at ASC -- contract-allow:order:frozen structural vocabulary
LIMIT $1
`;

export async function loadPendingMoveInternals(
  pool: Pool,
  limit = 8,
): Promise<readonly PendingMoveRow[]> {
  const result = await pool.query<{
    operation_id: string;
    implementer_id: string;
    node_id: string;
    source_wallet_id: string;
    destination_id: string;
    destination_wallet_id: string;
    source_public_key: string;
    destination_public_key: string;
    amount_zkz: string;
    lease_group_id: string;
    spawned_from_operation_id: string | null;
    row_version: number;
    status: string;
  }>(LOAD_PENDING_MOVES_SQL, [limit]);
  return result.rows.map((r) => ({
    operationId: r.operation_id,
    implementerId: r.implementer_id,
    nodeId: r.node_id,
    sourceWalletId: r.source_wallet_id,
    destinationId: r.destination_id,
    destinationWalletId: r.destination_wallet_id,
    sourcePublicKey: r.source_public_key,
    destinationPublicKey: r.destination_public_key,
    amountZkz: r.amount_zkz,
    leaseGroupId: r.lease_group_id,
    spawnedFromOperationId: r.spawned_from_operation_id,
    rowVersion: Number(r.row_version),
    status: r.status,
  }));
}

type SqlTx = {
  query: <R>(
    text: string,
    params?: readonly unknown[],
  ) => Promise<{ rows: R[]; rowCount: number | null }>;
};

async function withTransaction<T>(pool: Pool, fn: (tx: SqlTx) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const tx: SqlTx = {
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await client.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    };
    const out = await fn(tx);
    await client.query("COMMIT");
    return out;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* original */
    }
    throw err;
  } finally {
    client.release();
  }
}

function unbound(step: string): { readonly ok: false; readonly reason: string } {
  return {
    ok: false,
    reason: `${step} port not bound — inject advanced ports (offline composition) or Wave-4 live path`,
  };
}

/**
 * Production-shaped ports: dual-lease + durable progress from PG.
 * Baseline/form/sign/submit/land require injected advanced ports. Without them the
 * worker WAITs after lease (honest unbound production — not a CREATED→LANDED pass).
 * Offline composition injects full fakes; live gateway/vault is Wave-4.
 */
export function createMoveInternalLeaseAndProgressPorts(deps: {
  readonly pool: Pool;
  readonly ownerInstanceId: string;
  readonly advanced?: Partial<MoveInternalMoneyWorkerPorts>;
}): MoveInternalMoneyWorkerPorts {
  const pool = deps.pool;
  const advanced = deps.advanced ?? {};

  const loadProgress: MoveInternalMoneyWorkerPorts["loadProgress"] =
    advanced.loadProgress ??
    createSqlMoveWorkerProgressLoader(
      async (text, values) => {
        const result = await pool.query(text, values as unknown[]);
        return result.rows as readonly Record<string, unknown>[];
      },
      { ownerInstanceId: deps.ownerInstanceId },
    );

  const acquireDualLeases: MoveInternalMoneyWorkerPorts["acquireDualLeases"] =
    advanced.acquireDualLeases ??
    (async (operationId) => {
      // Refresh/revalidate every call: both roles + this owner + epoch>0 (not count≥2).
      const held = await pool.query<{
        wallet_id: string;
        lease_role: string;
        lease_epoch: string;
        owner_instance_id: string;
      }>(
        `SELECT wallet_id::text AS wallet_id, lease_role::text AS lease_role,
                lease_epoch::text AS lease_epoch,
                owner_instance_id::text AS owner_instance_id
           FROM wallet_active_leases
          WHERE operation_id = $1::uuid
            AND owner_instance_id = $2::uuid
            AND lease_role IN ('MOVE_SOURCE', 'MOVE_DESTINATION')`,
        [operationId, deps.ownerInstanceId],
      );
      const epochOk = (e: string): boolean => {
        try {
          return BigInt(e) > 0n;
        } catch {
          return false;
        }
      };
      const source = held.rows.find(
        (r) => r.lease_role === "MOVE_SOURCE" && epochOk(r.lease_epoch),
      );
      const destination = held.rows.find(
        (r) => r.lease_role === "MOVE_DESTINATION" && epochOk(r.lease_epoch),
      );
      if (source !== undefined && destination !== undefined) {
        return {
          ok: true,
          leases: {
            sourceWalletId: source.wallet_id,
            sourceLeaseEpoch: BigInt(source.lease_epoch),
            destinationWalletId: destination.wallet_id,
            destinationLeaseEpoch: BigInt(destination.lease_epoch),
          },
        };
      }

      const rows = await loadPendingMoveInternals(pool, 50);
      const row = rows.find((r) => r.operationId === operationId);
      if (row === undefined) {
        return { ok: false, reason: "operation not pending or leases incomplete" };
      }
      const moveTx: MoveLeaseTxFn = (body) =>
        withTransaction(pool, (tx) =>
          body({
            query: async <R>(text: string, params?: readonly unknown[]) => {
              const result = await tx.query<R>(text, params);
              return { rows: result.rows, rowCount: result.rowCount };
            },
          }),
        );
      const outcome = await acquireMoveLeases(moveTx, {
        operationId: row.operationId,
        leaseGroupId: row.leaseGroupId,
        sourceWalletId: row.sourceWalletId,
        destinationWalletId: row.destinationWalletId,
        ownerInstanceId: deps.ownerInstanceId,
        spawnedFromOperationId: row.spawnedFromOperationId,
      });
      if (outcome.outcome !== "HELD") {
        return { ok: false, reason: `lease outcome ${outcome.outcome}` };
      }
      return {
        ok: true,
        leases: {
          sourceWalletId: outcome.source.walletId,
          sourceLeaseEpoch: outcome.source.leaseEpoch,
          destinationWalletId: outcome.destination.walletId,
          destinationLeaseEpoch: outcome.destination.leaseEpoch,
        },
      };
    });

  return {
    loadProgress,
    acquireDualLeases,
    captureBaselines: advanced.captureBaselines ?? (async () => unbound("captureBaselines")),
    loadBaselineBound: advanced.loadBaselineBound ?? (async () => null),
    formInner: advanced.formInner ?? (async () => unbound("formInner")),
    signUnderLeases: advanced.signUnderLeases ?? (async () => unbound("signUnderLeases")),
    loadSignedMaterial: advanced.loadSignedMaterial ?? (async () => null),
    submitOnce: advanced.submitOnce ?? (async () => unbound("submitOnce")),
    reconcileAndLand:
      advanced.reconcileAndLand ??
      (async () => ({ ...unbound("reconcileAndLand"), holdReconcile: true })),
  };
}

export interface TickMoveInternalWorkersDeps {
  readonly pool: Pool;
  readonly ownerInstanceId: string;
  readonly logger: MoveInternalWorkerLogger;
  readonly ports: MoveInternalMoneyWorkerPorts;
  readonly moneyPathGates: MoneyPathSignerGates;
  readonly limit?: number;
  readonly trackSigningInflight?: (work: Promise<unknown>) => void;
  /** Operation lifecycle (MOVE_INTERNAL completed/failed) at the real seam. */
  readonly metricsHooks?: MetricsHooks;
}

/**
 * One tick: load pending MOVE_INTERNAL ops and advance each through the pipeline.
 */
export async function tickMoveInternalMoneyWorkers(
  deps: TickMoveInternalWorkersDeps,
): Promise<readonly MoveMoneyWorkerAdvance[]> {
  deps.moneyPathGates.assertMoneyAdmitted();
  const pending = await loadPendingMoveInternals(deps.pool, deps.limit ?? 8);
  const advances: MoveMoneyWorkerAdvance[] = [];

  for (const row of pending) {
    const run = (async () => {
      const { terminal, trail } = await runMoveInternalMoneyWorker(deps.ports, row.operationId);
      for (const a of trail) {
        advances.push(a);
      }
      if (terminal.kind === "TERMINAL") {
        deps.metricsHooks?.onOperationCompleted("MOVE_INTERNAL");
        deps.logger.info(
          `money-workers: MOVE_INTERNAL LANDED op=${row.operationId} amount=${row.amountZkz}`,
        );
      } else if (terminal.kind === "HOLD_RECONCILE") {
        deps.logger.info(
          `money-workers: MOVE_INTERNAL HOLD_RECONCILE op=${row.operationId} claim=${String(terminal.submitClaimed)} reason=${terminal.reason}`,
        );
      } else if (terminal.kind === "WAITING") {
        deps.logger.info(
          `money-workers: MOVE_INTERNAL WAITING op=${row.operationId} reason=${terminal.reason}`,
        );
      } else if (terminal.kind === "FAILED") {
        // MOVE_INTERNAL's closed durable lifecycle has no REJECTED/EXPIRED state. FAILED
        // here is a retryable worker-attempt outcome while the row remains CREATED or
        // NEEDS_ATTENTION, so it must not increment the terminal-operation failure metric.
        deps.logger.error(
          `money-workers: MOVE_INTERNAL FAILED op=${row.operationId} step=${terminal.step} reason=${terminal.reason}`,
        );
      }
      return terminal;
    })();

    deps.trackSigningInflight?.(run);
    try {
      await run;
    } catch (err) {
      deps.logger.error(`money-workers: MOVE_INTERNAL tick op=${row.operationId}`, err);
      advances.push({
        kind: "FAILED",
        operationId: row.operationId,
        step: "LOAD",
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return advances;
}

/** Module path anchor for composition census. */
export function moveInternalWorkerModuleId(): string {
  return "apps/generic-node/src/money-workers/move-internal-worker.ts";
}
