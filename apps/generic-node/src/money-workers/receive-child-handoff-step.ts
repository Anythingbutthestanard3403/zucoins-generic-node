// Continuous handoff after RECEIVE_LANDED.
// Spawns child MOVE_INTERNAL + continuous RECEIVE_WINDOW→MOVE_SOURCE transfer
// for receives with after_landing=INTERNAL_MOVE. Idempotent (ALREADY_EXISTS /
// ALREADY_TRANSFERRED). Never submits chain txs; MOVE money path owns form/sign/submit.

import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";

import {
  createChildMoveWithContinuousSourceTransfer,
  MOVE_ADMISSION_EVENTS_DDL,
  type ContinuousHandoffResult,
  type MoveSqlExecutor,
  type MoveSqlTxFn,
} from "@zucoins/node-core";

export interface ReceiveChildHandoffLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface ReceiveChildHandoffDeps {
  readonly pool: Pool;
  readonly ownerInstanceId: string;
  readonly logger: ReceiveChildHandoffLogger;
  readonly batchSize?: number;
}

/** RECEIVE_LANDED + INTERNAL_MOVE + no child MOVE yet (or child exists without MOVE_SOURCE). */
export const LOAD_HANDOFF_CANDIDATES_SQL = `
  SELECT o.id::text AS parent_operation_id,
         p.path_manifest_sha256 AS landing_proof_digest
    FROM operations o
    JOIN receive_landing_proofs p ON p.operation_id = o.id
   WHERE o.kind = 'RECEIVE_EXTERNAL'::operation_kind
     AND o.status = 'RECEIVE_LANDED'::operation_status
     AND o.after_landing = 'INTERNAL_MOVE'
     AND o.after_landing_destination_id IS NOT NULL
     AND EXISTS (
       SELECT 1 FROM wallet_active_leases l
        WHERE l.operation_id = o.id
          AND l.wallet_id = o.receiver_wallet_id
          AND l.lease_role = 'RECEIVE_WINDOW'
     )
     AND NOT EXISTS (
       SELECT 1 FROM operations c
        WHERE c.spawned_from_operation_id = o.id
          AND c.kind = 'MOVE_INTERNAL'::operation_kind
     )
   ORDER BY o.created_at ASC, o.id ASC -- contract-allow:order:frozen structural vocabulary
   LIMIT $1
`;

export interface ReceiveChildHandoffResult {
  readonly attempted: number;
  readonly spawned: number;
  readonly failed: number;
}

async function withTransaction<T>(pool: Pool, fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const out = await fn(client);
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

export async function runReceiveChildHandoffStep(
  deps: ReceiveChildHandoffDeps,
): Promise<ReceiveChildHandoffResult> {
  // Slice-local admission event table (MOVE_ADMISSION_EVENTS_DDL) is not yet in the
  // migrator pack — ensure before child insert (idempotent IF NOT EXISTS).
  await deps.pool.query(MOVE_ADMISSION_EVENTS_DDL);
  const limit = deps.batchSize ?? 16;
  const candidates = await deps.pool.query<{
    parent_operation_id: string;
    landing_proof_digest: string;
  }>(LOAD_HANDOFF_CANDIDATES_SQL, [limit]);

  let spawned = 0;
  let failed = 0;

  for (const row of candidates.rows) {
    try {
      const result: ContinuousHandoffResult = await withTransaction(deps.pool, async (client) => {
        const sql = {
          query: async <R>(text: string, params?: readonly unknown[]) => {
            const r = await client.query(text, params as never);
            return { rows: r.rows as R[], rowCount: r.rowCount };
          },
        };
        const withTx: MoveSqlTxFn = async (body) => body(sql as MoveSqlExecutor);
        return createChildMoveWithContinuousSourceTransfer(
          withTx,
          { sql: sql as MoveSqlExecutor },
          {
            parentOperationId: row.parent_operation_id,
            ownerInstanceId: deps.ownerInstanceId,
            landingProofDigest: row.landing_proof_digest,
            generateId: () => randomUUID(),
          },
        );
      });

      if (result.ok) {
        spawned += 1;
        deps.logger.info(
          `receive-child-handoff: parent=${row.parent_operation_id} child=${result.child.operationId} ` +
            `outcome=${result.childOutcome} transfer=${result.transfer.status}`,
        );
      } else {
        failed += 1;
        deps.logger.info(
          `receive-child-handoff: parent=${row.parent_operation_id} rejected ` +
            `reason=${"reason" in result ? result.reason : "unknown"} ` +
            `detail=${"detail" in result ? result.detail : ""}`,
        );
      }
    } catch (err) {
      failed += 1;
      deps.logger.error(
        `receive-child-handoff: parent=${row.parent_operation_id} failed`,
        err,
      );
    }
  }

  return { attempted: candidates.rows.length, spawned, failed };
}
