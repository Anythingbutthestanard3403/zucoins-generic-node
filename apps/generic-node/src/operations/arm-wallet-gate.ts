// Production wiring for the receive-arm wallet-row gate.
//
// Composition root for `createSqlArmWalletGate`: adapts a `pg.Pool` into the
// driver-agnostic SqlTxFactory node-core expects, so the arm mutation service
// holds `SELECT ... FOR UPDATE` on the receiver wallet across standing recheck +
// arm insert + READY→armed commit on **one** client.
//
// Boundary: apps/generic-node may import only `@zucoins/node-core` (no subpaths).
//
// Acceptance scope:
//   SHIPPED — pool→SqlTxFactory adapter, SQL gate factory, tx-bound ArmStore /
//     ArmOperationState factories (node-core), fail-closed ActionRouteStore.arm stub.
//   GATED ON ENGINE INJECT — live `operation_armed` path must call
//     `createPoolArmWalletGate` + `createSqlArmStore` / `createSqlTxBoundOperationState`
//     (or `commitArmUnderWalletLock`). Until then `createFailClosedPoolArmHandler`
//     refuses arm so an unbound store cannot silently arm.

import {
  createFailClosedArmHandler,
  createSqlArmWalletGate,
  type ArmSqlTxExecutor,
  type ArmSqlTxFactory,
  type ArmWalletGate,
} from "@zucoins/node-core";
import type { Pool, PoolClient } from "pg";

/**
 * Adapt a node-postgres Pool into the ArmSqlTxFactory surface.
 * BEGIN → body(client) → COMMIT; ROLLBACK on throw. One client is pinned for
 * the whole critical section so FOR UPDATE is meaningful.
 */
export function createPoolArmTxFactory(pool: Pool): ArmSqlTxFactory {
  return {
    async withTransaction<T>(fn: (tx: ArmSqlTxExecutor) => Promise<T>): Promise<T> {
      const client: PoolClient = await pool.connect();
      try {
        await client.query("BEGIN");
        const tx: ArmSqlTxExecutor = {
          async query<R>(text: string, params?: readonly unknown[]) {
            const result = await client.query(text, params as unknown[] | undefined);
            return { rows: result.rows as R[] };
          },
        };
        const value = await fn(tx);
        await client.query("COMMIT");
        return value;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // surface the original error
        }
        throw err;
      } finally {
        client.release();
      }
    },
  };
}

/** Production ArmWalletGate bound to this node's Postgres pool. */
export function createPoolArmWalletGate(pool: Pool): ArmWalletGate {
  return createSqlArmWalletGate(createPoolArmTxFactory(pool));
}

/**
 * Fail-closed arm handler for composition roots that have not yet injected the
 * gate + tx-bound ArmStore. Prefer this over leaving ActionRouteStore.arm unbound.
 */
export function createFailClosedPoolArmHandler(
  reason?: string,
): (operationId: string) => Promise<never> {
  return createFailClosedArmHandler(
    reason ??
      "arm path not wired: inject createPoolArmWalletGate + createSqlArmStore",
  );
}
