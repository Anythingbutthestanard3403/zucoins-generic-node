// SQL adapter for OperationLifecycleStore (operation lifecycle SSE).
// getLifecycle reads operations; subscribe is process-local notify with poll fallback in
// the SSE accelerator (operation-subscribe-sse.ts).

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import type {
  OperationLifecycleRow,
  OperationLifecycleStore,
} from "./subscription-handle.js";

export interface OperationLifecycleSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

const LOAD = `
SELECT id::text AS operation_id,
       kind::text AS operation_type,
       status::text AS state,
       row_version::bigint AS row_version,
       attention_required,
       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
  FROM operations
 WHERE id = $1::uuid
 LIMIT 1
`;

function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (value instanceof Date) return value.toISOString();
  throw new Error(`expected string, got ${typeof value}`);
}

function asNumber(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string") return Number(value);
  throw new Error(`expected number, got ${typeof value}`);
}

function asBool(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (value === "t" || value === "true") return true;
  if (value === "f" || value === "false") return false;
  throw new Error(`expected boolean, got ${typeof value}`);
}

function mapRow(row: Record<string, unknown>): OperationLifecycleRow {
  return Object.freeze({
    operationId: asString(row.operation_id),
    operationType: asString(row.operation_type) as OperationKind,
    state: asString(row.state),
    rowVersion: asNumber(row.row_version),
    attentionRequired: asBool(row.attention_required),
    updatedAt: asString(row.updated_at),
  });
}

/**
 * SQL-backed lifecycle store. subscribe is in-process only; multi-worker SSE relies
 * on the accelerator poll path (getLifecycle).
 */
export function createSqlOperationLifecycleStore(
  sql: OperationLifecycleSqlExecutor,
): OperationLifecycleStore {
  const listeners = new Map<string, Set<(row: OperationLifecycleRow) => void>>();

  return {
    async getLifecycle(operationId: string): Promise<OperationLifecycleRow | null> {
      const result = await sql.query(LOAD, [operationId]);
      const row = result.rows[0];
      return row === undefined ? null : mapRow(row);
    },

    subscribe(
      operationId: string,
      listener: (row: OperationLifecycleRow) => void,
    ): () => void {
      let set = listeners.get(operationId);
      if (set === undefined) {
        set = new Set();
        listeners.set(operationId, set);
      }
      set.add(listener);
      return () => {
        set?.delete(listener);
        if (set !== undefined && set.size === 0) listeners.delete(operationId);
      };
    },
  };
}
