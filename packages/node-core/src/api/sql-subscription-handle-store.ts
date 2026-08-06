// SQL adapter for SubscriptionHandleStore over session-subscription-stores.sql.
// Only the handle_hash is durable. implementer_id is joined from operations.
// Parameterized statements only.

import type {
  SubscriptionHandleRecord,
  SubscriptionHandleStore,
} from "./subscription-handle.js";

export interface SubscriptionHandleSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

const LOOKUP = `
SELECT sh.operation_id::text AS operation_id,
       sh.handle_hash,
       (EXTRACT(EPOCH FROM sh.expires_at) * 1000)::bigint AS expires_at_ms,
       o.implementer_id::text AS implementer_id,
       sh.node_id::text AS node_id
  FROM subscription_handles sh
  INNER JOIN operations o
          ON o.id = sh.operation_id
         AND o.node_id = sh.node_id
 WHERE sh.handle_hash = $1
   AND sh.consumed_at IS NULL
 LIMIT 1
`;

function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  throw new Error(`expected string, got ${typeof value}`);
}

function asMs(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string") return Number(value);
  throw new Error(`expected ms number, got ${typeof value}`);
}

/**
 * Durable SubscriptionHandleStore. Restart-safe: a fresh instance on the same DB
 * resolves the same handle_hash → operation binding.
 */
export function createSqlSubscriptionHandleStore(
  sql: SubscriptionHandleSqlExecutor,
): SubscriptionHandleStore {
  return {
    async lookupByHandleHash(handleHash: string): Promise<SubscriptionHandleRecord | null> {
      const result = await sql.query(LOOKUP, [handleHash]);
      const row = result.rows[0];
      if (row === undefined) return null;
      return Object.freeze({
        operationId: asString(row.operation_id),
        handleHash: asString(row.handle_hash),
        expiresAtMs: asMs(row.expires_at_ms),
        implementerId: asString(row.implementer_id),
        nodeId: asString(row.node_id),
      });
    },
  };
}
