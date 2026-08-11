// SQL adapter for SubscriptionHandleStore over session-subscription-stores.sql.
// Only the handle_hash is durable. implementer_id is joined from operations.
// Parameterized statements only.
//
// INSERT lives here as a statement constant so admission can write the hash in the
// same TX as receive_operations without importing this module (cycle safety).

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

// implementer_id is not on subscription_handles. Prefer the live operations
// mirror when present; fall back to receive_operations so subscribe works
// between admit (handle minted) and the money-worker mirror tick.
const LOOKUP = `
SELECT sh.operation_id::text AS operation_id,
       sh.handle_hash,
       (EXTRACT(EPOCH FROM sh.expires_at) * 1000)::bigint AS expires_at_ms,
       COALESCE(o.implementer_id::text, r.implementer_id::text) AS implementer_id,
       sh.node_id::text AS node_id
  FROM subscription_handles sh
  LEFT JOIN operations o
         ON o.id = sh.operation_id
        AND o.node_id = sh.node_id
  LEFT JOIN receive_operations r
         ON r.operation_id = sh.operation_id
        AND r.node_id = sh.node_id
 WHERE sh.handle_hash = $1
   AND sh.consumed_at IS NULL
   AND COALESCE(o.implementer_id, r.implementer_id) IS NOT NULL
 LIMIT 1
`;

/**
 * Persist a newly minted handle binding. Plaintext is NEVER a parameter —
 * only the SHA-256 hex of the utf-8 plaintext, plus binding metadata.
 * Call inside the same TX that inserts the receive operation row.
 *
 * $1 id, $2 node_id, $3 operation_id, $4 handle_hash, $5 expires_at (timestamptz).
 */
export const INSERT_SUBSCRIPTION_HANDLE = `
INSERT INTO subscription_handles (
  id, node_id, operation_id, handle_hash, expires_at
) VALUES (
  $1::uuid, $2::uuid, $3::uuid, $4::text, $5::timestamptz
)
`.replace(/\s+/g, " ").trim();

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
