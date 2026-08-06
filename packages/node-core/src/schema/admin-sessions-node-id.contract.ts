// Admin sessions: the node_id column (migration-pack ownership).
//
// Frozen inventory of the structural invariants carried by admin-sessions-node-id.sql — the
// single node_id column recording which node issued an admin session, previously written by
// a runtime `ALTER TABLE IF NOT EXISTS` in admin-session-sql-store.ts.

export const ADMIN_SESSIONS_NODE_ID_SCHEMA_FILE = "admin-sessions-node-id.sql" as const;

export interface AdminSessionsNodeIdInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const ADMIN_SESSIONS_NODE_ID_INVARIANTS: readonly AdminSessionsNodeIdInvariant[] = [
  {
    id: "NODE_ID_NOT_NULL_DEFAULT_EMPTY",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS node_id text NOT NULL DEFAULT ''",
    rule:
      "node_id is NOT NULL with a '' default: historical sessions predating this column have no recorded node_id, and the column must stay non-null for callers that key lookups on it.",
  },
] as const;

export const ADMIN_SESSIONS_NODE_ID_EXECUTION_OBLIGATIONS: readonly string[] = [
  "admin-sessions-node-id.sql applies after session-subscription-stores.sql (admin_sessions must already exist) and is a pure column extension: it creates no table, no index, no trigger.",
] as const;

export const ADMIN_SESSIONS_NODE_ID_SOURCE = "api-contract: admin sessions" as const;
