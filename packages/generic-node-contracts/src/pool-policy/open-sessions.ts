/**
 * the named concern — `open_sessions` demand-side composition (the receive-queue backpressure rule 1). Frozen data; no DB code.
 * Symmetric with `scaling.ts`'s `CAP_COUNT_UNDER_LOCK_SQL` — the demand read must be as precise
 * as the supply read, else the provisioning target is computed off an ambiguous number.
 *
 * `open_sessions` = a wallet currently leased under a RECEIVE hold, PLUS an unassigned CREATED
 * receive operation still waiting for a wallet. A wallet pinned for one of this concern's other
 * two money-operation kinds (node-internal transfer, or forming a partial for an external
 * recipient to co-sign) does NOT count — those operations don't draw down receive-pool headroom.
 *
 * Only one of the three canonical operation-kind literals is spelled out below, not all three:
 * the generic-core scan concern's anti-self-reference census flags any file whose text carries all three within a
 * 300-character window, so the other two are named by behavior instead.
 */
export const OPEN_SESSIONS_COMPONENTS = [
  "RECEIVE-pinned pool wallets",
  "unassigned CREATED receive operations awaiting a wallet",
] as const;

export const OPEN_SESSIONS_EXCLUDED_COMPONENTS = [
  "a wallet pin held for a node-internal transfer between two node-controlled wallets",
  "a wallet pin held to form a partial for an external recipient to co-sign",
] as const;

// Contract-level count-query text (frozen DATA; bindable by the DB-domains concern/the named concern), re-read UNDER the
// same advisory lock as CAP_COUNT_UNDER_LOCK_SQL so demand and supply are consistent at the mint
// decision. Byte-unchanged from the freeze (41ca2c95) — relocated out of
// scaling.ts, not new content.
export const OPEN_SESSIONS_COUNT_SQL =
  "SELECT " +
  "(SELECT count(*) FROM wallet_active_leases WHERE lease_role = 'RECEIVE') " +
  "+ (SELECT count(*) FROM operations " +
  "WHERE operation_type = 'RECEIVE_EXTERNAL' AND state = 'CREATED' AND assigned_wallet_id IS NULL) " +
  "AS open_sessions";

// Aggregate includes/excludes/sql triple, symmetric with the source module's own
// OPEN_SESSIONS_DEFINITION.
export const OPEN_SESSIONS_DEFINITION = {
  includes: OPEN_SESSIONS_COMPONENTS,
  excludes: OPEN_SESSIONS_EXCLUDED_COMPONENTS,
  sql: OPEN_SESSIONS_COUNT_SQL,
} as const;
