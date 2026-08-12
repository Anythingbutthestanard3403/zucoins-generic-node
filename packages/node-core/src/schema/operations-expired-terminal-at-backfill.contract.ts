/**
 * ZTR-1249 backfill: stamp terminal_at on EXPIRED operations that still have it NULL.
 *
 * Frozen inventory of the structural invariants carried by
 * operations-expired-terminal-at-backfill.sql.
 */

export const OPERATIONS_EXPIRED_TERMINAL_AT_BACKFILL_SCHEMA_FILE =
  "operations-expired-terminal-at-backfill.sql" as const;

export interface OperationsExpiredTerminalAtBackfillInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OPERATIONS_EXPIRED_TERMINAL_AT_BACKFILL_INVARIANTS: readonly OperationsExpiredTerminalAtBackfillInvariant[] =
  [
    {
      id: "BACKFILL_EXPIRED_NULL_TERMINAL_AT",
      sqlAnchor:
        "SET terminal_at = COALESCE(terminal_at, updated_at)\n   WHERE status = 'EXPIRED'\n     AND terminal_at IS NULL",
      rule:
        "only EXPIRED rows with a null terminal_at are touched; updated_at stands in for the missing flip clock so SPA in-flight (terminal_at IS NULL) drops them without inventing a new timestamp column.",
    },
    {
      id: "IDEMPOTENT_COALESCE",
      sqlAnchor: "COALESCE(terminal_at, updated_at)",
      rule:
        "re-applying the slice is a no-op on already-terminalized rows; COALESCE never overwrites a non-null terminal_at.",
    },
    {
      id: "FAIL_CLOSED_WITHOUT_OPERATIONS",
      sqlAnchor:
        "RAISE EXCEPTION\n      'operations-expired-terminal-at-backfill requires operations'",
      rule:
        "standalone apply without the operations table fails closed with a named exception rather than silently no-oping.",
    },
    {
      id: "PURE_DATA_FIX_FORWARD",
      sqlAnchor: "UPDATE operations",
      rule:
        "creates no table, column, index, trigger, or domain — data-only fix-forward on the already-created operations table.",
    },
  ] as const;

export const OPERATIONS_EXPIRED_TERMINAL_AT_BACKFILL_EXECUTION_OBLIGATIONS: readonly string[] =
  [
    "operations-expired-terminal-at-backfill.sql applies after operations.sql (operations must already exist) and is a pure data fix-forward.",
    "The UPDATE ships as its own money-pack slice appended to MONEY_SCHEMA_PACK_ORDER; operations.sql is already applied and its schema_migrations sql_sha256 must not change.",
  ] as const;

export const OPERATIONS_EXPIRED_TERMINAL_AT_BACKFILL_SOURCE =
  "ZTR-1249: queue-aged EXPIRED left terminal_at NULL; SPA in-flight = terminal_at IS NULL" as const;
