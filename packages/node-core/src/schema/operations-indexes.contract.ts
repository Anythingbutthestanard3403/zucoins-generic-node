// Worker-poll indexes on operations.
//
// Frozen inventory of the structural invariants carried by operations-indexes.sql — the
// partial indexes that keep the money-worker tick's kind/status polls off a sequential scan
// of an append-only table that only grows. operations_one_spawn_per_parent_uidx is owned by
// operations.sql and is deliberately not re-declared here.

export const OPERATIONS_INDEXES_SCHEMA_FILE = "operations-indexes.sql" as const;

export interface OperationsIndexInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OPERATIONS_INDEX_INVARIANTS: readonly OperationsIndexInvariant[] = [
  {
    id: "RECEIVE_QUEUE_CREATED_INDEX",
    sqlAnchor:
      "CREATE INDEX operations_receive_queue_created_idx\n" +
      "  ON operations (created_at, id)\n" +
      "  WHERE kind = 'RECEIVE_EXTERNAL'\n" +
      "    AND status = 'CREATED'\n" +
      "    AND receiver_wallet_id IS NULL;",
    rule:
      "partial index on the unassigned CREATED receive queue, matching pool-scaler.ts / pool-allocator.ts / metrics-snapshot.ts predicates verbatim so the allocator's depth/FIFO/aged-expiry polls are index-ordered on created_at rather than a seq scan of every operation ever created.",
  },
  {
    id: "RECEIVE_EXPIRY_CANDIDATES_INDEX",
    sqlAnchor:
      "CREATE INDEX operations_receive_expiry_candidates_idx\n" +
      "  ON operations (created_at, id)\n" +
      "  WHERE kind = 'RECEIVE_EXTERNAL'\n" +
      "    AND status IN ('CREATED', 'READY', 'EXPIRED')\n" +
      "    AND receive_release_status IS NULL;",
    rule:
      "partial index on the receive expiry sweep set (expiry-release.ts SELECT_EXPIRY_CANDIDATES), matching kind/status IN / receive_release_status IS NULL verbatim.",
  },
  {
    id: "RECEIVE_READY_INDEX",
    sqlAnchor:
      "CREATE INDEX operations_receive_ready_idx\n" +
      "  ON operations (created_at, id)\n" +
      "  WHERE kind = 'RECEIVE_EXTERNAL'\n" +
      "    AND status = 'READY';",
    rule:
      "partial index on READY receives for the settle/landing batch polls (receive-settle-step.ts, receive-landing-step.ts).",
  },
  {
    id: "RECEIVE_LANDED_HANDOFF_INDEX",
    sqlAnchor:
      "CREATE INDEX operations_receive_landed_handoff_idx\n" +
      "  ON operations (created_at, id)\n" +
      "  WHERE kind = 'RECEIVE_EXTERNAL'\n" +
      "    AND status = 'RECEIVE_LANDED'\n" +
      "    AND after_landing = 'INTERNAL_MOVE';",
    rule:
      "partial index on landed receives awaiting a MOVE_INTERNAL child (receive-child-handoff-step.ts), including after_landing = 'INTERNAL_MOVE' from the source predicate.",
  },
  {
    id: "MOVE_PENDING_INDEX",
    sqlAnchor:
      "CREATE INDEX operations_move_pending_idx\n" +
      "  ON operations (created_at, id)\n" +
      "  WHERE kind = 'MOVE_INTERNAL'\n" +
      "    AND status IN ('CREATED', 'NEEDS_ATTENTION');",
    rule:
      "partial index on pending MOVE_INTERNAL rows (move-internal-worker.ts LOAD_PENDING_MOVES_SQL), matching kind + status IN verbatim.",
  },
  {
    id: "PURE_INDEX_EXTENSION",
    // Named indexes, not the bare "CREATE INDEX" verb: that phrase also appears in this
    // file's prose, so a bare anchor would stay satisfied after the DDL itself was deleted.
    sqlAnchor: "CREATE INDEX operations_receive_queue_created_idx",
    rule:
      "applies after operations.sql (and after receive-expiry-release.sql for receive_release_status) and creates no table, column, trigger or domain, so the operations CHECK/ENUM invariants and operations_one_spawn_per_parent_uidx are untouched.",
  },
  {
    id: "SPAWN_INDEX_UNTOUCHED",
    sqlAnchor: "operations_one_spawn_per_parent_uidx",
    rule:
      "the file's prose names the spawn unique index as out-of-scope; the DDL never re-declares or drops it. The spawn arbiter stays owned by operations.sql.",
  },
] as const;

export const OPERATIONS_INDEXES_EXECUTION_OBLIGATIONS: readonly string[] = [
  "operations-indexes.sql applies after operations.sql and receive-expiry-release.sql and is a pure index extension: it creates no table, no column, no trigger, no domain.",
  "The indexes ship as their own money-pack slice appended to MONEY_SCHEMA_PACK_ORDER; operations.sql is already applied and its schema_migrations sql_sha256 must not change.",
  "CREATE INDEX is deliberately not CONCURRENTLY: db/migrate.ts applies migrations inside a transaction block, which CONCURRENTLY cannot join.",
  "operations_one_spawn_per_parent_uidx is not modified; it remains the sole spawn arbiter in operations.sql.",
  "EXPLAIN confirms each partial index serves its source worker-poll predicate (pool-scaler queue, expiry candidates, READY settle, landed handoff, pending MOVE).",
  "COUNT_OPERATIONS_BY_STATUS (full GROUP BY status) is intentionally not indexed; a full aggregate is not helped by a partial index.",
] as const;

export const OPERATIONS_INDEXES_SOURCE =
  "worker-poll access patterns on operations (pool-scaler, pool-allocator, expiry-release, receive settle/landing/handoff, move-internal-worker); ZTR-1158" as const;
