// Reporting persistence: the scalar domains, the enums and reporting_logical_fingerprint,
// and the reporting registries (nonce burns, lifecycle heads/states/
// events, restore state, mutation idempotency, reporting_lock_and_assert_admission);
// gapless per-node event counter (gapless counter); freeze / durable-store slice.
//
// Frozen inventory of the structural reporting-persistence invariants carried by
// reporting-persistence.sql. The census test binds every entry here to the literal SQL
// text, so the inventory and the schema contract cannot drift apart. Execution against a
// live database belongs to the schema-apply phase (and apps/generic-node's 0000 migration);
// packages/node-core carries this file as contract text only and gains no DB dependency.
//
// Greenfield note: the slice re-declares its full FK closure (nodes / implementers and the
// reporting tables) so it is not prerequisite-bound on another contract SQL. It still
// requires pgcrypto (digest) at CREATE FUNCTION time — provisioned by the generic-node
// migration runner before migrate, not by this contract text (byte-frozen).

export const REPORTING_PERSISTENCE_SCHEMA_FILE = "reporting-persistence.sql" as const;

export interface ReportingPersistenceInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const REPORTING_PERSISTENCE_INVARIANTS: readonly ReportingPersistenceInvariant[] = [
  {
    id: "NONCE_REPLAY_GUARD_UNIQUE",
    sqlAnchor: "UNIQUE (node_id, implementer_id, nonce),",
    rule: "a reporting nonce is burned at most once per (node, implementer): the UNIQUE is the durable replay guard the burn transaction relies on — a second insert of the same nonce is a unique_violation mapped to REPLAY, never a silent overwrite.",
  },
  {
    id: "NONCE_BURN_SEQUENCE_GAPLESS_COUNTER",
    sqlAnchor:
      "CREATE TABLE reporting_nonce_burn_counters (\n  node_id uuid PRIMARY KEY REFERENCES nodes(id),\n  next_burn_sequence bigint NOT NULL DEFAULT 1 CHECK (next_burn_sequence > 0)\n);",
    rule: "nonce_burn_sequence is allocated from a dedicated single-row-per-node counter table, never an identity column: the counter increment shares the burn transaction (and rolls back with a SAVEPOINT on REPLAY), so the sequence stays contiguous and gapless.",
  },
  {
    id: "NONCE_BURN_SEQUENCE_UNIQUE_PER_NODE",
    sqlAnchor: "UNIQUE (node_id, nonce_burn_sequence),",
    rule: "the burn sequence is unique per node: two concurrent burns cannot be assigned the same sequence number; a 23505 on this guard is a programming error, not a REPLAY.",
  },
  {
    id: "LOGICAL_FINGERPRINT_GENERATED",
    sqlAnchor:
      "logical_fingerprint sha256_hex GENERATED ALWAYS AS\n    (reporting_logical_fingerprint(method, raw_target, body_sha256)) STORED,",
    rule: "logical_fingerprint is GENERATED ALWAYS from the frozen reporting_logical_fingerprint function: the adapter omits it on INSERT and reads it back via RETURNING — it is never caller-supplied.",
  },
  {
    id: "ADMISSION_FUNCTION_SECURITY_DEFINER",
    sqlAnchor:
      "CREATE FUNCTION reporting_lock_and_assert_admission(\n  p_node_id uuid,\n  p_implementer_id uuid,\n  p_lifecycle_epoch bigint,\n  p_reporting_key_id uuid,\n  p_received_at timestamptz\n) RETURNS void LANGUAGE plpgsql SECURITY DEFINER",
    rule: "the burn transaction's admission authority is the SECURITY DEFINER function reporting_lock_and_assert_admission: it locks restore_state then lifecycle_heads, rechecks epoch/holds/key/overlap, and raises 55000 / P0002 for the adapter to map — TypeScript does not replicate the lock/recheck logic.",
  },
  {
    id: "RESTORE_STATE_ROW_PER_NODE",
    sqlAnchor: "CREATE TABLE reporting_restore_state (",
    rule: "restore hold is a single row per node: the admission function locks it FOR UPDATE first so a restore-hold flip serializes with every burn.",
  },
  {
    id: "LIFECYCLE_HEAD_PER_IMPLEMENTER",
    sqlAnchor: "CREATE TABLE reporting_key_lifecycle_heads (",
    rule: "each (node, implementer) carries exactly one lifecycle head: the admission function locks that head FOR UPDATE after restore_state, then rechecks epoch / auth_hold / current-or-prior key with overlap window.",
  },
  {
    id: "MUTATION_IDEMPOTENCY_KEY_GUARD",
    sqlAnchor: "CREATE TABLE reporting_mutation_idempotency (",
    rule: "completed mutation idempotency is durable: a second insert of the same (node, implementer, route, key) is a unique_violation mapped to CONFLICT, preserving the first completion's evidence.",
  },
] as const;
