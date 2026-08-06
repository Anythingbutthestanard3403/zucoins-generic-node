// Receive external landing: the landing DB-TX (the receiver lease stays held),
// operation_landing_proofs / lineage_path_proofs / lineage_path_bodies, node_events, and
// the ancestor_proofs wire shape.
//
// Frozen schema contract for receive-external-landing.sql. The slice
// EXTENDS operations.sql: the operations row already carries status, row_version,
// t0_observation_id, terminal_observation_id and verification_material_available_until, so the
// landing DB-TX adds no columns and writes only what exists. It never releases the receiver
// lease, so no statement in the SQL touches wallet_active_leases.
//
// Prerequisite-bound greenfield: the first CREATE TABLE foreign-keys operations, which this
// package creates only in operations.sql, so applied alone the slice fails on operations.
// Characterized in migration-integrity.test.ts; the real-Postgres behavioral proof is
// receive-external-landing-pg.test.ts.

export const RECEIVE_EXTERNAL_LANDING_SCHEMA_FILE = "receive-external-landing.sql" as const;

/** The slice this one extends — owner of the operations relation. */
export const RECEIVE_EXTERNAL_LANDING_EXTENDS = "operations.sql" as const;

export interface ReceiveExternalLandingInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const RECEIVE_EXTERNAL_LANDING_INVARIANTS: readonly ReceiveExternalLandingInvariant[] = [
  {
    id: "ONE_LANDING_PROOF_PER_OPERATION",
    sqlAnchor: "operation_id uuid PRIMARY KEY REFERENCES operations (id),",
    rule: "at most one landing proof per operation; the operation must already exist.",
  },
  {
    id: "SETTLED_BODY_PHASE_FROZEN",
    sqlAnchor: "attempt_phase text NOT NULL CHECK (attempt_phase = 'SETTLED_BODY_PERSISTED')",
    rule: "the transaction-record phase persisted by the landing DB-TX is exactly SETTLED_BODY_PERSISTED.",
  },
  {
    id: "PUBLIC_PHASE_FROZEN",
    sqlAnchor:
      "public_execution_phase text NOT NULL CHECK (public_execution_phase = 'LANDED_VERIFIED')",
    rule: "the derived public execution phase is exactly LANDED_VERIFIED.",
  },
  {
    id: "ONE_RECEIVER_PATH",
    sqlAnchor: "path_role text NOT NULL CHECK (path_role = 'RECEIVER')",
    rule: "a RECEIVE_EXTERNAL landing requires exactly one complete path, the receiver's (required_path_count = 1).",
  },
  {
    id: "LANDING_ORACLE_IS_EXACT_OR_COMPLETE_PATH",
    sqlAnchor: "verdict text NOT NULL CHECK (verdict IN ('LANDED_EXACT', 'LANDED_COMPLETE_PATH'))",
    rule: "only the two landing oracles are storable; there is no PROVEN_NOT_LANDED row and no LANDED_DIRECT_SUCCESSOR shortcut.",
  },
  {
    id: "PATH_DEPTH_MATCHES_ORACLE",
    sqlAnchor: "CONSTRAINT receive_landing_verdict_depth",
    rule: "LANDED_EXACT pins depth 0 and LANDED_COMPLETE_PATH pins depth >= 1 — a buried landing cannot be recorded as an exact-head one.",
  },
  {
    id: "EXACT_HEAD_IDENTITY_IFF_DEPTH_ZERO",
    sqlAnchor: "CONSTRAINT receive_landing_exact_head_identity",
    rule: "depth 0 holds if and only if the expected body digest equals the fresh-head digest — a buried attempt cannot claim the head's identity, structurally barred.",
  },
  {
    id: "BODY_COUNT_MATCHES_DEPTH",
    sqlAnchor: "path_depth bigint NOT NULL CHECK (path_depth >= 0 AND path_depth = body_count - 1)",
    rule: "the declared body count and the declared depth cannot disagree.",
  },
  {
    id: "ORDERED_PATH_PERSISTED",
    sqlAnchor: "PRIMARY KEY (operation_id, path_index),",
    rule: "the complete ordered path is persisted body by body in exact full-body form, one row per hop, index-unique.",
  },
  {
    id: "NO_PARTIAL_PATH_MAY_COMMIT",
    sqlAnchor: "CREATE CONSTRAINT TRIGGER receive_landing_path_bodies_complete",
    rule: "a deferred constraint trigger aborts the landing DB-TX at COMMIT unless the persisted path is exactly body_count rows, contiguous from 0, anchored at the expected attempt and the fresh head, and backlinked P(T[i]) = S(T[i-1]) at every hop — the database refuses a partial path, not application logic.",
  },
  {
    id: "ZERO_BODY_PATH_CANNOT_COMMIT",
    sqlAnchor: "CREATE CONSTRAINT TRIGGER receive_landing_proofs_path_complete",
    rule: "the same completeness check is attached to the header, so a landing that inserts no body rows at all still aborts — a per-body trigger cannot fire on zero bodies, which would otherwise commit RECEIVE_LANDED with an empty path.",
  },
  {
    id: "EXACT_BODY_BYTES_PERSISTED",
    sqlAnchor: "CHECK (octet_length(completed_transaction_text) = completed_transaction_octets)",
    rule: "each body's exact signed text is stored with its own octet count and sha256 — byte identity, never a parsed re-encoding (the byte-exact signing rule).",
  },
  {
    id: "ONE_LANDED_EVENT_PER_OPERATION",
    sqlAnchor: "CREATE UNIQUE INDEX receive_landing_events_one_per_operation",
    rule: "receive.landed is appended at most once per operation; two concurrent emitters collide on 23505 and one transaction aborts whole (indicator 4).",
  },
  {
    id: "EVENT_TYPE_FROZEN",
    sqlAnchor: "event_type text NOT NULL CHECK (event_type = 'receive.landed')",
    rule: "the slice-local event table carries exactly the receive.landed event.",
  },
] as const;

// Mutability regime. All three landing relations are insert-only: BEFORE UPDATE OR
// DELETE triggers raise rather than allowing any post-commit edit, so the persisted path,
// its proof header, and the appended event are durable evidence, not mutable state.
export const RECEIVE_EXTERNAL_LANDING_MUTABILITY_REGIMES = [
  {
    table: "receive_landing_proofs",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "RECEIVE_LANDING_INSERT_ONLY — the trigger rejects UPDATE and DELETE outright.",
  },
  {
    table: "receive_landing_path_bodies",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "RECEIVE_LANDING_INSERT_ONLY — the trigger rejects UPDATE and DELETE outright.",
  },
  {
    table: "receive_landing_events",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "RECEIVE_LANDING_INSERT_ONLY — the trigger rejects UPDATE and DELETE outright.",
  },
] as const;

// Live-database obligations the schema phase alone cannot discharge. The [pg] items are
// proven in packages/node-core/test/receive-external-landing-pg.test.ts.
export const SCHEMA_RECEIVE_EXTERNAL_LANDING_OBLIGATIONS = [
  "apply sequence: operations.sql before this slice — the first CREATE TABLE foreign-keys operations.",
  "[pg] the READY -> RECEIVE_LANDED advance, proof header, ordered path bodies, and receive.landed append co-commit in one DB-TX: no window where one is durable without the others.",
  "[pg] two concurrent emitters yield exactly one RECEIVE_LANDED and exactly one receive.landed row — the status/row_version CAS is the arbiter, the unique index the backstop (indicator 4).",
  "[pg] the receiver lease row is byte-identical before and after the transition — no statement here releases, renews or rewrites it.",
  "[pg] a path missing any body, mis-anchored at either end, or backlink-broken aborts the whole landing DB-TX at COMMIT and leaves the operation READY (indicator 1b).",
  "[pg] UPDATE and DELETE against any of the three landing relations raise the insert-only exception.",
] as const;

export const RECEIVE_EXTERNAL_LANDING_SOURCE =
  "operation-flows: receive landing; data-model: landing proofs and node events" as const;
