// Send external landing: the landing DB-TX (AWAITING_REDEMPTION/NEEDS_ATTENTION →
// EXTERNAL_SEND_LANDED with the external_send.landed event),
// verification_material_available_until, and the canonical-container retention rule.
//
// Frozen schema contract for send-external-landing.sql. The slice EXTENDS
// send-external-create.sql (send_operations) — it adds the landing columns to that relation and
// creates the two insert-only landing relations. It never releases the source lease: release is
// the separate verification-complete step, so no statement in the SQL touches
// wallet_active_leases.
//
// reconciliation note: the first statement ALTERs send_operations, which this package
// creates only in send-external-create.sql, so the slice is prerequisite-bound greenfield —
// applied alone it fails on send_operations. Characterized in migration-integrity.test.ts;
// the real-Postgres behavioral proof is send-external-landing-pg.test.ts.

export const SEND_EXTERNAL_LANDING_SCHEMA_FILE = "send-external-landing.sql" as const;

/** The slice this one extends — owner of send_operations. */
export const SEND_EXTERNAL_LANDING_EXTENDS = "send-external-create.sql" as const;

export interface SendExternalLandingInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const SEND_EXTERNAL_LANDING_INVARIANTS: readonly SendExternalLandingInvariant[] = [
  {
    id: "ONE_LANDING_RECORD_PER_OPERATION",
    sqlAnchor: "operation_id uuid PRIMARY KEY REFERENCES send_operations (operation_id),",
    rule: "at most one landing record per operation; the operation must already exist.",
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
    id: "EXACT_BODY_BYTES_PERSISTED",
    sqlAnchor:
      "completed_transaction_sha256 text NOT NULL CHECK (completed_transaction_sha256 ~ '^[0-9a-f]{64}$')",
    rule: "the exact completed settled body text is stored alongside its sha256 — byte identity, never a parsed re-encoding (the byte-exact signing rule).",
  },
  {
    id: "LANDING_ORACLE_IS_EXACT_OR_COMPLETE_PATH",
    sqlAnchor:
      "source_path_kind text NOT NULL CHECK (source_path_kind IN ('LANDED_EXACT', 'LANDED_COMPLETE_PATH'))",
    rule: "only the two landing oracles are storable; the one-hop LANDED_DIRECT_SUCCESSOR shortcut has no representation here.",
  },
  {
    id: "PATH_DEPTH_MATCHES_ORACLE",
    sqlAnchor: "CONSTRAINT external_send_landing_path_depth_kind",
    rule: "LANDED_EXACT pins depth 0 and LANDED_COMPLETE_PATH pins depth >= 1 — a buried landing cannot be recorded as an exact-head one.",
  },
  {
    id: "BOTH_ENTRY_STATES_ACCEPTED",
    sqlAnchor:
      "entry_status text NOT NULL CHECK (entry_status IN ('AWAITING_REDEMPTION', 'NEEDS_ATTENTION'))",
    rule: "the landing transition is reachable identically from both entry states, and which one it came from stays on the record.",
  },
  {
    id: "ONE_LANDED_EVENT_PER_OPERATION",
    sqlAnchor: "CREATE UNIQUE INDEX external_send_landing_events_one_per_operation",
    rule: "external_send.landed is appended at most once per operation.",
  },
  {
    id: "EVENT_TYPE_FROZEN",
    sqlAnchor: "event_type text NOT NULL CHECK (event_type = 'external_send.landed')",
    rule: "the slice-local event table carries exactly the landing event.",
  },
] as const;

// Mutability regime. Both landing relations are insert-only: the DDL installs BEFORE
// UPDATE OR DELETE triggers that raise rather than allowing any post-commit edit, so the
// persisted settled body and the appended event are durable evidence, not mutable state.
export const SEND_EXTERNAL_LANDING_MUTABILITY_REGIMES = [
  {
    table: "external_send_landing_records",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "EXTERNAL_SEND_LANDING_INSERT_ONLY — the trigger rejects UPDATE and DELETE outright.",
  },
  {
    table: "external_send_landing_events",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "EXTERNAL_SEND_LANDING_EVENT_INSERT_ONLY — the trigger rejects UPDATE and DELETE outright.",
  },
] as const;

// Live-database obligations the schema phase alone cannot discharge. The [pg] items are
// proven in packages/node-core/test/send-external-landing-pg.test.ts.
export const SCHEMA_SEND_EXTERNAL_LANDING_OBLIGATIONS = [
  "apply sequence: custody-eligibility.sql then send-external-create.sql before this slice — the opening ALTER targets send_operations.",
  "[pg] the status advance, landing-record insert, and event append co-commit in one DB-TX: no window where one is durable without the others.",
  "[pg] the source lease is still held after EXTERNAL_SEND_LANDED — no statement here releases it.",
  "[pg] a second landing attempt on an already-landed operation raises ALREADY_LANDED rather than writing a second record.",
  "[pg] UPDATE and DELETE against either landing relation raise the insert-only exception.",
] as const;

export const SEND_EXTERNAL_LANDING_SOURCE =
  "operation-flows: external send landing; state-event reference: landing event" as const;
