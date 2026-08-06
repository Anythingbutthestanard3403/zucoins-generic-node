// Send external expiry: the post-delivery park into NEEDS_ATTENTION, the closed
// attention-reason vocabulary, and the operations attention columns;
// SEND_EXTERNAL expiry single-source.
//
// Frozen schema contract for send-external-expiry.sql. The slice EXTENDS
// send-external-create.sql (send_operations) — it adds attention_reason /
// attention_episode and the insert-only external_send_attention_events relation.
// It never releases the source lease: no statement touches wallet_active_leases.
//
// reconciliation note: the first statement ALTERs send_operations, which this
// package creates only in send-external-create.sql, so the slice is prerequisite-bound
// greenfield — applied alone it fails on send_operations. Characterized in
// migration-integrity.test.ts; the real-Postgres behavioral proof is
// send-expiry-attention.pg.test.ts.

export const SEND_EXTERNAL_EXPIRY_SCHEMA_FILE = "send-external-expiry.sql" as const;

/** The slice this one extends — owner of send_operations. */
export const SEND_EXTERNAL_EXPIRY_EXTENDS = "send-external-create.sql" as const;

export interface SendExternalExpiryInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const SEND_EXTERNAL_EXPIRY_INVARIANTS: readonly SendExternalExpiryInvariant[] = [
  {
    id: "ATTENTION_FLAG_MATCHES_REASON",
    sqlAnchor: "CONSTRAINT send_operations_attention_flag_matches_reason",
    rule: "Co-presence: attention_required is true iff attention_reason is non-NULL.",
  },
  {
    id: "ATTENTION_REASON_CLOSED_VOCABULARY",
    sqlAnchor: "CONSTRAINT send_operations_attention_reason_closed",
    rule: "The closed 15-value attention_reason set; a typo cannot invent a 16th.",
  },
  {
    id: "ATTENTION_EPISODE_NON_NEGATIVE",
    sqlAnchor: "attention_episode integer NOT NULL DEFAULT 0",
    rule: "each needs_attention episode increments; the counter never goes negative.",
  },
  {
    id: "EVENT_TYPE_FROZEN",
    sqlAnchor: "event_type text NOT NULL CHECK (event_type = 'operation.needs_attention')",
    rule: "the slice-local event table carries exactly the needs_attention event.",
  },
  {
    id: "EVENT_EPISODE_POSITIVE",
    sqlAnchor: "attention_episode integer NOT NULL CHECK (attention_episode >= 1)",
    rule: "an appended needs_attention event always references a real (post-increment) episode.",
  },
  {
    id: "EVENT_DATA_NONEMPTY",
    sqlAnchor: "data_text text NOT NULL CHECK (octet_length(data_text) > 0)",
    rule: "The event data shape is non-empty bytes; empty audit rows are unrepresentable.",
  },
  {
    id: "EVENT_INSERT_ONLY",
    sqlAnchor:
      "CREATE TRIGGER external_send_attention_events_insert_only\n  BEFORE UPDATE OR DELETE ON external_send_attention_events",
    rule: "attention events are insert-only durable evidence — UPDATE/DELETE raise.",
  },
  {
    id: "NO_LEASE_TOUCH",
    sqlAnchor:
      "-- There is no AWAITING_REDEMPTION → EXPIRED / REJECTED path, and no statement in",
    rule: "The one-in-flight-per-wallet rule: this slice never DELETEs or UPDATEs wallet_active_leases.",
  },
] as const;

export const SEND_EXTERNAL_EXPIRY_MUTABILITY_REGIMES = [
  {
    table: "external_send_attention_events",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "EXTERNAL_SEND_ATTENTION_EVENT_INSERT_ONLY — the trigger rejects UPDATE and DELETE outright.",
  },
] as const;

// Live-database obligations the schema phase alone cannot discharge. The [pg] items are
// proven in packages/node-core/test/send-expiry-attention.pg.test.ts.
export const SCHEMA_SEND_EXTERNAL_EXPIRY_OBLIGATIONS = [
  "apply sequence: custody-eligibility.sql then send-external-create.sql before this slice — the opening ALTER targets send_operations.",
  "[pg] park CAS (AWAITING_REDEMPTION → NEEDS_ATTENTION) and operation.needs_attention event append co-commit in one DB statement/TX: no window where status is NEEDS_ATTENTION without the audit row.",
  "[pg] the source lease is still held after park — no statement here releases it.",
  "[pg] a second park on an already-attention operation returns ALREADY_ATTENTION rather than double-incrementing the episode.",
  "[pg] UPDATE and DELETE against external_send_attention_events raise the insert-only exception.",
  "[pg] AWAITING_REDEMPTION cannot transition to EXPIRED via any path in this gate.",
] as const;

export const SEND_EXTERNAL_EXPIRY_SOURCE =
  "operations-recovery: send expiry park; state-event reference: attention reasons" as const;
