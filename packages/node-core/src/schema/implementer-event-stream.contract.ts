// Frozen inventory for implementer-event-stream.sql.
// The implementer-scoped continuity stream and the event/SSE/snapshot serving surface.

export const IMPLEMENTER_EVENT_STREAM_SCHEMA_FILE = "implementer-event-stream.sql" as const;

export interface ImplementerEventStreamInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const IMPLEMENTER_EVENT_STREAM_INVARIANTS: readonly ImplementerEventStreamInvariant[] = [
  {
    id: "IMPLEMENTER_SEQ_COUNTER_COMPOSITE_PK",
    sqlAnchor:
      "CREATE TABLE implementer_event_seq_counters (\n  node_id uuid NOT NULL,\n  implementer_id uuid NOT NULL,\n  next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq > 0),\n  PRIMARY KEY (node_id, implementer_id)\n);",
    rule: "implementer_seq is allocated from a dedicated per-(node, implementer) counter, never an identity column.",
  },
  {
    id: "IMPLEMENTER_EVENTS_GAPLESS_PK",
    sqlAnchor: "PRIMARY KEY (node_id, implementer_id, implementer_seq),",
    rule: "each (node, implementer, implementer_seq) appears at most once — the gapless cursor primary key.",
  },
  {
    id: "IMPLEMENTER_EVENTS_CLOSED_TYPE_SET",
    sqlAnchor: "event_type text NOT NULL CHECK (event_type IN (",
    rule: "event_type is constrained to the closed nine-value event set.",
  },
  {
    id: "IMPLEMENTER_EVENTS_APPEND_ONLY_UPDATE",
    sqlAnchor: "CREATE TRIGGER implementer_events_no_update",
    rule: "implementer_events rejects UPDATE (append-only evidence).",
  },
  {
    id: "IMPLEMENTER_EVENTS_APPEND_ONLY_DELETE",
    sqlAnchor: "CREATE TRIGGER implementer_events_no_delete",
    rule: "implementer_events rejects DELETE (append-only evidence).",
  },
  {
    id: "SNAPSHOT_LATEST_PER_IMPLEMENTER",
    sqlAnchor: "CREATE TABLE implementer_state_snapshots (",
    rule: "one latest snapshot row per (node, implementer); watermark is the exclusive resume cursor.",
  },
  {
    id: "IMPLEMENTER_CHECKPOINTS_PK",
    sqlAnchor: "CREATE TABLE implementer_checkpoints (",
    rule: "durable zp-implementer-checkpoint-v1 proofs for GET /v1/events checkpoints[].",
  },
  {
    id: "IMPLEMENTER_CHECKPOINTS_APPEND_ONLY_UPDATE",
    sqlAnchor: "CREATE TRIGGER implementer_checkpoints_no_update",
    rule: "implementer_checkpoints rejects UPDATE (append-only evidence).",
  },
  {
    id: "IMPLEMENTER_CHECKPOINTS_APPEND_ONLY_DELETE",
    sqlAnchor: "CREATE TRIGGER implementer_checkpoints_no_delete",
    rule: "implementer_checkpoints rejects DELETE (append-only evidence).",
  },
] as const;
