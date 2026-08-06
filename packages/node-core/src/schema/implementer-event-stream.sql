-- The implementer-scoped continuity stream (dual continuity): events, SSE and snapshot
-- serve the calling implementer's own zp-implementer-event-v1 stream, checkpoints ride
-- GET /v1/events, and event_type is drawn from the closed nine-value event set.
--
-- Contract text for the durable serving tables behind GET /v1/events, GET /v1/events/stream and
-- GET /v1/state/snapshot. Byte-exact zp-implementer-event-v1 / -checkpoint-v1 preimage field
-- sequences are frozen elsewhere; this fragment stores already-signed proof
-- representations as opaque text plus the gapless implementer_seq cursor. The mint/writer that
-- produces the proofs is a separate slice; this schema is the read/serve durability surface.
--
-- Scope: per-(node_id, implementer_id) sequence counter, append-only implementer event rows,
-- append-only implementer checkpoint rows (GET /v1/events `checkpoints[]`), and the latest
-- transactionally consistent tenant snapshot row. No node-global event ledger / zp-node-
-- event-v1 columns appear here (NC2).

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE TABLE implementer_event_seq_counters (
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq > 0),
  PRIMARY KEY (node_id, implementer_id)
);

CREATE TABLE implementer_events (
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  implementer_seq bigint NOT NULL CHECK (implementer_seq > 0),
  event_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type IN (
    'receive.ready',
    'receive.landed',
    'internal_move.created',
    'internal_move.landed',
    'external_send.created',
    'external_send.awaiting_redemption',
    'external_send.landed',
    'operation.needs_attention',
    'operation.expired'
  )),
  -- Exact zp-implementer-event-v1 public proof representation text as served on the wire
  --. Stored opaque — never re-serialized by the serve path (the byte-exact signing rule).
  proof_representation text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (node_id, implementer_id, implementer_seq),
  UNIQUE (node_id, implementer_id, event_id)
);

CREATE INDEX implementer_events_scan_idx
  ON implementer_events (node_id, implementer_id, implementer_seq);

-- Latest snapshot per implementer. Overwritten on each capture; history is the event stream.
CREATE TABLE implementer_state_snapshots (
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  implementer_watermark_seq bigint NOT NULL CHECK (implementer_watermark_seq >= 0),
  snapshot_body text NOT NULL,
  captured_at timestamptz NOT NULL,
  PRIMARY KEY (node_id, implementer_id)
);

-- Durable zp-implementer-checkpoint-v1 proofs served on GET /v1/events as checkpoints[]
-- One row per accepted (node, implementer, checkpoint_epoch); anti-rollback
-- consumer role is the platform (C3) — this table is the node's emission durability surface.
CREATE TABLE implementer_checkpoints (
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  checkpoint_epoch bigint NOT NULL CHECK (checkpoint_epoch > 0),
  implementer_seq_head bigint NOT NULL CHECK (implementer_seq_head >= 0),
  -- Exact zp-implementer-checkpoint-v1 public proof representation text as served on the wire.
  -- Stored opaque — never re-serialized by the serve path (the byte-exact signing rule).
  proof_representation text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (node_id, implementer_id, checkpoint_epoch)
);

CREATE INDEX implementer_checkpoints_scan_idx
  ON implementer_checkpoints (node_id, implementer_id, checkpoint_epoch);

-- Append-only guards on the event rows (same rejector shape as event-ledger.sql).
CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER implementer_events_no_update
  BEFORE UPDATE ON implementer_events
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER implementer_events_no_delete
  BEFORE DELETE ON implementer_events
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER implementer_events_no_truncate
  BEFORE TRUNCATE ON implementer_events
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER implementer_checkpoints_no_update
  BEFORE UPDATE ON implementer_checkpoints
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER implementer_checkpoints_no_delete
  BEFORE DELETE ON implementer_checkpoints
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER implementer_checkpoints_no_truncate
  BEFORE TRUNCATE ON implementer_checkpoints
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
