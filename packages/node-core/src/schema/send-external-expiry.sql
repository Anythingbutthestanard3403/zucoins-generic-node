-- Send external expiry: the post-delivery park into NEEDS_ATTENTION, the closed
-- attention-reason vocabulary, and the operations attention columns.
-- Frozen schema contract extension on send_operations for post-delivery expiry
-- attention. Prerequisite: send-external-create.sql (send_operations).
--
-- Post-delivery expiry parks AWAITING_REDEMPTION → NEEDS_ATTENTION only.
-- There is no AWAITING_REDEMPTION → EXPIRED / REJECTED path, and no statement in
-- this file DELETEs or UPDATEs wallet_active_leases.
--
-- Single-shot contract text (no IF NOT EXISTS / DROP guards): re-application over an
-- already-migrated schema fails, matching every other SCHEMA_FILES slice.

-- Attention columns matching operations.sql: flag and reason are co-present
-- or co-absent; episode increments on each new needs_attention episode.
ALTER TABLE send_operations
  ADD COLUMN attention_reason text,
  ADD COLUMN attention_episode integer NOT NULL DEFAULT 0
    CHECK (attention_episode >= 0);

ALTER TABLE send_operations
  ADD CONSTRAINT send_operations_attention_flag_matches_reason
  CHECK (attention_required = (attention_reason IS NOT NULL));

-- Closed attention-reason vocabulary (15 values). Adding a reason is schema-compatible;
-- this CHECK pins the launch set so a typo cannot invent a 16th.
ALTER TABLE send_operations
  ADD CONSTRAINT send_operations_attention_reason_closed
  CHECK (
    attention_reason IS NULL
    OR attention_reason IN (
      'GATEWAY_RESPONSE_INVALID',
      'GATEWAY_UNAVAILABLE_BEYOND_BUDGET',
      'UNEXPECTED_HEAD_CHANGE',
      'LINEAGE_GAP',
      'SUBMIT_OUTCOME_AMBIGUOUS',
      'SIGNING_OUTCOME_AMBIGUOUS',
      'DESTINATION_NO_LONGER_BLESSED',
      'T0_RELEASE_MISMATCH',
      'VERIFICATION_REJECTED',
      'VERIFICATION_INDETERMINATE',
      'VERIFICATION_RESOURCE_EXHAUSTED',
      'LEASE_INVARIANT_VIOLATION',
      'EXACT_BYTES_UNAVAILABLE',
      'OPERATOR_PARKED',
      'POST_EXPIRY_RECONCILING'
    )
  );

-- Slice-local event append for operation.needs_attention.
-- The full node_events ledger remains the event-ledger surface; this table proves the
-- attention transition co-commits an audit row without touching leases or partial bytes.
CREATE TABLE external_send_attention_events (
  event_id bigserial PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES send_operations (operation_id),
  event_type text NOT NULL CHECK (event_type = 'operation.needs_attention'),
  attention_reason text NOT NULL,
  attention_episode integer NOT NULL CHECK (attention_episode >= 1),
  data_text text NOT NULL CHECK (octet_length(data_text) > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX external_send_attention_events_operation_id_idx
  ON external_send_attention_events (operation_id);

CREATE FUNCTION external_send_attention_event_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'EXTERNAL_SEND_ATTENTION_EVENT_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER external_send_attention_events_insert_only
  BEFORE UPDATE OR DELETE ON external_send_attention_events
  FOR EACH ROW EXECUTE FUNCTION external_send_attention_event_reject_mutation();
