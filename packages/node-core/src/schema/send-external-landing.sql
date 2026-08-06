-- Send external landing: the landing DB-TX, the landing event,
-- verification_material_available_until, and the canonical-container retention rule.
-- Frozen schema contract. Prerequisite: send-external-create.sql
-- (send_operations) and custody-eligibility.sql (wallet_active_leases).
--
-- Extends the SEND_EXTERNAL create surface with the durable landing commit:
-- status advance to EXTERNAL_SEND_LANDED, exact settled body at SETTLED_BODY_PERSISTED,
-- public execution phase LANDED_VERIFIED, external_send.landed event, and proof-access
-- expiry. The source lease is NOT released by any statement in this file.

-- Landing columns on the create-time operation row. Written only by the landing DB-TX.
ALTER TABLE send_operations
  ADD COLUMN verification_material_available_until timestamptz,
  ADD COLUMN landed_at timestamptz,
  ADD COLUMN terminal_observation_id uuid;

-- Exact completed settled body + terminal observation at SETTLED_BODY_PERSISTED.
-- One landing record per operation (insert-only).
CREATE TABLE external_send_landing_records (
  operation_id uuid PRIMARY KEY REFERENCES send_operations (operation_id),
  attempt_phase text NOT NULL CHECK (attempt_phase = 'SETTLED_BODY_PERSISTED'),
  public_execution_phase text NOT NULL CHECK (public_execution_phase = 'LANDED_VERIFIED'),
  completed_transaction_text text NOT NULL CHECK (octet_length(completed_transaction_text) > 0),
  completed_transaction_sha256 text NOT NULL CHECK (completed_transaction_sha256 ~ '^[0-9a-f]{64}$'),
  terminal_observation_id uuid NOT NULL,
  source_path_kind text NOT NULL CHECK (source_path_kind IN ('LANDED_EXACT', 'LANDED_COMPLETE_PATH')),
  source_path_depth integer NOT NULL CHECK (source_path_depth >= 0),
  landed_at timestamptz NOT NULL,
  verification_material_available_until timestamptz NOT NULL,
  entry_status text NOT NULL CHECK (entry_status IN ('AWAITING_REDEMPTION', 'NEEDS_ATTENTION')),
  CONSTRAINT external_send_landing_path_depth_kind
    CHECK (
      (source_path_kind = 'LANDED_EXACT' AND source_path_depth = 0)
      OR (source_path_kind = 'LANDED_COMPLETE_PATH' AND source_path_depth >= 1)
    )
);

CREATE FUNCTION external_send_landing_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'EXTERNAL_SEND_LANDING_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER external_send_landing_records_insert_only
  BEFORE UPDATE OR DELETE ON external_send_landing_records
  FOR EACH ROW EXECUTE FUNCTION external_send_landing_reject_mutation();

-- Slice-local event append for external_send.landed.
-- The full node_events ledger remains the event-ledger surface; this table proves atomic
-- event append co-committed with the status transition for the landing money path.
CREATE TABLE external_send_landing_events (
  event_id bigserial PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES send_operations (operation_id),
  event_type text NOT NULL CHECK (event_type = 'external_send.landed'),
  terminal_observation_id uuid NOT NULL,
  landed_at timestamptz NOT NULL,
  data_text text NOT NULL CHECK (octet_length(data_text) > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX external_send_landing_events_one_per_operation
  ON external_send_landing_events (operation_id);

CREATE FUNCTION external_send_landing_event_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'EXTERNAL_SEND_LANDING_EVENT_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER external_send_landing_events_insert_only
  BEFORE UPDATE OR DELETE ON external_send_landing_events
  FOR EACH ROW EXECUTE FUNCTION external_send_landing_event_reject_mutation();
