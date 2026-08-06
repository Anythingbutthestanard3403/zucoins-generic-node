-- Receive expiry release: the expiry flow, the recovery release predicates, the receive
-- barriers, and the event ledger.
--
-- Extension of operations.sql and the receive_release_proofs relation. The service
-- performs the status CAS, code revocation, proof append, exact-tuple lease release,
-- wallet unpin, and event append inside one SERIALIZABLE transaction.
-- Parent FK is operations(id), not receive_codes: pre-code and PROVEN_NOT_STARTED
-- releases predate any code row.

ALTER TABLE operations
  ADD COLUMN attention_episode integer NOT NULL DEFAULT 0
    CHECK (attention_episode >= 0),
  ADD COLUMN receive_release_status text
    CHECK (
      receive_release_status IS NULL
      OR receive_release_status IN (
        'RELEASED_T0_UNCHANGED',
        'RELEASED_PROVEN_NOT_STARTED'
      )
    );

CREATE TABLE receive_release_proofs (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  release_kind text NOT NULL CHECK (release_kind IN (
    'VERIFICATION_COMPLETE','EXPIRED_T0_UNCHANGED','EXPIRED_PROVEN_NOT_STARTED')),
  t0_observation_id uuid,
  fresh_observation_id uuid,
  verification_acknowledgement_id uuid,
  proof_manifest_text text NOT NULL CHECK (octet_length(proof_manifest_text) > 0),
  proof_manifest_sha256 sha256_hex NOT NULL,
  released_at timestamptz NOT NULL,
  CHECK (
    (release_kind = 'VERIFICATION_COMPLETE'
      AND verification_acknowledgement_id IS NOT NULL
      AND t0_observation_id IS NOT NULL AND fresh_observation_id IS NOT NULL)
    OR
    (release_kind = 'EXPIRED_T0_UNCHANGED'
      AND verification_acknowledgement_id IS NULL
      AND t0_observation_id IS NOT NULL AND fresh_observation_id IS NOT NULL)
    OR
    (release_kind = 'EXPIRED_PROVEN_NOT_STARTED'
      AND verification_acknowledgement_id IS NULL
      AND t0_observation_id IS NULL AND fresh_observation_id IS NULL)
  )
);

-- Observation FKs (nullable-ok for EXPIRED_PROVEN_NOT_STARTED). observation-ledger
-- precedes this file in SCHEMA_FILES; verification-proofs owns the ack FK ALTER.
ALTER TABLE receive_release_proofs
  ADD FOREIGN KEY (t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (fresh_observation_id) REFERENCES gateway_observations(id);

CREATE TABLE receive_expiry_events (
  event_id bigserial PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  event_type text NOT NULL CHECK (event_type = 'operation.expired'),
  data_text text NOT NULL CHECK (octet_length(data_text) > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX receive_expiry_events_one_per_operation
  ON receive_expiry_events (operation_id);

CREATE TABLE receive_expiry_attention_events (
  event_id bigserial PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  event_type text NOT NULL CHECK (event_type = 'operation.needs_attention'),
  attention_reason text NOT NULL,
  attention_episode integer NOT NULL CHECK (attention_episode >= 1),
  data_text text NOT NULL CHECK (octet_length(data_text) > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX receive_expiry_attention_events_one_per_episode
  ON receive_expiry_attention_events (operation_id, attention_episode);

CREATE FUNCTION receive_expiry_event_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'RECEIVE_EXPIRY_EVENT_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER receive_release_proofs_insert_only
  BEFORE UPDATE OR DELETE ON receive_release_proofs
  FOR EACH ROW EXECUTE FUNCTION receive_expiry_event_reject_mutation();

CREATE TRIGGER receive_expiry_events_insert_only
  BEFORE UPDATE OR DELETE ON receive_expiry_events
  FOR EACH ROW EXECUTE FUNCTION receive_expiry_event_reject_mutation();

CREATE TRIGGER receive_expiry_attention_events_insert_only
  BEFORE UPDATE OR DELETE ON receive_expiry_attention_events
  FOR EACH ROW EXECUTE FUNCTION receive_expiry_event_reject_mutation();
