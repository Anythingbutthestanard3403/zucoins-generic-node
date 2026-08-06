-- Receive barriers: the durable receive-arm acknowledgement, the operation store /
-- readiness surface, the migration lock and classifier discipline, and the
-- receive_release_proofs parent being operations(id).
--
-- receive_arms is the durable idempotency proof that the arm step committed.
-- It inherits its append-only regime from the reporting_arms_immutable trigger
-- in verification-proofs.sql and the matching
-- REVOKE UPDATE, DELETE, TRUNCATE below; both the BEFORE trigger and the REVOKE
-- are replicated here so the table is structurally protected whether
-- verification-proofs.sql has applied yet or not.
--
-- Prerequisite slices (must exist EARLIER in apply sequence):
--   custody-eligibility.sql   — nodes(id), implementers(id), wallets(id)
--   operations.sql            — operations(id) + UNIQUE(id, node_id, implementer_id)
--   receive-codes.sql         — receive_codes(operation_id)
--   reporting-persistence.sql — reporting_request_nonces + reporting_mutation_idempotency
--   verification-proofs.sql   — verification_acknowledgements (constraint trigger target)
--
-- FKs are added after CREATE TABLE so the block stays readable and each FK text
-- can anchor an independent invariant inventory entry.

CREATE TABLE receive_arms (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES receive_codes(operation_id),
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  route_id text NOT NULL DEFAULT 'operation_armed'
    CHECK (route_id = 'operation_armed'),
  reporting_purpose text NOT NULL DEFAULT 'zp-report-request-v1'
    CHECK (reporting_purpose = 'zp-report-request-v1'),
  request_class reporting_request_class NOT NULL DEFAULT 'MUTATION'
    CHECK (request_class = 'MUTATION'),
  retention_class text NOT NULL DEFAULT 'PERMANENT_MUTATION'
    CHECK (retention_class = 'PERMANENT_MUTATION'),
  method text NOT NULL DEFAULT 'POST' CHECK (method = 'POST'),
  raw_target text NOT NULL,
  node_t0_observation_id uuid NOT NULL,
  acknowledged_s text NOT NULL,
  acknowledged_p text NOT NULL,
  acknowledged_b zkz_balance_text NOT NULL,
  opened_cursor bigint NOT NULL CHECK (opened_cursor >= 0),
  request_body_sha256 sha256_hex NOT NULL,
  logical_fingerprint sha256_hex GENERATED ALWAYS AS
    (reporting_logical_fingerprint(method, raw_target, request_body_sha256)) STORED,
  reporting_nonce_id uuid NOT NULL UNIQUE,
  mutation_idempotency_id uuid NOT NULL UNIQUE,
  armed_at timestamptz NOT NULL,
  UNIQUE (node_id, implementer_id, route_id, method, raw_target,
    request_body_sha256),
  FOREIGN KEY (operation_id, node_id, implementer_id)
    REFERENCES operations(id, node_id, implementer_id),
  FOREIGN KEY (
    reporting_nonce_id, node_id, implementer_id, reporting_purpose, route_id,
    request_class, retention_class, method, raw_target, request_body_sha256,
    logical_fingerprint
  )
    REFERENCES reporting_request_nonces
      (id, node_id, implementer_id, purpose, route_id, request_class,
       retention_class, method, raw_target, body_sha256, logical_fingerprint),
  FOREIGN KEY (
    mutation_idempotency_id, node_id, implementer_id, route_id, method,
    raw_target, request_body_sha256, logical_fingerprint
  ) REFERENCES reporting_mutation_idempotency
    (id, node_id, implementer_id, route_id, method, raw_target,
     body_sha256, logical_fingerprint)
    DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE receive_arms
  ADD FOREIGN KEY (node_t0_observation_id) REFERENCES gateway_observations(id);

CREATE FUNCTION receive_arms_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'RECEIVE_ARMS_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER receive_arms_insert_only
  BEFORE UPDATE OR DELETE ON receive_arms
  FOR EACH ROW EXECUTE FUNCTION receive_arms_reject_mutation();

CREATE TRIGGER receive_arms_no_truncate
  BEFORE TRUNCATE ON receive_arms
  FOR EACH STATEMENT EXECUTE FUNCTION receive_arms_reject_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON receive_arms FROM node_runtime;
