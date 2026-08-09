-- Frozen contract text: enumerations and operation verification acknowledgements.
-- This is a contract artifact: forward references into the separately owned landing-proof
-- tables are intentional and do not imply standalone executability.

CREATE TYPE lineage_proof_verdict AS ENUM (
  'LANDED_EXACT',
  'LANDED_COMPLETE_PATH',
  'INDETERMINATE',
  'INVARIANT_BREACH'
);

CREATE TYPE verification_verdict AS ENUM (
  'PENDING',
  'VERIFIED',
  'REJECTED',
  'INDETERMINATE'
);

CREATE TYPE reporting_request_class AS ENUM ('READ', 'MUTATION');

CREATE TABLE operation_verifications (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  verifier_observer_id uuid NOT NULL REFERENCES observers(id),
  t0_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  terminal_observation_id uuid REFERENCES gateway_observations(id),
  landing_proof_id uuid,
  verdict verification_verdict NOT NULL,
  reason_code text NOT NULL,
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (operation_id, verifier_observer_id, t0_observation_id, terminal_observation_id),
  FOREIGN KEY (landing_proof_id, operation_id, verifier_observer_id)
    REFERENCES operation_landing_proofs(id, operation_id, verifier_observer_id),
  CHECK (verdict <> 'VERIFIED' OR landing_proof_id IS NOT NULL)
);

CREATE TABLE verification_acknowledgements (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  route_id text NOT NULL DEFAULT 'verification_complete'
    CHECK (route_id = 'verification_complete'),
  reporting_purpose text NOT NULL DEFAULT 'zp-report-request-v1'
    CHECK (reporting_purpose = 'zp-report-request-v1'),
  request_class reporting_request_class NOT NULL DEFAULT 'MUTATION'
    CHECK (request_class = 'MUTATION'),
  retention_class text NOT NULL DEFAULT 'PERMANENT_MUTATION'
    CHECK (retention_class = 'PERMANENT_MUTATION'),
  method text NOT NULL DEFAULT 'POST' CHECK (method = 'POST'),
  raw_target text NOT NULL,
  consumed_cursor bigint NOT NULL CHECK (consumed_cursor >= 0),
  verdict verification_verdict NOT NULL CHECK (verdict <> 'PENDING'),
  evidence_set_sha256 sha256_hex NOT NULL,
  request_body_sha256 sha256_hex NOT NULL,
  logical_fingerprint sha256_hex GENERATED ALWAYS AS
    (reporting_logical_fingerprint(method, raw_target, request_body_sha256)) STORED,
  reporting_nonce_id uuid NOT NULL UNIQUE,
  mutation_idempotency_id uuid NOT NULL UNIQUE,
  acknowledged_at timestamptz NOT NULL,
  UNIQUE (id, node_id, implementer_id),
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

CREATE FUNCTION reporting_assert_completed_mutation(p_idempotency_id uuid)
RETURNS void LANGUAGE plpgsql
AS $$
DECLARE
  p reporting_mutation_idempotency%ROWTYPE;
  matching_children integer;
BEGIN
  SELECT * INTO STRICT p
    FROM reporting_mutation_idempotency
    WHERE id = p_idempotency_id;

  CASE p.route_id
    WHEN 'operation_armed' THEN
      SELECT count(*) INTO matching_children
      FROM receive_arms a
      WHERE a.id = p.child_record_id
        AND a.mutation_idempotency_id = p.id
        AND a.reporting_nonce_id = p.reporting_nonce_id
        AND a.node_id = p.node_id
        AND a.implementer_id = p.implementer_id
        AND a.route_id = p.route_id
        AND a.method = p.method
        AND a.raw_target = p.raw_target
        AND a.request_body_sha256 = p.body_sha256
        AND a.logical_fingerprint = p.logical_fingerprint;
    WHEN 'verification_complete' THEN
      SELECT count(*) INTO matching_children
      FROM verification_acknowledgements a
      WHERE a.id = p.child_record_id
        AND a.mutation_idempotency_id = p.id
        AND a.reporting_nonce_id = p.reporting_nonce_id
        AND a.node_id = p.node_id
        AND a.implementer_id = p.implementer_id
        AND a.route_id = p.route_id
        AND a.method = p.method
        AND a.raw_target = p.raw_target
        AND a.request_body_sha256 = p.body_sha256
        AND a.logical_fingerprint = p.logical_fingerprint;
    ELSE
      RAISE EXCEPTION 'unsupported completed reporting mutation route %', p.route_id
        USING ERRCODE = '23514';
  END CASE;

  IF matching_children <> 1 THEN
    RAISE EXCEPTION 'completed idempotency/child correlation is incomplete'
      USING ERRCODE = '23514';
  END IF;
END
$$;

CREATE FUNCTION reporting_validate_mutation_deferred()
RETURNS trigger LANGUAGE plpgsql
AS $$
DECLARE
  parent_id uuid;
BEGIN
  -- A branch, never a CASE expression: plpgsql resolves EVERY column reference in one
  -- expression against NEW's actual row type, so the unused arm's
  -- `NEW.mutation_idempotency_id` raises 42703 on reporting_mutation_idempotency, which
  -- has no such column. IF arms are planned only when taken.
  IF TG_TABLE_NAME = 'reporting_mutation_idempotency' THEN
    parent_id := NEW.id;
  ELSE
    parent_id := NEW.mutation_idempotency_id;
  END IF;
  PERFORM reporting_assert_completed_mutation(parent_id);
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER reporting_completed_parent_has_child
  AFTER INSERT ON reporting_mutation_idempotency
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();
CREATE CONSTRAINT TRIGGER reporting_arm_has_completed_parent
  AFTER INSERT ON receive_arms
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();
CREATE CONSTRAINT TRIGGER reporting_ack_has_completed_parent
  AFTER INSERT ON verification_acknowledgements
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();

CREATE TRIGGER reporting_arms_immutable
  BEFORE UPDATE OR DELETE ON receive_arms
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_acks_immutable
  BEFORE UPDATE OR DELETE ON verification_acknowledgements
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_arms_no_truncate
  BEFORE TRUNCATE ON receive_arms
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_acks_no_truncate
  BEFORE TRUNCATE ON verification_acknowledgements
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

REVOKE UPDATE, DELETE, TRUNCATE ON receive_arms,
  verification_acknowledgements FROM node_runtime;

CREATE TABLE verification_ack_wallet_evidence (
  acknowledgement_id uuid NOT NULL REFERENCES verification_acknowledgements(id),
  evidence_role text NOT NULL CHECK (evidence_role IN
    ('SOURCE','RECEIVER','DESTINATION')),
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  t0_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  terminal_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  PRIMARY KEY (acknowledgement_id, evidence_role),
  UNIQUE (acknowledgement_id, wallet_public_key)
);

ALTER TABLE receive_release_proofs
  ADD FOREIGN KEY (verification_acknowledgement_id)
    REFERENCES verification_acknowledgements(id);
