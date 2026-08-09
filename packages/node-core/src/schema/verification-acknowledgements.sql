-- Stands up verification_acknowledgements + verification_ack_wallet_evidence, required by
-- the live verification-complete route.
--
-- landing-proof-verifications.sql deliberately excludes this surface.
-- Appended pack slice — never renumber prior slices.
--
-- Does NOT re-declare operation_verifications (landing-proof-verifications owns it).
-- Does NOT re-declare reporting_request_class (reporting 0000 / base-enums-domains).
--
-- Correlation discipline: the composition root writes the completed
-- idempotency parent and the ack child in ONE transaction (verification-complete-route
-- freezeResponse + acknowledgement-sql). This slice installs the composite child→parent FK
-- above and nothing else; the deferred correlation triggers that close the parent→child
-- direction live in mutation-correlation.sql, the pack slice applied immediately after this
-- one (both attachment targets have to exist first). They are DEFERRABLE INITIALLY DEFERRED,
-- so either write sequence inside that single transaction is lawful.
--
-- The ack table shape is verbatim from verification-proofs.sql.

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

CREATE TRIGGER reporting_acks_immutable
  BEFORE UPDATE OR DELETE ON verification_acknowledgements
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_acks_no_truncate
  BEFORE TRUNCATE ON verification_acknowledgements
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER verification_ack_wallet_evidence_immutable
  BEFORE UPDATE OR DELETE ON verification_ack_wallet_evidence
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

-- Optional FK from receive_release_proofs when that table + column exist.
DO $$
BEGIN
  IF to_regclass('public.receive_release_proofs') IS NOT NULL
     AND EXISTS (
       SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'receive_release_proofs'
          AND column_name = 'verification_acknowledgement_id'
     )
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint
        WHERE conname = 'receive_release_proofs_verification_acknowledgement_id_fkey'
     ) THEN
    ALTER TABLE receive_release_proofs
      ADD CONSTRAINT receive_release_proofs_verification_acknowledgement_id_fkey
      FOREIGN KEY (verification_acknowledgement_id)
      REFERENCES verification_acknowledgements(id);
  END IF;
EXCEPTION
  WHEN undefined_column THEN
    NULL;
  WHEN duplicate_object THEN
    NULL;
END
$$;
