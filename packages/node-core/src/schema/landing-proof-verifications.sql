-- Stands up operation_landing_proofs and wires operation_verifications into the
-- production money schema pack.
--
-- verification-proofs.sql's operation_verifications already carries a FK to
-- operation_landing_proofs, but no pack slice created that table, so
-- verification-proofs.sql stayed in MONEY_SCHEMA_PACK_EXCLUDED_AFTER_REPORTING
-- (see money-schema-pack.ts) and wallet_settled_ledger's landed-verbatim trigger
-- had nothing to query. This slice creates operation_landing_proofs and
-- re-declares operation_verifications (verbatim from verification-proofs.sql)
-- so both exist in the real production schema.
--
-- Deliberately excludes verification_acknowledgements and the reporting-mutation
-- idempotency machinery verification-proofs.sql also carries: this slice is exactly
-- operation_landing_proofs + operation_verifications, no more. verification-proofs.sql
-- remains excluded from the pack for that unrelated remaining surface.
--
-- Backs settlement-confirmation reads and the buried-landing any-depth complete-path
-- landing oracle.

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

CREATE TABLE operation_landing_proofs (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  verifier_observer_id uuid NOT NULL REFERENCES observers(id),
  expected_transaction_attempt_no integer NOT NULL CHECK (expected_transaction_attempt_no = 1),
  verdict lineage_proof_verdict NOT NULL,
  required_path_count integer NOT NULL CHECK (required_path_count IN (1,2)),
  declared_body_count bigint NOT NULL CHECK (declared_body_count > 0),
  declared_total_body_bytes bigint NOT NULL CHECK (declared_total_body_bytes > 0),
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  verified_at timestamptz,
  created_at timestamptz NOT NULL,
  UNIQUE (id, operation_id, verifier_observer_id),
  FOREIGN KEY (operation_id, expected_transaction_attempt_no)
    REFERENCES operation_transactions(operation_id, attempt_no),
  CHECK ((verdict IN ('LANDED_EXACT','LANDED_COMPLETE_PATH')) = (verified_at IS NOT NULL))
);

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
