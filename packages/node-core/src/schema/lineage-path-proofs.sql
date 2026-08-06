-- Stands up lineage_path_proofs + lineage_path_bodies for the production money schema
-- pack.
--
-- The landing-proof slice landed operation_landing_proofs + operation_verifications but
-- deliberately deferred the per-path tables. The verification-material read joins
-- lineage_path_proofs / lineage_path_bodies through operation_landing_proofs; without
-- these relations the verification-material route 500s after auth and
-- verification-complete cannot release leases.
--
-- DDL is the frozen lineage-path shape (byte-compatible with the LINEAGE_SPEC_FIXTURE used
-- by proof-access-verdict-history.pg.test.ts). Appended pack slice -- never renumber prior
-- slices. FK target operation_landing_proofs is created by landing-proof-verifications.

CREATE TABLE lineage_path_proofs (
  id uuid PRIMARY KEY,
  landing_proof_id uuid NOT NULL REFERENCES operation_landing_proofs(id),
  path_role text NOT NULL CHECK (path_role IN ('RECEIVER', 'SOURCE', 'DESTINATION')),
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  t0_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  fresh_head_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  expected_completed_transaction_sha256 sha256_hex NOT NULL,
  fresh_head_completed_transaction_sha256 sha256_hex NOT NULL,
  body_count bigint NOT NULL CHECK (body_count > 0),
  path_depth bigint NOT NULL CHECK (path_depth >= 0 AND path_depth = body_count - 1),
  verdict lineage_proof_verdict NOT NULL,
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (landing_proof_id, path_role),
  UNIQUE (landing_proof_id, wallet_public_key)
);

CREATE TABLE lineage_path_bodies (
  path_proof_id uuid NOT NULL REFERENCES lineage_path_proofs(id),
  path_index bigint NOT NULL CHECK (path_index >= 0),
  source_kind text NOT NULL CHECK (source_kind IN
    ('EXPECTED_OPERATION', 'CANONICAL_LEDGER', 'PROOF_CHANNEL', 'FRESH_GATEWAY_HEAD')),
  completed_transaction_text text NOT NULL,
  completed_transaction_sha256 sha256_hex NOT NULL,
  completed_transaction_octets bigint NOT NULL CHECK (completed_transaction_octets > 0),
  wallet_role text NOT NULL CHECK (wallet_role IN ('sender', 'receiver')),
  s_signature padded_base64url_signature NOT NULL,
  p_signature text NOT NULL CHECK
    (p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$'),
  b_amount zkz_balance_text NOT NULL,
  inner_preimage_text text NOT NULL,
  inner_sha256 sha256_hex NOT NULL,
  step_1_signature padded_base64url_signature NOT NULL,
  step_2_signature padded_base64url_signature NOT NULL,
  verification_manifest_text text NOT NULL,
  verification_manifest_sha256 sha256_hex NOT NULL,
  PRIMARY KEY (path_proof_id, path_index),
  CHECK (octet_length(completed_transaction_text) = completed_transaction_octets),
  CHECK (octet_length(inner_preimage_text) > 0)
);

CREATE INDEX lineage_path_bodies_state_signature_idx
  ON lineage_path_bodies(path_proof_id, s_signature);
CREATE INDEX lineage_path_bodies_backlink_idx
  ON lineage_path_bodies(path_proof_id, p_signature);
CREATE INDEX lineage_path_bodies_body_digest_idx
  ON lineage_path_bodies(completed_transaction_sha256);
CREATE INDEX lineage_path_proofs_fresh_head_idx
  ON lineage_path_proofs(fresh_head_observation_id);

CREATE TRIGGER lineage_path_proofs_no_update
  BEFORE UPDATE ON lineage_path_proofs
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER lineage_path_proofs_no_delete
  BEFORE DELETE ON lineage_path_proofs
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER lineage_path_bodies_no_update
  BEFORE UPDATE ON lineage_path_bodies
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER lineage_path_bodies_no_delete
  BEFORE DELETE ON lineage_path_bodies
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
