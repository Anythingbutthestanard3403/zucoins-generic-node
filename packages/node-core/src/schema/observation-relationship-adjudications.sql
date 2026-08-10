-- observation_relationship_adjudications: permanent store for complete-path
-- relationship adjudication (doc 04 §11 / §15).
--
-- A gateway_observations row with observed_relationship = UNEXPLAINED_JUMP is
-- immutable. When a D9.6 complete-path proof explains the jump, the derived
-- COMPLETE_PATH_SUCCESSOR relationship is recorded here — never by rewriting
-- the observation. Append-only (UPDATE/DELETE/TRUNCATE refused).
--
-- Pack position: appended after lineage-path-proofs (FK target) so earlier money-
-- pack version numbers stay stable. Never renumber prior slices.

CREATE TABLE observation_relationship_adjudications (
  id uuid PRIMARY KEY,
  observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  lineage_path_proof_id uuid NOT NULL UNIQUE REFERENCES lineage_path_proofs(id),
  observed_relationship observation_relationship NOT NULL
    CHECK (observed_relationship = 'UNEXPLAINED_JUMP'),
  effective_relationship observation_relationship NOT NULL
    CHECK (effective_relationship = 'COMPLETE_PATH_SUCCESSOR'),
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  adjudicated_at timestamptz NOT NULL,
  UNIQUE (observation_id, lineage_path_proof_id)
);

CREATE TRIGGER observation_relationship_adjudications_no_update
  BEFORE UPDATE ON observation_relationship_adjudications
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER observation_relationship_adjudications_no_delete
  BEFORE DELETE ON observation_relationship_adjudications
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER observation_relationship_adjudications_no_truncate
  BEFORE TRUNCATE ON observation_relationship_adjudications
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
