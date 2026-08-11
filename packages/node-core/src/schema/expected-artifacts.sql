-- Exact expected artifacts: frozen byte surfaces, byte-exact signing (the byte-exact signing rule).
-- Frozen schema contract. This file is contract text: it is executed only by the schema-apply phase against a live database; nothing in this package runs it. Every invariant
-- below is inventoried in expected-artifacts.contract.ts and censused by
-- test/expected-artifacts.census.test.ts.
-- The reference scalar domains are owned by base-enums-domains.sql and consumed here
-- without redeclaration. Durable receive material and receive barriers are explicitly
-- deferred to their separately owned schema slice.
--
-- Single owning slice for operation_expected_artifacts (one-slice-one-contract).
-- move-baseline-binding.sql references this table only -- it must not re-CREATE it.

-- Exact expected artifacts (verbatim):

CREATE TABLE operation_expected_artifacts (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  purpose text NOT NULL CONSTRAINT operation_expected_artifacts_purpose_check CHECK (purpose IN (
    'zp-receive-expected-v1',
    'zp-move-internal-expected-v1',
    'zp-send-external-expected-v1'
  )),
  canonical_version integer NOT NULL
    CONSTRAINT operation_expected_artifacts_canonical_version_check CHECK (canonical_version = 1),
  signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  signature padded_base64url_signature NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT operation_expected_artifacts_preimage_text_check
    CHECK (octet_length(preimage_text) > 0)
);

-- Retention: expected artifact rows are permanent and insert-only (conventions:
-- exact-content tables are append-only or have byte-immutability triggers). Without this
-- the table is insert-only by convention only -- an UPDATE could rewrite the exact preimage
-- bytes a later recovery must resume from.

CREATE FUNCTION expected_artifact_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'EXPECTED_ARTIFACT_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER operation_expected_artifacts_insert_only
  BEFORE UPDATE OR DELETE ON operation_expected_artifacts
  FOR EACH ROW EXECUTE FUNCTION expected_artifact_reject_mutation();
