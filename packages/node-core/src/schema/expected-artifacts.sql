-- Exact expected artifacts: frozen byte surfaces, byte-exact signing (the byte-exact signing rule).
-- Frozen schema contract. This file is contract text: it is executed only by the schema-apply phase against a live database; nothing in this package runs it. Every invariant
-- below is inventoried in expected-artifacts.contract.ts and censused by
-- test/expected-artifacts.census.test.ts.
-- The reference scalar domains are owned by base-enums-domains.sql and consumed here
-- without redeclaration. Durable receive material and receive barriers are explicitly
-- deferred to their separately owned schema slice.

-- Exact expected artifacts (verbatim):

CREATE TABLE operation_expected_artifacts (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  purpose text NOT NULL CHECK (purpose IN (
    'zp-receive-expected-v1',
    'zp-move-internal-expected-v1',
    'zp-send-external-expected-v1'
  )),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  signature padded_base64url_signature NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (octet_length(preimage_text) > 0)
);
