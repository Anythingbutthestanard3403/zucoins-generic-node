-- Exact SplitChain transaction material: the reference scalar checks, the sign-intent /
-- transaction / partial relations, and the mandatory database tests over them.
-- Frozen schema contract. This file is contract text: it is
-- executed only by the schema-apply phase against a live database; nothing in this package
-- runs it. Every invariant below is inventoried in transaction-material.contract.ts and
-- censused by test/transaction-material.census.test.ts. The CREATE TABLE block below is
-- byte-identical to the frozen relation block, and the two CREATE DOMAIN statements are
-- byte-identical to the reference scalar checks -- the only two domains these relations
-- reference.

-- Reference scalar checks (verbatim; only the two domains these relations use):

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_signature AS text
  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');

-- Exact SplitChain transaction material (verbatim):

CREATE TABLE external_send_sign_intents (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  approval_id uuid NOT NULL UNIQUE REFERENCES operation_approvals(id),
  source_wallet_id uuid NOT NULL REFERENCES wallets(id),
  source_t0_observation_id uuid NOT NULL,
  destination_t0_observation_id uuid NOT NULL,
  lease_group_id uuid NOT NULL,
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  inner_preimage_text text NOT NULL,
  inner_sha256 sha256_hex NOT NULL,
  redemption_expiry_at timestamptz NOT NULL,
  prepared_at timestamptz NOT NULL,
  CHECK (octet_length(inner_preimage_text) > 0)
);

CREATE TABLE operation_transactions (
  operation_id uuid NOT NULL REFERENCES operations(id),
  attempt_no integer NOT NULL CHECK (attempt_no = 1),
  attempt_phase text NOT NULL CHECK (attempt_phase IN
    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED',
     'STEP2_PREIMAGE_PERSISTED','STEP2_SIGNATURE_PERSISTED',
     'SETTLED_BODY_PERSISTED')),
  inner_preimage_text text NOT NULL,
  inner_sha256 sha256_hex NOT NULL,
  step_1_signature padded_base64url_signature,
  step_2_preimage_text text,
  step_2_preimage_sha256 sha256_hex,
  step_2_signature padded_base64url_signature,
  completed_transaction_text text,
  completed_transaction_sha256 sha256_hex,
  formed_at timestamptz NOT NULL,
  settled_at timestamptz,
  PRIMARY KEY (operation_id, attempt_no),
  CHECK ((attempt_phase = 'INNER_PREIMAGE_PERSISTED') = (step_1_signature IS NULL)),
  CHECK ((attempt_phase IN ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED')) =
    (step_2_preimage_text IS NULL)),
  CHECK ((attempt_phase IN ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED')) =
    (step_2_preimage_sha256 IS NULL)),
  CHECK ((attempt_phase IN
    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =
    (step_2_signature IS NULL)),
  CHECK ((attempt_phase IN
    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =
    (completed_transaction_text IS NULL)),
  CHECK ((attempt_phase IN
    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =
    (completed_transaction_sha256 IS NULL)),
  CHECK ((attempt_phase <> 'SETTLED_BODY_PERSISTED') = (settled_at IS NULL))
);

CREATE TABLE external_send_partials (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  approval_id uuid NOT NULL UNIQUE REFERENCES operation_approvals(id),
  inner_sha256 sha256_hex NOT NULL,
  step_1_signature padded_base64url_signature NOT NULL,
  transfer_code_text text NOT NULL,
  transfer_code_sha256 sha256_hex NOT NULL,
  persisted_at timestamptz NOT NULL,
  first_delivered_at timestamptz,
  last_redelivered_at timestamptz,
  redelivery_count integer NOT NULL DEFAULT 0 CHECK (redelivery_count >= 0)
);
