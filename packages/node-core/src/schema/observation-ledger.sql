-- Independent raw observation ledger: raw capture before decode, bounded/jittered read
-- retry for transport ambiguity only, and the reference scalar checks and enumerations the
-- ledger's two tables use.
-- Frozen schema contract. This file is contract text: it is
-- executed only by the schema-apply phase against a live database; nothing in this
-- package runs it. Every invariant below is inventoried in
-- observation-ledger.contract.ts and censused by test/observation-ledger.census.test.ts.
--
-- Scope: the two tables the transport evidence lands in (observers and
-- gateway_observations). The remaining observation relations (wallet_observation_cursors,
-- observation_anomalies, operation_landing_proofs, lineage_path_proofs,
-- lineage_path_bodies, observation_relationship_adjudications) belongs to the
-- observation-verification and landing-oracle slices and is deliberately not
-- transcribed here.

-- Reference scalar checks (verbatim; the three domains these two tables use).
-- b_amount is a role-relative absolute BALANCE, so it takes the balance domain, in
-- which '0' is legal - never the strictly-positive zkz_amount_positive_text, which would
-- reject a swept payer, a genesis row, or a landed payer partial.
-- The unbounded single zkz_amount_text domain is retired; the predicate below is
-- frozen in packages/generic-node-contracts (ZKZ_AMOUNT_CHECK_DOMAINS). See CONVENTIONS.md
-- "ZKZ amount CHECK domains" for why this file re-declares rather than references.
--
-- b_amount is a typed PROJECTION of a foreign signed value, not the evidence itself: the
-- authoritative bytes are raw_response_bytes, which carries no CHECK. An observed amount
-- outside the balance domain is written as b_amount NULL and classified as an anomaly - the
-- observation row still lands in full. Rejecting the row would drop gateway-accepted evidence
-- That obligation belongs to the ingest path, not to the DDL.

CREATE DOMAIN zkz_balance_text AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$');

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

-- Enumerations (verbatim; the three enums these two tables use):

CREATE TYPE observer_domain AS ENUM ('NODE', 'PLATFORM');
CREATE TYPE observation_parse_result AS ENUM (
  'VERIFIED_GENESIS',
  'VERIFIED_HEAD',
  'TRANSPORT_ERROR',
  'MALFORMED_ENVELOPE',
  'MALFORMED_TRANSACTION',
  'UNVERIFIED_SIGNATURE',
  'WALLET_ROLE_INVALID'
);
CREATE TYPE observation_relationship AS ENUM (
  'FIRST',
  'SUCCESSOR',
  'COMPLETE_PATH_SUCCESSOR',
  'DUPLICATE',
  'EQUIVALENT_STATE_DIFFERENT_ENVELOPE',
  'REGRESSION',
  'UNEXPLAINED_JUMP',
  'GENESIS_AFTER_HISTORY',
  'SIGNATURE_COLLISION',
  'NOT_APPLICABLE'
);

-- Independent raw observation ledger (verbatim, observers and
-- gateway_observations):

CREATE TABLE observers (
  id uuid PRIMARY KEY,
  domain observer_domain NOT NULL,
  owner_id uuid NOT NULL,
  gateway_endpoint_fingerprint sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (domain, owner_id)
);

CREATE TABLE gateway_observations (
  id uuid PRIMARY KEY,
  observer_id uuid NOT NULL REFERENCES observers(id),
  endpoint_fingerprint sha256_hex NOT NULL,
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  wallet_seq bigint NOT NULL CHECK (wallet_seq > 0),
  observed_at timestamptz NOT NULL,
  http_status integer,
  raw_response_bytes bytea NOT NULL,
  raw_response_sha256 sha256_hex NOT NULL,
  parse_result observation_parse_result NOT NULL,
  relationship observation_relationship NOT NULL,
  semantic_fingerprint sha256_hex,
  state_changed boolean,
  wallet_role text CHECK (wallet_role IN ('sender','receiver','genesis')),
  s_signature text,
  p_signature text,
  b_amount zkz_balance_text,
  inner_preimage_text text,
  step_1_signature text,
  step_2_signature text,
  completed_transaction_text text,
  completed_transaction_sha256 sha256_hex,
  previous_recorded_observation_id uuid REFERENCES gateway_observations(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (observer_id, wallet_public_key, wallet_seq),
  CHECK (
    (parse_result IN ('VERIFIED_GENESIS','VERIFIED_HEAD')) =
    (semantic_fingerprint IS NOT NULL)
  ),
  CHECK (
    (parse_result IN ('VERIFIED_GENESIS','VERIFIED_HEAD')) =
    (state_changed IS NOT NULL)
  ),
  CHECK (
    (parse_result = 'VERIFIED_HEAD') =
    (inner_preimage_text IS NOT NULL AND step_1_signature IS NOT NULL
      AND step_2_signature IS NOT NULL AND completed_transaction_text IS NOT NULL
      AND completed_transaction_sha256 IS NOT NULL)
  ),
  CHECK (
    parse_result <> 'VERIFIED_GENESIS'
    OR (
      wallet_role = 'genesis' AND s_signature = '' AND p_signature = '' AND b_amount = '0'
      AND inner_preimage_text IS NULL AND step_1_signature IS NULL AND step_2_signature IS NULL
      AND completed_transaction_text IS NULL AND completed_transaction_sha256 IS NULL
    )
  ),
  CHECK (
    parse_result <> 'VERIFIED_HEAD'
    OR (
      wallet_role IN ('sender','receiver')
      AND s_signature ~ '^[A-Za-z0-9_-]{86}==$'
      AND (p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$')
      AND b_amount IS NOT NULL AND octet_length(inner_preimage_text) > 0
      AND step_1_signature ~ '^[A-Za-z0-9_-]{86}==$'
      AND step_2_signature ~ '^[A-Za-z0-9_-]{86}==$'
      AND octet_length(completed_transaction_text) > 0
    )
  ),
  CHECK (
    parse_result IN ('VERIFIED_GENESIS','VERIFIED_HEAD')
    OR (
      relationship = 'NOT_APPLICABLE' AND wallet_role IS NULL
      AND s_signature IS NULL AND p_signature IS NULL AND b_amount IS NULL
      AND inner_preimage_text IS NULL AND step_1_signature IS NULL AND step_2_signature IS NULL
      AND completed_transaction_text IS NULL AND completed_transaction_sha256 IS NULL
    )
  )

);

-- Append-only at the trigger level (mandatory database test 15: observation/event/audit
-- append-only triggers reject update and delete; all observation and anomaly rows are
-- append-only forever). Discharges the guard obligation observation-ledger.contract.ts previously
-- carried as schema-apply work.
--
-- Application-level insert-only discipline is not the guarantee. The observation ledger
-- is the anti-phantom-settle evidence floor: an attacker (or a buggy retention path)
-- that could UPDATE raw_response_bytes / relationship / endpoint_fingerprint, or DELETE
-- a row, would silently defeat consecutive-dedup authority and anomaly halt. Only an
-- engine-level BEFORE UPDATE/DELETE trigger stops every connection.
--
-- The function is 04's reporting_reject_immutable_change transcribed VERBATIM, including
-- its '55000' ERRCODE -- the canonical append-only rejector, consumed rather than
-- re-invented under a second name. Re-declared here so this fragment applies standalone
-- (CONVENTIONS.md, "ZKZ amount CHECK domains"); combined application onto one database de-duplicates it.

CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER gateway_observations_no_update
  BEFORE UPDATE ON gateway_observations
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER gateway_observations_no_delete
  BEFORE DELETE ON gateway_observations
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER gateway_observations_no_truncate
  BEFORE TRUNCATE ON gateway_observations
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

-- observers carry endpoint provenance that is copied into every observation row; rewriting
-- an observer's fingerprint after the fact would re-attribute historical evidence.
CREATE TRIGGER observers_no_update
  BEFORE UPDATE ON observers
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER observers_no_delete
  BEFORE DELETE ON observers
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER observers_no_truncate
  BEFORE TRUNCATE ON observers
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
