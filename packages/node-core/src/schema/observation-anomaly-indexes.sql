-- Observation anomalies: the anomaly table
-- and the gateway_observations classification/exact-body/fingerprint indexes);
-- and its indexes. Serialized capture appends the matching anomaly row in the same
-- transaction; the S/P projections are role-relative; relationship classification and
-- verification-material access read from here.
--
-- Frozen schema contract. This file is contract text: it is executed only by the schema-apply phase against a live database; nothing in this package runs it. Every invariant
-- below is inventoried in observation-anomaly-indexes.contract.ts and censused by
-- test/observation-anomaly-indexes.census.test.ts; the real-PostgreSQL behaviour proof
-- is test/observation-anomaly-indexes.pg.test.ts.
--
-- Scope: the observation_anomalies table, the classification and exact-body
-- indexes the observation writer and relationship classifier require, and the deferred
-- collision-guard that makes an anomaly-classified observation row inseparable from its
-- anomaly record. The reference domains (padded_base64url_pubkey), the observers table,
-- and the gateway_observations table are created by observation-ledger.sql; this file is
-- an EXTENSION applied immediately after it and depends on those objects; it does not
-- re-declare them.

-- Independent raw observation ledger (verbatim, observation_anomalies).
-- Column sequence is the frozen fact (OBSERVATION_ANOMALY_RECORD_FIELDS); no default on
-- any column. One permanent anomaly row per anomalous observation
-- (observation_id UNIQUE); appended even when the raw bytes repeat.

CREATE TABLE observation_anomalies (
  id uuid PRIMARY KEY,
  observation_id uuid NOT NULL UNIQUE REFERENCES gateway_observations(id),
  observer_id uuid NOT NULL REFERENCES observers(id),
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  kind text NOT NULL CHECK (kind IN (
    'TRANSPORT_ERROR','MALFORMED_ENVELOPE','MALFORMED_TRANSACTION',
    'UNVERIFIED_SIGNATURE','WALLET_ROLE_INVALID','REGRESSION',
    'UNEXPLAINED_JUMP','GENESIS_AFTER_HISTORY','SIGNATURE_COLLISION'
  )),
  prior_observation_id uuid REFERENCES gateway_observations(id),
  details text NOT NULL,
  detected_at timestamptz NOT NULL
);

-- Classification prior-state index. The read stream is
-- (observer_id, wallet_public_key). S is the role-relative current-state signature
-- (s_signature), NOT the raw head step_2_signature column; classification (REGRESSION
-- recurrence, SIGNATURE_COLLISION) tests membership of the appended S in the stream's
-- accepted S history and reads the prior row's semantic_fingerprint, so the index carries
-- semantic_fingerprint as an INCLUDE payload. Partial on the verified rows, which are the
-- only rows that carry an s_signature.

CREATE INDEX gateway_observations_prior_state_idx
  ON gateway_observations(observer_id, wallet_public_key, s_signature)
  INCLUDE (semantic_fingerprint)
  WHERE s_signature IS NOT NULL;

-- Exact-body resolution index. Given a matched head, resolve the full
-- prior row (raw_response_bytes, completed_transaction_text/_sha256, semantic_fingerprint)
-- by wallet public key and the head step_2_signature, the signature that identifies the
-- exact completed transaction body. Partial on head rows, which are the only rows that
-- carry a step_2_signature.

CREATE INDEX gateway_observations_exact_body_idx
  ON gateway_observations(wallet_public_key, step_2_signature)
  WHERE step_2_signature IS NOT NULL;

-- Semantic-fingerprint index. Two byte-different envelopes with the same
-- fingerprint claim the same verified state (EQUIVALENT_STATE_DIFFERENT_ENVELOPE);
-- fingerprints are compared per read stream, with no global deduplication. Partial
-- on verified rows, which are the only rows that carry a fingerprint.

CREATE INDEX gateway_observations_semantic_fingerprint_idx
  ON gateway_observations(observer_id, wallet_public_key, semantic_fingerprint)
  WHERE semantic_fingerprint IS NOT NULL;

-- Consecutive-dedup body-hash index. Exact raw-byte equality is the
-- consecutive dedup key; this index supports the exact-body candidate lookup without a
-- full-table scan (equality still recomputes length and compares exact bytes).

CREATE INDEX gateway_observations_body_hash_idx
  ON gateway_observations(raw_response_sha256);

-- Cross-observer wallet stream-position index. The UNIQUE (observer_id, wallet_public_key,
-- wallet_seq) already serves single-observer stream reads; this composite serves reads of
-- a wallet's history across observers by (wallet_public_key, wallet_seq).

CREATE INDEX gateway_observations_wallet_stream_idx
  ON gateway_observations(wallet_public_key, wallet_seq);

-- Verification-material anomaly access index. The server-authenticated
-- verification-material surface and the fail-closed anomaly actions retrieve a wallet
-- stream's anomaly records; observation_id (UNIQUE) already resolves the per-observation
-- anomaly, this composite resolves the per-stream anomaly set.

CREATE INDEX observation_anomalies_stream_idx
  ON observation_anomalies(observer_id, wallet_public_key);

-- Collision guard for the anomaly ledger. The never-blind-retry rule forbids a
-- blind submit retry; the anomaly ledger is the mechanism that halts automation on an
-- anomalous classification, so an anomaly-classified observation row that carries no
-- anomaly record would silently defeat that halt. This deferred constraint mirrors the
-- The acknowledgement pattern lets the writer append the gateway_observations row
-- and then its observation_anomalies row within one transaction, and
-- checks the pairing at end-of-transaction. The stored classification carriers are frozen:
-- relationship carries the four relationship anomalies {SIGNATURE_COLLISION, REGRESSION,
-- GENESIS_AFTER_HISTORY, UNEXPLAINED_JUMP}; parse_result carries the five non-verified
-- parse failures. Either implies a matching anomaly row whose
-- kind equals that classification. A verified, non-anomalous head requires no anomaly row.

CREATE FUNCTION observation_anomaly_required_kind(
  p_parse_result observation_parse_result,
  p_relationship observation_relationship
) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
  SELECT CASE
    WHEN p_relationship IN (
      'SIGNATURE_COLLISION','REGRESSION','GENESIS_AFTER_HISTORY','UNEXPLAINED_JUMP'
    ) THEN p_relationship::text
    WHEN p_parse_result IN (
      'TRANSPORT_ERROR','MALFORMED_ENVELOPE','MALFORMED_TRANSACTION',
      'UNVERIFIED_SIGNATURE','WALLET_ROLE_INVALID'
    ) THEN p_parse_result::text
    ELSE NULL
  END
$$;

CREATE FUNCTION observation_anomaly_guard()
RETURNS trigger LANGUAGE plpgsql
AS $$
DECLARE
  required_kind text;
  present_kind text;
BEGIN
  required_kind := observation_anomaly_required_kind(NEW.parse_result, NEW.relationship);
  IF required_kind IS NULL THEN
    RETURN NULL;
  END IF;

  SELECT kind INTO present_kind
    FROM observation_anomalies
    WHERE observation_id = NEW.id;

  IF present_kind IS NULL THEN
    RAISE EXCEPTION
      'observation % classified % has no observation_anomalies row (anomaly ledger)',
      NEW.id, required_kind
      USING ERRCODE = '23514';
  END IF;
  IF present_kind <> required_kind THEN
    RAISE EXCEPTION
      'observation % classified % has mismatched anomaly kind %',
      NEW.id, required_kind, present_kind
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER observation_anomaly_pairing_complete
  AFTER INSERT ON gateway_observations
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION observation_anomaly_guard();

-- Append-only at the trigger level (mandatory database test 15; all observation and
-- anomaly rows are append-only forever; every anomaly response is permanent data).
-- Discharges the append-only obligation
-- observation-anomaly-indexes.contract.ts previously carried as schema-apply work.
--
-- reporting_reject_immutable_change is created by observation-ledger.sql (applied first);
-- this file is an extension and does not re-declare it. TRUNCATE guard closes the
-- statement-level bypass that row-level DELETE triggers alone leave open.

CREATE TRIGGER observation_anomalies_no_update
  BEFORE UPDATE ON observation_anomalies
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER observation_anomalies_no_delete
  BEFORE DELETE ON observation_anomalies
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER observation_anomalies_no_truncate
  BEFORE TRUNCATE ON observation_anomalies
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

