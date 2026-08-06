// Observation anomalies: the anomaly table and
// the gateway_observations classification/exact-body/fingerprint indexes);
// its indexes, the S/P role-relative projections, serialized capture, relationship
// classification, verification-material access, and fail-closed anomaly actions. Transport
// acknowledgement is receipt-only.
//
// Frozen inventory of the structural invariants carried by observation-anomaly-indexes.sql:
// the observation_anomalies table, the classification and exact-body indexes on
// gateway_observations, and the deferred collision guard that keeps an anomaly-classified
// observation row inseparable from its anomaly record. The census test binds every entry
// here to the literal SQL text.

export const OBSERVATION_ANOMALY_INDEXES_SCHEMA_FILE = "observation-anomaly-indexes.sql" as const;

export interface ObservationAnomalyIndexInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OBSERVATION_ANOMALY_INDEX_INVARIANTS: readonly ObservationAnomalyIndexInvariant[] = [
  {
    id: "ANOMALY_ONE_PER_OBSERVATION",
    sqlAnchor: "observation_id uuid NOT NULL UNIQUE REFERENCES gateway_observations(id),",
    rule: "each observation produces at most one anomaly row: the UNIQUE on observation_id enforces one-to-one linkage between an observation and its anomaly classification.",
  },
  {
    id: "ANOMALY_KIND_CLOSED_SET",
    sqlAnchor: "kind text NOT NULL CHECK (kind IN (",
    rule: "anomaly kind is a closed set matching the five non-verified parse results plus the four relationship anomalies: no open-ended classification; new kinds require a contract-version change.",
  },
  {
    id: "ANOMALY_PRIOR_OBSERVATION_LINK",
    sqlAnchor: "prior_observation_id uuid REFERENCES gateway_observations(id),",
    rule: "anomalies that reference a prior state (REGRESSION, UNEXPLAINED_JUMP) carry the prior observation foreign key: the anomaly chain is navigable through actual foreign keys.",
  },
  {
    id: "ANOMALY_WALLET_PUBLIC_KEY_REQUIRED",
    sqlAnchor: "wallet_public_key padded_base64url_pubkey NOT NULL,",
    rule: "every anomaly is bound to a wallet public key: anomalies are always attributable to a specific wallet stream, even when wallet_id is null for externally owned addresses.",
  },
  {
    id: "ANOMALY_DETAILS_REQUIRED",
    sqlAnchor: "details text NOT NULL,",
    rule: "every anomaly carries a human-readable details field: the evidence context is never empty.",
  },
  {
    id: "ANOMALY_DETECTED_AT_REQUIRED",
    sqlAnchor: "detected_at timestamptz NOT NULL",
    rule: "every anomaly records when it was detected: the detection instant of every anomaly is always recorded; detected_at is never a uniqueness or sequencing key.",
  },
  {
    id: "PRIOR_STATE_INDEX",
    sqlAnchor:
      "CREATE INDEX gateway_observations_prior_state_idx\n  ON gateway_observations(observer_id, wallet_public_key, s_signature)",
    rule: "classification indexes the accepted S-signature history per read stream on s_signature, the role-relative current-state projection, NOT the raw step_2_signature head column: REGRESSION recurrence and SIGNATURE_COLLISION are stream-scoped s_signature lookups.",
  },
  {
    id: "PRIOR_STATE_INDEX_COVERS_FINGERPRINT",
    sqlAnchor: "INCLUDE (semantic_fingerprint)",
    rule: "the prior-state index carries semantic_fingerprint as an INCLUDE payload: SIGNATURE_COLLISION reads the prior row's fingerprint from the same index without a heap fetch.",
  },
  {
    id: "EXACT_BODY_INDEX",
    sqlAnchor:
      "CREATE INDEX gateway_observations_exact_body_idx\n  ON gateway_observations(wallet_public_key, step_2_signature)",
    rule: "exact-body resolution indexes (wallet_public_key, step_2_signature), the head signature that identifies the exact completed transaction: resolving a matched head to its full retained body is a keyed lookup, not a scan.",
  },
  {
    id: "SEMANTIC_FINGERPRINT_INDEX",
    sqlAnchor:
      "CREATE INDEX gateway_observations_semantic_fingerprint_idx\n  ON gateway_observations(observer_id, wallet_public_key, semantic_fingerprint)",
    rule: "the semantic-fingerprint index is scoped to the read stream: equivalent-envelope detection compares fingerprints per (observer_id, wallet_public_key); there is no global deduplication.",
  },
  {
    id: "BODY_HASH_INDEX",
    sqlAnchor:
      "CREATE INDEX gateway_observations_body_hash_idx\n  ON gateway_observations(raw_response_sha256);",
    rule: "exact raw-byte equality is the consecutive dedup key: the body-hash index on raw_response_sha256 supports the exact-body candidate lookup without a full-table scan (equality still recomputes length and compares exact bytes).",
  },
  {
    id: "WALLET_STREAM_POSITION_INDEX",
    sqlAnchor:
      "CREATE INDEX gateway_observations_wallet_stream_idx\n  ON gateway_observations(wallet_public_key, wallet_seq);",
    rule: "cross-observer stream reads by wallet public key and sequence are indexed: the UNIQUE (observer_id, wallet_public_key, wallet_seq) covers single-observer stream reads, this composite covers reads of a wallet's history across observers.",
  },
  {
    id: "ANOMALY_STREAM_ACCESS_INDEX",
    sqlAnchor:
      "CREATE INDEX observation_anomalies_stream_idx\n  ON observation_anomalies(observer_id, wallet_public_key);",
    rule: "verification-material access and fail-closed anomaly actions retrieve a wallet stream's anomaly set: observation_id already resolves the per-observation anomaly, this composite resolves the per-stream anomaly set.",
  },
  {
    id: "COLLISION_GUARD_DEFERRED_TRIGGER",
    sqlAnchor: "CREATE CONSTRAINT TRIGGER observation_anomaly_pairing_complete",
    rule: "Anomaly-ledger integrity is DB-enforced: a constraint trigger on gateway_observations requires that an anomaly-classified observation is paired with its observation_anomalies record.",
  },
  {
    id: "COLLISION_GUARD_INITIALLY_DEFERRED",
    sqlAnchor: "DEFERRABLE INITIALLY DEFERRED",
    rule: "the pairing check runs at end-of-transaction (the acknowledgement pattern): the writer appends the observation then its anomaly within one transaction, and the pairing is verified at commit.",
  },
  {
    id: "COLLISION_GUARD_CLASSIFICATION_MAP",
    sqlAnchor: "observation_anomaly_required_kind",
    rule: "the required anomaly kind is derived from the frozen classification carriers: relationship for the four relationship anomalies {SIGNATURE_COLLISION, REGRESSION, GENESIS_AFTER_HISTORY, UNEXPLAINED_JUMP}, parse_result for the five non-verified parse failures; a verified non-anomalous head requires no anomaly row.",
  },
  {
    id: "ANOMALIES_APPEND_ONLY_UPDATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER observation_anomalies_no_update\n  BEFORE UPDATE ON observation_anomalies\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "a committed anomaly cannot be rewritten (observation and anomaly rows are append-only forever; every anomaly response is permanent data; mandatory database test 15): the engine refuses UPDATE.",
  },
  {
    id: "ANOMALIES_APPEND_ONLY_DELETE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER observation_anomalies_no_delete\n  BEFORE DELETE ON observation_anomalies\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "a committed anomaly cannot be removed: deleting an anomaly would silently defeat the halt that pairs with the observation row.",
  },
  {
    id: "ANOMALIES_APPEND_ONLY_TRUNCATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER observation_anomalies_no_truncate\n  BEFORE TRUNCATE ON observation_anomalies\n  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "TRUNCATE does not fire row-level DELETE triggers, so a statement-level BEFORE TRUNCATE guard is required or the whole anomaly ledger stays removable in one statement.",
  },
] as const;

export const SCHEMA_OBSERVATION_ANOMALY_INDEXES_OBLIGATIONS = [
  "execution sequence: apply observation-ledger.sql (the padded_base64url_pubkey domain, the observers and gateway_observations tables) and the wallets table before this file's table, indexes, and constraint trigger; this file is an extension, not a self-contained slice, and re-declares none of those objects.",
  "append-only (DISCHARGED): the BEFORE UPDATE / DELETE / TRUNCATE triggers making observation_anomalies append-only forever (every anomaly response is permanent data; mandatory database test 15) now ship in observation-anomaly-indexes.sql and are executed against a live PostgreSQL by test/observation-migration-integrity.test.ts.",
  "negative: an observation classified in {SIGNATURE_COLLISION, REGRESSION, GENESIS_AFTER_HISTORY, UNEXPLAINED_JUMP} or with a non-verified parse_result that carries no matching observation_anomalies row is rejected at commit by the deferred collision guard with check_violation (23514).",
  "negative: a duplicate observation_id insert into observation_anomalies is rejected with unique_violation (23505).",
  "negative: an anomaly kind outside the closed CHECK set is rejected with check_violation (23514).",
  "negative: a null wallet_public_key or null details or null detected_at is rejected with not_null_violation (23502).",
  "index verification: EXPLAIN confirms gateway_observations_prior_state_idx serves the stream-scoped s_signature classification lookup (observer_id, wallet_public_key, s_signature).",
  "index verification: EXPLAIN confirms gateway_observations_exact_body_idx serves the (wallet_public_key, step_2_signature) exact-body resolution.",
] as const;

export const OBSERVATION_ANOMALY_INDEXES_SOURCE = "data-model: observation anomalies" as const;
