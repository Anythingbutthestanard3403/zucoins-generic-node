-- Observation stores: the mutable per-stream cursor behind serialized
-- capture-and-persist. Schema contract.
-- Scope: wallet_observation_cursors only. observers/gateway_observations: observation-ledger.sql.
-- observation_anomalies is a prerequisite, as are the domains (no re-declaration).

CREATE TABLE wallet_observation_cursors (
  observer_id uuid NOT NULL REFERENCES observers(id),
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  last_recorded_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  last_raw_response_sha256 sha256_hex NOT NULL,
  last_semantic_fingerprint sha256_hex,
  last_seen_at timestamptz NOT NULL,
  consecutive_repeat_count bigint NOT NULL DEFAULT 0 CHECK (consecutive_repeat_count >= 0),
  next_wallet_seq bigint NOT NULL CHECK (next_wallet_seq > 0),
  PRIMARY KEY (observer_id, wallet_public_key)
);

CREATE INDEX wallet_observation_cursors_wallet_id_idx
  ON wallet_observation_cursors(wallet_id)
  WHERE wallet_id IS NOT NULL;

CREATE INDEX wallet_observation_cursors_last_seen_idx
  ON wallet_observation_cursors(observer_id, last_seen_at);
