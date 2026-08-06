// The mutable per-stream observation cursor and the serialized capture-and-persist path.
//
// Frozen inventory of the structural observation-store invariants carried by
// observation-stores.sql: wallet_observation_cursors, the mutable operational
// position index for a single (observer, wallet) read stream. The observers and
// gateway_observations tables are inventoried in observation-ledger.contract.ts
// the append-only observation_anomalies evidence table belongs to
// and is inventoried there, not here.

export const OBSERVATION_STORES_SCHEMA_FILE = "observation-stores.sql" as const;

export interface ObservationStoresInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OBSERVATION_STORES_INVARIANTS: readonly ObservationStoresInvariant[] = [
  {
    id: "CURSOR_COMPOSITE_PRIMARY_KEY",
    sqlAnchor: "PRIMARY KEY (observer_id, wallet_public_key)",
    rule: "at most one cursor per (observer, wallet public key): the cursor is the mutable operational position index for a single observer watching a single wallet.",
  },
  {
    id: "CURSOR_LAST_OBSERVATION_REQUIRED",
    sqlAnchor: "last_recorded_observation_id uuid NOT NULL REFERENCES gateway_observations(id),",
    rule: "every cursor references the last recorded observation: the cursor always points to a concrete evidence row, never to nothing.",
  },
  {
    id: "CURSOR_RAW_DIGEST_REQUIRED",
    sqlAnchor: "last_raw_response_sha256 sha256_hex NOT NULL,",
    rule: "the cursor tracks the SHA-256 of the last raw response: exact raw-byte equality is the consecutive dedup key, so the cursor must carry the digest for comparison.",
  },
  {
    id: "CURSOR_SEMANTIC_FINGERPRINT_NULLABLE",
    sqlAnchor: "last_semantic_fingerprint sha256_hex,",
    rule: "the semantic fingerprint is nullable on the cursor: it is computed only after complete verification; a transport-error cursor has no semantic fingerprint.",
  },
  {
    id: "CURSOR_REPEAT_COUNT_NON_NEGATIVE",
    sqlAnchor: "consecutive_repeat_count bigint NOT NULL DEFAULT 0 CHECK (consecutive_repeat_count >= 0),",
    rule: "the consecutive repeat count is non-negative: byte-identical responses increment this counter rather than inserting a new observation row.",
  },
  {
    id: "CURSOR_NEXT_SEQ_POSITIVE",
    sqlAnchor: "next_wallet_seq bigint NOT NULL CHECK (next_wallet_seq > 0),",
    rule: "the next expected wallet sequence is positive: wallet sequences start at 1, so the next expected value is always > 0.",
  },
  {
    id: "CURSOR_WALLET_ID_OPTIONAL_PROJECTION",
    sqlAnchor: "wallet_id uuid REFERENCES wallets(id),",
    rule: "wallet_id is an optional projection for node-owned wallets: externally owned payer/recipient addresses have no wallets row and are still fully observable by public key.",
  },
] as const;

// Live-database proofs discharged by test/observation-stores.pg.test.ts.
export const SCHEMA_OBSERVATION_STORES_OBLIGATIONS = [
  "execution sequence: create the reference scalar domains (sha256_hex, padded_base64url_pubkey), the observer_domain / observation_parse_result / observation_relationship enums, and the observers / gateway_observations / wallets tables (observation-ledger.sql) before this file's cursor table.",
  "guards: wallet_observation_cursors is mutable by design (operational index, not evidence); cursor mutations must be serialized per (observer_id, wallet_public_key) via advisory lock at the head of serialized capture.",
  "negative: a duplicate (observer_id, wallet_public_key) cursor insert is rejected with unique_violation (23505).",
  "negative: a cursor with next_wallet_seq = 0 or negative is rejected by the CHECK constraint.",
  "negative: a cursor with consecutive_repeat_count < 0 is rejected by the CHECK constraint.",
  "negative: malformed sha256_hex or padded_base64url_pubkey values are rejected by their domains.",
  "write path: SqlStreamWriterEffects (src/observation/stream-writer-sql.ts) is the production StreamWriterEffects; restart resumes from the persisted cursor with no gap or duplicate wallet_seq.",
] as const;

export const OBSERVATION_STORES_SOURCE =
  "data-model: observation cursors and stores" as const;
