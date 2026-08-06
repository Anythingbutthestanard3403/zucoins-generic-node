/**
 * SOURCE: the data-model observation tables (the
 * `gateway_observations`, `wallet_observation_cursors`, and `observation_anomalies` tables)
 * and the observation-verification capture contract. Transcribed verbatim; field SEQUENCE is the
 * frozen fact (the DDL column sequence), which is why every list preserves that sequence
 * rather than being sorted.
 *
 * `type` is the logical column domain (see scalars.contract.ts / enums.contract.ts). The one
 * field with no persisted column is the capture's `raw_response_octets` — the persisted row
 * derives length via `octet_length(raw_response_bytes)`; the capture models it as the
 * first-class "length" fact that the consecutive-dedup predicate compares (capture step 7).
 */

export interface FieldSpec {
  readonly name: string;
  readonly type: string;
  readonly nullable: boolean;
  readonly note: string;
}

/** Capture steps 2-5: the complete response captured BEFORE decode, parse, or validation. */
export const RAW_OBSERVATION_CAPTURE_FIELDS = [
  { name: "observer_id", type: "uuid", nullable: false, note: "observing domain identity; read stream is (observer_id, wallet_public_key)" },
  { name: "endpoint_fingerprint", type: "sha256_hex", nullable: false, note: "the independently configured endpoint selected for this read" },
  { name: "wallet_public_key", type: "padded_base64url_pubkey", nullable: false, note: "queried wallet; external addresses have no wallet_id" },
  { name: "observed_at", type: "timestamptz", nullable: false, note: "capture / request timing; never a uniqueness or sequencing key" },
  { name: "http_status", type: "integer", nullable: true, note: "transport status; null when no HTTP response arrived" },
  { name: "raw_response_bytes", type: "bytea", nullable: false, note: "complete body exactly as received, before UTF-8 decode or JSON parse" },
  { name: "raw_response_octets", type: "integer_nonneg", nullable: false, note: "byte length of raw_response_bytes; a consecutive-dedup comparison key" },
  { name: "raw_response_sha256", type: "sha256_hex", nullable: false, note: "SHA-256 of raw_response_bytes; a candidate index, not equality authority" },
] as const satisfies readonly FieldSpec[];

/** `gateway_observations`: the permanent, append-only observation row. */
export const GATEWAY_OBSERVATION_RECORD_FIELDS = [
  { name: "id", type: "uuid", nullable: false, note: "primary key" },
  { name: "observer_id", type: "uuid", nullable: false, note: "references observers(id)" },
  { name: "endpoint_fingerprint", type: "sha256_hex", nullable: false, note: "copied per row so later reconfiguration cannot rewrite provenance" },
  { name: "wallet_id", type: "uuid", nullable: true, note: "optional projection for a node-owned wallet; null for external addresses" },
  { name: "wallet_public_key", type: "padded_base64url_pubkey", nullable: false, note: "the observed public key" },
  { name: "wallet_seq", type: "bigint_positive", nullable: false, note: "per-stream sequence; unique with (observer_id, wallet_public_key)" },
  { name: "observed_at", type: "timestamptz", nullable: false, note: "capture time" },
  { name: "http_status", type: "integer", nullable: true, note: "transport status" },
  { name: "raw_response_bytes", type: "bytea", nullable: false, note: "authoritative evidence; never JSONB; never parse/re-serialized by retention jobs" },
  { name: "raw_response_sha256", type: "sha256_hex", nullable: false, note: "candidate index; equality still recomputes length and compares exact bytes" },
  { name: "parse_result", type: "observation_parse_result", nullable: false, note: "verification disposition" },
  { name: "relationship", type: "observation_relationship", nullable: false, note: "what the fresh response proved at capture; immutable" },
  { name: "semantic_fingerprint", type: "sha256_hex", nullable: true, note: "present iff verified (CHECK A); computed only after complete verification" },
  { name: "state_changed", type: "boolean", nullable: true, note: "present iff verified (CHECK B)" },
  { name: "wallet_role", type: "wallet_observation_role", nullable: true, note: "sender | receiver | genesis; null when non-verified (CHECK F)" },
  { name: "s_signature", type: "text", nullable: true, note: "current state signature; empty string at genesis" },
  { name: "p_signature", type: "text", nullable: true, note: "previous state signature; empty string permitted" },
  { name: "b_amount", type: "zkz_balance_text", nullable: true, note: "role-relative absolute balance; '0' is legal (canonical ZKZ balance domain)" },
  { name: "inner_preimage_text", type: "text", nullable: true, note: "exact JSON.stringify(inner) preimage; head only" },
  { name: "step_1_signature", type: "text", nullable: true, note: "head only" },
  { name: "step_2_signature", type: "text", nullable: true, note: "head only" },
  { name: "completed_transaction_text", type: "text", nullable: true, note: "exact complete body, top-level sequence inner, step_1_signature, step_2_signature; head only; never reconstructed from projections" },
  { name: "completed_transaction_sha256", type: "sha256_hex", nullable: true, note: "head only; recomputed and byte-compared" },
  { name: "previous_recorded_observation_id", type: "uuid", nullable: true, note: "dedup linkage to the immediately prior recorded row; references gateway_observations(id)" },
  { name: "created_at", type: "timestamptz", nullable: false, note: "insertion time; defaults to now()" },
] as const satisfies readonly FieldSpec[];

/**
 * `wallet_observation_cursors`: mutable operational index, explicitly NOT evidence. Its
 * counters carry the suppressed-sighting tally and the per-stream sequence allocator.
 */
export const WALLET_OBSERVATION_CURSOR_FIELDS = [
  { name: "observer_id", type: "uuid", nullable: false, note: "primary key part" },
  { name: "wallet_id", type: "uuid", nullable: true, note: "optional node-owned wallet projection" },
  { name: "wallet_public_key", type: "padded_base64url_pubkey", nullable: false, note: "primary key part" },
  { name: "last_recorded_observation_id", type: "uuid", nullable: false, note: "the most recently appended row for this stream" },
  { name: "last_raw_response_sha256", type: "sha256_hex", nullable: false, note: "candidate index for the consecutive byte-identical check" },
  { name: "last_semantic_fingerprint", type: "sha256_hex", nullable: true, note: "prior verified semantic identity, when the last row was verified" },
  { name: "last_seen_at", type: "timestamptz", nullable: false, note: "updated on every sighting, appended or suppressed" },
  { name: "consecutive_repeat_count", type: "bigint_nonneg", nullable: false, note: "count of suppressed byte-identical verified repeats since the last appended row" },
  { name: "next_wallet_seq", type: "bigint_positive", nullable: false, note: "allocator for the next appended row's wallet_seq" },
] as const satisfies readonly FieldSpec[];

/**
 * `observation_anomalies`: one permanent anomaly row per anomalous observation
 * (`observation_id` is UNIQUE). Always appended, even when the raw bytes repeat (capture step 9).
 */
export const OBSERVATION_ANOMALY_RECORD_FIELDS = [
  { name: "id", type: "uuid", nullable: false, note: "primary key" },
  { name: "observation_id", type: "uuid", nullable: false, note: "unique; references the appended gateway_observations row" },
  { name: "observer_id", type: "uuid", nullable: false, note: "references observers(id)" },
  { name: "wallet_id", type: "uuid", nullable: true, note: "optional node-owned wallet projection" },
  { name: "wallet_public_key", type: "padded_base64url_pubkey", nullable: false, note: "the observed public key" },
  { name: "kind", type: "observation_anomaly_kind", nullable: false, note: "anomaly classification" },
  { name: "prior_observation_id", type: "uuid", nullable: true, note: "the prior accepted state this anomaly was judged against, when applicable" },
  { name: "details", type: "text", nullable: false, note: "human-readable anomaly detail" },
  { name: "detected_at", type: "timestamptz", nullable: false, note: "detection time" },
] as const satisfies readonly FieldSpec[];
