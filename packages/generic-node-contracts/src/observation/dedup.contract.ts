/**
 * SOURCE: the observation-verification contract (serialized capture algorithm and retention),
 * the data-model writer rules, the permanent-retention requirement, and the canonical
 * observation-dedup decision.
 *
 * These freeze the RECORD-CREATION rules the raw ledger obeys: the consecutive-dedup key and
 * the permanent-retention facts. The pairwise decision function lives in dedup-predicate.ts.
 * The semantic classification of an appended row is the observation concern.2; multi-capture sequence proofs
 * are the observation concern.3.
 */

/** Exact raw-byte equality is the ONLY suppression key; there is no global deduplication. */
export const CONSECUTIVE_DEDUP_KEY = "EXACT_RAW_BYTE_EQUALITY" as const;

/** The digest is a fast candidate index; exact bytes are the equality authority. */
export const DIGEST_ROLE = "CANDIDATE_INDEX_NOT_EQUALITY_AUTHORITY" as const;

/** The frozen decision vocabulary the pairwise predicate returns. */
export const APPEND_OUTCOMES = ["APPEND", "SUPPRESS_AS_SIGHTING"] as const;
export type AppendOutcome = (typeof APPEND_OUTCOMES)[number];

/**
 * Suppression preconditions, in evaluation sequence. All must hold to SUPPRESS_AS_SIGHTING;
 * any failure APPENDs. digest and length are candidate gates only — the exact-byte check is
 * authoritative and is never skipped on a digest/length match.
 */
export const SUPPRESSION_PRECONDITIONS = [
  "prior recorded row exists",
  "prior recorded row was verified",
  "next capture is verified",
  "equal raw_response_sha256",
  "equal raw_response octet length",
  "exact raw-byte equality",
] as const;

/**
 * Permanent-retention facts (observation-dedup decision). Every byte-changed verified response and every
 * anomaly sighting is appended forever; only cursor counters are mutable.
 */
export const RETENTION_RULE = {
  append_only: true,
  anomalies_always_append: true,
  global_deduplication: false,
  recurrence_of_older_state_retained: true,
  raw_bytes_storage: "BYTEA_NEVER_JSONB",
  raw_bytes_never_reserialized: true,
} as const;
