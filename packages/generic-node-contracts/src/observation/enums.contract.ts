/**
 * SOURCE: the data-model enum declarations and the `gateway_observations` /
 * `observation_anomalies` CHECK domains, cross-read with the observation-verification
 * classification table. Transcribed verbatim: value sequence is the frozen
 * fact (the SQL `CREATE TYPE` declaration sequence), not an alphabetisation.
 *
 * Adding, removing, renaming, or resequencing any member is a contract-version change, never
 * a local edit (a contract-version change, never a local migration).
 */

/** `observer_domain`. The node and the platform keep independent ledgers (the observation-dedup rule).*/
export const OBSERVER_DOMAINS = ["NODE", "PLATFORM"] as const;

/**
 * `observation_parse_result`. The two `VERIFIED_*` members are the only ones that carry a
 * derived semantic state; the rest are non-verified dispositions whose record shape is
 * constrained by the record CHECK domain (CHECK F).
 */
export const OBSERVATION_PARSE_RESULTS = [
  "VERIFIED_GENESIS",
  "VERIFIED_HEAD",
  "TRANSPORT_ERROR",
  "MALFORMED_ENVELOPE",
  "MALFORMED_TRANSACTION",
  "UNVERIFIED_SIGNATURE",
  "WALLET_ROLE_INVALID",
] as const;

/** The parse results that establish a derived, verified semantic state (CHECK A/B). */
export const VERIFIED_PARSE_RESULTS = ["VERIFIED_GENESIS", "VERIFIED_HEAD"] as const;

/**
 * `observation_relationship`. `COMPLETE_PATH_SUCCESSOR` and `UNEXPLAINED_JUMP` semantics are
 * owned by the landing-proof complete-path rule landing oracle; here they are frozen only as members of the record's
 * `relationship` field domain. `NOT_APPLICABLE` is mandatory for every non-verified row.
 */
export const OBSERVATION_RELATIONSHIPS = [
  "FIRST",
  "SUCCESSOR",
  "COMPLETE_PATH_SUCCESSOR",
  "DUPLICATE",
  "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
  "REGRESSION",
  "UNEXPLAINED_JUMP",
  "GENESIS_AFTER_HISTORY",
  "SIGNATURE_COLLISION",
  "NOT_APPLICABLE",
] as const;

/** `gateway_observations.wallet_role` CHECK domain. Genesis is a distinct role here. */
export const WALLET_OBSERVATION_ROLES = ["sender", "receiver", "genesis"] as const;

/**
 * `observation_anomalies.kind` CHECK domain. A strict subset of the non-`FIRST`/
 * non-`SUCCESSOR` failure vocabulary: it is exactly the non-verified parse results plus the
 * four verified-but-anomalous relationships. Anomalies always append (capture step 9; retention).
 */
export const OBSERVATION_ANOMALY_KINDS = [
  "TRANSPORT_ERROR",
  "MALFORMED_ENVELOPE",
  "MALFORMED_TRANSACTION",
  "UNVERIFIED_SIGNATURE",
  "WALLET_ROLE_INVALID",
  "REGRESSION",
  "UNEXPLAINED_JUMP",
  "GENESIS_AFTER_HISTORY",
  "SIGNATURE_COLLISION",
] as const;

export type ObserverDomain = (typeof OBSERVER_DOMAINS)[number];
export type ObservationParseResult = (typeof OBSERVATION_PARSE_RESULTS)[number];
export type VerifiedParseResult = (typeof VERIFIED_PARSE_RESULTS)[number];
export type ObservationRelationship = (typeof OBSERVATION_RELATIONSHIPS)[number];
export type WalletObservationRole = (typeof WALLET_OBSERVATION_ROLES)[number];
export type ObservationAnomalyKind = (typeof OBSERVATION_ANOMALY_KINDS)[number];

export const isVerifiedParseResult = (value: string): value is VerifiedParseResult =>
  (VERIFIED_PARSE_RESULTS as readonly string[]).includes(value);
