// Signer support: the signer-leadership and recovery surfaces, the destination blessing
// artifact, the approval-challenge shape, globally single-use TOTP timestep burns, the
// auth-failure/lockout state and rate limits, and the recovery-action idempotency store;
// the key-custody rule (the platform never touches private keys).
//
// Frozen inventory of the structural signer/auth-support invariants carried by
// signer-support.sql: signer_audit, destination_blessing_artifacts,
// recovery_nonces, totp_timestep_burns, api_rate_buckets, auth_failure_state. The census
// test binds every entry here to the literal SQL text, so the inventory and the schema
// contract cannot drift apart. Execution against a live database belongs to the schema-apply phase, recorded below as obligations rather than silently omitted.

export const SIGNER_SUPPORT_SCHEMA_FILE = "signer-support.sql" as const;

export interface SignerSupportInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

/** Reference domain: a 64-byte Ed25519 sig → 86 base64url chars + `==` (length 88). */
export const SIGNER_SUPPORT_PADDED_BASE64URL_SIGNATURE_CHECK =
  "length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$'" as const;

/**
 * A.4.2 golden `zp-destination-bless-v1` device signature
 * (the canonical-fields appendix; crypto-goldens).
 * Domain CHECK must accept this exact vector.
 */
export const A42_DESTINATION_BLESS_DEVICE_SIGNATURE =
  "W490dwQEKHVOCP2npX1QABoGNwDALJ9KqijN7D-yu9b4GRsScdJEcqtOoKq1z0f2EP0Rf5MOaKu9I6hplLa8BQ==" as const;

export const SIGNER_SUPPORT_INVARIANTS: readonly SignerSupportInvariant[] = [
  {
    id: "DOMAIN_PADDED_BASE64URL_SIGNATURE",
    sqlAnchor:
      "CREATE DOMAIN padded_base64url_signature AS text\n  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');",
    rule: "padded_base64url_signature is 86 base64url chars + '==' (the reference domain in base-enums-domains): {87}=$ rejects every valid Ed25519 padded signature, including the golden device signature.",
  },
  {
    id: "AUDIT_OPERATION_BINDING",
    sqlAnchor: "operation_id uuid NOT NULL,\n  lease_group_id uuid,\n  lease_epoch bigint CHECK (lease_epoch IS NULL OR lease_epoch > 0),",
    rule: "every signer invocation is bound to an operation and records the lease group/epoch presented: lease fields are nullable because some sign paths predate lease acquisition, but a positive epoch is required when present.",
  },
  {
    id: "AUDIT_PREIMAGE_DIGEST",
    sqlAnchor: "preimage_sha256 sha256_hex NOT NULL,",
    rule: "the exact preimage digest signed is persisted: recovery classifies INVARIANT_BREACH when a signer audit row exists but the expected exact byte record is missing.",
  },
  {
    id: "AUDIT_TIMESTAMP_PRESENT",
    sqlAnchor: "called_at timestamptz NOT NULL,",
    rule: "the exact invocation timestamp is recorded (audit-trail discipline): called_at is NOT NULL, so the audit trail is temporally sequenced.",
  },
  {
    id: "AUDIT_OUTCOME_CLOSED_SET",
    sqlAnchor: "outcome text NOT NULL CHECK (outcome IN\n    ('SUCCEEDED','FAILED','UNKNOWN')),",
    rule: "outcome is one of SUCCEEDED / FAILED / UNKNOWN: UNKNOWN is how recovery records \"a call occurred and the result is unknown\" without inventing a success.",
  },
  {
    id: "AUDIT_PURPOSE_CLOSED_SET",
    sqlAnchor:
      "purpose text NOT NULL CHECK (purpose IN\n    ('STEP_1','STEP_2','REPORTING_ENVELOPE','DEVICE_APPROVAL','EXPECTED_ARTIFACT')),",
    rule: "the signing purpose is one of the five frozen categories: STEP_1, STEP_2, REPORTING_ENVELOPE, DEVICE_APPROVAL, EXPECTED_ARTIFACT -- no sixth purpose is representable.",
  },
  {
    id: "BLESS_PURPOSE_AND_VERSION",
    sqlAnchor:
      "purpose text NOT NULL CHECK (purpose = 'zp-destination-bless-v1'),\n  canonical_version integer NOT NULL CHECK (canonical_version = 1),",
    rule: "blessing artifacts are exactly the A.4.2 purpose and canonical version 1: any other purpose or version is a constraint violation.",
  },
  {
    id: "BLESS_FROZEN_TUPLE_FIELDS",
    sqlAnchor:
      "node_id uuid NOT NULL,\n  destination_id uuid NOT NULL,\n  wallet_id uuid NOT NULL,\n  wallet_pubkey padded_base64url_pubkey NOT NULL,\n  nonce uuid NOT NULL UNIQUE,\n  issued_at timestamptz NOT NULL,\n  expires_at timestamptz NOT NULL,\n  device_signature padded_base64url_signature NOT NULL,",
    rule: "the A.4.2 signed tuple fields (node/destination/wallet ids, wallet pubkey, single-use nonce, issued/expires, device signature) are all NOT NULL and the nonce is UNIQUE.",
  },
  {
    id: "BLESS_PREIMAGE_EXACT_PLUS_DIGEST",
    sqlAnchor: "preimage_text text NOT NULL,\n  preimage_sha256 sha256_hex NOT NULL,",
    rule: "exact blessing preimage text and its SHA-256 are persisted together: the signed tuple is never re-derived from mutable columns.",
  },
  {
    id: "BLESS_WINDOW_CEILING",
    sqlAnchor: "CHECK (EXTRACT(EPOCH FROM (expires_at - issued_at)) <= 300),",
    rule: "the blessing ceremony window is at most 300 seconds (A.4.2 ceiling): a wider window is a constraint violation.",
  },
  {
    id: "RECOVERY_NONCE_UNIQUE",
    sqlAnchor: "nonce uuid NOT NULL UNIQUE,",
    rule: "a recovery nonce value is single-use at the database level: a replayed recovery action presenting a stale nonce hits unique_violation or status mismatch.",
  },
  {
    id: "RECOVERY_NONCE_ONE_ISSUED",
    sqlAnchor:
      "CREATE UNIQUE INDEX recovery_nonces_one_issued_per_operation\n  ON recovery_nonces (operation_id)\n  WHERE status = 'ISSUED';",
    rule: "at most one ISSUED recovery nonce per operation (the approval-challenge pattern): concurrent issue races collapse to one winner.",
  },
  {
    id: "RECOVERY_NONCE_STATUS_CLOSED_SET",
    sqlAnchor:
      "status text NOT NULL CHECK (status IN\n    ('ISSUED','CONSUMED','SUPERSEDED')),",
    rule: "recovery nonce status is ISSUED / CONSUMED / SUPERSEDED only -- the same lifecycle shape as approval_challenges.",
  },
  {
    id: "TOTP_BURN_GLOBAL_UNIQUE",
    sqlAnchor: "UNIQUE (node_id, totp_timestep)",
    rule: "a (node_id, totp_timestep) pair is globally single-use across every guarded mutation: approval, blessing, and recovery share this registry so a cross-purpose race cannot both succeed.",
  },
  {
    id: "TOTP_BURN_PURPOSE_CLOSED_SET",
    sqlAnchor:
      "purpose text NOT NULL CHECK (purpose IN\n    ('SEND_EXTERNAL_APPROVAL','DESTINATION_BLESS','RECOVERY_ACTION')),",
    rule: "the burn purpose is one of SEND_EXTERNAL_APPROVAL / DESTINATION_BLESS / RECOVERY_ACTION: purpose is metadata; uniqueness is global on (node_id, totp_timestep).",
  },
  {
    id: "RATE_BUCKET_DIMENSIONS",
    sqlAnchor:
      "dimension text NOT NULL CHECK (dimension IN\n    ('ACCOUNT','SOURCE_IP','DEVICE','OPERATION')),",
    rule: "rate buckets exist for the four rate-limit dimensions (account, source IP, device, operation): no fifth dimension is representable, and rate limiting never replaces TOTP/nonce checks.",
  },
  {
    id: "RATE_BUCKET_UNIQUE_WINDOW",
    sqlAnchor: "UNIQUE (node_id, dimension, dimension_key, window_start)",
    rule: "at most one rate-bucket row per (node, dimension, key, window): the window is the throttling unit.",
  },
  {
    id: "RATE_BUCKET_COUNT_NON_NEGATIVE",
    sqlAnchor: "request_count integer NOT NULL DEFAULT 0 CHECK (request_count >= 0),",
    rule: "the request count is non-negative: a negative count is a constraint violation, not an application-level rejection.",
  },
  {
    id: "AUTH_FAILURE_PER_ACCOUNT",
    sqlAnchor: "UNIQUE (node_id, account_key)",
    rule: "auth-failure state is keyed per (node, account) with a non-negative failed_login_count and an optional locked_until window.",
  },
  {
    id: "AUTH_FAILURE_COUNT_NON_NEGATIVE",
    sqlAnchor:
      "failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),",
    rule: "failed_login_count is non-negative: lockout math never starts from a negative counter.",
  },
  {
    id: "BLESS_ARTIFACT_FK_TARGET",
    sqlAnchor:
      "ALTER TABLE destinations\n  ADD CONSTRAINT destinations_blessing_artifact_fk\n  FOREIGN KEY (blessing_artifact_id)\n  REFERENCES destination_blessing_artifacts (id);",
    rule: "destinations.blessing_artifact_id has a real foreign-key target: a bless mutation that points at a missing or corrupted artifact fails closed at the database.",
  },
] as const;

export const SIGNER_SUPPORT_AUDIT_OUTCOMES = [
  "SUCCEEDED",
  "FAILED",
  "UNKNOWN",
] as const;

export const SIGNER_SUPPORT_AUDIT_PURPOSES = [
  "STEP_1",
  "STEP_2",
  "REPORTING_ENVELOPE",
  "DEVICE_APPROVAL",
  "EXPECTED_ARTIFACT",
] as const;

export const SIGNER_SUPPORT_TOTP_PURPOSES = [
  "SEND_EXTERNAL_APPROVAL",
  "DESTINATION_BLESS",
  "RECOVERY_ACTION",
] as const;

export const SIGNER_SUPPORT_RATE_DIMENSIONS = [
  "ACCOUNT",
  "SOURCE_IP",
  "DEVICE",
  "OPERATION",
] as const;

export const SIGNER_SUPPORT_MUTABILITY_REGIMES = [
  {
    table: "signer_audit",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "append-only: no column is updatable or deletable; every invocation attempt is a permanent evidence row.",
  },
  {
    table: "destination_blessing_artifacts",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "insert-only (exact-content): the signed device-enrolment tuple and its preimage bytes are frozen at insert.",
  },
  {
    table: "totp_timestep_burns",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "insert-only: a burned (node_id, timestep) is never restored, even if the guarded mutation later fails.",
  },
  {
    table: "recovery_nonces",
    regime: "guarded_projection",
    updatableColumns: ["status", "consumed_at", "superseded_by"] as readonly string[],
    rule: "status/consumed_at/superseded_by may change under the lifecycle CHECKs; nonce, operation_id, and issued_at are immutable after insert.",
  },
  {
    table: "api_rate_buckets",
    regime: "guarded_projection",
    updatableColumns: ["request_count"] as readonly string[],
    rule: "request_count may increment within a window; dimension keys and window_start are immutable.",
  },
  {
    table: "auth_failure_state",
    regime: "guarded_projection",
    updatableColumns: ["failed_login_count", "locked_until", "last_failed_at"] as readonly string[],
    rule: "failure counters and lock windows are updatable; (node_id, account_key) identity is immutable.",
  },
] as const;

export const SCHEMA_SIGNER_SUPPORT_OBLIGATIONS = [
  "execution sequence: create nodes and destinations (custody-eligibility.sql) before this file; the ALTER TABLE destinations FK is prerequisite-bound on destinations, and bare node_id columns are reconciled to nodes(id) FKs at schema-apply assembly.",
  "guards: install BEFORE UPDATE/DELETE enforcement making signer_audit, destination_blessing_artifacts, and totp_timestep_burns append-only; recovery_nonces may only mutate status/consumed_at/superseded_by; api_rate_buckets may only mutate request_count; auth_failure_state may only mutate failed_login_count/locked_until/last_failed_at.",
  "negative: a second totp_timestep_burns row for the same (node_id, totp_timestep) with a different purpose is rejected by UNIQUE (node_id, totp_timestep) (23505) -- proving the burn is global across approval/blessing/recovery.",
  "negative: a second ISSUED recovery_nonces row for the same operation_id is rejected by recovery_nonces_one_issued_per_operation.",
  "negative: a recovery action replaying a CONSUMED or SUPERSEDED nonce fails closed (status mismatch and/or unique_violation on nonce).",
  "negative: destinations.blessing_artifact_id referencing a missing destination_blessing_artifacts.id is rejected by destinations_blessing_artifact_fk.",
  "negative: a blessing artifact with expires_at - issued_at > 300s is rejected by the window ceiling CHECK.",
  "negative: outcome or purpose outside the closed CHECK sets is rejected.",
  "negative: a malformed preimage_sha256 / wallet_pubkey / device_signature value is rejected by its domain.",
  "recovery classification: a signer_audit row for operation_id with no matching exact-byte record classifies INVARIANT_BREACH; absence of any signer_audit row with no other evidence classifies PROVEN_NOT_STARTED.",
  "secret-free content: no TOTP code, TOTP secret, private key, or session secret column exists; totp_timestep is a counter identity only.",
  "rate limits never become the sole replay defense: TOTP burns and recovery/blessing nonces remain mandatory even when a rate bucket admits the request.",
] as const;

export const SIGNER_SUPPORT_SOURCE =
  "signing-custody: TOTP single-use, rate limits, and recovery support" as const;
