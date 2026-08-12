// Database-wide conventions: the reference scalar checks and the enumerations.
//
// Frozen inventory of the database-wide foundation invariants carried by
// base-enums-domains.sql: the required extension, the five reference scalar
// domains (four reference scalars, with the ZKZ amount domain split into a pair), and the
// full closed enumeration set that every table-bearing schema contract depends on. The
// census test binds every entry here to the literal SQL text, so the inventory and the
// schema contract cannot drift apart.

export const BASE_ENUMS_DOMAINS_SCHEMA_FILE = "base-enums-domains.sql" as const;

export interface BaseEnumsDomainsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const BASE_ENUMS_DOMAINS_INVARIANTS: readonly BaseEnumsDomainsInvariant[] = [
  {
    id: "EXTENSION_PGCRYPTO",
    sqlAnchor: "CREATE EXTENSION IF NOT EXISTS pgcrypto;",
    rule: "pgcrypto is required for digest() used by reporting_logical_fingerprint and any future SHA-256 computation.",
  },
  {
    id: "DOMAIN_ZKZ_BALANCE_TEXT",
    sqlAnchor:
      "CREATE DOMAIN zkz_balance_text AS text\n  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$');",
    rule: "Balance-role ZKZ amounts are canonical decimal text bounded 0 <= amount < 1e8; '0' is legal. No money-path column is real, double precision, or a JavaScript-number-derived numeric.",
  },
  {
    id: "DOMAIN_ZKZ_AMOUNT_POSITIVE_TEXT",
    sqlAnchor:
      "CREATE DOMAIN zkz_amount_positive_text AS text\n  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$' AND VALUE::numeric > 0);",
    rule: "Operation-role ZKZ amounts are canonical decimal text bounded 0 < amount < 1e8. Positivity is NUMERIC, not the string test VALUE <> '0': '0.0', '0.00' and '0.' + 32 zeros all pass the regex and differ from '0' as strings while being mathematically zero.",
  },
  {
    id: "DOMAIN_SHA256_HEX",
    sqlAnchor: "CREATE DOMAIN sha256_hex AS text\n  CHECK (VALUE ~ '^[0-9a-f]{64}$');",
    rule: "SHA-256 digests are lowercase hex, exactly 64 characters.",
  },
  {
    id: "DOMAIN_PADDED_BASE64URL_PUBKEY",
    sqlAnchor: "CREATE DOMAIN padded_base64url_pubkey AS text\n  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');",
    rule: "Ed25519 public keys are padded base64url, exactly 44 characters with trailing '='.",
  },
  {
    id: "DOMAIN_PADDED_BASE64URL_SIGNATURE",
    sqlAnchor: "CREATE DOMAIN padded_base64url_signature AS text\n  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');",
    rule: "Ed25519 signatures are padded base64url, exactly 88 characters with trailing '=='.",
  },
  {
    id: "ENUM_OPERATION_KIND",
    sqlAnchor: "CREATE TYPE operation_kind AS ENUM (\n  'RECEIVE_EXTERNAL',\n  'MOVE_INTERNAL',\n  'SEND_EXTERNAL'\n);",
    rule: "operation_kind is a closed 3-value enum: RECEIVE_EXTERNAL, MOVE_INTERNAL, SEND_EXTERNAL.",
  },
  {
    id: "ENUM_OPERATION_STATUS",
    sqlAnchor: "CREATE TYPE operation_status AS ENUM (\n  'CREATED',\n  'READY',\n  'RECEIVE_LANDED',\n  'INTERNAL_MOVE_LANDED',\n  'APPROVED',\n  'AWAITING_REDEMPTION',\n  'EXTERNAL_SEND_LANDED',\n  'EXPIRED',\n  'REJECTED',\n  'NEEDS_ATTENTION'\n);",
    rule: "operation_status is a closed 10-value enum covering the full operation lifecycle.",
  },
  {
    id: "ENUM_WALLET_KEY_ORIGIN",
    sqlAnchor: "CREATE TYPE wallet_key_origin AS ENUM ('node_generated', 'imported');",
    rule: "wallet_key_origin is a closed 2-value enum: node_generated, imported.",
  },
  {
    id: "ENUM_WALLET_STATE",
    sqlAnchor: "CREATE TYPE wallet_state AS ENUM ('AVAILABLE', 'PINNED', 'QUARANTINED', 'RETIRED');",
    rule: "wallet_state is a closed 4-value enum: AVAILABLE, PINNED, QUARANTINED, RETIRED.",
  },
  {
    id: "ENUM_DESTINATION_STATE",
    sqlAnchor: "CREATE TYPE destination_state AS ENUM ('PENDING', 'BLESSED', 'RETIRED');",
    rule: "destination_state is a closed 3-value enum: PENDING, BLESSED, RETIRED.",
  },
  {
    id: "ENUM_WALLET_LEASE_ROLE",
    sqlAnchor: "CREATE TYPE wallet_lease_role AS ENUM (\n  'RECEIVE_WINDOW',\n  'MOVE_SOURCE',\n  'MOVE_DESTINATION',\n  'SEND_SOURCE',\n  'RECONCILIATION'\n);",
    rule: "wallet_lease_role is a closed 5-value enum covering all lease purposes.",
  },
  {
    id: "ENUM_APPROVAL_METHOD",
    sqlAnchor: "CREATE TYPE approval_method AS ENUM ('TOTP_ONLY', 'TOTP_AND_DEVICE', 'AUTO_POLICY');",
    rule: "approval_method is a closed 3-value enum: TOTP_ONLY, TOTP_AND_DEVICE, AUTO_POLICY.",
  },
  {
    id: "ENUM_APPROVAL_CHALLENGE_STATUS",
    sqlAnchor: "CREATE TYPE approval_challenge_status AS ENUM ('ISSUED', 'CONSUMED', 'SUPERSEDED', 'EXPIRED');",
    rule: "approval_challenge_status is a closed 4-value enum: ISSUED, CONSUMED, SUPERSEDED, EXPIRED.",
  },
  {
    id: "ENUM_EXTERNAL_FORMATION_STATE",
    sqlAnchor: "CREATE TYPE external_formation_state AS ENUM (\n  'NOT_REQUIRED',\n  'APPROVAL_PENDING',\n  'APPROVED_UNSIGNED',\n  'SIGNING_CLAIMED',\n  'PARTIAL_PERSISTED',\n  'PARTIAL_DELIVERED'\n);",
    rule: "external_formation_state is a closed 6-value enum tracking external send formation.",
  },
  {
    id: "ENUM_OBSERVER_DOMAIN",
    sqlAnchor: "CREATE TYPE observer_domain AS ENUM ('NODE', 'PLATFORM');",
    rule: "observer_domain is a closed 2-value enum: NODE, PLATFORM.",
  },
  {
    id: "ENUM_OBSERVATION_PARSE_RESULT",
    sqlAnchor: "CREATE TYPE observation_parse_result AS ENUM (\n  'VERIFIED_GENESIS',\n  'VERIFIED_HEAD',\n  'TRANSPORT_ERROR',\n  'MALFORMED_ENVELOPE',\n  'MALFORMED_TRANSACTION',\n  'UNVERIFIED_SIGNATURE',\n  'WALLET_ROLE_INVALID'\n);",
    rule: "observation_parse_result is a closed 7-value enum covering all parse outcomes.",
  },
  {
    id: "ENUM_OBSERVATION_RELATIONSHIP",
    sqlAnchor: "CREATE TYPE observation_relationship AS ENUM (\n  'FIRST',\n  'SUCCESSOR',\n  'COMPLETE_PATH_SUCCESSOR',\n  'DUPLICATE',\n  'EQUIVALENT_STATE_DIFFERENT_ENVELOPE',\n  'REGRESSION',\n  'UNEXPLAINED_JUMP',\n  'GENESIS_AFTER_HISTORY',\n  'SIGNATURE_COLLISION',\n  'NOT_APPLICABLE'\n);",
    rule: "observation_relationship is a closed 10-value enum covering all adjacency classifications.",
  },
  {
    id: "ENUM_VERIFICATION_VERDICT",
    sqlAnchor: "CREATE TYPE verification_verdict AS ENUM (\n  'PENDING',\n  'VERIFIED',\n  'REJECTED',\n  'INDETERMINATE'\n);",
    rule: "verification_verdict is a closed 4-value enum: PENDING, VERIFIED, REJECTED, INDETERMINATE.",
  },
  {
    id: "ENUM_LINEAGE_PROOF_VERDICT",
    sqlAnchor: "CREATE TYPE lineage_proof_verdict AS ENUM (\n  'LANDED_EXACT',\n  'LANDED_COMPLETE_PATH',\n  'INDETERMINATE',\n  'INVARIANT_BREACH'\n);",
    rule: "lineage_proof_verdict is a closed 4-value enum: LANDED_EXACT, LANDED_COMPLETE_PATH, INDETERMINATE, INVARIANT_BREACH.",
  },
  {
    id: "ENUM_REPORTING_KEY_STATE",
    sqlAnchor: "CREATE TYPE reporting_key_state AS ENUM (\n  'PENDING',\n  'ACTIVE',\n  'RETIRED',\n  'REVOKED'\n);",
    rule: "reporting_key_state is a closed 4-value enum: PENDING, ACTIVE, RETIRED, REVOKED.",
  },
  {
    id: "ENUM_REPORTING_KEY_LIFECYCLE_EVENT_TYPE",
    sqlAnchor: "CREATE TYPE reporting_key_lifecycle_event_type AS ENUM (\n  'FIRST_KEY_ACTIVATED',\n  'KEY_ROTATED',\n  'PRIOR_KEY_RETIRED',\n  'KEY_REVOKED',\n  'AUTH_HOLD_SET',\n  'AUTH_HOLD_RELEASED'\n);",
    rule: "reporting_key_lifecycle_event_type is a closed 6-value enum covering all key lifecycle events.",
  },
  {
    id: "ENUM_REPORTING_REQUEST_CLASS",
    sqlAnchor: "CREATE TYPE reporting_request_class AS ENUM ('READ', 'MUTATION');",
    rule: "reporting_request_class is a closed 2-value enum: READ, MUTATION.",
  },
  {
    id: "FUNCTION_REPORTING_LOGICAL_FINGERPRINT",
    sqlAnchor: "CREATE FUNCTION reporting_logical_fingerprint(",
    rule: "reporting_logical_fingerprint is an IMMUTABLE STRICT PARALLEL SAFE SQL function computing a deterministic SHA-256 fingerprint over method, target, and body hash.",
  },
];
