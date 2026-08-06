// Durable receive-code material: the receive barriers and the admission-to-ready flow;
// canonical ZKZ amount contract (ZKZ amount bound — shared with operations.sql), receive TTL policy (receive TTL
// whole-second text; the expiry_unix_time_secs CHECK mirrors the operations twin).
//
// Frozen inventory of the structural invariants carried by receive-codes.sql.
// Execution against a live database belongs to the schema-apply phase; this file
// is contract text only — nothing in this package opens a socket from it.
// The census test binds every entry here to the literal SQL text, so inventory
// and schema contract cannot drift apart silently.

export const RECEIVE_CODES_SCHEMA_FILE = "receive-codes.sql" as const;
export const RECEIVE_CODES_EXTENDS = "operations.sql" as const;

export interface ReceiveCodesInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const RECEIVE_CODES_INVARIANTS: readonly ReceiveCodesInvariant[] = [
  {
    id: "CODE_PK_IS_OPERATION_ID",
    sqlAnchor: "operation_id uuid PRIMARY KEY REFERENCES operations(id),",
    rule: "receive_codes.row is 1:1 with its operation — operation_id is the primary key and REFERENCES operations(id).",
  },
  {
    id: "RECEIVER_WALLET_REQUIRED",
    sqlAnchor: "receiver_wallet_id uuid NOT NULL REFERENCES wallets(id),",
    rule: "a receive_code row cannot exist without a receiver wallet — the wallet is assigned before READY.",
  },
  {
    id: "T0_OBSERVATION_REQUIRED",
    sqlAnchor: "t0_observation_id uuid NOT NULL,",
    rule: "the T0 gateway observation id is persisted before READY; the FK to gateway_observations is added by ALTER TABLE after CREATE TABLE so the CREATE block stays readable.",
  },
  {
    id: "EXPECTED_ARTIFACT_UNIQUE",
    sqlAnchor: "expected_artifact_id uuid NOT NULL UNIQUE REFERENCES operation_expected_artifacts(id),",
    rule: "each expected artifact is referenced from at most one receive_codes row — at most one receive may own a given artifact preimage commitment.",
  },
  {
    id: "ANCHOR_FORMAT",
    sqlAnchor: "anchor text NOT NULL CHECK (anchor ~ '^[A-Za-z0-9_-]{1,96}$'),",
    rule: "the receive anchor is a 1..96 printable-ASCII alphanumeric-plus-dash/underscore string, validated at rest (the operations twin).",
  },
  {
    id: "EXPIRY_WHOLE_SECONDS_TEXT",
    sqlAnchor: "expiry_unix_time_secs text NOT NULL CHECK (expiry_unix_time_secs ~ '^[0-9]+$'),",
    rule: "Expiry is persisted as a bare digit string of unix SECONDS (never ms / JS-number / signed / fractional). The CHECK text is byte-identical to operations.sql's twin so a millisecond render cannot survive (the twin pattern).",
  },
  {
    id: "TRANSFER_CODE_SHA256",
    sqlAnchor: "transfer_code_text text NOT NULL,\n  transfer_code_sha256 sha256_hex NOT NULL,",
    rule: "The exact transfer code plaintext and its SHA-256 are co-persisted; the digest is a constraint-checkable derivative of the canonical preimage (the byte-exact signing rule).",
  },
  {
    id: "CODE_STATUS_CLOSED_SET",
    sqlAnchor: "code_status text NOT NULL CHECK (code_status IN ('AWAITING_ARM','RELEASED','EXPIRED')),",
    rule: "the receive code state is one of the three frozen values; no other status is representable at rest.",
  },
  {
    id: "RELEASED_CARRIES_TIMESTAMP",
    sqlAnchor: "CHECK (code_status <> 'RELEASED' OR released_at IS NOT NULL),",
    rule: "when code_status transitions to RELEASED released_at MUST be stamped simultaneously; a released code without a timestamp is unrepresentable.",
  },
  {
    id: "RELEASED_AT_IFF_RELEASED_OR_EXPIRED",
    sqlAnchor: "CHECK (released_at IS NULL OR code_status IN ('RELEASED','EXPIRED')),",
    rule: "released_at is set only for RELEASED or EXPIRED terminal states; an AWAITING_ARM row can never carry a released_at.",
  },
] as const;

export const RECEIVE_CODES_MUTABILITY_REGIMES = [
  {
    table: "receive_codes",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
  },
] as const;

export const SCHEMA_RECEIVE_CODES_OBLIGATIONS = [
  "apply after operations.sql and custody-eligibility.sql; this file's FKs need operations(id), wallets(id), gateway_observations(id), and operation_expected_artifacts(id) to exist EARLIER in the apply sequence.",
  "expiry_unix_time_secs format CHECK is byte-identical to the operations.sql twin — a millisecond render is rejected at rest.",
] as const;

export const RECEIVE_CODES_SOURCE =
  "data-model: receive barriers and receive code material" as const;
