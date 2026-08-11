// Exact expected artifacts: frozen byte surfaces, byte-exact signing (the byte-exact signing rule).
//
// Frozen inventory of the structural expected-artifact invariants carried by
// expected-artifacts.sql. The census test binds every entry here to the literal SQL
// text, so the inventory and the schema contract cannot drift apart. Execution against
// a live database belongs to the schema-apply phase, recorded below as obligations rather
// than silently omitted.

export const EXPECTED_ARTIFACTS_SCHEMA_FILE = "expected-artifacts.sql" as const;

export interface ExpectedArtifactsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const EXPECTED_ARTIFACTS_INVARIANTS: readonly ExpectedArtifactsInvariant[] = [
  {
    id: "ARTIFACT_PK",
    sqlAnchor: "id uuid PRIMARY KEY,",
    rule: "each expected artifact has a unique UUID primary key.",
  },
  {
    id: "ARTIFACT_ONE_PER_OPERATION",
    sqlAnchor: "operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),",
    rule: "at most one expected artifact per operation: operation_id is UNIQUE, so a second artifact for the same operation is a unique_violation.",
  },
  {
    id: "ARTIFACT_PURPOSE_CLOSED_SET",
    sqlAnchor:
      "purpose text NOT NULL CONSTRAINT operation_expected_artifacts_purpose_check CHECK (purpose IN (\n    'zp-receive-expected-v1',\n    'zp-move-internal-expected-v1',\n    'zp-send-external-expected-v1'\n  )),",
    rule: "exactly three frozen purpose literals: receive, move-internal, send-external. A fourth purpose is a constraint violation; changing any field/field-sequence requires a new purpose/version and new goldens.",
  },
  {
    id: "ARTIFACT_CANONICAL_VERSION_ONE",
    sqlAnchor:
      "canonical_version integer NOT NULL\n    CONSTRAINT operation_expected_artifacts_canonical_version_check CHECK (canonical_version = 1),",
    rule: "only canonical version 1 is representable: a version other than 1 is a constraint violation.",
  },
  {
    id: "ARTIFACT_SIGNING_KEY_FK",
    sqlAnchor: "signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),",
    rule: "the signing key is bound by FK to node_signing_keys; storage column signing_key_id maps to wire field key_id exactly — the API MUST NOT expose a second signing_key_id alias.",
  },
  {
    id: "ARTIFACT_PREIMAGE_AND_DIGEST",
    sqlAnchor: "preimage_text text NOT NULL,\n  preimage_sha256 sha256_hex NOT NULL,",
    rule: "the exact preimage text and its SHA-256 digest are always present: the preimage is authoritative, the digest is a constraint-checkable derivative.",
  },
  {
    id: "ARTIFACT_SIGNATURE",
    sqlAnchor: "signature padded_base64url_signature NOT NULL,",
    rule: "the Ed25519 signature over the preimage is always present: insert-only, never rebuilt.",
  },
  {
    id: "ARTIFACT_CREATED_AT",
    sqlAnchor: "created_at timestamptz NOT NULL DEFAULT now(),",
    rule: "creation timestamp defaults to now().",
  },
  {
    id: "ARTIFACT_PREIMAGE_NONEMPTY",
    sqlAnchor:
      "CONSTRAINT operation_expected_artifacts_preimage_text_check\n    CHECK (octet_length(preimage_text) > 0)",
    rule: "the persisted preimage is never the empty byte string.",
  },
  {
    id: "ARTIFACT_INSERT_ONLY_TRIGGER",
    sqlAnchor: "BEFORE UPDATE OR DELETE ON operation_expected_artifacts",
    rule: "insert-only byte-immutability: a row-level trigger rejects UPDATE and DELETE so the preimage a crash-recovery resumes from cannot be rewritten.",
  },
] as const;

export const EXPECTED_ARTIFACTS_MUTABILITY_REGIMES = [
  {
    table: "operation_expected_artifacts",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "insert-only: artifact rows are insert-only; no column is updatable or deletable.",
  },
] as const;

export const SCHEMA_EXPECTED_ARTIFACTS_OBLIGATIONS = [
  "execution sequence: create the FK target relations (operations, node_signing_keys) and the sha256_hex / padded_base64url_signature domains before this file's table.",
  "guards: BEFORE UPDATE/DELETE insert-only trigger is frozen in this file (EXPECTED_ARTIFACT_INSERT_ONLY).",
  "negative: a second operation_expected_artifacts row for the same operation_id violates the UNIQUE constraint on operation_id.",
  "negative: a purpose literal outside the three frozen values is rejected by the column CHECK.",
  "negative: canonical_version other than 1 is rejected by the column CHECK.",
  "negative: an empty preimage_text (octet_length = 0) is rejected by the table-level CHECK.",
  "negative: a malformed sha256_hex or padded_base64url_signature value is rejected by the domain CHECK.",
] as const;

export const EXPECTED_ARTIFACTS_SOURCE =
  "data-model: exact expected artifacts; the byte-exact signing rule" as const;
