/**
 * Move baseline binding: operation_observation_bindings, operation_expected_artifacts, and
 * move_observation_evidence, with the observation foreign keys deferred until the
 * observation ledger exists. Expected artifacts are insert-only and their bytes are frozen.
 *
 * Frozen inventory of the structural invariants carried by move-baseline-binding.sql.
 * The census test binds every entry here to the literal SQL text, so inventory and schema cannot
 * drift apart. Live-database execution is discharged by test/move-baseline-binding.pg.test.ts.
 */

export const MOVE_BASELINE_SCHEMA_FILE = "move-baseline-binding.sql" as const;

export interface MoveBaselineSchemaInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const MOVE_BASELINE_SCHEMA_INVARIANTS: readonly MoveBaselineSchemaInvariant[] = [
  {
    id: "ARTIFACT_ONE_PER_OPERATION",
    sqlAnchor: "operation_id uuid NOT NULL UNIQUE",
    rule: "An operation carries exactly ONE expected artifact. The UNIQUE is the durable form of that bound -- a second artifact insert for the same operation is rejected by the database, not by a caller's memory.",
  },
  {
    id: "ARTIFACT_PURPOSE_CLOSED_SET",
    sqlAnchor: "CONSTRAINT operation_expected_artifacts_purpose_check CHECK (purpose IN (",
    rule: "purpose is closed over the three frozen byte surfaces; a move persists 'zp-move-internal-expected-v1' and nothing else is admissible.",
  },
  {
    id: "ARTIFACT_CANONICAL_VERSION_ONE",
    sqlAnchor: "CHECK (canonical_version = 1)",
    rule: "Every expected artifact is version 1; a field or sequence change requires a NEW purpose/version, never an in-place rewrite of a -v1 surface.",
  },
  {
    id: "ARTIFACT_PREIMAGE_NONEMPTY",
    sqlAnchor: "CHECK (octet_length(preimage_text) > 0)",
    rule: "The exact preimage bytes are the artifact; an empty preimage_text is not a persisted artifact.",
  },
  {
    id: "ARTIFACT_DIGEST_AND_SIGNATURE_DOMAINS",
    sqlAnchor: "signature padded_base64url_signature NOT NULL",
    rule: "The digest is typed sha256_hex and the signature padded_base64url_signature -- domain CHECKs are the first boundary; runtime still re-decodes and re-verifies.",
  },
  {
    id: "ARTIFACT_INSERT_ONLY_TRIGGER",
    sqlAnchor: "BEFORE UPDATE OR DELETE ON operation_expected_artifacts",
    rule: "Retention is insert-only and exact-content tables are append-only or carry byte-immutability triggers: a row-level trigger rejects UPDATE and DELETE, so the preimage a crash-recovery resumes from cannot be rewritten.",
  },
  {
    id: "BINDING_ROLE_ONCE_PER_OPERATION",
    sqlAnchor: "PRIMARY KEY (operation_id, evidence_role)",
    rule: "Each evidence role binds at most once per operation, so a move cannot acquire two SOURCE_T0 bindings.",
  },
  {
    id: "BINDING_OBSERVATION_NOT_REUSED",
    sqlAnchor: "UNIQUE (operation_id, observation_id)",
    rule: "One observation row cannot be bound under two roles of the same operation -- the relational half of the distinct-T0 rule below.",
  },
  {
    id: "BINDING_EVIDENCE_ROLE_CLOSED_SET",
    sqlAnchor: "CONSTRAINT operation_observation_bindings_evidence_role_check",
    rule: "evidence_role is closed over the seven canonical roles; SOURCE_T0 and DESTINATION_T0 are the two this slice writes.",
  },
  {
    id: "BINDING_WALLET_PUBKEY_DOMAIN",
    sqlAnchor: "wallet_public_key padded_base64url_pubkey NOT NULL",
    rule: "A binding names the wallet public key it belongs to, typed by the reference domain; the binding service additionally verifies it equals the owning wallet's key.",
  },
  {
    id: "EVIDENCE_ONE_ROW_PER_OPERATION",
    sqlAnchor: "operation_id uuid PRIMARY KEY",
    rule: "One move-evidence row per operation. A second capture attempt for the same operation is rejected by the primary key (unique_violation), which is what makes the binding durable rather than advisory.",
  },
  {
    id: "EVIDENCE_BOTH_T0_MANDATORY",
    sqlAnchor: "source_t0_observation_id uuid NOT NULL",
    rule: "Both T0 observations are NOT NULL from this slice's write onward -- 'for a move, source and destination T0 are mandatory before signing'.",
  },
  {
    id: "EVIDENCE_DISTINCT_T0",
    sqlAnchor: "CHECK (source_t0_observation_id <> destination_t0_observation_id)",
    rule: "The two T0s must be genuinely distinct observation ROWS. The CHECK targets the row id, not the projected values, so two wallets that both read genesis (S0=\"\", P0=\"\", B0=\"0\") still require two separate observations.",
  },
  {
    id: "EVIDENCE_TERMINAL_ALL_OR_NOTHING",
    sqlAnchor: "CONSTRAINT move_observation_evidence_terminal_set_together",
    rule: "The terminal pair and verified_at are set together or not at all. This slice writes the T0 half only; landing verification fills the terminal half.",
  },
] as const;

/**
 * References this slice deliberately carries as bare uuid columns. Declared here so the omission
 * is inventoried rather than silent: the schema-apply assembly adds each by ALTER TABLE once the
 * owning slice exists.
 */
export const DEFERRED_FOREIGN_KEYS = [
  "operation_expected_artifacts.operation_id, operation_observation_bindings.operation_id, move_observation_evidence.operation_id -> operations(id): no operations schema slice exists in the tree yet.",
  "operation_expected_artifacts.signing_key_id -> node_signing_keys(id): owned by signing-key-registry.sql; added when the two slices are assembled.",
  "operation_observation_bindings.observation_id and move_observation_evidence's four observation columns -> gateway_observations(id): deferred by the observation ledger itself, which adds them by ALTER TABLE after the observation tables exist.",
] as const;

/**
 * Live-database proofs this package cannot run in this package.
 * test/move-baseline-binding.pg.test.ts discharges each when TEST_DATABASE_URL is set.
 */
export const SCHEMA_EXECUTION_OBLIGATIONS = [
  "greenfield: applied alone into an empty schema this slice applies clean and materialises operation_expected_artifacts, operation_observation_bindings, and move_observation_evidence.",
  "unique: a second move_observation_evidence row for the same operation_id is rejected (unique_violation 23505) -- the durable one-capture-per-operation bound.",
  "unique: a second operation_expected_artifacts row for the same operation_id is rejected (unique_violation 23505) -- the durable one-artifact-per-operation bound.",
  "check reject: a move_observation_evidence row whose two T0 observation ids are equal is rejected (check_violation 23514) even when both wallets project identical genesis state.",
  "check reject: an operation_expected_artifacts row with a purpose outside the three frozen surfaces, or canonical_version <> 1, or an empty preimage_text, is rejected.",
  "insert-only: UPDATE and DELETE against a persisted operation_expected_artifacts row are rejected by the byte-immutability trigger (EXPECTED_ARTIFACT_INSERT_ONLY).",
  "unique: a second operation_observation_bindings row for the same (operation_id, evidence_role) is rejected, and rebinding one observation_id under a second role of the same operation is rejected.",
  "end-to-end: the capture flow, driven through a real SqlExecutor, persists both bindings, the evidence row, and the artifact for one operation; a rejected capture persists nothing.",
] as const;

export const MOVE_BASELINE_SCHEMA_SOURCE =
  "data-model: observation bindings, expected artifacts, and move observation evidence" as const;
