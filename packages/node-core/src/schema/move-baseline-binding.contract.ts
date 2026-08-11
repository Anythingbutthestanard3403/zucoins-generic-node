/**
 * Move baseline binding: operation_observation_bindings and move_observation_evidence,
 * with the observation foreign keys deferred until the observation ledger exists.
 * operation_expected_artifacts is owned solely by expected-artifacts.sql (one-slice-one-contract);
 * this contract inventories only the binding/evidence shape this slice creates.
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
  "operation_observation_bindings.operation_id, move_observation_evidence.operation_id -> operations(id): no operations schema slice exists in the tree yet.",
  "operation_observation_bindings.observation_id and move_observation_evidence's four observation columns -> gateway_observations(id): deferred by the observation ledger itself, which adds them by ALTER TABLE after the observation tables exist.",
] as const;

/**
 * Live-database proofs this package cannot run in this package.
 * test/move-baseline-binding.pg.test.ts discharges each when TEST_DATABASE_URL is set.
 */
export const SCHEMA_EXECUTION_OBLIGATIONS = [
  "greenfield: applied alone into an empty schema this slice applies clean and materialises operation_observation_bindings and move_observation_evidence (operation_expected_artifacts is owned by expected-artifacts.sql).",
  "unique: a second move_observation_evidence row for the same operation_id is rejected (unique_violation 23505) -- the durable one-capture-per-operation bound.",
  "check reject: a move_observation_evidence row whose two T0 observation ids are equal is rejected (check_violation 23514) even when both wallets project identical genesis state.",
  "unique: a second operation_observation_bindings row for the same (operation_id, evidence_role) is rejected, and rebinding one observation_id under a second role of the same operation is rejected.",
  "composition: when expected-artifacts.sql is applied first (pack sequence), capture flow through a real SqlExecutor persists both bindings, the evidence row, and the artifact for one operation; a rejected capture persists nothing.",
] as const;

export const MOVE_BASELINE_SCHEMA_SOURCE =
  "data-model: observation bindings and move observation evidence (expected artifacts owned by expected-artifacts.sql)" as const;
