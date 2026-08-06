// Send external create: the create steps, the operations and expected-artifact relations,
// the create/response wire shapes, idempotency, and one active lease per wallet;
// appendices/A-canonical-fields.md SSA.3.3, SSA.3.4; three public money operations;
// the one-in-flight-per-wallet rule.
//
// Frozen inventory of the structural invariants carried by send-external-create.sql
// the create-time SEND_EXTERNAL row that doubles as the
// idempotency record, plus its one exact expected artifact. Execution against a live
// database belongs to the schema-apply phase; the money-path invariants this slice exists to
// guarantee -- the idempotency scope uniqueness, the one-in-flight-per-wallet one-unsettled-send-per-
// source-wallet index, the economic-field immutability guard, and the artifact's
// exactly-one/insert-only pair -- are additionally drilled against a real PostgreSQL by
// test/send-external-create-pg.test.ts, so none can be satisfied by an in-memory fake alone.

export const SEND_EXTERNAL_CREATE_SCHEMA_FILE = "send-external-create.sql" as const;

export interface SendExternalCreateInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const SEND_EXTERNAL_CREATE_INVARIANTS: readonly SendExternalCreateInvariant[] = [
  {
    id: "AMOUNT_POSITIVE_CHECK",
    sqlAnchor:
      "CONSTRAINT send_operations_amount_positive\n    CHECK (amount_zkz ~ '^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$' AND amount_zkz::numeric > 0)",
    rule: "The canonical ZKZ amount bound is enforced at rest by a CHECK, not by application validation alone. Numeric positivity closes the zero-form bypass ('0.0', '0.00', '0.' + 32 zeros) that string positivity leaves open, and the grammar's own 8-digit integer part carries the < 1e8 upper bound.",
  },
  {
    id: "IDEMPOTENCY_FULL_TUPLE_UNIQUE",
    sqlAnchor:
      "CONSTRAINT send_operations_idempotency_scope\n    UNIQUE (implementer_id, http_method, route, idempotency_key)",
    rule: "The idempotency scope is the FULL (implementer_id, HTTP method, canonical route, idempotency_key) tuple and is enforced by a database UNIQUE constraint. kind, http_method and route are each pinned to one value by CHECK, so this is exactly the operations UNIQUE (implementer_id, kind, idempotency_key). Concurrent first use of one key yields exactly one inserter; every follower gets unique_violation (23505).",
  },
  {
    id: "REQUEST_HASH_REQUIRED",
    sqlAnchor: "request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),",
    rule: "The SHA-256 of the exact validated canonical request object is stored with the idempotency record, so same key + different hash is 409 idempotency_key_reused instead of a silent replay of a different request's operation.",
  },
  {
    id: "IN_PROGRESS_MARKER_IS_THE_ROW",
    sqlAnchor:
      "CONSTRAINT send_operations_completion_together\n    CHECK ((completed_at IS NULL) = (response_status IS NULL)\n           AND (completed_at IS NULL) = (response_body IS NULL)),",
    rule: "The in-progress marker is the row itself while completed_at IS NULL, held under the idempotency UNIQUE constraint. Status and exact response body from the first completed execution are stored together or not at all, so a half-written completion cannot be replayed as authoritative.",
  },
  {
    id: "GOLDEN_RULE_2_SOURCE_WALLET_INDEX",
    sqlAnchor:
      "CREATE UNIQUE INDEX send_operations_one_unsettled_per_source_wallet\n  ON send_operations (source_wallet_id)\n  WHERE status NOT IN ('EXTERNAL_SEND_LANDED', 'REJECTED');",
    rule: "The one-in-flight-per-wallet rule, structural: a second unsettled external send from one source wallet is rejected by the database with unique_violation. The guarantee does not depend on an application read that races the insert following it.",
  },
  {
    id: "UNSETTLED_PREDICATE_IS_TERMINAL_BLOCKLIST",
    sqlAnchor: "WHERE status NOT IN ('EXTERNAL_SEND_LANDED', 'REJECTED');",
    rule: "The unsettled predicate excludes the TERMINAL states rather than listing the non-terminal ones positively, and the direction is the safety property: a partial index does not index a row its predicate excludes, so a positive non-terminal allowlist would leave a status added to the frozen vocabulary holding no wallet and would silently ADMIT the next send (fail-open). Excluding the terminal pair makes an unknown status unsettled by construction, so it blocks (fail-closed); status is NOT NULL, so NOT IN carries no three-valued-logic hole. NEEDS_ATTENTION is excluded from the terminal pair because the source lease stays held there. Drilled both ways by test/send-external-create-pg.test.ts.",
  },
  {
    id: "ECONOMIC_FIELDS_IMMUTABLE",
    sqlAnchor:
      "CREATE TRIGGER send_operations_immutable_fields_guard\n  BEFORE UPDATE ON send_operations\n  FOR EACH ROW EXECUTE FUNCTION send_reject_economic_field_mutation();",
    rule: "Approval cannot change source, destination, amount, or reference. Immutability is structural, so no later code path can rewrite an economic field the create-time artifact already signed -- which is what makes the approval-tuple rebuild-and-compare check meaningful.",
  },
  {
    id: "ONE_ARTIFACT_PER_OPERATION",
    sqlAnchor: "operation_id uuid NOT NULL UNIQUE REFERENCES send_operations (operation_id),",
    rule: "Every operation has exactly one artifact of its own kind. A second artifact insert for the same operation_id violates the UNIQUE constraint; a parent artifact is never a substitute.",
  },
  {
    id: "ARTIFACT_INSERT_ONLY",
    sqlAnchor:
      "CREATE TRIGGER send_operation_expected_artifacts_insert_only\n  BEFORE UPDATE OR DELETE ON send_operation_expected_artifacts\n  FOR EACH ROW EXECUTE FUNCTION send_reject_artifact_mutation();",
    rule: "Artifact rows are insert-only. A signed byte surface that can be updated or deleted in place is not evidence of anything.",
  },
  {
    id: "ARTIFACT_SIGNATURE_REQUIRED",
    sqlAnchor:
      "signature text NOT NULL CHECK (length(signature) = 88 AND signature ~ '^[A-Za-z0-9_-]{86}==$'),",
    rule: "A-canonical-fields SSA.3.4: the artifact envelope is key_id, preimage_text, preimage_sha256, signature. The signature is NOT NULL and shaped as a padded base64url Ed25519 signature, so an unsigned artifact is unrepresentable at rest.",
  },
  {
    id: "NO_SEND_EXPIRY_COLUMN",
    sqlAnchor:
      "-- There is deliberately NO send expiry column here.",
    rule: "No SEND_EXTERNAL expiry column exists on the operation row and none may be added. The only authoritative redemption expiry is the signed inner expiry__unix_time_secs byte-frozen inside external_send_sign_intents.inner_preimage_text at sign-intent formation (SEND_REDEMPTION_WINDOW_SECS), never the payer-chosen RECEIVE expiry.",
  },
  {
    id: "SOURCE_WALLET_FK_AFTER_TARGET",
    sqlAnchor: "source_wallet_id uuid NOT NULL REFERENCES wallets (id),",
    rule: "The source reference is a real foreign key into the frozen wallets table. Prerequisite sequencing is explicit: custody-eligibility.sql declares wallets and must be applied EARLIER in the sequence, which is why this slice cannot apply greenfield alone.",
  },
];

// Obligations discharged only against a live database. Like the sibling receive slice, most
// are NOT deferred to the schema-apply phase: test/send-external-create-pg.test.ts provisions a hermetic scratch
// database, applies the real frozen DDL, and drills them.
export const SEND_EXTERNAL_CREATE_GN3_OBLIGATIONS: readonly string[] = [
  "DISCHARGED (test/send-external-create-pg.test.ts): a duplicate (implementer_id, http_method, route, idempotency_key) insert raises unique_violation 23505 on send_operations_idempotency_scope.",
  "DISCHARGED (test/send-external-create-pg.test.ts): a second unsettled send from one source wallet raises unique_violation 23505 on send_operations_one_unsettled_per_source_wallet, a terminal predecessor does not block a fresh send, and a status added to the vocabulary WITHOUT touching the index still blocks -- the fail-closed direction, drilled rather than asserted.",
  "DISCHARGED (test/send-external-create-pg.test.ts): a mathematically zero amount ('0.00') is rejected by send_operations_amount_positive with check_violation 23514.",
  "DISCHARGED (test/send-external-create-pg.test.ts): updating source_wallet_id, destination_address, amount_zkz or references_operation_id raises SEND_IMMUTABLE_FIELD_REJECTED, while a status advance succeeds.",
  "DISCHARGED (test/send-external-create-pg.test.ts): a second expected-artifact row for one operation raises unique_violation 23505, and updating or deleting an artifact row raises SEND_ARTIFACT_INSERT_ONLY.",
  "DEFERRED to the schema-apply phase: references_operation_id has no foreign key in this slice because the unified operations relation it points at is created by the schema-apply phase, not by this package.",
  "DEFERRED to the schema-apply phase: signing_key_id has no foreign key to node_signing_keys here; signing-key-registry.sql is a sibling slice and an FK needs its target EARLIER in the apply sequence, which would make this slice depend on two prerequisites instead of one.",
  "DEFERRED to the approval and sign-intent slices: the approval challenge, TOTP consumption, source lease, sign intent, and transfer code. None exists while the operation is CREATED.",
];
