// Durable receive-arm acknowledgement: the receive barrier that proves the arm step
// committed. Governed by the receive barriers and the migration lock / classifier.
//
// Frozen inventory of the structural invariants carried by receive-arms.sql.
// Execution against a live database belongs to the schema-apply phase; nothing
// in this package opens a socket from this file. The census test binds every
// entry here to the literal SQL text, so inventory and schema contract cannot
// drift apart silently.
//
// Append-only regime: verification-proofs.sql installs
// reporting_arms_immutable and reporting_arms_no_truncate on receive_arms,
// and REVOKEs UPDATE/DELETE/TRUNCATE from node_runtime. That file may apply
// AFTER this one (or be re-applied idempotently); the duplicate trigger+REVOKE
// here is defensive — re-adding an identical trigger or REVOKE on an existing
// grant is a no-op.

export const RECEIVE_ARMS_SCHEMA_FILE = "receive-arms.sql" as const;
export const RECEIVE_ARMS_EXTENDS = "receive-codes.sql" as const;

export interface ReceiveArmsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const RECEIVE_ARMS_INVARIANTS: readonly ReceiveArmsInvariant[] = [
  {
    id: "ARM_PK",
    sqlAnchor: "id uuid PRIMARY KEY,",
    rule: "each arm acknowledgement carries a unique UUID primary key.",
  },
  {
    id: "ARM_ONE_PER_OPERATION",
    sqlAnchor: "operation_id uuid NOT NULL UNIQUE REFERENCES receive_codes(operation_id),",
    rule: "at most one arm acknowledgement per receive operation: UNIQUE(operation_id) enforces a second arm is a unique_violation.",
  },
  {
    id: "ARM_NODE_FK",
    sqlAnchor: "node_id uuid NOT NULL REFERENCES nodes(id),",
    rule: "every arm acknowledgement belongs to exactly one node.",
  },
  {
    id: "ARM_IMPLEMENTER_FK",
    sqlAnchor: "implementer_id uuid NOT NULL REFERENCES implementers(id),",
    rule: "every arm acknowledgement is owned by exactly one implementer.",
  },
  {
    id: "ARM_ROUTE_CLOSED_SET",
    sqlAnchor: "route_id text NOT NULL DEFAULT 'operation_armed' CHECK (route_id = 'operation_armed'),",
    rule: "the sole admitted route_id for arm acknowledgements is 'operation_armed'; a different route_id is a constraint violation.",
  },
  {
    id: "ARM_REPORTING_PURPOSE_CLOSED_SET",
    sqlAnchor: "reporting_purpose text NOT NULL DEFAULT 'zp-report-request-v1' CHECK (reporting_purpose = 'zp-report-request-v1'),",
    rule: "the sole admitted reporting_purpose for arm requests is 'zp-report-request-v1'.",
  },
  {
    id: "ARM_REQUEST_CLASS_CLOSED_SET",
    sqlAnchor: "request_class reporting_request_class NOT NULL DEFAULT 'MUTATION' CHECK (request_class = 'MUTATION'),",
    rule: "arm requests are always MUTATION class for the reporting nonce burn.",
  },
  {
    id: "ARM_RETENTION_CLASS_CLOSED_SET",
    sqlAnchor: "retention_class text NOT NULL DEFAULT 'PERMANENT_MUTATION' CHECK (retention_class = 'PERMANENT_MUTATION'),",
    rule: "arm rows are permanently retained (retention_class = 'PERMANENT_MUTATION'); no soft-delete or pruning path exists.",
  },
  {
    id: "ARM_METHOD_POST",
    sqlAnchor: "method text NOT NULL DEFAULT 'POST' CHECK (method = 'POST'),",
    rule: "the HTTP method for the arm nonce-burn request is always POST.",
  },
  {
    id: "ARM_T0_OBSERVATION_REQUIRED",
    sqlAnchor: "node_t0_observation_id uuid NOT NULL,",
    rule: "the node's T0 observation at arm-time is required before the arm row commits; the FK to gateway_observations is added by ALTER TABLE after CREATE TABLE so the CREATE block stays readable.",
  },
  {
    id: "ARM_ACK_BALANCE_POSITIVE",
    sqlAnchor: "acknowledged_b zkz_balance_text NOT NULL,",
    rule: "the balance acknowledged at arm-time is the canonical zkz_balance_text domain: 0 <= amount < 1e8.",
  },
  {
    id: "ARM_OPENED_CURSOR_NONNEGATIVE",
    sqlAnchor: "opened_cursor bigint NOT NULL CHECK (opened_cursor >= 0),",
    rule: "the observation cursor opened for this arm is non-negative.",
  },
  {
    id: "ARM_REPORTING_NONCE_UNIQUE",
    sqlAnchor: "reporting_nonce_id uuid NOT NULL UNIQUE,",
    rule: "the burned reporting nonce is referenced from exactly one arm row (parent-child 1:1 enforced by reporting-mutation-idempotency child_record_id).",
  },
  {
    id: "ARM_MUTATION_IDEMPOTENCY_UNIQUE",
    sqlAnchor: "mutation_idempotency_id uuid NOT NULL UNIQUE,",
    rule: "the completed reporting_mutation_idempotency row is referenced from exactly one arm row; DEFERRABLE INITIALLY DEFERRED allows the arm to be inserted before the idempotency row in the same transaction.",
  },
  {
    id: "ARM_COMPOSITE_TENANT_ROUTE_UNIQUE",
    sqlAnchor: "UNIQUE (node_id, implementer_id, route_id, method, raw_target, request_body_sha256),",
    rule: "two arms with the same (node_id, implementer_id, route_id, method, raw_target, request_body_sha256) are identical replays; the UNIQUE prevents a second arm row.",
  },
  {
    id: "ARM_OPERATION_TENANT_FK",
    sqlAnchor: "FOREIGN KEY (operation_id, node_id, implementer_id) REFERENCES operations(id, node_id, implementer_id),",
    rule: "the arm row's node_id and implementer_id must match the operation's (id, node_id, implementer_id) composite — a foreign-arm-attach is structurally impossible.",
  },
  {
    id: "ARM_REPORTING_NONCE_FK",
    sqlAnchor: "FOREIGN KEY (reporting_nonce_id, node_id, implementer_id, ...)",
    rule: "the arm row's reporting_nonce_id FK binds to reporting_request_nonces on the full composite (id, node_id, implementer_id, purpose, route_id, request_class, retention_class, method, raw_target, body_sha256, logical_fingerprint).",
  },
  {
    id: "ARM_INSERT_ONLY",
    sqlAnchor: "CREATE TRIGGER receive_arms_insert_only BEFORE UPDATE OR DELETE ON receive_arms FOR EACH ROW EXECUTE FUNCTION receive_arms_reject_mutation();",
    rule: "receive_arms rows are append-only; UPDATE and DELETE are structurally rejected.",
  },
  {
    id: "ARM_NO_TRUNCATE",
    sqlAnchor: "CREATE TRIGGER receive_arms_no_truncate BEFORE TRUNCATE ON receive_arms FOR EACH STATEMENT EXECUTE FUNCTION receive_arms_reject_mutation();",
    rule: "TRUNCATE on receive_arms is structurally rejected.",
  },
] as const;

export const RECEIVE_ARMS_MUTABILITY_REGIMES = [
  {
    table: "receive_arms",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
  },
] as const;

export const SCHEMA_RECEIVE_ARMS_OBLIGATIONS = [
  "apply after custody-eligibility.sql, operations.sql, receive-codes.sql, reporting-persistence.sql, and observation-ledger.sql; the FKs need those relations to exist EARLIER in the apply sequence.",
  "[pg] append-only: BEFORE UPDATE OR DELETE trigger + BEFORE TRUNCATE trigger reject all mutations; REVOKE UPDATE, DELETE, TRUNCATE FROM node_runtime.",
] as const;

export const RECEIVE_ARMS_SOURCE =
  "data-model: receive barriers" as const;
