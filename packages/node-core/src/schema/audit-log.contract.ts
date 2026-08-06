// Audit log: the reference scalar checks, the audit_log table, permanent append-only
// retention, and the append-only triggers that reject update and delete.
//
// Frozen inventory of the structural audit-trail invariants carried by audit-log.sql:
// the audit_log table every money-state transition, lease acquisition/release,
// approval burn, signature formation, delivery, submit decision, observation anomaly,
// destination blessing/retirement, recovery verification, and operator resolution lands in.
// The census test binds every entry here to the literal SQL text, so the inventory and the
// schema contract cannot drift apart. Execution against a live database belongs to the
// schema-apply phase, recorded below as obligations rather than silently omitted.
//
// The audit table is transcribed verbatim, so its FKs target nodes(id), operations(id), and
// wallets(id), and custody-eligibility.sql declares wallets(id) to match. What remains is
// execution sequence / domain prerequisites, not naming -- those relations and the
// sha256_hex domain must exist before this file's table.

export const AUDIT_LOG_SCHEMA_FILE = "audit-log.sql" as const;

export interface AuditLogInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const AUDIT_LOG_INVARIANTS: readonly AuditLogInvariant[] = [
  {
    id: "AUDIT_SEQ_IDENTITY",
    sqlAnchor: "seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,",
    rule: "audit rows are globally sequenced by a monotonic identity column: this is the audit log's own sequence only -- the reporting cursor tracks the node_events seq, never audit_log.seq/id, so a rolled-back audit insert burning an identity value gaps the audit sequence alone and never the reporting stream.",
  },
  {
    id: "AUDIT_ID_UNIQUE",
    sqlAnchor: "id uuid NOT NULL UNIQUE,",
    rule: "every audit entry carries a stable unique id: downstream evidence (e.g. an operator approval) references a specific audit entry by id, never by sequence position.",
  },
  {
    id: "AUDIT_NODE_SCOPED",
    sqlAnchor: "node_id uuid NOT NULL REFERENCES nodes(id),",
    rule: "every audit entry is bound to the node it occurred on: the node and platform instantiate this logical schema without sharing rows.",
  },
  {
    id: "AUDIT_ACTOR_KIND_CLOSED_SET",
    sqlAnchor:
      "actor_kind text NOT NULL CHECK (actor_kind IN\n    ('SYSTEM','OPERATOR_SESSION','ACTION_KEY','DEVICE_KEY','IMPLEMENTER')),",
    rule: "the actor kind is one of the five frozen categories: SYSTEM, OPERATOR_SESSION, ACTION_KEY, DEVICE_KEY, IMPLEMENTER -- no sixth actor kind is representable.",
  },
  {
    id: "AUDIT_ACTOR_ID_NULLABLE",
    sqlAnchor: "actor_id text,",
    rule: "the actor id is nullable: a SYSTEM actor has no external identity, while session/key/device/implementer actors carry their identifying text.",
  },
  {
    id: "AUDIT_ACTION_REQUIRED",
    sqlAnchor: "action text NOT NULL,",
    rule: "every audit entry records the action that occurred: an audit row without an action is not representable.",
  },
  {
    id: "AUDIT_TYPED_TARGETS",
    sqlAnchor: "operation_id uuid REFERENCES operations(id),\n  wallet_id uuid REFERENCES wallets(id),",
    rule: "the audited target is typed by foreign key -- an operation and/or a wallet -- rather than a free-text target pair: the targets are real rows, structurally bound.",
  },
  {
    id: "AUDIT_DETAILS_EXACT_PLUS_DIGEST",
    sqlAnchor: "details_text text NOT NULL,\n  details_sha256 sha256_hex NOT NULL,",
    rule: "the exact audit-details JSON text and its SHA-256 are persisted together : the details survive round-trip as exact bytes plus digest, never a reconstruction.",
  },
  {
    id: "AUDIT_CREATED_AT_REQUIRED",
    sqlAnchor: "created_at timestamptz NOT NULL,",
    rule: "every audit entry carries its creation timestamp: the trail is sequenced by an explicit, writer-supplied instant.",
  },
  {
    id: "AUDIT_COMPOSITE_ID_NODE_UNIQUE",
    sqlAnchor: "UNIQUE (id, node_id)",
    rule: "the (id, node_id) pair is unique: downstream composite foreign keys (e.g. reporting_key_bootstrap_evidence.operator_approval_audit_id) reference an audit entry by (id, node_id), so cross-node attachment is rejected before it exists.",
  },
  {
    id: "AUDIT_APPEND_ONLY_UPDATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER audit_log_no_update\n  BEFORE UPDATE ON audit_log\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "an audit entry cannot be rewritten by ANY connection (retention: audit log permanent, append-only): the engine, not the application, refuses UPDATE. This is the anti-forensics permanence guarantee, which insert-only application discipline alone does not provide.",
  },
  {
    id: "AUDIT_APPEND_ONLY_DELETE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER audit_log_no_delete\n  BEFORE DELETE ON audit_log\n  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "an audit entry cannot be removed (retention: no nonce, idempotency, enrolment, lifecycle, event, or audit evidence may be pruned while held): deletion of the forensic trail is refused at the engine, so a retention path cannot quietly prune it.",
  },
  {
    id: "AUDIT_APPEND_ONLY_TRUNCATE_GUARD",
    sqlAnchor:
      "CREATE TRIGGER audit_log_no_truncate\n  BEFORE TRUNCATE ON audit_log\n  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();",
    rule: "TRUNCATE does not fire row-level DELETE triggers, so a statement-level BEFORE TRUNCATE guard is required or the whole trail stays removable in one statement -- append-only would hold row by row and fail table-wide.",
  },
  {
    id: "AUDIT_APPEND_ONLY_REJECTOR_IS_THE_DOC_FUNCTION",
    sqlAnchor:
      "CREATE FUNCTION reporting_reject_immutable_change()\nRETURNS trigger LANGUAGE plpgsql\nAS $$\nBEGIN\n  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP\n    USING ERRCODE = '55000';\nEND\n$$;",
    rule: "the rejector is the canonical reporting_reject_immutable_change transcribed VERBATIM, ERRCODE '55000' included: the canonical append-only rejector is consumed, never re-invented under a second name (a parallel definition of an existing schema concept is the defect class this anchor exists to prevent).",
  },
] as const;

// Actor-kind vocabulary: the single source of truth the census binds the SQL
// actor_kind CHECK literals to, so the schema and the frozen actor taxonomy cannot drift.
export const AUDIT_LOG_ACTOR_KINDS = [
  "SYSTEM",
  "OPERATOR_SESSION",
  "ACTION_KEY",
  "DEVICE_KEY",
  "IMPLEMENTER",
] as const;

// Audit details never carry key material or credentials. The schema itself has no
// column for any of these categories; the census asserts their literal absence from the
// DDL. Content-level scrubbing of details_text is an application-boundary obligation
// recorded as a schema-apply obligation below.
export const AUDIT_LOG_FORBIDDEN_SECRET_TOKENS = [
  "private_key",
  "totp",
  "secret",
  "authorization",
  "vault",
] as const;

// Retention records the signed node event / audit log as permanent and append-only, and the
// append-only triggers must reject update and delete. The schema conventions sanction
// append-only exact-content tables or byte-immutability triggers; audit-log.sql lands the
// trigger form, so the regime below is enforced by the engine rather than carried as
// inventory plus a deferred obligation.
export const AUDIT_LOG_MUTABILITY_REGIMES = [
  {
    table: "audit_log",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "append-only (permanent retention): no column is updatable or deletable; an audit entry is frozen at insert and is never rewritten or pruned while held. Enforced by the BEFORE UPDATE / DELETE / TRUNCATE triggers in audit-log.sql, executed against a live PostgreSQL by test/evidence-append-only.pg.test.ts.",
  },
] as const;

// Live-database proofs this package cannot run (no database harness lands in node-core;
// network containment forbids a live PG socket in-package). The schema-apply phase
// MUST discharge each of these against a real Postgres before the schema contract is
// considered enforced.
export const SCHEMA_AUDIT_LOG_OBLIGATIONS = [
  "execution sequence: create the FK target relations (nodes, operations, wallets) and the sha256_hex domain before this file's table; the custody wallets(wallet_id) naming conflict this obligation used to carry is closed -- custody-eligibility.sql declares wallets(id) -- so only the execution sequence and domain prerequisites remain to be honoured.",
  "guards (DISCHARGED): the BEFORE UPDATE / DELETE / TRUNCATE triggers making audit_log append-only now ship in audit-log.sql and are executed against a live PostgreSQL by test/evidence-append-only.pg.test.ts, so no audit entry can be rewritten or deleted by any connection.",
  "negative (DISCHARGED): an UPDATE, DELETE, or TRUNCATE against audit_log is rejected with SQLSTATE 55000 by the append-only triggers.",
  "negative: actor_kind outside ('SYSTEM','OPERATOR_SESSION','ACTION_KEY','DEVICE_KEY','IMPLEMENTER') is rejected by the column CHECK.",
  "negative: a malformed details_sha256 value is rejected by the sha256_hex domain.",
  "negative: a duplicate id is rejected by id UNIQUE, and a duplicate (id, node_id) is rejected by the composite UNIQUE (23505).",
  "downstream: reporting_key_bootstrap_evidence takes a composite FK (operator_approval_audit_id, node_id) REFERENCES audit_log(id, node_id) -- the schema-apply phase must create audit_log before that table so the composite reference resolves.",
  "secret-free content: details_text is scrubbed at the application boundary and never carries a private key, TOTP code/secret, session secret, unredacted authorization header, or decrypted vault material; the schema-apply phase and the writing code paths must prove the scrubbing -- the schema's column absence is necessary but not sufficient.",
] as const;

export const AUDIT_LOG_SOURCE = "data-model: audit log" as const;
