// Submit attempts and retry authority: a single submit per attempt, the reference scalar
// check, and the receipt-only acknowledgement posture (status:true is receipt-only; landing
// oracle); the never-blind-retry rule (never blind-retry a submit).
//
// Frozen inventory of the structural single-shot submit invariants carried by
// submit-attempts.sql. The census test binds every entry here to
// the literal SQL text, so the inventory and the schema contract cannot drift apart.
// Execution against a live database belongs to the schema-apply phase, recorded below as
// obligations rather than silently omitted.
//
// closed the naming conflict this note used to report:
// custody-eligibility.sql declares wallets(id) to match. The relations are transcribed
// verbatim, so its FKs target operations(id) and operation_transactions(operation_id,
// attempt_no); what remains is execution sequence, not naming — those
// relations must exist before this file's tables.

export const SUBMIT_ATTEMPTS_SCHEMA_FILE = "submit-attempts.sql" as const;

export interface SubmitAttemptsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const SUBMIT_ATTEMPTS_INVARIANTS: readonly SubmitAttemptsInvariant[] = [
  {
    id: "DECISION_INITIAL_SINGLE_SHOT_ONLY",
    sqlAnchor: "decision text NOT NULL CHECK (decision = 'INITIAL_SINGLE_SHOT'),",
    rule: "the only representable decision is INITIAL_SINGLE_SHOT: any retry-authority decision literal is a constraint violation, not an application-level rejection — the never-blind-retry rule made structural.",
  },
  {
    id: "DECISION_TRANSACTION_ATTEMPT_ONE",
    sqlAnchor: "transaction_attempt_no integer NOT NULL CHECK (transaction_attempt_no = 1),",
    rule: "a decision binds exactly transaction attempt 1: a second transaction attempt is a constraint violation.",
  },
  {
    id: "DECISION_UNIQUE_PER_OPERATION_ATTEMPT",
    sqlAnchor: "UNIQUE (id, operation_id, transaction_attempt_no),\n  UNIQUE (operation_id, transaction_attempt_no),",
    rule: "at most one decision per (operation, transaction attempt): no second decision for the one immutable transaction attempt is representable.",
  },
  {
    id: "ATTEMPT_ONE_PER_DECISION",
    sqlAnchor: "decision_id uuid NOT NULL UNIQUE,",
    rule: "at most one gateway call per decision: decision_id is UNIQUE across gateway_submit_attempts, so a second call under the same authorization is a unique_violation.",
  },
  {
    id: "ATTEMPT_NO_POSITIVE",
    sqlAnchor: "attempt_no integer NOT NULL CHECK (attempt_no > 0),",
    rule: "gateway call attempt numbers are positive; combined with the composite uniqueness below, the single shot is the only representable call.",
  },
  {
    id: "ATTEMPT_UNIQUE_OPERATION_ATTEMPT_NO",
    sqlAnchor: "UNIQUE (operation_id, attempt_no),",
    rule: "DB-enforced non-reuse: a second gateway_submit_attempts row for the same (operation_id, attempt_no) is a unique_violation — the composite uniqueness permits at most one gateway call.",
  },
  {
    id: "ATTEMPT_UNIQUE_OPERATION_TRANSACTION_ATTEMPT_NO",
    sqlAnchor: "UNIQUE (operation_id, attempt_no),\n  UNIQUE (operation_id, transaction_attempt_no),",
    rule: "DB-enforced non-reuse: at most one gateway call for the one immutable transaction attempt — a second row for the same (operation_id, transaction_attempt_no) is a unique_violation even under a fresh decision id.",
  },
  {
    id: "ATTEMPT_OUTCOME_CLOSED_SET",
    sqlAnchor: "transport_outcome text NOT NULL CHECK (transport_outcome IN\n    ('ACK','REJECT','INDETERMINATE')),",
    rule: "the transport outcome is one of the three frozen categories: ACK (2xx receipt), REJECT (definite 4xx), INDETERMINATE (transport ambiguity / non-2xx-non-4xx) — no fourth outcome and no generic proven-not-landed category.",
  },
  {
    id: "ATTEMPT_ACK_RECEIPT_ONLY",
    sqlAnchor: "('ACK','REJECT','INDETERMINATE')),",
    rule: "ACK is receipt-only, never settlement: this table carries no landing or settlement column — landing is adjudicated only by the complete-path landing oracle (operation_landing_proofs), never by a transport acknowledgement.",
  },
  {
    id: "ATTEMPT_REQUEST_EVIDENCE_ALWAYS_PRESENT",
    sqlAnchor: "request_body bytea NOT NULL,\n  request_sha256 sha256_hex NOT NULL,",
    rule: "the exact request bytes POSTed and their SHA-256 are persisted on every attempt row: the evidence is the bytes themselves, never a reconstruction.",
  },
  {
    id: "ATTEMPT_RESPONSE_BYTES_IFF_DIGEST",
    sqlAnchor: "CHECK ((response_body IS NULL) = (response_sha256 IS NULL))",
    rule: "response bytes and their digest are set together or absent together: both are NULL exactly when transport ambiguity left no complete response to capture.",
  },
  {
    id: "ATTEMPT_FOREIGN_KEYED_TO_DECISION",
    sqlAnchor: "FOREIGN KEY (decision_id, operation_id, transaction_attempt_no)\n    REFERENCES submit_decisions(id, operation_id, transaction_attempt_no),",
    rule: "every gateway call is bound to exactly one persisted decision with matching operation and transaction attempt: an attempt without a decision, or with a mismatched one, is rejected before it exists.",
  },
] as const;

// Decision and submit rows are append-only. The conventions sanction append-only
// exact-content tables or byte-immutability triggers, and no trigger DDL is frozen, so
// the regime lives here as inventory plus a schema-apply obligation.
export const SUBMIT_ATTEMPTS_MUTABILITY_REGIMES = [
  {
    table: "submit_decisions",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "append-only: no column is updatable or deletable.",
  },
  {
    table: "gateway_submit_attempts",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "append-only: no column is updatable or deletable; the transport outcome and captured bytes are frozen at insert.",
  },
] as const;

// Live-database proofs this package cannot run (no database harness lands in this package). The schema-apply phase MUST discharge each of these against a
// real Postgres before the schema contract is considered enforced.
export const SCHEMA_SUBMIT_ATTEMPTS_OBLIGATIONS = [
  "execution sequence: create the FK target relations (operations, operation_transactions) and the sha256_hex domain before this file's tables; the custody wallets(wallet_id) naming conflict this obligation used to carry is closed, so only the execution sequence below remains to be honoured.",
  "guards: install BEFORE UPDATE/DELETE enforcement for the two append-only regimes (the conventions sanction byte-immutability triggers; no trigger DDL is frozen in this file).",
  "negative: a second gateway_submit_attempts row for the same (operation_id, attempt_no) is rejected with unique_violation (23505) — DB-enforced non-reuse of the gateway call slot.",
  "negative: a second gateway_submit_attempts row for the same (operation_id, transaction_attempt_no) is rejected with unique_violation even under a fresh decision_id — at most one gateway call for the one immutable transaction attempt.",
  "negative: a second submit_decisions row for the same (operation_id, transaction_attempt_no) is rejected with unique_violation — no second decision is representable.",
  "negative: decision = 'RETRY_AFTER_TRANSPORT_FAILURE' (any literal other than INITIAL_SINGLE_SHOT) is rejected by the column CHECK, and transaction_attempt_no = 2 is rejected by its CHECK.",
  "negative: transport_outcome outside ('ACK','REJECT','INDETERMINATE') — e.g. a legacy proven-not-landed literal — is rejected by the column CHECK.",
  "negative: response_body set with response_sha256 NULL (and the converse) is rejected by the biconditional CHECK.",
  "negative: a gateway_submit_attempts row whose decision_id is absent from submit_decisions is rejected by the composite foreign key, and a second row referencing an existing decision_id violates decision_id UNIQUE.",
  "application-level: the node never creates a submit attempt for the external-send operation kind — enforced at the operation-kind boundary that authorizes decisions, not by this table's constraints; the schema-apply phase must prove no code path inserts one.",
] as const;

export const SUBMIT_ATTEMPTS_SOURCE =
  "data-model: submit attempts and retry authority; the never-blind-retry rule" as const;
