// Receive admission: the request-admission row, custody and one-active-lease
// (the one-in-flight-per-wallet rule), the idempotency record, the receive queue, and the canonical ZKZ
// amount contract.
//
// Frozen inventory of the structural invariants carried by receive-admission.sql
// the admission-time RECEIVE_EXTERNAL row that doubles as the
// idempotency record. Execution against a live database belongs to the schema-apply phase;
// the two money-path invariants this slice exists to guarantee -- the idempotency scope
// uniqueness and the one-in-flight-per-wallet one-unsettled-receive-per-wallet index -- are additionally
// drilled against a real PostgreSQL by test/receive-admission-pg.test.ts, so neither can be
// satisfied by an in-memory fake alone.

export const RECEIVE_ADMISSION_SCHEMA_FILE = "receive-admission.sql" as const;

export interface ReceiveAdmissionInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const RECEIVE_ADMISSION_INVARIANTS: readonly ReceiveAdmissionInvariant[] = [
  {
    id: "AMOUNT_POSITIVE_CHECK",
    sqlAnchor:
      "CONSTRAINT receive_operations_amount_positive\n    CHECK (amount_zkz ~ '^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$' AND amount_zkz::numeric > 0)",
    rule: "The canonical ZKZ amount bound is enforced at rest by a CHECK, not by application validation alone. Numeric positivity closes the zero-form bypass ('0.0', '0.00', '0.' + 32 zeros) that string positivity leaves open. Column CHECK rather than CREATE DOMAIN because base-enums-domains.sql already declares zkz_amount_positive_text.",
  },
  {
    id: "IDEMPOTENCY_FULL_TUPLE_UNIQUE",
    sqlAnchor:
      "CONSTRAINT receive_operations_idempotency_scope\n    UNIQUE (implementer_id, http_method, route, idempotency_key)",
    rule: "The idempotency scope is the FULL (implementer_id, HTTP method, canonical route, idempotency_key) tuple and is enforced by a database UNIQUE constraint. Concurrent first use of one key yields exactly one inserter; every follower gets unique_violation (23505) rather than a second operation row.",
  },
  {
    id: "REQUEST_HASH_REQUIRED",
    sqlAnchor: "request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),",
    rule: "The SHA-256 of the exact validated canonical request object is stored with the idempotency record, so same key + different hash is 409 idempotency_key_reused instead of a silent replay of a different request's operation.",
  },
  {
    id: "IN_PROGRESS_MARKER_IS_THE_ROW",
    sqlAnchor:
      "CONSTRAINT receive_operations_completion_together\n    CHECK ((completed_at IS NULL) = (response_status IS NULL)\n           AND (completed_at IS NULL) = (response_body IS NULL)),",
    rule: "The in-progress marker is the row itself while completed_at IS NULL, held under the idempotency UNIQUE constraint. Status and exact response body from the first completed execution are stored together or not at all, so a half-written completion cannot be replayed as authoritative.",
  },
  {
    id: "GOLDEN_RULE_2_DESTINATION_INDEX",
    sqlAnchor:
      "CREATE UNIQUE INDEX receive_operations_one_unsettled_per_destination\n  ON receive_operations (destination_wallet_id)\n  WHERE destination_wallet_id IS NOT NULL AND status IN ('CREATED', 'READY');",
    rule: "The one-in-flight-per-wallet rule, structural: a second unsettled receive naming the same INTERNAL_MOVE destination wallet is rejected by the database with unique_violation. The guarantee does not depend on an application read that races the insert following it.",
  },
  {
    id: "GOLDEN_RULE_2_RECEIVER_INDEX",
    sqlAnchor:
      "CREATE UNIQUE INDEX receive_operations_one_unsettled_per_wallet\n  ON receive_operations (wallet_id)\n  WHERE wallet_id IS NOT NULL AND status IN ('CREATED', 'READY');",
    rule: "The one-in-flight-per-wallet rule over the receiver wallet the assignment slice stamps onto the row: both wallet references a receive row can hold are covered, so neither wallet can carry two unsettled receives.",
  },
  {
    id: "NON_TERMINAL_STATES_ARE_ALLOWLIST_POSITIVE",
    sqlAnchor: "WHERE destination_wallet_id IS NOT NULL AND status IN ('CREATED', 'READY');",
    rule: "The unsettled predicate is the POSITIVE non-terminal state list, not the complement of a terminal blocklist: a status added to the frozen vocabulary without updating this index is denied by default (fail-closed) rather than silently admitted.",
  },
  {
    id: "NO_RECEIVER_WHILE_CREATED",
    sqlAnchor:
      "CONSTRAINT receive_operations_no_receiver_while_created\n    CHECK (status <> 'CREATED' OR wallet_id IS NULL),",
    rule: "Admission exit invariant: no receiver address exists while an unassigned receive is CREATED. Admission can never stamp a wallet onto the row.",
  },
  {
    id: "AFTER_LANDING_DESTINATION_IFF",
    sqlAnchor:
      "CONSTRAINT receive_operations_destination_iff\n    CHECK ((after_landing_kind = 'INTERNAL_MOVE') = (destination_id IS NOT NULL)),",
    rule: "A-canonical-fields SSA.2: a destination exists exactly when after_landing.kind is INTERNAL_MOVE. A HOLD carrying a destination, or an INTERNAL_MOVE without one, is unrepresentable.",
  },
  {
    id: "DESTINATION_FK_AFTER_TARGET",
    sqlAnchor:
      "ALTER TABLE receive_operations\n  ADD CONSTRAINT receive_operations_destination_fk\n  FOREIGN KEY (destination_id)\n  REFERENCES destinations (id);",
    rule: "The destination reference is a real foreign key into the frozen destinations table, added after the table exists. Prerequisite sequencing is explicit: custody-eligibility.sql declares wallets and destinations and must be applied EARLIER in the sequence, which is why this slice cannot apply greenfield alone.",
  },
];

// Obligations discharged against a live database by test/receive-admission-pg.test.ts, plus
// the single ticket-agreed carve-out for the lease-group surface owned by a sibling ticket.
export const RECEIVE_ADMISSION_GN3_OBLIGATIONS: readonly string[] = [
  "DISCHARGED (test/receive-admission-pg.test.ts): a duplicate (implementer_id, http_method, route, idempotency_key) insert raises unique_violation 23505 on receive_operations_idempotency_scope.",
  "DISCHARGED (test/receive-admission-pg.test.ts): a second unsettled receive naming one destination wallet raises unique_violation 23505 on receive_operations_one_unsettled_per_destination, and a terminal predecessor does not block a fresh receive.",
  "DISCHARGED (test/receive-admission-pg.test.ts): a mathematically zero amount ('0.00') is rejected by receive_operations_amount_positive with check_violation 23514.",
  "DISCHARGED (test/receive-admission-pg.test.ts): the queue-depth statement counts exactly this node's unassigned CREATED receives, so the RECEIVE_QUEUE_CAP admission gate reads a real depth.",
  // Deliberate carve-out: do not build lease_group_id /
  // subscription-handle here — the lease-group table is / assignment by.
  "OUT_OF_SCOPE: lease_group_id and the subscription-handle hash written by the assignment DB-TX belong to the assignment slice that owns the lease-group table; this admission slice creates the RECEIVE_EXTERNAL/CREATED row only.",
];
