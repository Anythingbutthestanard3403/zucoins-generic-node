// receive expiry, attention and safe-terminal release.
// Receive expiry release: the expiry flow, the recovery release predicates, the receive
// barriers, the event ledger, and the attention hold.

export const RECEIVE_EXPIRY_RELEASE_SCHEMA_FILE = "receive-expiry-release.sql" as const;
export const RECEIVE_EXPIRY_RELEASE_EXTENDS = "operations.sql" as const;

export const RECEIVE_EXPIRY_RELEASE_INVARIANTS = [
  {
    id: "DURABLE_RELEASE_STATUS",
    sqlAnchor:
      "receive_release_status IN (\n        'RELEASED_T0_UNCHANGED',\n        'RELEASED_PROVEN_NOT_STARTED'\n      )",
    rule:
      "successful expiry-release statuses are RELEASED_T0_UNCHANGED and RELEASED_PROVEN_NOT_STARTED.",
  },
  {
    id: "PRE_CODE_RELEASE_PROOF",
    sqlAnchor: "operation_id uuid NOT NULL UNIQUE REFERENCES operations(id)",
    rule:
      "receive release proof ownership binds to operations(id) so pre-code releases and PROVEN_NOT_STARTED releases are representable.",
  },
  {
    id: "RELEASE_KIND_BICONDITIONAL",
    sqlAnchor: "EXPIRED_PROVEN_NOT_STARTED",
    rule:
      "release_kind is the VERIFICATION_COMPLETE / EXPIRED_T0_UNCHANGED / EXPIRED_PROVEN_NOT_STARTED triple with ack and observation-id biconditionals.",
  },
  {
    id: "ONE_EXPIRED_EVENT",
    sqlAnchor: "CREATE UNIQUE INDEX receive_expiry_events_one_per_operation",
    rule: "operation.expired is appended at most once for one receive.",
  },
  {
    id: "ONE_ATTENTION_EVENT_PER_EPISODE",
    sqlAnchor: "CREATE UNIQUE INDEX receive_expiry_attention_events_one_per_episode",
    rule: "operation.needs_attention is appended once for each durable attention episode.",
  },
  {
    id: "EVENTS_INSERT_ONLY",
    sqlAnchor: "CREATE FUNCTION receive_expiry_event_reject_mutation()",
    rule: "expiry and attention audit evidence cannot be updated or deleted.",
  },
] as const;

export type ReceiveExpiryReleaseInvariant =
  (typeof RECEIVE_EXPIRY_RELEASE_INVARIANTS)[number];

export const RECEIVE_EXPIRY_RELEASE_MUTABILITY_REGIMES = [
  {
    table: "receive_release_proofs",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
  },
  {
    table: "receive_expiry_events",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
  },
  {
    table: "receive_expiry_attention_events",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
  },
] as const;

export const SCHEMA_RECEIVE_EXPIRY_RELEASE_OBLIGATIONS = [
  "apply after operations.sql and observation-ledger.sql; this schema owns receive_release_proofs (parent operations(id); observation FKs nullable-ok).",
  "[pg] status and row_version CAS arbitrates expiry against landing.",
  "[pg] successful release co-commits release proof, exact-tuple active lease deletion, membership close, PINNED->AVAILABLE, release status and operation.expired.",
  "[pg] EXPIRED_PROVEN_NOT_STARTED requires null T0/fresh/ack and zero formation evidence; EXPIRED_T0_UNCHANGED requires both observation snapshots.",
  "[pg] every failed release predicate opens one attention episode and retains the active lease.",
  "[pg] wallet identity comes from wallet_active_leases plus operation_wallets RECEIVER, never operations.receiver_wallet_id.",
] as const;

export const RECEIVE_EXPIRY_RELEASE_SOURCE =
  "operation-flows: receive expiry release; operations-recovery: release predicates" as const;
