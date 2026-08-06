// The gapless event-sequence ALLOCATION contract. A naive
// `seq bigint GENERATED ALWAYS AS IDENTITY` is rejected: an identity/bigserial column
// allocates its value at insert and a rolled-back transaction burns that value permanently, leaving
// a gap that freezes the cursor and causes silent stall + silent data loss past 500 rows. The
// canonical fix is a dedicated per-node counter row incremented in the SAME transaction as the event
// insert, so a rollback un-does the increment — the sequence stays contiguous and gapless.
// The consumer cursor tracks this dedicated sequence. CONTRACT_FREEZE — no runtime allocation code.

// The frozen allocation model: a dedicated single-row per-node counter, transactionally serialized
// with the event insert, monotonic, gapless (rollback-safe), and durable-before-visible.
export const ALLOCATION_MODEL = {
  source: "per_node_gapless_counter_allocated_pre_sign",
  storage: "dedicated_single_row_counter_table_per_node",
  serialization: "same_transaction_as_event_insert",
  monotonic: true,
  gapless: true,
  rollbackSafe: true,
  durableBeforeVisible: true,
  countersPerNode: 1,
} as const;

// Rejected allocation mechanisms, kept as data so a future edit cannot silently reintroduce a
// rollback-gapped or chain-breaking source. The census test asserts none is the frozen source and
// that the naive identity posture is explicitly named as rejected.
export const REJECTED_ALLOCATIONS = [
  {
    mechanism: "generated_always_as_identity",
    reason: "allocates at insert; a rolled-back txn burns the value → permanent gap",
  },
  { mechanism: "bigserial", reason: "same rollback-gap failure as identity" },
  { mechanism: "serial", reason: "same rollback-gap failure as identity" },
  { mechanism: "uuid_or_random", reason: "not monotonically increasing; no gapless cursor" },
  { mechanism: "per_tenant_counter", reason: "fragments the node-global hash chain" },
  { mechanism: "audit_log_id", reason: "payload metadata only; the cursor tracks the dedicated seq" },
] as const;

// Bind-before-sign: the sequence and previous_event_hash are bound into the exact preimage BEFORE the
// Ed25519 signature, so the signature covers them and a signed event can never be re-sequenced. Both
// fields live in the signed node-event tuple (seq is field 5, previous_event_hash field 10).
export const ALLOCATION_STEP_ORDER = [
  "lock_and_increment_counter",
  "read_previous_event_hash",
  "construct_exact_preimage_with_seq_and_prev_hash",
  "sign",
  "insert_event_row",
] as const;

export const SIGN_STEP = "sign" as const;
export const BIND_STEPS = ["lock_and_increment_counter", "read_previous_event_hash"] as const;

// Transactional coherence: allocation, previous hash, signing, state
// transition, and insertion commit together or roll back together. This module freezes the coherence
// invariant and the allocation half; the full atomic state-event-outbox step sequence lives in
// the event-commit concern.
export const COHERENT_UNIT = [
  "allocation",
  "previous_hash",
  "signing",
  "state_transition",
  "insertion",
] as const;
