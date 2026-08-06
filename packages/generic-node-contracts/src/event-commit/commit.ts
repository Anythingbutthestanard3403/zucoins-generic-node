// the events concern.2 — The atomic state-event-outbox commit contract. One guarded transaction allocates the
// gapless sequence (the gap-detection fact), constructs the exact preimage, signs, inserts the event row, updates
// the operation state, and enqueues delivery — with no unsigned gap. The whole unit commits together
// or rolls back together; a rollback burns no sequence (the gap-detection fact gapless guarantee).
//
// Governing contract: node_events data model (event row + operation transition in one transaction); canonical
// the frozen rule/the frozen rule. Consumes the gap-detection fact's ALLOCATION_STEP_ORDER / COHERENT_UNIT — the gap-detection fact wins on conflict.
// CONTRACT_FREEZE — no runtime transaction code.

// The full in-transaction step sequence (checklist). Its first five steps are exactly
// the gap-detection fact's ALLOCATION_STEP_ORDER; this slice appends the operation update and the outbox enqueue.
export const COMMIT_STEP_ORDER = [
  "lock_and_increment_counter",
  "read_previous_event_hash",
  "construct_exact_preimage_with_seq_and_prev_hash",
  "sign",
  "insert_event_row",
  "update_operation_state",
  "enqueue_outbox_delivery",
] as const;

export const INSERT_EVENT_STEP = "insert_event_row" as const;
export const SIGN_STEP = "sign" as const;

// The transactional coherence unit: every member commits together or rolls back together. Extends
// the gap-detection fact's COHERENT_UNIT (allocation, previous_hash, signing, state_transition, insertion) with the
// outbox enqueue, so the outbox entry is atomic with the event it advertises.
export const COMMIT_UNIT = [
  "allocation",
  "previous_hash",
  "signing",
  "state_transition",
  "insertion",
  "outbox_enqueue",
] as const;

// Atomicity + partial-failure semantics. A single guarded transaction; any step failing rolls back
// the whole unit, and because the counter increment is in the same transaction, a rollback burns no
// sequence (no permanent gap). There is never a committed event row without its signature: `sign`
// precedes `insert_event_row` inside the transaction.
export const ATOMICITY = {
  transaction: "single_guarded_transaction",
  semantics: "all_or_nothing",
  partialFailure: "rolls_back_whole_unit",
  rollbackBurnsSeq: false,
  unsignedGapPossible: false,
} as const;
