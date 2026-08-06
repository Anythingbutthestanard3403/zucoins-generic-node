// the events concern.2 — Outbox delivery decoupling and the idempotent-redelivery contract. The outbox entry is
// enqueued INSIDE the commit transaction (atomic with the event), but delivery runs AFTER commit; a
// delivery failure never mutates the committed unit, and a redelivered event is byte-identical.
//
// Governing contract: node_events data model; event-pull API (event delivery is a cursor accelerator, not the ledger). Canonical
// the frozen rule/the frozen rule. CONTRACT_FREEZE.

// The outbox is enqueued transactionally with the event but delivered post-commit. An event/outbox
// entry is visible to consumers only after the transaction commits durably (durable-before-visible,
// the gap-detection fact). A delivery failure retries the outbox only; it never mutates the committed event row
// operation state, or sequence — those are immutable once committed.
export const OUTBOX_DECOUPLING = {
  enqueuedInsideTransaction: true,
  deliveryAfterCommit: true,
  visibleOnlyPostCommit: true,
  deliveryFailureMutatesCommittedUnit: false,
} as const;

// Redelivery is idempotent: the committed preimage, signature, seq, and event_hash never change, so
// a redelivered event is byte-identical. Consumers dedup by these stable keys; redelivery never
// re-signs or re-sequences.
export const IDEMPOTENT_REDELIVERY = {
  dedupKeys: ["event_id", "event_hash", "seq"],
  redeliveryReSigns: false,
  redeliveryReSequences: false,
  consumerDedup: "by_event_id_or_event_hash",
} as const;
