// the events concern.2 — The DDL constraint manifest: the load-bearing schema constraints that ENFORCE the atomic
// state-event-outbox commit at the database layer. This slice does NOT define the `node_events` table
// (that is the node_events data model, built under the event-sequencing slice) — it enumerates, as a constraint manifest, the
// schema guarantees the commit contract depends on, so a future schema edit cannot silently weaken
// atomicity, gaplessness, or idempotency. The canonical the events concern.2 acceptance calls for "transaction
// and constraint manifests"; this is the constraint half.
//
// Governing contract: `node_events` DDL; event signing; durable events. CONTRACT_FREEZE — a
// constraint manifest, not a migration (migrations belong to the BUILD_BLOCKED the named concern.x tickets).

export const DDL_CONSTRAINTS = {
  // The event insert and the operation-state UPDATE execute in ONE transaction ("the event row
  // and the operation status transition commit in the same transaction"). The outbox enqueue is
  // in that SAME transaction (transactional outbox), but the outbox is a store SEPARATE from neutral
  // truth (the named concern: "delivery cursors and attempts separately from neutral truth"), so delivery state
  // can never mutate a committed event or operation row.
  eventAndStateSameTransaction: true,
  outboxEnqueuedInSameTransaction: true,
  outboxSeparateFromNeutralTruth: true,
  // `seq` comes from the dedicated per-node counter, NOT `GENERATED ALWAYS AS IDENTITY` — the earlier
  // draft posture the gap-detection fact rejected against the frozen rule (an identity value is allocated at insert and burns
  // on rollback, leaving a gap that freezes the cursor).
  seqSource: "dedicated_per_node_counter",
  seqRejectedSource: "generated_always_as_identity",
  // Idempotent redelivery is enforced structurally: a redelivered insert collides on these UNIQUE
  // constraints (`event_id ... UNIQUE`, `event_hash ... UNIQUE`), so a duplicate committed
  // event is impossible at the schema layer.
  uniqueEventId: true,
  uniqueEventHash: true,
  // Neutral truth is insert-only: event (and audit) rows reject UPDATE/DELETE (events "are never
  // edited or deleted"; the named concern acceptance), so a committed event's signed bytes can never be rewritten.
  eventsInsertOnly: true,
} as const;
