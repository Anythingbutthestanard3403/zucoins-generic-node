// the events concern.2 — Restart/recovery + key-rotation contract for the atomic commit unit.
//
// RESTART: an in-flight (uncommitted) commit is rolled back whole — no event row, no outbox entry, no
// operation transition, and NO burned seq (the counter increment rolls back with its transaction, the
// the gap-detection fact gapless guarantee). On restart the counter resumes from the durable high-water mark and
// never reuses a seq (the gap-detection fact RESTART_INVARIANTS, writer side). A committed-but-undelivered outbox
// entry survives the restart and is redelivered idempotently post-commit — never re-signed, never
// re-sequenced (the committed preimage/signature/seq/event_hash are immutable).
//
// KEY_ROTATION mid-stream: rotating the node event-signing key does NOT reset the counter (seq stays
// monotonic across the boundary) and NEVER re-signs already-committed events — their preimage_text,
// signature, and event_hash are immutable ("serving the event never reconstructs or changes
// preimage_text"). The A.6 preimage tuple is UNCHANGED by rotation because the key identifier (wire
// `key_id` <-> `node_events.signing_key_id`) lives OUTSIDE the signed object, so no
// signed byte depends on which key signed. The previous_event_hash chain is therefore continuous
// across the key boundary regardless of signer. The prior key is retired by SEQ-CURSOR — after the
// consumer cursor passes the last seq the prior key signed (the pull-cursor authority rule) — NOT by the frozen rule's "first batch
// verified" rule, which stalls a chained stream and is explicitly rejected for the v2 event stream.
//
// Governing contract: node_events data model; event signing; event serving; canonical the pull-cursor authority decision. Consumes the gap-detection fact's
// RESTART_INVARIANTS. CONTRACT_FREEZE — no runtime transaction code.

export const RESTART_COMMIT = {
  uncommittedCommitLeavesEvent: false,
  uncommittedCommitLeavesOutboxEntry: false,
  uncommittedCommitTransitionsOperation: false,
  uncommittedCommitBurnsSeq: false,
  counterResumesFrom: "durable_high_water_mark",
  reusesSeq: false,
  committedUndeliveredOutboxRedelivered: true,
  redeliveryReSigns: false,
} as const;

export const KEY_ROTATION = {
  resetsCounter: false,
  seqMonotonicAcrossRotation: true,
  reSignsCommittedEvents: false,
  preimageTupleChangedByRotation: false,
  keyIdInSignedPreimage: false,
  hashChainContinuousAcrossRotation: true,
  priorKeyRetiredBy: "seq_cursor",
  rejectedRetirement: "first_batch_verified",
} as const;
