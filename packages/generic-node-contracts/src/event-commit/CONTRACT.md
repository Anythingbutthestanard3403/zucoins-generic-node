# event-commit — CONTRACT

Freeze slice: **freeze the atomic state-event-outbox transaction contract** (part of the events
group, depends on the event-sequencing slice). Gate: `CONTRACT_FREEZE`.

Governing sources: the data model's event ledger (the event row and operation status transition
commit in the same transaction), canonical fields A.6 (the `zp-node-event-v1` signed tuple), the
state-event reference 6.1 (the exact proof envelope; the wire `key_id` lives outside the signed
object), the API contract's event delivery (a cursor accelerator, not the ledger). Decisions:
`signed-event-log` / `sealed-store` (gapless counter, cursor, key lifetime) and `reporting-channel`
(event-key rotation retires the prior key by seq-cursor). Consumes the event-sequencing slice —
event-sequencing wins on conflict.

## Scope boundary

Under CONTRACT_FREEZE this slice freezes the CONTRACT that the guarded transaction must satisfy
and builds no runtime transaction code.

## What is frozen

- **`commit.ts` — `COMMIT_STEP_ORDER`.** The full in-transaction sequence: lock+increment counter →
  read previous_event_hash → construct exact preimage (seq + prev-hash) → sign → insert event row →
  update operation state → enqueue outbox delivery. Its first five steps are exactly
  event-sequencing's `ALLOCATION_STEP_ORDER`; this slice appends the operation update and the
  outbox enqueue. `sign` precedes `insert_event_row`, so no committed event is ever unsigned (no
  unsigned gap).
- **`COMMIT_UNIT` + `ATOMICITY`.** The transactional coherence unit (allocation, previous_hash,
  signing, state_transition, insertion, outbox_enqueue) commits together or rolls back together. A
  partial failure rolls back the whole unit; because the counter increment is in the same
  transaction, a rollback burns no sequence — the event-sequencing gapless guarantee holds.
- **`outbox.ts` — `OUTBOX_DECOUPLING`.** The outbox entry is enqueued inside the transaction (atomic
  with the event) but delivered post-commit; an event/outbox entry is visible to consumers only after
  commit (durable-before-visible); a delivery failure retries the outbox only and never
  mutates the committed event row, operation state, or sequence.
- **`IDEMPOTENT_REDELIVERY`.** The committed preimage, signature, seq, and event_hash never change,
  so a redelivered event is byte-identical; consumers dedup by `event_id` / `event_hash` / `seq`;
  redelivery never re-signs or re-sequences.
- **`concurrency.ts` — `CONCURRENCY`.** Concurrent full commits serialize on the counter increment
  (event-sequencing step 1), so exactly one writer wins each seq, no two committed events share a
  seq, the loser proceeds on the next seq, and the sequence is contiguous under contention; no
  concurrent reader observes a half-built event (durable-before-visible).
- **`recovery.ts` — `RESTART_COMMIT`.** An uncommitted commit leaves no event, no outbox entry, no
  operation transition, and burns no seq; the counter resumes from the durable high-water without
  reusing a seq; a committed-but-undelivered outbox entry redelivers idempotently.
- **`recovery.ts` — `KEY_ROTATION`.** Rotating the event-signing key never resets the counter, never
  re-signs a committed event, and leaves the A.6 preimage tuple and the previous_event_hash chain
  unchanged — the wire `key_id` is outside the signed object (A.6 / state-event reference 6.1), so
  no signed byte depends on which key signed. The prior key is retired by **seq-cursor**, never by
  the rejected "first batch verified" rule from the earlier reporting-ingest-auth posture.
- **`ddl.ts` — `DDL_CONSTRAINTS`.** The constraint-manifest half of the acceptance. It does NOT define
  `node_events` (that is the data model's event-ledger section, built in the schema-migration
  slices); it names the load-bearing constraints the commit depends on: event insert + operation
  update in one transaction; the outbox a store separate from neutral truth; `seq` from the
  dedicated per-node counter (never `GENERATED ALWAYS AS IDENTITY`, the posture `signed-event-log`
  rejects); `event_id` / `event_hash` UNIQUE (idempotency); insert-only truth.

## Vectors

`__vectors__/commit.vectors.json` is the executable rollback/concurrency/restart/rotation vector set
the acceptance calls for. Each vector feeds a model to its class verifier and pins
the required verdict; `vectors.test.ts` drives them. Classes: concurrency, rollback, restart, rotation,
ddl, state_transition, previous_hash — each with at least one negative (rejecting) case.

## Consuming event-sequencing

The freeze test asserts `COMMIT_STEP_ORDER` begins with event-sequencing's exact
`ALLOCATION_STEP_ORDER` prefix (extends, never reorders), and that `COMMIT_UNIT` is a superset of
event-sequencing's `COHERENT_UNIT` plus the outbox. Any drift from event-sequencing fails here.

## Scope handoff + negatives

CONTRACT_FREEZE only — the frozen transaction/constraint manifests plus executable contract vectors,
no runtime transaction code and no migration (migrations belong to the schema-migration slices). This
slice publishes the concurrency/rollback/restart/rotation **contract vectors and structural
verifiers**; the sibling **sequence-recovery** slice consumes the same verifiers for the exhaustive
runtime race/crash/replay proof. Negatives are present and demonstrated
to fire for every fact class — burned-seq-on-rollback, event-visible-before-commit, unsigned gap,
delivery-mutates-committed, non-idempotent redelivery, two-events-share-seq, restart-reuses-seq,
rotation-re-signs, rotation-retires-by-first-batch, outbox-not-separate, event-insert-without-state-
transition, and mixed-previous-hash.
