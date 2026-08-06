# event-sequencing — CONTRACT

Freeze slice: **gapless event sequence allocation**. Gate: `CONTRACT_FREEZE`.

Governing sources: the data model: `node_events`; A.6 (the signed node-event tuple); the API
contract: events cursor. Canonical: `gapless-counter-allocation` (node-local gapless monotonic
counter, Option A) and `cursor-tracks-dedicated-sequence` (the cursor tracks this dedicated
sequence). `gapless-counter-allocation` wins over the draft.

## The resolution (identity rejected, dedicated counter canon)

The data-model draft declares `seq bigint GENERATED ALWAYS AS IDENTITY`. That is exactly the
rollback-gapped allocation `gapless-counter-allocation` rejects: an identity/serial column allocates
its value at insert, and a rolled-back transaction burns that value permanently, leaving a gap that
freezes the cursor and causes silent stall plus silent data loss past 500 rows. This concern freezes
the canonical fix:

- **`ALLOCATION_MODEL`** — a dedicated single-row per-node counter, incremented in the SAME
  transaction as the event insert, monotonic, gapless (a rollback un-does the increment), and
  durable-before-visible (a consumer never sees a seq that could still be rolled back).
- **`REJECTED_ALLOCATIONS`** — `generated_always_as_identity` (the draft posture), `bigserial`,
  `serial`, `uuid_or_random`, `per_tenant_counter`, and `audit_log_id`, kept as data so the census
  test can assert none is the frozen source.

## Bind-before-sign (`ALLOCATION_STEP_ORDER`)

The checklist requires "bind prior hash and event sequence before signing." The frozen sequence is
lock+increment counter → read previous_event_hash → construct the exact preimage with seq and
prev-hash → sign → insert. Because `seq` (A.6 field 5) and `previous_event_hash` (A.6 field 10) live
inside the `reporting-tuples` signed preimage, signing after binding covers them: a signed event can
never be re-sequenced. `COHERENT_UNIT` records the shared acceptance that allocation, previous hash,
signing, state transition, and insertion commit or roll back together; this concern owns the
allocation half, and `event-commit` owns the full atomic step sequence.

## Cursor / restart (`CURSOR_CONTRACT`, `RESTART_INVARIANTS`, `GAP_DETECTION`)

The events cursor uses an exclusive `after_seq`, a `watermark_seq`, and a `next_after_seq`; consumers
apply strictly after the watermark; the cursor tracks the dedicated gapless sequence
(`cursor-tracks-dedicated-sequence`), and a checkpoint is the consumer's durable cursor. On restart
the counter resumes from the durable high-water — never resetting, never reusing a seq — and an
allocated-but-uncommitted seq rolls back with its transaction, so no phantom gap is possible. The
counter is node-global, so a tenant-filtered consumer sees a sparse subset (a skipped seq is another
tenant's event, not a gap); the node-global `previous_event_hash` chain is the sole authoritative
gap/tamper detector.

## Consuming the signed node-event tuple (`reporting-tuples` wins)

The freeze test asserts `ALLOCATION_MODEL.source` and `countersPerNode` equal `reporting-tuples`'
`SEQUENCE_MODEL`, that `seq`/`previous_event_hash` sit at the expected indices in `reporting-tuples`'
`NODE_EVENT_FIELD_ORDER`, and that the gap-detection facts are consistent with `reporting-behavior`'s
`evaluateTenantSeq` (sparse jump → advance) and `evaluateChainAppend` (break → hard stop). Any drift
from those upstream contracts fails here.

## Scope boundary + negatives

CONTRACT_FREEZE only — no runtime allocation code. The full atomic state-event-outbox commit step
sequence is `event-commit`; the concurrency / rollback / restart / rotation behavioural tests are
`sequence-recovery`; the package index/registry is assembled separately. One negative per fact class
(rollback-gap, bind-sequence, cursor monotonicity, restart reset, gap-detector) is present and
demonstrated to fire.
