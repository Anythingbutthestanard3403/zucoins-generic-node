# sequence-recovery — CONTRACT

Freeze slice: **prove sequence concurrency and recovery** (the final slice of the events group;
depends on event-sequencing + event-commit, consumes the reporting-behavior verifiers).
Gate: `CONTRACT_FREEZE`.

Governing sources: the data model's event ledger; canonical fields A.6; the state-event reference
6.1. Decisions: `signed-event-log` (gapless counter), `sealed-store` (byte-frozen wire + key
lifetime), `reporting-channel` (event-key rotation retires the prior key by seq-cursor; `key_id`
outside the signed object).

## Scope boundary

There is no runtime server or database in this CONTRACT_FREEZE group, so each concurrency/recovery
behaviour is a pure decision over a frozen (or deliberately perturbed) model, and the freeze test drives
the full matrix. A live-Postgres run — real concurrent writers, forced rollback, crash injection, key
rotation, restart, cursor replay — belongs to a later implementation/acceptance slice.
What is contract-level provable here is that event-commit's frozen atomic-commit contract, fed to
event-commit's own verifiers, *admits* the correct concurrent/recovery/rotation behaviour and
*rejects* every violation; what is NOT provable without a database (real process-kill crash
injection, real advisory-lock contention, real outbox redelivery) is deferred and flagged, never
faked.

## Consume, don't re-derive (the event-commit boundary)

event-commit ships the atomic-state-event-outbox **contract** plus **structural verifiers**
(`verifier.ts`, whose header states that this slice consumes them). This slice does NOT
re-implement those facts: its decision functions call the landed verifiers over the landed frozen
`as const` shapes — `concurrentWritersOneWinnerGapless(CONCURRENCY)`, `rollbackBurnsNoSeq(ATOMICITY)` +
`outboxVisibleOnlyPostCommit(OUTBOX_DECOUPLING)` + `noUnsignedGap(...)` (crash),
`restartResumesGaplessAndRedelivers(RESTART_COMMIT)`, `keyRotationPreservesChain(KEY_ROTATION)`,
`redeliveryIsIdempotent(IDEMPOTENT_REDELIVERY)` — and the rotation chain link is judged by the
reporting-behavior slice's `evaluateChainAppend`. Drift in any consumed slice reddens the matrix here.

## What is frozen (`decisions.ts` + `matrix.ts`)

Five dimensions, 17 frozen outcome cells snapshotted in `gen/sequence-recovery.json`:

- **concurrency** (2) — the frozen concurrency contract plus a contiguous allocation serialize to a
  unique, gapless sequence; an unlocked model plus a raced (duplicate) sequence is rejected.
- **crash** (8) — a per-commit-step matrix over event-commit's `COMMIT_STEP_ORDER`: a crash before
  commit at EACH step rolls the whole guarded unit back (`ROLLBACK_CLEAN`). The crash `stepIndex`
  determines which partial `COMMIT_UNIT` members exist at crash time (`partialCommitUnitAtCrash`),
  so each cell exercises a different obligation — the no-unsigned-gap check engages once the row is
  inserted, the outbox-not-leaked check once the outbox is enqueued — rather than a step-independent
  constant. A crash after commit leaves the unit durable (`COMMIT_DURABLE`).
- **restart** (2) — resumes gaplessly from the durable high-water with any uncommitted seq rolled back;
  a model that resets the counter / reuses a seq is a phantom gap.
- **rotation** (3) — an event-key rotation mid-stream keeps the hash chain intact (`evaluateChainAppend`
  ACCEPT) and the seq continuous (the counter is independent of the signing key; the `key_id` is outside
  the signed object, so no signed byte depends on which key signed — `reporting-channel` / A.6 /
  state-event reference 6.1). A chain break is rejected first; a counter-resetting rotation is a seq
  reset.
- **redelivery** (2) — concurrent delivery of the same committed event dedups idempotently (stable dedup
  key, no re-signing); no dedup key / re-signing double-counts.

## Negatives

One reject/negative per dimension, each **perturbing exactly one frozen event-commit shape** and
demonstrated to fire in `manifest.freeze.test.ts` (unlocked-model race, burned-seq atomicity /
leaky-outbox crash, reset-to-zero restart, counter-resetting rotation + mismatched chain link,
no-dedup-key re-signing redelivery). Breaking a consumed verifier or its frozen shape reddens the
dimension's negatives.

## Group complete

This completes the events group: gapless allocation (event-sequencing), atomic commit
(event-commit), concurrency/recovery (this slice). The `seq` column is the dedicated per-node
counter, never `GENERATED ALWAYS AS IDENTITY` — the posture `signed-event-log` rejects that form,
and the data model's event ledger matches.
