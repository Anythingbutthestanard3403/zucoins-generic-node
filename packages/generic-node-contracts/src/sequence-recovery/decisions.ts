// the events concern.3 — Pure decision functions for the concurrency / rollback / restart / rotation behavioural
// matrix. There is no runtime server or database in this CONTRACT_FREEZE slice, so each behaviour is a
// deterministic decision over a frozen (or deliberately perturbed) model. Crucially, the events concern.3 does NOT
// re-derive the atomic-commit facts: it CONSUMES the events concern.2's landed verifiers (`verifier.ts`, whose
// header states "the events concern.3 consumes these") over the events concern.2's frozen shapes, plus the reporting bootstrap enrolment's event-stream
// chain rule (`evaluateChainAppend`). A drift in any consumed slice reddens the matrix here.
//
// Covers the dedicated per-node counter (same-transaction commit, durable-before-visible),
// the zp-node-event-v1 signed tuple (A.6), and the serving rules (never reconstructs preimage;
// key_id is outside the signed object). Canonical: the gapless-counter rule, the byte-frozen
// wire/key-lifetime rule, the pull-cursor authority rule (v2 event-key rotation retires the
// prior key by seq-cursor). The gap-detection fact + the reporting concern
// win on conflict.

import {
  COMMIT_STEP_ORDER,
  COMMIT_UNIT,
  INSERT_EVENT_STEP,
  SIGN_STEP,
  type AtomicityShape,
  type ConcurrencyShape,
  type KeyRotationShape,
  type OutboxShape,
  type RedeliveryShape,
  type RestartCommitShape,
  concurrentWritersOneWinnerGapless,
  keyRotationPreservesChain,
  noUnsignedGap,
  outboxVisibleOnlyPostCommit,
  redeliveryIsIdempotent,
  restartResumesGaplessAndRedelivers,
  rollbackBurnsNoSeq,
} from "../event-commit/index.js";
import { evaluateChainAppend } from "../reporting-behavior/index.js";

// -------- concurrent allocators (race writers) --------

export type AllocationRaceOutcome = "SERIALIZED_CONTIGUOUS" | "RACE_DUPLICATE_OR_GAP";

// Concurrent full commits serialize to a contiguous, unique sequence ONLY when the frozen concurrency
// contract holds (the events concern.2 `concurrentWritersOneWinnerGapless`: serialized on the counter lock, one
// winner per seq, contiguous under contention) AND the observed allocation is in fact contiguous and
// unique. Perturb either — an unlocked model, or a raced sequence with a duplicate/gap — and the race
// is rejected.
export function evaluateConcurrentAllocation(
  model: ConcurrencyShape,
  observedSeqs: readonly bigint[],
): AllocationRaceOutcome {
  return concurrentWritersOneWinnerGapless(model) && seqsContiguousUnique(observedSeqs)
    ? "SERIALIZED_CONTIGUOUS"
    : "RACE_DUPLICATE_OR_GAP";
}

// True iff a sequence of allocated seqs is strictly contiguous and unique (no duplicate, no gap).
export function seqsContiguousUnique(seqs: readonly bigint[]): boolean {
  for (let i = 1; i < seqs.length; i += 1) {
    if (seqs[i] !== seqs[i - 1] + 1n) return false;
  }
  return new Set(seqs.map(String)).size === seqs.length;
}

// -------- per-commit-step crash --------

export type CrashOutcome = "ROLLBACK_CLEAN" | "COMMIT_DURABLE" | "BURNED_SEQ_OR_PHANTOM";

// Maps each COMMIT_STEP_ORDER step to the COMMIT_UNIT member it realizes inside the guarded
// transaction (or `null` for the in-memory preimage build, which touches no durable member). Used to
// derive the partial in-transaction state present at a crash step, so the per-step matrix is genuinely
// per-step rather than a step-independent constant.
const STEP_TO_UNIT: Readonly<Record<string, string | null>> = {
  lock_and_increment_counter: "allocation",
  read_previous_event_hash: "previous_hash",
  construct_exact_preimage_with_seq_and_prev_hash: null,
  sign: "signing",
  insert_event_row: "insertion",
  update_operation_state: "state_transition",
  enqueue_outbox_delivery: "outbox_enqueue",
};

// The COMMIT_UNIT members with partial in-transaction effect once steps 0..stepIndex (inclusive) have
// run but the transaction has NOT committed. The set grows monotonically with stepIndex.
export function partialCommitUnitAtCrash(stepIndex: number): readonly string[] {
  const members: string[] = [];
  for (const step of COMMIT_STEP_ORDER.slice(0, stepIndex + 1)) {
    const member = STEP_TO_UNIT[step];
    if (member !== null && member !== undefined) members.push(member);
  }
  return members;
}

// A crash AFTER the guarded transaction commits leaves the whole unit durable (only post-commit outbox
// delivery remains). A crash BEFORE commit at step k: steps 0..k ran inside the single guarded
// transaction but never committed, so their partial COMMIT_UNIT effects must all roll back atomically
// (the events concern.2 ATOMICITY) — no burned seq, no unsigned event row (sign precedes insert), no externally
// visible outbox entry (delivery is post-commit). Each check consumes the matching the events concern.2 verifier and
// engages only once the relevant step has been reached, so different crash steps exercise different
// obligations. Perturb the atomicity/outbox shape and the clean rollback flips to a burned-seq/phantom.
export function evaluateCrash(
  crash: { readonly committed: boolean; readonly stepIndex: number },
  atomicity: AtomicityShape,
  outbox: OutboxShape,
): CrashOutcome {
  if (crash.committed) return "COMMIT_DURABLE";

  const touched = partialCommitUnitAtCrash(crash.stepIndex);
  const allWithinAtomicUnit = touched.every((member) => (COMMIT_UNIT as readonly string[]).includes(member));
  const rollbackClean = allWithinAtomicUnit && rollbackBurnsNoSeq(atomicity);
  const insertedRowIsSigned =
    !touched.includes("insertion") || noUnsignedGap(COMMIT_STEP_ORDER, SIGN_STEP, INSERT_EVENT_STEP);
  const outboxNotLeaked = !touched.includes("outbox_enqueue") || outboxVisibleOnlyPostCommit(outbox);

  return rollbackClean && insertedRowIsSigned && outboxNotLeaked ? "ROLLBACK_CLEAN" : "BURNED_SEQ_OR_PHANTOM";
}

// -------- restart --------

export type RestartOutcome = "RESUME_GAPLESS" | "PHANTOM_GAP";

// Restart resumes gaplessly iff the frozen restart contract holds (the events concern.2
// `restartResumesGaplessAndRedelivers`: uncommitted commit leaves no event/outbox/transition and burns
// no seq; the counter resumes from the durable high-water without reusing a seq; a committed-undelivered
// outbox redelivers without re-signing). Perturb the model — resume from zero, or reuse a seq — and the
// restart is a phantom gap.
export function evaluateRestart(model: RestartCommitShape): RestartOutcome {
  return restartResumesGaplessAndRedelivers(model) ? "RESUME_GAPLESS" : "PHANTOM_GAP";
}

// -------- event-key rotation mid-stream --------

export type RotationOutcome = "CHAIN_INTACT_SEQ_CONTINUOUS" | "CHAIN_BREAK" | "SEQ_RESET";

// An event-key rotation mid-stream keeps the hash chain intact and the seq continuous. The chain link
// is judged by the reporting bootstrap enrolment's `evaluateChainAppend` (the next event's previous_event_hash must equal the
// prior event's event_hash, regardless of signing key — the key_id is outside the signed object,
// A.6 / the pull-cursor authority rule). Given an intact chain link, seq continuity is judged by the events concern's
// `keyRotationPreservesChain` (counter not reset, seq monotonic across the boundary, prior key retired
// by seq-cursor). A broken chain link is rejected first (CHAIN_BREAK); an intact link with a
// counter-resetting rotation is a SEQ_RESET.
export function evaluateRotationBoundary(
  priorEventHash: string,
  next: { readonly previous_event_hash: string | null; readonly model: KeyRotationShape },
): RotationOutcome {
  if (evaluateChainAppend(priorEventHash, next.previous_event_hash) === "HARD_STOP_CHAIN_BREAK") {
    return "CHAIN_BREAK";
  }
  return keyRotationPreservesChain(next.model) ? "CHAIN_INTACT_SEQ_CONTINUOUS" : "SEQ_RESET";
}

// -------- redelivery idempotence under concurrent delivery --------

export type RedeliveryOutcome = "IDEMPOTENT_DEDUP" | "DOUBLE_COUNT";

// Concurrent delivery of the same committed event dedups to one apply iff the frozen redelivery contract
// holds (the events concern.2 `redeliveryIsIdempotent`: stable dedup keys, and redelivery never re-signs or
// re-sequences — the committed preimage/signature/seq/event_hash are immutable). Perturb the model —
// drop the dedup keys, or re-sign on redelivery — and concurrent delivery double-counts.
export function evaluateConcurrentRedelivery(model: RedeliveryShape): RedeliveryOutcome {
  return redeliveryIsIdempotent(model) ? "IDEMPOTENT_DEDUP" : "DOUBLE_COUNT";
}
