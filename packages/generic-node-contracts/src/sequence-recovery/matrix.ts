// the events concern.3 — The concurrency / rollback / restart / rotation behavioural matrix. Each cell runs a
// decision over a fixed scenario and records the frozen outcome. Positive cells feed the events concern.2's frozen
// `as const` shapes (CONCURRENCY, ATOMICITY/OUTBOX_DECOUPLING, RESTART_COMMIT, KEY_ROTATION,
// IDEMPOTENT_REDELIVERY) to the events concern.3's decisions, which consume the matching the events concern.2 verifiers; each
// negative cell feeds a deliberately perturbed model of the SAME shape, so the negative is a genuine
// rejection of a contract violation rather than a re-labelled tautology. The per-step crash cells
// iterate the events concern.2's COMMIT_STEP_ORDER; the rotation cells consume the reporting node-event purpose's event-hash golden and
// the reporting bootstrap enrolment's chain rule.
//
// Covers the event-ledger data model, the signed event tuple A.6, and the event-serving
// rules; signed-event-log, sealed-store, reporting-channel.

import {
  ATOMICITY,
  COMMIT_STEP_ORDER,
  CONCURRENCY,
  IDEMPOTENT_REDELIVERY,
  KEY_ROTATION,
  OUTBOX_DECOUPLING,
  RESTART_COMMIT,
  type ConcurrencyShape,
  type KeyRotationShape,
  type RedeliveryShape,
  type RestartCommitShape,
} from "../event-commit/index.js";
import { NODE_EVENT_A_EVENT_HASH } from "../reporting-tuples/index.js";
import {
  evaluateConcurrentAllocation,
  evaluateConcurrentRedelivery,
  evaluateCrash,
  evaluateRestart,
  evaluateRotationBoundary,
} from "./decisions.js";

const ZERO_HASH = "0".repeat(64);

// -------- negative (violating) models: each perturbs exactly one frozen the events concern.2 shape --------

// Unlocked race: not serialized on the counter lock, so writers can share/skip a seq.
const UNLOCKED_RACE: ConcurrencyShape = {
  ...CONCURRENCY,
  serializedOn: "no_lock",
  oneWinnerPerSeq: false,
  distinctSeqPerCommittedEvent: false,
  contiguousUnderContention: false,
};

// Restart that resets the counter and reuses a seq instead of resuming from the durable high-water.
const RESTART_NO_HIGH_WATER: RestartCommitShape = {
  ...RESTART_COMMIT,
  counterResumesFrom: "reset_to_zero",
  reusesSeq: true,
};

// Rotation that resets the counter (seq no longer monotonic across the boundary).
const ROTATION_SEQ_RESET: KeyRotationShape = {
  ...KEY_ROTATION,
  resetsCounter: true,
  seqMonotonicAcrossRotation: false,
};

// Redelivery with no dedup key that re-signs on redelivery (byte-varying, double-countable).
const REDELIVERY_NON_IDEMPOTENT: RedeliveryShape = {
  ...IDEMPOTENT_REDELIVERY,
  dedupKeys: [],
  redeliveryReSigns: true,
};

export interface MatrixCell {
  readonly dimension: string;
  readonly scenario: string;
  readonly outcome: string;
}

export function buildSequenceRecoveryMatrix(): MatrixCell[] {
  const cell = (dimension: string, scenario: string, outcome: string): MatrixCell => ({ dimension, scenario, outcome });
  const cells: MatrixCell[] = [
    // concurrency: the frozen contract + a contiguous allocation serialize; an unlocked model + a raced
    // (duplicate) sequence is rejected.
    cell("concurrency", "locked_same_txn", evaluateConcurrentAllocation(CONCURRENCY, [1n, 2n, 3n])),
    cell("concurrency", "unlocked_race", evaluateConcurrentAllocation(UNLOCKED_RACE, [1n, 1n])),
  ];

  // Per-step crash matrix: a crash before commit at EACH commit step rolls the whole unit back. The
  // stepIndex determines which partial COMMIT_UNIT members exist at crash time, so each cell exercises a
  // different rollback obligation (see decisions.partialCommitUnitAtCrash).
  COMMIT_STEP_ORDER.forEach((step, stepIndex) => {
    cells.push(
      cell("crash", `crash_before_commit_at_${step}`, evaluateCrash({ committed: false, stepIndex }, ATOMICITY, OUTBOX_DECOUPLING)),
    );
  });
  cells.push(
    cell(
      "crash",
      "crash_after_commit",
      evaluateCrash({ committed: true, stepIndex: COMMIT_STEP_ORDER.length - 1 }, ATOMICITY, OUTBOX_DECOUPLING),
    ),
  );

  cells.push(
    cell("restart", "resume_high_water_uncommitted_rolled_back", evaluateRestart(RESTART_COMMIT)),
    cell("restart", "resume_without_high_water", evaluateRestart(RESTART_NO_HIGH_WATER)),

    cell(
      "rotation",
      "boundary_chain_intact_seq_continuous",
      evaluateRotationBoundary(NODE_EVENT_A_EVENT_HASH, {
        previous_event_hash: NODE_EVENT_A_EVENT_HASH,
        model: KEY_ROTATION,
      }),
    ),
    cell(
      "rotation",
      "boundary_seq_reset",
      evaluateRotationBoundary(NODE_EVENT_A_EVENT_HASH, {
        previous_event_hash: NODE_EVENT_A_EVENT_HASH,
        model: ROTATION_SEQ_RESET,
      }),
    ),
    cell(
      "rotation",
      "boundary_chain_break",
      evaluateRotationBoundary(NODE_EVENT_A_EVENT_HASH, { previous_event_hash: ZERO_HASH, model: KEY_ROTATION }),
    ),

    cell("redelivery", "concurrent_deduped", evaluateConcurrentRedelivery(IDEMPOTENT_REDELIVERY)),
    cell("redelivery", "no_dedup_key_resigns", evaluateConcurrentRedelivery(REDELIVERY_NON_IDEMPOTENT)),
  );

  return cells;
}
