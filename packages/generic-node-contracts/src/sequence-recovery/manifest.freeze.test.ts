// the events concern.3 freeze + concurrency/recovery behavioural matrix.
//
// Covers the event-ledger data model, the signed event tuple A.6, and the event-serving
// rules. Consumes the gap-detection fact's allocation
// the events concern.2's atomic-commit verifiers, and the reporting bootstrap enrolment's event-stream chain rule. Proves the frozen outcome
// for every scenario across five dimensions — with a per-commit-step crash cell, a demonstrated-to-fire
// negative per dimension, and evidence that the events concern.3 drives its positives from the events concern.2's frozen shapes.
import { describe, expect, it } from "vitest";

import golden from "./gen/sequence-recovery.json" with { type: "json" };
import {
  ATOMICITY,
  COMMIT_STEP_ORDER,
  COMMIT_UNIT,
  CONCURRENCY,
  IDEMPOTENT_REDELIVERY,
  INSERT_EVENT_STEP,
  KEY_ROTATION,
  OUTBOX_DECOUPLING,
  RESTART_COMMIT,
  SIGN_STEP,
  concurrentWritersOneWinnerGapless,
  keyRotationPreservesChain,
  noUnsignedGap,
  redeliveryIsIdempotent,
  restartResumesGaplessAndRedelivers,
  rollbackBurnsNoSeq,
} from "../event-commit/index.js";
import { NODE_EVENT_A_EVENT_HASH } from "../reporting-tuples/index.js";
import { evaluateChainAppend } from "../reporting-behavior/index.js";
import { RECOVERY_DIMENSIONS, buildSequenceRecoveryManifest } from "./manifest.js";
import {
  buildSequenceRecoveryMatrix,
  evaluateConcurrentAllocation,
  evaluateConcurrentRedelivery,
  evaluateCrash,
  evaluateRestart,
  evaluateRotationBoundary,
  partialCommitUnitAtCrash,
  seqsContiguousUnique,
} from "./index.js";

const ZERO_HASH = "0".repeat(64);
const MATRIX = buildSequenceRecoveryMatrix();
const outcome = (dimension: string, scenario: string): string | undefined =>
  MATRIX.find((c) => c.dimension === dimension && c.scenario === scenario)?.outcome;

describe("the events concern.3 sequence-recovery matrix freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildSequenceRecoveryManifest()).toEqual(golden);
  });

  it("covers every dimension and each cell is uniquely keyed", () => {
    const keys = MATRIX.map((c) => `${c.dimension}/${c.scenario}`);
    expect(new Set(keys).size).toBe(keys.length);
    for (const dimension of RECOVERY_DIMENSIONS) {
      expect(MATRIX.some((c) => c.dimension === dimension)).toBe(true);
    }
  });

  it("is exactly the 17-cell matrix (2 concurrency, 8 crash, 2 restart, 3 rotation, 2 redelivery)", () => {
    expect(MATRIX.length).toBe(17);
    const count = (d: string): number => MATRIX.filter((c) => c.dimension === d).length;
    expect(count("concurrency")).toBe(2);
    expect(count("crash")).toBe(COMMIT_STEP_ORDER.length + 1); // one per commit step + crash_after_commit
    expect(count("crash")).toBe(8);
    expect(count("restart")).toBe(2);
    expect(count("rotation")).toBe(3);
    expect(count("redelivery")).toBe(2);
  });
});

describe("the events concern.3 consumes the events concern.2's landed verifiers (drift in either reddens here)", () => {
  it("every positive cell is driven by the events concern.2 frozen shape passing its verifier", () => {
    expect(concurrentWritersOneWinnerGapless(CONCURRENCY)).toBe(true);
    expect(rollbackBurnsNoSeq(ATOMICITY)).toBe(true);
    expect(restartResumesGaplessAndRedelivers(RESTART_COMMIT)).toBe(true);
    expect(keyRotationPreservesChain(KEY_ROTATION)).toBe(true);
    expect(redeliveryIsIdempotent(IDEMPOTENT_REDELIVERY)).toBe(true);
    // sign precedes insert, so a committed event is never unsigned (consumed by the crash cells).
    expect(noUnsignedGap(COMMIT_STEP_ORDER, SIGN_STEP, INSERT_EVENT_STEP)).toBe(true);
  });
});

describe("the events concern.3 concurrent allocators serialize (no duplicate, no gap)", () => {
  it("locked same-txn allocation is contiguous; unlocked races", () => {
    expect(outcome("concurrency", "locked_same_txn")).toBe("SERIALIZED_CONTIGUOUS");
    expect(outcome("concurrency", "unlocked_race")).toBe("RACE_DUPLICATE_OR_GAP");
    expect(seqsContiguousUnique([1n, 2n, 3n])).toBe(true);
  });

  it("each conjunct half alone discriminates the outcome (single-perturbation cross-checks)", () => {
    // Good lock, duplicate seq: the lock half alone is not enough — a duplicate observed allocation is
    // still rejected. Discriminates seqsContiguousUnique's dedup half.
    expect(evaluateConcurrentAllocation(CONCURRENCY, [1n, 1n])).toBe("RACE_DUPLICATE_OR_GAP");
    // Good lock, gapped seq: same shape, gap half of seqsContiguousUnique.
    expect(evaluateConcurrentAllocation(CONCURRENCY, [1n, 3n])).toBe("RACE_DUPLICATE_OR_GAP");
    // Bad lock, contiguous+unique seq: the frozen concurrency contract's serialization is broken (same
    // perturbation as UNLOCKED_RACE) but the observed seqs alone are pristine. Discriminates the
    // lock-model half of the conjunct.
    expect(
      evaluateConcurrentAllocation({ ...CONCURRENCY, serializedOn: "no_lock", oneWinnerPerSeq: false }, [1n, 2n, 3n]),
    ).toBe("RACE_DUPLICATE_OR_GAP");
  });
});

describe("the events concern.3 per-step crash matrix (consumes the events concern.2 commit sequence + atomicity)", () => {
  it("a crash before commit at EVERY commit step rolls the whole unit back", () => {
    for (const step of COMMIT_STEP_ORDER) {
      expect(outcome("crash", `crash_before_commit_at_${step}`)).toBe("ROLLBACK_CLEAN");
    }
    expect(outcome("crash", "crash_after_commit")).toBe("COMMIT_DURABLE");
  });

  it("the per-step partial commit-unit set grows with the step (cells are not a constant)", () => {
    expect(partialCommitUnitAtCrash(0)).toEqual(["allocation"]);
    expect(partialCommitUnitAtCrash(3)).toContain("signing");
    expect(partialCommitUnitAtCrash(3)).not.toContain("insertion");
    expect(partialCommitUnitAtCrash(4)).toContain("insertion");
    // By the final step the touched set is exactly the whole COMMIT_UNIT.
    expect(new Set(partialCommitUnitAtCrash(COMMIT_STEP_ORDER.length - 1))).toEqual(new Set(COMMIT_UNIT));
  });
});

describe("the events concern.3 restart / rotation (consumes the events concern.2 restart + the reporting bootstrap enrolment chain)", () => {
  it("restart resumes gaplessly from the durable high-water", () => {
    expect(outcome("restart", "resume_high_water_uncommitted_rolled_back")).toBe("RESUME_GAPLESS");
  });

  it("event-key rotation keeps the chain intact and the seq continuous", () => {
    expect(outcome("rotation", "boundary_chain_intact_seq_continuous")).toBe("CHAIN_INTACT_SEQ_CONTINUOUS");
    // The boundary cell is exactly a valid the reporting node-event purpose/.3 chain link across the rotation.
    expect(evaluateChainAppend(NODE_EVENT_A_EVENT_HASH, NODE_EVENT_A_EVENT_HASH)).toBe("ACCEPT_CHAIN");
  });

  it("redelivery under concurrent delivery dedups idempotently", () => {
    expect(outcome("redelivery", "concurrent_deduped")).toBe("IDEMPOTENT_DEDUP");
  });
});

describe("the events concern.3 mandatory negatives — each perturbs a frozen shape and is demonstrated to fire", () => {
  it("concurrency: an unlocked race is rejected", () => {
    expect(outcome("concurrency", "unlocked_race")).toBe("RACE_DUPLICATE_OR_GAP");
    expect(seqsContiguousUnique([1n, 3n])).toBe(false); // gap
    expect(seqsContiguousUnique([1n, 1n])).toBe(false); // duplicate
    // The frozen concurrency contract passes its verifier; the perturbed (unlocked) model does not.
    expect(concurrentWritersOneWinnerGapless({ ...CONCURRENCY, serializedOn: "no_lock", oneWinnerPerSeq: false })).toBe(
      false,
    );
  });

  it("crash: perturbing ATOMICITY so a rollback burns a seq flips EVERY pre-commit cell to a rejection", () => {
    const burnedSeqAtomicity = { ...ATOMICITY, rollbackBurnsSeq: true };
    for (let stepIndex = 0; stepIndex < COMMIT_STEP_ORDER.length; stepIndex += 1) {
      expect(evaluateCrash({ committed: false, stepIndex }, burnedSeqAtomicity, OUTBOX_DECOUPLING)).toBe(
        "BURNED_SEQ_OR_PHANTOM",
      );
    }
  });

  it("crash: a leaky outbox is rejected ONLY at the outbox step (proves the per-step check engages)", () => {
    const leakyOutbox = { ...OUTBOX_DECOUPLING, visibleOnlyPostCommit: false };
    const outboxStep = COMMIT_STEP_ORDER.indexOf("enqueue_outbox_delivery");
    // Before the outbox is enqueued, the leak is irrelevant — still a clean rollback.
    expect(evaluateCrash({ committed: false, stepIndex: outboxStep - 1 }, ATOMICITY, leakyOutbox)).toBe("ROLLBACK_CLEAN");
    // Once the outbox entry exists in-transaction, a pre-commit-visible outbox is a phantom.
    expect(evaluateCrash({ committed: false, stepIndex: outboxStep }, ATOMICITY, leakyOutbox)).toBe(
      "BURNED_SEQ_OR_PHANTOM",
    );
  });

  it("crash: durability hinges on the commit, not on step completion", () => {
    const lastStep = COMMIT_STEP_ORDER.length - 1;
    expect(evaluateCrash({ committed: true, stepIndex: lastStep }, ATOMICITY, OUTBOX_DECOUPLING)).toBe("COMMIT_DURABLE");
    expect(evaluateCrash({ committed: false, stepIndex: lastStep }, ATOMICITY, OUTBOX_DECOUPLING)).toBe("ROLLBACK_CLEAN");
  });

  it("restart: resuming without the high-water is a phantom gap", () => {
    expect(outcome("restart", "resume_without_high_water")).toBe("PHANTOM_GAP");
    // Negative model: reset-to-zero + seq reuse fails the landed restart verifier.
    expect(evaluateRestart({ ...RESTART_COMMIT, counterResumesFrom: "reset_to_zero", reusesSeq: true })).toBe(
      "PHANTOM_GAP",
    );
  });

  it("rotation: a seq reset or a chain break is rejected", () => {
    expect(outcome("rotation", "boundary_seq_reset")).toBe("SEQ_RESET");
    expect(outcome("rotation", "boundary_chain_break")).toBe("CHAIN_BREAK");
    // A counter-resetting rotation fails the landed key-rotation verifier even with an intact chain link.
    expect(
      evaluateRotationBoundary(NODE_EVENT_A_EVENT_HASH, {
        previous_event_hash: NODE_EVENT_A_EVENT_HASH,
        model: { ...KEY_ROTATION, resetsCounter: true, seqMonotonicAcrossRotation: false },
      }),
    ).toBe("SEQ_RESET");
    // A mismatched previous_event_hash is a hard chain break regardless of the rotation model.
    expect(
      evaluateRotationBoundary(NODE_EVENT_A_EVENT_HASH, { previous_event_hash: ZERO_HASH, model: KEY_ROTATION }),
    ).toBe("CHAIN_BREAK");
  });

  it("redelivery: no dedup key / re-signing double-counts", () => {
    expect(outcome("redelivery", "no_dedup_key_resigns")).toBe("DOUBLE_COUNT");
    expect(evaluateConcurrentRedelivery({ ...IDEMPOTENT_REDELIVERY, dedupKeys: [], redeliveryReSigns: true })).toBe(
      "DOUBLE_COUNT",
    );
    // Sanity: the frozen redelivery contract dedups (idempotent) — the perturbation is what breaks it.
    expect(evaluateConcurrentAllocation(CONCURRENCY, [1n, 2n, 3n])).toBe("SERIALIZED_CONTIGUOUS");
  });
});
