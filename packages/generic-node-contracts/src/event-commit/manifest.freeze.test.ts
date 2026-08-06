// the events concern.2 freeze + census gate for the atomic state-event-outbox commit contract.
//
// Governing contract: node_events data model; event signing; event pull. Consumes the gap-detection fact's allocation
// sequencing and coherent unit. Proves: (a) the manifest matches the golden; (b) the commit step
// sequence extends the gap-detection fact's allocation prefix and never emits an unsigned event; (c) partial failure rolls
// back with no burned seq; (d) the outbox is visible only post-commit and delivery failure is
// immutable; (e) redelivery is idempotent; and (f) a negative per fact class.
import { describe, expect, it } from "vitest";

import golden from "./gen/event-commit.json" with { type: "json" };
import { ALLOCATION_STEP_ORDER, COHERENT_UNIT } from "../event-sequencing/index.js";
import {
  ATOMICITY,
  COMMIT_STEP_ORDER,
  COMMIT_UNIT,
  CONCURRENCY,
  DDL_CONSTRAINTS,
  IDEMPOTENT_REDELIVERY,
  INSERT_EVENT_STEP,
  KEY_ROTATION,
  OUTBOX_DECOUPLING,
  RESTART_COMMIT,
  SIGN_STEP,
  allocationPrefixValid,
  concurrentWritersOneWinnerGapless,
  ddlEnforcesAtomicCommit,
  deliveryFailureImmutable,
  keyRotationPreservesChain,
  noUnsignedGap,
  outboxVisibleOnlyPostCommit,
  preimageBindsCurrentHead,
  redeliveryIsIdempotent,
  restartResumesGaplessAndRedelivers,
  rollbackBurnsNoSeq,
  unitBindsStateTransition,
} from "./index.js";
import { buildEventCommitManifest } from "./manifest.js";

describe("the events concern.2 event-commit manifest freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildEventCommitManifest()).toEqual(golden);
  });
});

describe("the events concern.2 extends the gap-detection fact's allocation (the gap-detection fact wins)", () => {
  it("the commit step sequence begins with the gap-detection fact's exact allocation prefix", () => {
    expect(allocationPrefixValid(COMMIT_STEP_ORDER, ALLOCATION_STEP_ORDER)).toBe(true);
    // The appended steps are the operation update and the outbox enqueue.
    expect(COMMIT_STEP_ORDER.slice(ALLOCATION_STEP_ORDER.length)).toEqual([
      "update_operation_state",
      "enqueue_outbox_delivery",
    ]);
  });

  it("the commit unit is a superset of the gap-detection fact's coherent unit plus the outbox", () => {
    for (const member of COHERENT_UNIT) {
      expect(COMMIT_UNIT).toContain(member);
    }
    expect(COMMIT_UNIT).toContain("outbox_enqueue");
  });
});

describe("the events concern.2 atomicity + no unsigned gap", () => {
  it("signing precedes the event insert, so no committed event is unsigned", () => {
    expect(noUnsignedGap(COMMIT_STEP_ORDER, SIGN_STEP, INSERT_EVENT_STEP)).toBe(true);
    expect(ATOMICITY.unsignedGapPossible).toBe(false);
  });

  it("a partial failure rolls the whole unit back with no burned seq", () => {
    expect(rollbackBurnsNoSeq(ATOMICITY)).toBe(true);
    expect(ATOMICITY.semantics).toBe("all_or_nothing");
  });
});

describe("the events concern.2 outbox decoupling + idempotent redelivery", () => {
  it("the outbox is enqueued in-transaction but visible only post-commit", () => {
    expect(outboxVisibleOnlyPostCommit(OUTBOX_DECOUPLING)).toBe(true);
    expect(deliveryFailureImmutable(OUTBOX_DECOUPLING)).toBe(true);
  });

  it("redelivery is idempotent and never re-signs or re-sequences", () => {
    expect(redeliveryIsIdempotent(IDEMPOTENT_REDELIVERY)).toBe(true);
    expect(IDEMPOTENT_REDELIVERY.dedupKeys).toContain("event_hash");
  });
});

describe("the events concern.2 negative path (one per fact class)", () => {
  it("burned-seq-on-rollback: a model that burns the seq is rejected", () => {
    expect(rollbackBurnsNoSeq({ ...ATOMICITY, rollbackBurnsSeq: true })).toBe(false);
  });

  it("event-visible-before-commit: a pre-commit-visible model is rejected", () => {
    expect(outboxVisibleOnlyPostCommit({ ...OUTBOX_DECOUPLING, visibleOnlyPostCommit: false })).toBe(false);
  });

  it("unsigned gap: inserting the event before signing is rejected", () => {
    expect(noUnsignedGap(["insert_event_row", "sign"], SIGN_STEP, INSERT_EVENT_STEP)).toBe(false);
  });

  it("delivery mutating the committed unit is rejected", () => {
    expect(deliveryFailureImmutable({ ...OUTBOX_DECOUPLING, deliveryFailureMutatesCommittedUnit: true })).toBe(false);
  });

  it("non-idempotent redelivery (re-signing) is rejected", () => {
    expect(redeliveryIsIdempotent({ ...IDEMPOTENT_REDELIVERY, redeliveryReSigns: true })).toBe(false);
  });
});

describe("the events concern.2 concurrent writers (one winner, gapless)", () => {
  it("the frozen concurrency fact serializes on the counter and stays gapless under contention", () => {
    expect(concurrentWritersOneWinnerGapless(CONCURRENCY)).toBe(true);
    expect(CONCURRENCY.serializedOn).toBe("lock_and_increment_counter");
  });

  it("two committed events sharing a seq is rejected", () => {
    expect(
      concurrentWritersOneWinnerGapless({ ...CONCURRENCY, distinctSeqPerCommittedEvent: false }),
    ).toBe(false);
  });

  it("a concurrent reader observing a half-built event is rejected", () => {
    expect(
      concurrentWritersOneWinnerGapless({ ...CONCURRENCY, concurrentReaderObservesHalfBuiltEvent: true }),
    ).toBe(false);
  });
});

describe("the events concern.2 restart / recovery", () => {
  it("the frozen restart fact resumes gaplessly and redelivers a committed-but-undelivered outbox entry", () => {
    expect(restartResumesGaplessAndRedelivers(RESTART_COMMIT)).toBe(true);
    expect(RESTART_COMMIT.counterResumesFrom).toBe("durable_high_water_mark");
  });

  it("an uncommitted commit that burns a seq on restart is rejected", () => {
    expect(
      restartResumesGaplessAndRedelivers({ ...RESTART_COMMIT, uncommittedCommitBurnsSeq: true }),
    ).toBe(false);
  });

  it("reusing a seq after restart is rejected", () => {
    expect(restartResumesGaplessAndRedelivers({ ...RESTART_COMMIT, reusesSeq: true })).toBe(false);
  });
});

describe("the events concern.2 key rotation mid-stream", () => {
  it("the frozen rotation fact keeps the chain continuous, never re-signs, and retires by seq-cursor", () => {
    expect(keyRotationPreservesChain(KEY_ROTATION)).toBe(true);
    expect(KEY_ROTATION.priorKeyRetiredBy).toBe("seq_cursor");
    // The key id is outside the A.6 signed object, so rotation changes no signed byte.
    expect(KEY_ROTATION.keyIdInSignedPreimage).toBe(false);
    expect(KEY_ROTATION.preimageTupleChangedByRotation).toBe(false);
  });

  it("re-signing already-committed events on rotation is rejected", () => {
    expect(keyRotationPreservesChain({ ...KEY_ROTATION, reSignsCommittedEvents: true })).toBe(false);
  });

  it("resetting the counter on rotation is rejected", () => {
    expect(keyRotationPreservesChain({ ...KEY_ROTATION, resetsCounter: true })).toBe(false);
  });

  it("retiring the prior key by 'first batch verified' (the frozen rule, rejected) instead of seq-cursor is rejected", () => {
    expect(keyRotationPreservesChain({ ...KEY_ROTATION, priorKeyRetiredBy: "first_batch_verified" })).toBe(false);
  });
});

describe("the events concern.2 DDL constraint manifest", () => {
  it("the frozen DDL constraints enforce atomic commit + outbox decoupling + idempotency", () => {
    expect(ddlEnforcesAtomicCommit(DDL_CONSTRAINTS)).toBe(true);
    expect(DDL_CONSTRAINTS.seqSource).toBe("dedicated_per_node_counter");
    expect(DDL_CONSTRAINTS.seqRejectedSource).toBe("generated_always_as_identity");
  });

  it("an outbox NOT separate from neutral truth is rejected", () => {
    expect(ddlEnforcesAtomicCommit({ ...DDL_CONSTRAINTS, outboxSeparateFromNeutralTruth: false })).toBe(false);
  });
});

describe("the events concern.2 additional per-clause negatives", () => {
  it("state-transition clause: the frozen commit unit binds both insertion and state_transition", () => {
    expect(unitBindsStateTransition(COMMIT_UNIT)).toBe(true);
  });

  it("event insert without a state transition is rejected", () => {
    expect(
      unitBindsStateTransition(["allocation", "previous_hash", "signing", "insertion", "outbox_enqueue"]),
    ).toBe(false);
  });

  it("previous-hash clause: a preimage built on the current chain head is accepted", () => {
    expect(preimageBindsCurrentHead(null, null)).toBe(true);
    expect(preimageBindsCurrentHead("abc", "abc")).toBe(true);
  });

  it("a mixed / stale previous_event_hash is rejected", () => {
    expect(preimageBindsCurrentHead("stale", "current")).toBe(false);
  });
});
