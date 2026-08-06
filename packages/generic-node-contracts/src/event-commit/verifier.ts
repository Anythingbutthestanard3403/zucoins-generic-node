// the events concern.2 — Pure verifiers over the atomic-commit / outbox contract. the events concern.3 consumes these to
// prove partial-failure, no-unsigned-gap, and idempotent-redelivery behaviour. Structural inputs are
// deliberately looser than the frozen `as const` shapes so a hypothetical model can be tested.
//
// Governing contract: node_events data model; event signing; canonical atomic-commit decisions.

export interface AtomicityShape {
  readonly transaction: string;
  readonly semantics: string;
  readonly partialFailure: string;
  readonly rollbackBurnsSeq: boolean;
  readonly unsignedGapPossible: boolean;
}
export interface OutboxShape {
  readonly enqueuedInsideTransaction: boolean;
  readonly deliveryAfterCommit: boolean;
  readonly visibleOnlyPostCommit: boolean;
  readonly deliveryFailureMutatesCommittedUnit: boolean;
}
export interface RedeliveryShape {
  readonly dedupKeys: readonly string[];
  readonly redeliveryReSigns: boolean;
  readonly redeliveryReSequences: boolean;
}

// True iff the gap-detection fact's allocation sequence is the exact prefix of the commit sequence — the commit
// unit extends, never reorders, the frozen allocation sequencing (the gap-detection fact wins).
export function allocationPrefixValid(
  commitOrder: readonly string[],
  allocationOrder: readonly string[],
): boolean {
  return commitOrder.slice(0, allocationOrder.length).join("|") === allocationOrder.join("|");
}

// True iff signing precedes the event-row insert — there is never a committed unsigned event.
export function noUnsignedGap(stepOrder: readonly string[], signStep: string, insertStep: string): boolean {
  const s = stepOrder.indexOf(signStep);
  const i = stepOrder.indexOf(insertStep);
  return s >= 0 && i >= 0 && s < i;
}

// True iff a partial failure rolls the whole unit back and burns no sequence (the gapless guarantee).
export function rollbackBurnsNoSeq(atomicity: AtomicityShape): boolean {
  return (
    atomicity.semantics === "all_or_nothing" &&
    atomicity.partialFailure === "rolls_back_whole_unit" &&
    atomicity.rollbackBurnsSeq === false
  );
}

// True iff the event/outbox entry is visible only after commit (durable-before-visible).
export function outboxVisibleOnlyPostCommit(outbox: OutboxShape): boolean {
  return outbox.enqueuedInsideTransaction && outbox.deliveryAfterCommit && outbox.visibleOnlyPostCommit;
}

// True iff a delivery failure never mutates the committed unit.
export function deliveryFailureImmutable(outbox: OutboxShape): boolean {
  return outbox.deliveryFailureMutatesCommittedUnit === false;
}

// True iff redelivery is idempotent: stable dedup keys, and no re-signing or re-sequencing.
export function redeliveryIsIdempotent(redelivery: RedeliveryShape): boolean {
  return (
    redelivery.dedupKeys.length > 0 &&
    redelivery.redeliveryReSigns === false &&
    redelivery.redeliveryReSequences === false
  );
}

// ----------------------------------------------------------------------------------------------------
// Concurrency / restart / key-rotation / DDL verifiers (the events concern.2 rollback-concurrency vectors).
// These prove the frozen contract ADMITS the correct concurrent/recovery/rotation behaviour and
// REJECTS violations; the events concern.3 consumes them for the exhaustive runtime race/crash/replay proof.
// ----------------------------------------------------------------------------------------------------

export interface ConcurrencyShape {
  readonly serializedOn: string;
  readonly oneWinnerPerSeq: boolean;
  readonly distinctSeqPerCommittedEvent: boolean;
  readonly loserProceedsOnNextSeq: boolean;
  readonly contiguousUnderContention: boolean;
  readonly concurrentReaderObservesHalfBuiltEvent: boolean;
}
export interface RestartCommitShape {
  readonly uncommittedCommitLeavesEvent: boolean;
  readonly uncommittedCommitLeavesOutboxEntry: boolean;
  readonly uncommittedCommitTransitionsOperation: boolean;
  readonly uncommittedCommitBurnsSeq: boolean;
  readonly counterResumesFrom: string;
  readonly reusesSeq: boolean;
  readonly committedUndeliveredOutboxRedelivered: boolean;
  readonly redeliveryReSigns: boolean;
}
export interface KeyRotationShape {
  readonly resetsCounter: boolean;
  readonly seqMonotonicAcrossRotation: boolean;
  readonly reSignsCommittedEvents: boolean;
  readonly preimageTupleChangedByRotation: boolean;
  readonly keyIdInSignedPreimage: boolean;
  readonly hashChainContinuousAcrossRotation: boolean;
  readonly priorKeyRetiredBy: string;
}
export interface DdlConstraintShape {
  readonly eventAndStateSameTransaction: boolean;
  readonly outboxEnqueuedInSameTransaction: boolean;
  readonly outboxSeparateFromNeutralTruth: boolean;
  readonly seqSource: string;
  readonly uniqueEventId: boolean;
  readonly uniqueEventHash: boolean;
  readonly eventsInsertOnly: boolean;
}

// True iff concurrent full commits serialize on the counter so exactly one writer wins each seq, the
// loser proceeds on the next seq, the sequence is contiguous under contention, and no concurrent
// reader ever observes a half-built (uncommitted) event.
export function concurrentWritersOneWinnerGapless(c: ConcurrencyShape): boolean {
  return (
    c.serializedOn === "lock_and_increment_counter" &&
    c.oneWinnerPerSeq &&
    c.distinctSeqPerCommittedEvent &&
    c.loserProceedsOnNextSeq &&
    c.contiguousUnderContention &&
    c.concurrentReaderObservesHalfBuiltEvent === false
  );
}

// True iff restart is gapless: an uncommitted commit leaves no event/outbox/transition and burns no
// seq; the counter resumes from the durable high-water without reusing a seq; and a committed-but-
// undelivered outbox entry redelivers without re-signing.
export function restartResumesGaplessAndRedelivers(r: RestartCommitShape): boolean {
  return (
    r.uncommittedCommitLeavesEvent === false &&
    r.uncommittedCommitLeavesOutboxEntry === false &&
    r.uncommittedCommitTransitionsOperation === false &&
    r.uncommittedCommitBurnsSeq === false &&
    r.counterResumesFrom === "durable_high_water_mark" &&
    r.reusesSeq === false &&
    r.committedUndeliveredOutboxRedelivered &&
    r.redeliveryReSigns === false
  );
}

// True iff key rotation mid-stream never resets the counter or re-signs a committed event, keeps the
// A.6 preimage tuple and the hash chain unchanged (the key id is outside the signed object), and
// retires the prior key by seq-cursor (the pull-cursor authority rule) rather than the rejected "first batch verified" rule.
export function keyRotationPreservesChain(k: KeyRotationShape): boolean {
  return (
    k.resetsCounter === false &&
    k.seqMonotonicAcrossRotation &&
    k.reSignsCommittedEvents === false &&
    k.preimageTupleChangedByRotation === false &&
    k.keyIdInSignedPreimage === false &&
    k.hashChainContinuousAcrossRotation &&
    k.priorKeyRetiredBy === "seq_cursor"
  );
}

// True iff the load-bearing node_events DDL constraints that enforce atomic commit + outbox decoupling +
// idempotent redelivery all hold (event+state one txn, outbox separate store, dedicated-counter seq,
// unique event_id/event_hash, insert-only truth).
export function ddlEnforcesAtomicCommit(d: DdlConstraintShape): boolean {
  return (
    d.eventAndStateSameTransaction &&
    d.outboxEnqueuedInSameTransaction &&
    d.outboxSeparateFromNeutralTruth &&
    d.seqSource === "dedicated_per_node_counter" &&
    d.uniqueEventId &&
    d.uniqueEventHash &&
    d.eventsInsertOnly
  );
}

// True iff the commit unit binds BOTH the event insertion and the operation state transition — an
// event committed without its state transition (or vice versa) violates the atomic-commit contract.
export function unitBindsStateTransition(unit: readonly string[]): boolean {
  return unit.includes("insertion") && unit.includes("state_transition");
}

// True iff the preimage was built on the CURRENT chain-head previous_event_hash. A preimage built on a
// stale or mismatched previous hash breaks the previous_event_hash chain and must be rejected
// (`null` is the legitimate genesis head).
export function preimageBindsCurrentHead(
  builtOnHash: string | null,
  chainHeadHash: string | null,
): boolean {
  return builtOnHash === chainHeadHash;
}
