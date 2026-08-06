// Pure verifiers over the allocation / cursor contract. Downstream event-commit checks consume
// these to prove that no allocation reintroduces a rollback gap, that binding precedes signing,
// and that the cursor advances monotonically. All checks are structural over the frozen data;
// none does I/O.

import { ALLOCATION_STEP_ORDER, BIND_STEPS, REJECTED_ALLOCATIONS, SIGN_STEP } from "./allocation.js";

// Structural verifier inputs — deliberately looser than the frozen `as const` shapes so a test
// (or a downstream caller) can present a hypothetical model with different flag values.
export interface AllocationModelShape {
  readonly source: string;
  readonly serialization: string;
  readonly rollbackSafe: boolean;
  readonly gapless: boolean;
  readonly durableBeforeVisible: boolean;
}
export interface RestartShape {
  readonly resumesFrom: string;
  readonly resetsToZero: boolean;
  readonly reusesSeq: boolean;
  readonly phantomGapPossible: boolean;
}
export interface GapDetectionShape {
  readonly authoritativeGapDetector: string;
  readonly seqContiguityIsGapDetector: boolean;
}

// True iff an allocation model is rollback-safe and gapless via the dedicated per-node counter —
// i.e. NOT an insert-time identity/serial column.
export function isRollbackSafeAllocation(model: AllocationModelShape): boolean {
  return (
    model.source === "per_node_gapless_counter_allocated_pre_sign" &&
    model.serialization === "same_transaction_as_event_insert" &&
    model.rollbackSafe &&
    model.gapless &&
    model.durableBeforeVisible
  );
}

// True iff a candidate allocation mechanism is one of the rejected (rollback-gapped or chain-breaking)
// sources — the census guard that keeps the naive identity posture out of the frozen model.
export function isRejectedAllocation(mechanism: string): boolean {
  return REJECTED_ALLOCATIONS.some((r) => r.mechanism === mechanism);
}

// True iff every binding step (counter increment, previous-hash read) precedes the signing step in
// the allocation step sequence — the "bind prior hash and event sequence before signing" rule.
export function bindsBeforeSign(stepOrder: readonly string[]): boolean {
  const signIndex = stepOrder.indexOf(SIGN_STEP);
  if (signIndex < 0) return false;
  return BIND_STEPS.every((step) => {
    const i = stepOrder.indexOf(step);
    return i >= 0 && i < signIndex;
  });
}

// True iff the step sequence also emits the exact preimage (with seq + prev-hash) before signing and
// inserts the row after — the canonical allocation step sequence.
export function isCanonicalAllocationOrder(stepOrder: readonly string[]): boolean {
  return bindsBeforeSign(stepOrder) && stepOrder.join("|") === ALLOCATION_STEP_ORDER.join("|");
}

// True iff a cursor advance is strictly monotonic (the exclusive after_seq contract).
export function isMonotonicCursorAdvance(fromSeq: bigint, toSeq: bigint): boolean {
  return toSeq > fromSeq;
}

// True iff restart resumes gaplessly: from the durable high-water, never resetting or reusing a seq,
// with no phantom gap from an uncommitted allocation.
export function restartResumesGapless(state: RestartShape): boolean {
  return (
    state.resumesFrom === "durable_high_water_mark" &&
    state.resetsToZero === false &&
    state.reusesSeq === false &&
    state.phantomGapPossible === false
  );
}

// True iff the authoritative gap/tamper detector is the hash chain (not seq contiguity).
export function gapDetectorIsHashChain(detection: GapDetectionShape): boolean {
  return (
    detection.authoritativeGapDetector === "previous_event_hash_chain" &&
    detection.seqContiguityIsGapDetector === false
  );
}
