// The durable-candidate boundary. The boundary after which a receive expiry
// can no longer discard a possible landing is `EXISTS(operation_transactions)` for the op at min
// phase STEP1_SIGNATURE_PERSISTED, evaluated under the op-row lock. It is keyed off
// operation_transactions EXISTS, NEVER the public execution_phase — which still reads NOT_STARTED
// at the boundary, so keying off it reopens the hole. Frozen data + a pure predicate; no DB code.

// The single authoritative source of the boundary, and the field that must NOT be used for it.
export const DURABLE_CANDIDATE_BOUNDARY_SOURCE = "operation_transactions" as const;
export const DURABLE_CANDIDATE_BOUNDARY_MIN_PHASE = "STEP1_SIGNATURE_PERSISTED" as const;
export const BOUNDARY_MUST_NOT_KEY_ON = "execution_phase" as const;

// The `operation_transactions.attempt_phase` CHECK domain in its canonical sequence; the
// boundary is crossed at or beyond STEP1_SIGNATURE_PERSISTED. NEVER the public
// execution_phase vocabulary — attempt-phase-domain.test.ts pins this domain.
export const OPERATION_TRANSACTION_PHASES = [
  "INNER_PREIMAGE_PERSISTED",
  "STEP1_SIGNATURE_PERSISTED",
  "STEP2_PREIMAGE_PERSISTED",
  "STEP2_SIGNATURE_PERSISTED",
  "SETTLED_BODY_PERSISTED",
] as const;
export type OperationTransactionPhase = (typeof OPERATION_TRANSACTION_PHASES)[number];

function phaseRank(phase: OperationTransactionPhase): number {
  return OPERATION_TRANSACTION_PHASES.indexOf(phase);
}

// True once a durable operation_transactions row exists at or beyond STEP1_SIGNATURE_PERSISTED.
// `maxPersistedTxPhase` is null when no operation_transactions row exists for the op (pre-boundary).
export function isPastDurableCandidateBoundary(
  maxPersistedTxPhase: OperationTransactionPhase | null,
): boolean {
  if (maxPersistedTxPhase === null) return false;
  return phaseRank(maxPersistedTxPhase) >= phaseRank(DURABLE_CANDIDATE_BOUNDARY_MIN_PHASE);
}

// The forbidden defect: the public execution_phase still reads NOT_STARTED at the
// boundary, so a boundary computed from it disagrees with the operation_transactions truth. This
// predicate exists ONLY to prove the divergence in tests; it must never drive real behaviour.
export function boundaryFromExecutionPhaseIsUnsafe(
  executionPhaseReadsNotStarted: boolean,
  operationTransactionPersisted: boolean,
): boolean {
  return executionPhaseReadsNotStarted && operationTransactionPersisted;
}
