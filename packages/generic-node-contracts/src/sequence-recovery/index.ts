// the events concern.3 — Public surface of the sequence-recovery concern. Concern-local barrel owned by the
// the events concern.3 slice; NOT the package index (src/index.ts, owned by the concern-manifest registry). Completes the events concern group.

export {
  type AllocationRaceOutcome,
  type CrashOutcome,
  type RestartOutcome,
  type RotationOutcome,
  type RedeliveryOutcome,
  evaluateConcurrentAllocation,
  seqsContiguousUnique,
  partialCommitUnitAtCrash,
  evaluateCrash,
  evaluateRestart,
  evaluateRotationBoundary,
  evaluateConcurrentRedelivery,
} from "./decisions.js";

export { type MatrixCell, buildSequenceRecoveryMatrix } from "./matrix.js";

export {
  type SequenceRecoveryManifest,
  sequenceRecoveryConcernManifest,
  RECOVERY_DIMENSIONS,
  buildSequenceRecoveryManifest,
} from "./manifest.js";
