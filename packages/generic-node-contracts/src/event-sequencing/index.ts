// the gap-detection fact — Public surface of the event-sequencing concern. Concern-local barrel owned by the
// the gap-detection fact slice; NOT the package index (src/index.ts, owned by the concern-manifest registry). the events concern.2/.3 consume this.

export {
  ALLOCATION_MODEL,
  REJECTED_ALLOCATIONS,
  ALLOCATION_STEP_ORDER,
  BIND_STEPS,
  SIGN_STEP,
  COHERENT_UNIT,
} from "./allocation.js";

export { CURSOR_CONTRACT, RESTART_INVARIANTS, GAP_DETECTION } from "./cursor.js";

export {
  isRollbackSafeAllocation,
  isRejectedAllocation,
  bindsBeforeSign,
  isCanonicalAllocationOrder,
  isMonotonicCursorAdvance,
  restartResumesGapless,
  gapDetectorIsHashChain,
} from "./verifier.js";

export {
  type EventSequencingManifest,
  eventSequencingConcernManifest,
  buildEventSequencingManifest,
} from "./manifest.js";
