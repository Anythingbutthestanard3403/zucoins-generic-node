// Concern barrel for the frozen receive expiry-after-candidate contract (the named concern). Lives inside
// the exclusive receive-expiry/ concern dir. NOT the package root src/index.ts (the concern-manifest registry-owned).
// Consistent with the wallet-state lease-hold predicate (the receive-expiry rule); see manifest.test.ts.
export {
  DURABLE_CANDIDATE_BOUNDARY_SOURCE,
  DURABLE_CANDIDATE_BOUNDARY_MIN_PHASE,
  BOUNDARY_MUST_NOT_KEY_ON,
  OPERATION_TRANSACTION_PHASES,
  isPastDurableCandidateBoundary,
  boundaryFromExecutionPhaseIsUnsafe,
  type OperationTransactionPhase,
} from "./boundary.js";
export {
  RECEIVE_STATES,
  TERMINAL_RECEIVE_STATES,
  POST_EXPIRY_RECONCILING,
  POST_BOUNDARY_EXPIRY_OUTCOME,
  isTerminalReceiveState,
  isExpiryToExpiredLegal,
  receiveExpiryEvents,
  type ReceiveState,
  type PostBoundaryExpiryOutcome,
} from "./lifecycle.js";
export {
  POST_BOUNDARY_RESOLUTIONS,
  FOLD_OUT_ALLOWED,
  UNATTRIBUTED_SUCCESSOR_DISPOSITION,
  isPostBoundaryResolutionLegal,
  isInvariantBreach,
  type PostBoundaryResolution,
} from "./resolution.js";
export {
  SAFE_TERMINAL_RELEASE_STATUS,
  RELEASED_WALLET_SAFETY,
  isTerminalPaymentFailure,
  releasedWalletDisposition,
  isEligibleAsT0Baseline,
} from "./consumer.js";
export { LIVE_CHAIN_PREMISE } from "./assumptions.js";
export { receiveExpiryContract, receiveExpiryConcernManifest } from "./manifest.js";

// the named concern — expiry -> reconcile -> release sequencing.
export {
  EXPIRY_RECONCILE_RELEASE_ORDER,
  postBoundaryExpiryDisposition,
  leaseDropAllowed,
  type PostBoundaryDisposition,
} from "./ordering.js"; // contract-allow:ordering-module-path
export {
  FORBIDDEN_SHORTCUTS,
  EVIDENCE_DISPOSAL_ON_EXPIRY_ALLOWED,
  releaseShortcutViolation,
  evidenceDisposalViolation,
  leaseDropViolation,
  type ForbiddenShortcut,
} from "./shortcuts.js";
export { expiryOrderingContract } from "./ordering-manifest.js"; // contract-allow:ordering-manifest-module-path

// the named concern — fault-injection phase catalog.
export {
  RECEIVE_EXPIRY_PHASES,
  RECEIVE_EXPIRY_PHASE_INVARIANTS,
  receiveExpiryFaultInjectionContract,
  type ReceiveExpiryPhase,
} from "./phases.js";
