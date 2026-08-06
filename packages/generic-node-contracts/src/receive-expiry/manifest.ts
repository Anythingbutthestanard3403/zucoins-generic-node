import {
  DURABLE_CANDIDATE_BOUNDARY_SOURCE,
  DURABLE_CANDIDATE_BOUNDARY_MIN_PHASE,
  BOUNDARY_MUST_NOT_KEY_ON,
  OPERATION_TRANSACTION_PHASES,
} from "./boundary.js";
import {
  RECEIVE_STATES,
  TERMINAL_RECEIVE_STATES,
  POST_EXPIRY_RECONCILING,
  POST_BOUNDARY_EXPIRY_OUTCOME,
} from "./lifecycle.js";
import {
  POST_BOUNDARY_RESOLUTIONS,
  FOLD_OUT_ALLOWED,
  UNATTRIBUTED_SUCCESSOR_DISPOSITION,
} from "./resolution.js";
import { SAFE_TERMINAL_RELEASE_STATUS, RELEASED_WALLET_SAFETY } from "./consumer.js";
import { LIVE_CHAIN_PREMISE } from "./assumptions.js";

// Receive-expiry aggregate: the receive late-landing / expiry-after-candidate contract, frozen as data.
export const receiveExpiryContract = {
  boundary: {
    source: DURABLE_CANDIDATE_BOUNDARY_SOURCE,
    minPhase: DURABLE_CANDIDATE_BOUNDARY_MIN_PHASE,
    mustNotKeyOn: BOUNDARY_MUST_NOT_KEY_ON,
    operationTransactionPhases: OPERATION_TRANSACTION_PHASES,
  },
  lifecycle: {
    states: RECEIVE_STATES,
    terminalStates: TERMINAL_RECEIVE_STATES,
    newAttentionReason: POST_EXPIRY_RECONCILING,
    postBoundaryExpiryOutcome: POST_BOUNDARY_EXPIRY_OUTCOME,
  },
  resolution: {
    postBoundaryResolutions: POST_BOUNDARY_RESOLUTIONS,
    foldOutAllowed: FOLD_OUT_ALLOWED,
    unattributedSuccessorDisposition: UNATTRIBUTED_SUCCESSOR_DISPOSITION,
  },
  consumer: {
    safeTerminalReleaseStatus: SAFE_TERMINAL_RELEASE_STATUS,
    releasedWalletSafety: RELEASED_WALLET_SAFETY,
  },
  liveChainPremise: LIVE_CHAIN_PREMISE,
} as const;

export const receiveExpiryConcernManifest = {
  concern: "receive-expiry",
  frozenBy: "receive-expiry-freeze",
  governedBy: [
    "receive-expiry-freeze",
    "durable-candidate-boundary",
    "lease-hold-precedence",
    "released-wallet-safety",
  ],
  contract: receiveExpiryContract,
} as const;
