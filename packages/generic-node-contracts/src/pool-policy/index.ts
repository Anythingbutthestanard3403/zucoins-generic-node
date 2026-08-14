// Concern barrel for the frozen receive-pool policy (the named concern). Lives inside the exclusive
// pool-policy/ concern dir. NOT the package root src/index.ts (the concern-manifest registry-owned); the concern-manifest registry wires this
// concern into the package registry.
export {
  POOL_FLOOR,
  SEND_POOL_FLOOR,
  POOL_CAP_DEFAULT,
  POOL_CAP_CEILING,
  MINT_BATCH_LIMIT,
  HEADROOM_NUMERATOR,
  HEADROOM_DENOMINATOR,
  RECEIVE_QUEUE_MAX_WAIT_MS,
  RECEIVE_QUEUE_RETRY_AFTER_SECONDS,
} from "./constants.js";
export {
  computeProvisioningTarget,
  computeMintBatch,
  planSharedCapMint,
  type PoolMintRole,
} from "./sizing.js";
export {
  POOL_WALLET_STATES,
  POOL_WALLET_TRANSITIONS,
  POOL_KEY_DELETION_ALLOWED,
  isValidPoolTransition,
  countsTowardCap,
  type PoolWalletState,
} from "./states.js";
export {
  KEY_ORIGIN_NODE_GENERATED,
  isAvailableForReceive,
  availableWalletCount,
  capCount,
  type PoolWalletDescriptor,
} from "./eligibility.js";
export {
  receiveQueueCap,
  receiveAdmissionDecision,
  RECEIVE_QUEUE_DEQUEUE_ORDER,
  RECEIVE_QUEUE_QUEUED_PREDICATE,
  RECEIVE_QUEUE_PROMOTION_TRANSACTION,
  isQueuedReceiveCandidate,
  selectNextQueuedReceive,
  isReceiveExpired,
  receiveQueuePromotionDecision,
  type ReceiveAdmission,
  type ReceiveQueueCandidate,
  type ReceiveQueuePromotionDecision,
} from "./queue.js";
export {
  poolPolicyContract,
  poolPolicyConcernManifest,
  POOL_POLICY_FLAGS,
} from "./manifest.js";

// the named concern — selection / hold / scale-up transaction contract.
export {
  WALLET_SELECTION_ORDER,
  WALLET_SELECTION_LOCK,
  SELECT_ASSIGNABLE_WALLET_SQL,
  selectAssignableWallet,
  type SelectableWallet,
} from "./selection.js";
export {
  POOL_CAS_COLUMN,
  RESERVE_WALLET_CAS_SQL,
  REPLENISHMENT_CRASH_SAFETY,
  reserveWallet,
  isAssignable,
  type ReservationOutcome,
} from "./reservation.js"; // contract-allow:reservation-module-path
export {
  RETIRE_WALLET_CAS_SQL,
  retireWallet,
  type RetirementOutcome,
} from "./retirement.js";
export {
  SCALE_UP_ADVISORY_LOCK_NAMESPACE,
  CAP_COUNT_UNDER_LOCK_SQL,
  planScaleUp,
} from "./scaling.js";
export {
  OPEN_SESSIONS_COMPONENTS,
  OPEN_SESSIONS_EXCLUDED_COMPONENTS,
  OPEN_SESSIONS_COUNT_SQL,
  OPEN_SESSIONS_DEFINITION,
  SEND_OPEN_SESSIONS_COMPONENTS,
  SEND_OPEN_SESSIONS_COUNT_SQL,
} from "./open-sessions.js";
export { poolTransactionsContract } from "./transactions-manifest.js";

// the named concern — published pressure-scenario catalog.
export { POOL_PRESSURE_SCENARIOS, type PoolPressureScenario } from "./scenarios.js";
