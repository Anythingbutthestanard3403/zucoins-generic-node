export {
  VERIFICATION_MATERIAL_PATH,
  VERIFICATION_MATERIAL_ROUTE_ID,
  createVerificationMaterialRouteHandler,
  operationIdFromVerificationMaterialTarget,
  verificationMaterialHandlerEntry,
  type VerificationMaterialRouteDeps,
} from "./verification-material-route.js";

export {
  createFailClosedPoolArmHandler,
  createPoolArmTxFactory,
  createPoolArmWalletGate,
} from "./arm-wallet-gate.js";

export {
  ARM_ROUTE_ID,
  OPERATION_ARMED_ROUTE_ID,
  armHandlerEntry,
  createArmRouteHandler,
  type ArmRouteDeps,
} from "./arm-route.js";

export {
  createArmCommitHook,
  defaultArmInsertEnvelope,
  type ArmCommitDeps,
  type ArmCommitPreopen,
} from "./arm-commit.js";

// Live ARM composition (SQL arm stores + wallet gate + durable T0).
export {
  ARM_LIVE_SQL,
  LIVE_ARM_ENGINE,
  createLiveArmRouteHandler,
  createSqlArmDurableT0,
  type LiveArmDeps,
} from "./arm-live.js";

export {
  VERIFICATION_COMPLETE_RELEASE_REASON,
  computeReleaseProofDigest,
  createPoolVerificationCompleteTxFactory,
  createSqlVerificationCompleteStore,
  type VerificationCompleteEnvelope,
  type VerificationCompleteStoreDeps,
  type VerificationCompleteTx,
  type VerificationCompleteTxFactory,
} from "./verification-complete-store.js";

// Live verification-complete composition (SQL ack + lease release on the reporting
// route, mounted against the signed reporting credential pipeline).
export {
  LIVE_VERIFICATION_COMPLETE_ENGINE,
  VERIFICATION_COMPLETE_PATH,
  VERIFICATION_COMPLETE_ROUTE_ID,
  createVerificationCompleteRouteHandler,
  operationIdFromVerificationCompleteTarget,
  verificationCompleteHandlerEntry,
  type VerificationCompleteRouteDeps,
} from "./verification-complete-route.js";

// Recovery inspection (read-only).
export {
  FORBIDDEN_RECOVERY_ACTIONS,
  NEEDS_ATTENTION_DEFAULT_LIMIT,
  NEEDS_ATTENTION_MAX_LIMIT,
  NEEDS_ATTENTION_PATH,
  NeedsAttentionQuerySchema,
  OPERATOR_RECOVERY_ACTIONS,
  RECOVERY_CLASSIFICATIONS,
  RECOVERY_DETAIL_PATH,
  classifyRecovery,
  derivePermittedActions,
  handleGetRecovery,
  handleNeedsAttention,
  inspectRecovery,
  type EvidenceManifestEntry,
  type GetRecoveryOutcome,
  type IssuedRecoveryNonce,
  type NeedsAttentionListItem,
  type NeedsAttentionQuery,
  type NeedsAttentionResponse,
  type NeedsAttentionStorePage,
  type OperatorRecoveryAction,
  type RecoveryClassification,
  type RecoveryDetailResponse,
  type RecoveryFacts,
  type RecoveryInspectionStore,
} from "./recovery-inspection.js";

// recovery-actions POST (mutating).
export {
  RECOVERY_ACTIONS_PATH,
  STRUCTURALLY_ABSENT_RECOVERY_EFFECTS,
  executeRecoveryAction,
  handleRecoveryAction,
  isForbiddenRecoveryAction,
  isOperatorRecoveryAction,
  planRecoveryEffect,
  recoveryActionErrorEnvelope,
  type HandleRecoveryActionResult,
  type RecoveryActionAuthContext,
  type RecoveryActionCommitInput,
  type RecoveryActionCommitResult,
  type RecoveryActionEffect,
  type RecoveryActionOutcome,
  type RecoveryActionRejectReason,
  type RecoveryActionRequest,
  type RecoveryActionStore,
  type RecoveryActionSuccessBody,
} from "./recovery-actions.js";
