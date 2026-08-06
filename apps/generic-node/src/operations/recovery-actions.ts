// generic-node shell re-export for recovery-actions POST.
// Mutating service lives in @zucoins/node-core; this file satisfies the
// apps/generic-node mount bullet without inventing parallel logic.

export {
  RECOVERY_ACTIONS_PATH,
  handleRecoveryAction,
  recoveryActionErrorEnvelope,
  type HandleRecoveryActionResult,
  type RecoveryActionAuthContext,
  // Pure guard / evaluator surface
  STRUCTURALLY_ABSENT_RECOVERY_EFFECTS,
  executeRecoveryAction,
  isForbiddenRecoveryAction,
  isOperatorRecoveryAction,
  planRecoveryEffect,
  type RecoveryActionCommitInput,
  type RecoveryActionCommitResult,
  type RecoveryActionEffect,
  type RecoveryActionOutcome,
  type RecoveryActionRejectReason,
  type RecoveryActionRequest,
  type RecoveryActionStore,
  type RecoveryActionSuccessBody,
  FORBIDDEN_RECOVERY_ACTIONS,
  OPERATOR_RECOVERY_ACTIONS,
} from "@zucoins/node-core";
