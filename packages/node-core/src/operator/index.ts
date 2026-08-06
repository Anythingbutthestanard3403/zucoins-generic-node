export interface OperatorPort<Request = unknown, Result = unknown> {
  evaluate(request: Request): Promise<Result>;
}

// audited operator retraction of a false-positive attention_required flag.
export * from "./attention-retraction.js";
export * from "./cas.js";
export * from "./halt.js";
export * from "./halt-evidence.js";
export * from "./halt-gate.js";
export * from "./halt-sql.js";
export * from "./idempotency.js";
// pure recovery classification + permitted-action derivation.
export {
  FORBIDDEN_RECOVERY_ACTIONS,
  OPERATOR_RECOVERY_ACTIONS,
  RECOVERY_CLASSIFICATIONS,
  classifyRecovery,
  derivePermittedActions,
  inspectRecovery,
  type ClassificationResult,
  type EvidenceManifestEntry,
  type ForbiddenRecoveryAction,
  type MoveRecoveryFacts,
  type OperatorRecoveryAction,
  type PermittedActionsResult,
  type ReceiveRecoveryFacts,
  type RecoveryClassification,
  type RecoveryFacts,
  type SendRecoveryFacts,
} from "./recovery-inspection.js";
// closed recovery-action evaluator + store port.
export {
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
} from "./recovery-actions.js";
// Selective export: sql-store's SqlExecutor / SqlQueryResult / IDEMPOTENCY_IN_PROGRESS_*
// collide with send + leases barrels. Named surface only; full port types import from
// "./sql-store.js" directly (same pattern as send/index.ts).
export {
  SqlOperationStateStore,
  SqlOperationCreateStore,
  CAS_STATEMENTS,
  OPERATION_CREATE_STATEMENTS,
  TERMINAL_OPERATION_STATUSES,
  isTerminalOperationStatus,
  isUniqueViolation,
  SQLSTATE_UNIQUE_VIOLATION,
  type OperationCreateRequest,
  type OperationCreateOutcome,
  type TerminalOperationStatus,
} from "./sql-store.js";
export * from "./safety-alerts.js";
export * from "./slo.js";
export * from "./storage-backpressure.js";
// Optional operator Web Push — separate from wallet push_subscriptions.
export * from "./operator-push.js";
