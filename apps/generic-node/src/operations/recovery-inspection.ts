// generic-node shell re-export for recovery inspection.
// Transport implementation lives in @zucoins/node-core; this file satisfies the
// apps/generic-node mount bullet of the ticket without inventing parallel logic.

export {
  NEEDS_ATTENTION_DEFAULT_LIMIT,
  NEEDS_ATTENTION_MAX_LIMIT,
  NEEDS_ATTENTION_PATH,
  NeedsAttentionQuerySchema,
  RECOVERY_DETAIL_PATH,
  handleGetRecovery,
  handleNeedsAttention,
  type GetRecoveryOutcome,
  type IssuedRecoveryNonce,
  type NeedsAttentionListItem,
  type NeedsAttentionQuery,
  type NeedsAttentionResponse,
  type NeedsAttentionStorePage,
  type RecoveryDetailResponse,
  type RecoveryInspectionStore,
  // Pure classification / permitted-actions (operator surface)
  FORBIDDEN_RECOVERY_ACTIONS,
  OPERATOR_RECOVERY_ACTIONS,
  RECOVERY_CLASSIFICATIONS,
  classifyRecovery,
  derivePermittedActions,
  inspectRecovery,
  type EvidenceManifestEntry,
  type OperatorRecoveryAction,
  type RecoveryClassification,
  type RecoveryFacts,
} from "@zucoins/node-core";
