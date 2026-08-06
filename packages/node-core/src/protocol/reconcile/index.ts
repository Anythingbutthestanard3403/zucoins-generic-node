// concern barrel for the reconcile-outcome vocabulary.

export {
  RECONCILE_CLASSIFICATION_KINDS,
  assertUnreachable,
  type ReconcileClassificationKind,
  type ClassifierOutputRelationship,
  type IndeterminateObservationAnomaly,
  type InvariantBreachObservationAnomaly,
  type ReconcilableObservationAnomaly,
  type ReconcileIndeterminateReason,
  type ReconcileInvariantBreachReason,
} from "./types.js";

export {
  LANDING_PROOF_FAULTS,
  // seal/mint are NOT barrel-exported and not on landing-proof.ts.
  // Settle-grade mint is confined to landing-oracle-mint.ts + landing-path oracle producers.
  // Stage-2 uses isLandingPathProof / revalidateLandingPathProofBindings only.
  isLandingPathProof,
  revalidateLandingPathProofBindings,
  type LandingPathProof,
  type LandingPathProofBinding,
  type LandingProofFault,
  type LandingProofFailure,
  type LandingProofOutcome,
} from "./landing-proof.js";

export {
  LANDING_VERDICTS,
  adjudicateLanding,
  type LandingAdjudication,
  type LandingAdjudicationEvidence,
  type LandingIndeterminateReason,
  type LandingRejectionReason,
  type LandingVerdict,
} from "./landing-adjudicator.js";

export {
  classifyPathObservation,
  type PathObservation,
  type PathClassification,
} from "./observation-input.js";

export {
  captureSubmitAcknowledgement,
  mintSettlementAuthority,
  mintSubmitClaim,
  isSettlementAuthority,
  isSubmitAcknowledgement,
  type SubmitAcknowledgement,
  type SettlementAuthority,
  type SubmitClaim,
} from "./submit-authority.js";

export {
  classifyReceiveReconcile,
  type ReceiveReconcileOutcome,
  type ReceiveReconcileInput,
  type ReceiveFormationEvidence,
  type ReceiveObservationEvidence,
  type ReceiveNeverCrossedBoundary,
  type ReceiveResumeAction,
} from "./receive.js";

export {
  classifyMoveReconcile,
  type MoveReconcileOutcome,
  type MoveReconcileInput,
  type MoveFormationEvidence,
  type MoveObservationEvidence,
  type MoveNeverCrossedBoundary,
  type MoveResumeAction,
} from "./move.js";

export {
  MOVE_AMBIGUITY_FORBIDDEN_ACTIONS,
  assertMoveAmbiguityLeasesHeld,
  classifyMoveAmbiguity,
  continueMoveAmbiguityReconciliation,
  isMoveAmbiguityActionPermitted,
  moveAmbiguityPermitsSecondAttempt,
  moveAmbiguityPermitsSubmitCall,
  moveAmbiguityRetainsBothLeases,
  type MoveAmbiguityAutomaticEffect,
  type MoveAmbiguityEvidenceKind,
  type MoveAmbiguityForbiddenAction,
  type MoveAmbiguityInput,
  type MoveAmbiguityOutcome,
  type MoveAmbiguityPostSubmitInput,
  type MoveAmbiguityPreSubmitInput,
  type MoveSubmitTransportEvidence,
} from "./move-ambiguity.js";

export {
  classifySendReconcile,
  type SendReconcileOutcome,
  type SendReconcileInput,
  type SendFormationEvidence,
  type SendDeliveredEvidence,
  type SendNeverCrossedBoundary,
  type SendResumeAction,
} from "./send.js";

export {
  MOVE_BREACH_ANOMALY_KINDS,
  MOVE_BREACH_FORBIDDEN_OPERATOR_ACTIONS,
  MOVE_BREACH_LINEAGE_VERDICT,
  MOVE_BREACH_PERMITTED_OPERATOR_ACTIONS,
  OPERATOR_RECOVERY_ACTION_CATALOG,
  MoveInvariantBreachError,
  acknowledgeMoveInvariantBreach,
  anomalyKindForBreachReason,
  applyMoveBreachOperatorAction,
  applyMoveInvariantBreachQuarantine,
  assertMoveBreachActionCatalogCoherent,
  getMoveBreachDiagnostics,
  isMoveBreachOperatorActionForbidden,
  isMoveBreachOperatorActionPermitted,
  isMoveBreachWalletFrozen,
  quarantineReasonForBreach,
  rejectMoveBreachOperatorAction,
  type MoveBreachAcknowledgeInput,
  type MoveBreachAcknowledgeResult,
  type MoveBreachAnomalyKind,
  type MoveBreachAttemptBytes,
  type MoveBreachAuditEntry,
  type MoveBreachDiagnostics,
  type MoveBreachForbiddenOperatorAction,
  type MoveBreachLeaseSnapshot,
  type MoveBreachLineageProofRow,
  type MoveBreachLineageVerdict,
  type MoveBreachObservationAnomalyRow,
  type MoveBreachOperationSnapshot,
  type MoveBreachPermittedOperatorAction,
  type MoveBreachWalletSnapshot,
  type MoveInvariantBreachQuarantineInput,
  type MoveInvariantBreachQuarantineResult,
  type MoveInvariantBreachStore,
  type OperatorRecoveryActionCatalog,
  type WalletLifecycleState,
} from "./invariant-breach.js";
