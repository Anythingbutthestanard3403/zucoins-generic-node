export {
  MOVE_INTERNAL_POLICY,
  PROOF_POLICIES,
  RECEIVE_EXTERNAL_POLICY,
  SEND_EXTERNAL_POLICY,
} from "./policies.js";

export { evaluateProof, getPolicy, getRequiredEvidenceKinds } from "./evaluate.js";

// the three operation policies that decide the frozen predicate lists above from
// real evidence. One per operation kind; three public money operations admits no fourth.
export { evaluateReceiveProof } from "./policies/receive.js";
export { evaluateMoveProof } from "./policies/move.js";
export { evaluateSendProof } from "./policies/send.js";

export type {
  ArtifactVerification,
  EvaluatedPredicate,
  OperationProofResult,
} from "./policies/shared.js";
export type {
  ReceiveExpectedArtifact,
  ReceivePolicyInput,
  ReceiverBaseline,
} from "./policies/receive.js";
export type {
  MoveDestinationCustody,
  MoveDestinationPath,
  MoveExpectedArtifact,
  MovePolicyInput,
  MoveSourceCustody,
  MoveSourcePath,
  SpawnedMoveParent,
} from "./policies/move.js";
export type {
  DeliveredPartial,
  SendExpectedArtifact,
  SendPolicyInput,
  SendRecipientConfirmation,
  SendSubmitEvidence,
  SignIntentRow,
  TotpApproval,
} from "./policies/send.js";

export type {
  EvidenceKind,
  EvidenceRequirement,
  OperationType,
  PredicateId,
  PredicateResult,
  ProofEvaluationInput,
  ProofPolicy,
  ProofVerdict,
  VerificationStep,
  VerdictOutcome,
} from "./types.js";
