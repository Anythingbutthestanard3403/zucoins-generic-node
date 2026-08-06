import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

// Frozen union lives in @zucoins/generic-node-contracts (single source);
// alias kept so the proof module's existing OperationType references stay unchanged.
export type OperationType = OperationKind;

export type EvidenceKind =
  | "gateway_confirmation"
  | "observation_match"
  | "source_path_confirmation"
  | "destination_path_confirmation"
  | "recipient_confirmation"
  | "submit_evidence";

export type PredicateId =
  | "successor_relationship"
  | "receiver_role_match"
  | "predecessor_signature_bindsource"
  | "receiver_pubkey_match"
  | "amount_exact"
  | "version_constants"
  | "message_discriminator"
  | "expiry_constraints"
  | "dual_signatures_verify"
  | "artifact_digest_verify"
  | "source_role_verify"
  | "source_predecessor_bind"
  | "destination_role_verify"
  | "destination_predecessor_bind"
  | "source_balance_delta"
  | "destination_balance_delta"
  | "artifact_key_bindsource"
  | "spawn_continuity"
  | "send_artifact_verify"
  | "approval_consumed"
  | "sign_intent_bind"
  | "preimage_exact_match"
  | "source_sender_bind"
  | "destination_key_approved"
  | "destination_predecessor_consistent"
  | "source_exact_head"
  | "single_partial_delivery";

export type VerdictOutcome = "VERIFIED" | "REJECTED" | "INDETERMINATE";

export interface EvidenceRequirement {
  readonly kind: EvidenceKind;
  readonly mandatory: boolean;
}

export interface VerificationStep {
  readonly predicate: PredicateId;
  readonly evidenceKinds: readonly EvidenceKind[];
}

export interface ProofPolicy {
  readonly operationType: OperationType;
  readonly requiredEvidence: readonly EvidenceRequirement[];
  readonly verificationSteps: readonly VerificationStep[];
  readonly passCriteria: "ALL_PREDICATES";
  readonly failCriteria: "ANY_DETERMINATE_MISMATCH";
  readonly indeterminateCriteria: "READ_FAILURE_OR_ANOMALY";
}

export interface PredicateResult {
  readonly predicate: PredicateId;
  readonly passed: boolean;
  readonly determinate: boolean;
}

export interface ProofEvaluationInput {
  readonly operationType: OperationType;
  readonly predicateResults: readonly PredicateResult[];
  readonly evidencePresent: readonly EvidenceKind[];
}

export interface ProofVerdict {
  readonly outcome: VerdictOutcome;
  readonly operationType: OperationType;
  readonly failedPredicates: readonly PredicateId[];
  readonly missingEvidence: readonly EvidenceKind[];
}
