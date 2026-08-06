import type { ProofPolicy } from "./types.js";

export const RECEIVE_EXTERNAL_POLICY: ProofPolicy = {
  operationType: "RECEIVE_EXTERNAL",
  requiredEvidence: [
    { kind: "gateway_confirmation", mandatory: true },
    { kind: "observation_match", mandatory: true },
  ],
  verificationSteps: [
    { predicate: "successor_relationship", evidenceKinds: ["gateway_confirmation"] },
    { predicate: "receiver_role_match", evidenceKinds: ["observation_match"] },
    { predicate: "predecessor_signature_bindsource", evidenceKinds: ["observation_match"] },
    { predicate: "receiver_pubkey_match", evidenceKinds: ["observation_match"] },
    { predicate: "amount_exact", evidenceKinds: ["observation_match"] },
    { predicate: "version_constants", evidenceKinds: ["observation_match"] },
    { predicate: "message_discriminator", evidenceKinds: ["observation_match"] },
    { predicate: "expiry_constraints", evidenceKinds: ["observation_match"] },
    { predicate: "dual_signatures_verify", evidenceKinds: ["observation_match"] },
    { predicate: "artifact_digest_verify", evidenceKinds: ["observation_match"] },
  ],
  passCriteria: "ALL_PREDICATES",
  failCriteria: "ANY_DETERMINATE_MISMATCH",
  indeterminateCriteria: "READ_FAILURE_OR_ANOMALY",
};

export const MOVE_INTERNAL_POLICY: ProofPolicy = {
  operationType: "MOVE_INTERNAL",
  requiredEvidence: [
    { kind: "source_path_confirmation", mandatory: true },
    { kind: "destination_path_confirmation", mandatory: true },
  ],
  verificationSteps: [
    { predicate: "send_artifact_verify", evidenceKinds: ["source_path_confirmation"] },
    { predicate: "source_role_verify", evidenceKinds: ["source_path_confirmation"] },
    { predicate: "source_predecessor_bind", evidenceKinds: ["source_path_confirmation"] },
    { predicate: "destination_role_verify", evidenceKinds: ["destination_path_confirmation"] },
    { predicate: "destination_predecessor_bind", evidenceKinds: ["destination_path_confirmation"] },
    { predicate: "source_balance_delta", evidenceKinds: ["source_path_confirmation"] },
    { predicate: "destination_balance_delta", evidenceKinds: ["destination_path_confirmation"] },
    {
      predicate: "artifact_key_bindsource",
      evidenceKinds: ["source_path_confirmation", "destination_path_confirmation"],
    },
    { predicate: "spawn_continuity", evidenceKinds: ["source_path_confirmation"] },
  ],
  passCriteria: "ALL_PREDICATES",
  failCriteria: "ANY_DETERMINATE_MISMATCH",
  indeterminateCriteria: "READ_FAILURE_OR_ANOMALY",
};

export const SEND_EXTERNAL_POLICY: ProofPolicy = {
  operationType: "SEND_EXTERNAL",
  requiredEvidence: [
    { kind: "recipient_confirmation", mandatory: true },
    { kind: "submit_evidence", mandatory: true },
  ],
  verificationSteps: [
    { predicate: "send_artifact_verify", evidenceKinds: ["submit_evidence"] },
    { predicate: "approval_consumed", evidenceKinds: ["submit_evidence"] },
    { predicate: "sign_intent_bind", evidenceKinds: ["submit_evidence"] },
    { predicate: "preimage_exact_match", evidenceKinds: ["submit_evidence"] },
    { predicate: "source_sender_bind", evidenceKinds: ["submit_evidence"] },
    { predicate: "destination_key_approved", evidenceKinds: ["recipient_confirmation"] },
    { predicate: "destination_predecessor_consistent", evidenceKinds: ["recipient_confirmation"] },
    { predicate: "source_exact_head", evidenceKinds: ["submit_evidence"] },
    { predicate: "single_partial_delivery", evidenceKinds: ["submit_evidence"] },
  ],
  passCriteria: "ALL_PREDICATES",
  failCriteria: "ANY_DETERMINATE_MISMATCH",
  indeterminateCriteria: "READ_FAILURE_OR_ANOMALY",
};

export const PROOF_POLICIES: Record<ProofPolicy["operationType"], ProofPolicy> = {
  RECEIVE_EXTERNAL: RECEIVE_EXTERNAL_POLICY,
  MOVE_INTERNAL: MOVE_INTERNAL_POLICY,
  SEND_EXTERNAL: SEND_EXTERNAL_POLICY,
};
