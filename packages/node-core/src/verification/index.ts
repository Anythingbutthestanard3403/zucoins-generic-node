// public surface of the verification-complete acknowledgement concern
//.
// Registered as the `verification` module in test/boundaries.test.ts.

export {
  ACK_EVIDENCE_ROLES,
  ACK_VERDICTS,
  LEASE_RELEASE_STATUSES,
  REQUIRED_EVIDENCE_ROLES,
  clampReleaseToVerdict,
  evaluateGroupRelease,
  expectedWalletsForOperation,
  isAckEvidenceRole,
  isAckVerdict,
  validateEvidenceIdentity,
  validateEvidenceSet,
  validateRoleSet,
  type AckEvidenceRole,
  type AckVerdict,
  type DurableEvidenceFact,
  type EvidenceEntry,
  type EvidenceSetFailure,
  type GroupOperationFact,
  type GroupReleaseDecision,
  type GroupReleaseFacts,
  type GroupReleaseReason,
  type LeaseReleaseStatus,
  type OperationWalletAssignment,
} from "./predicates.js";

export {
  AcknowledgementError,
  AcknowledgementInsertConflict,
  computeEvidenceSetSha256,
  createAcknowledgementService,
  type AckObservationRef,
  type AckOpenMembership,
  type AckOperationFacts,
  type AckWalletEvidenceInput,
  type AcknowledgementDraft,
  type AcknowledgementFailureReason,
  type AcknowledgementInput,
  type AcknowledgementOutcome,
  type AcknowledgementResponseBody,
  type AcknowledgementService,
  type AcknowledgementServiceDeps,
  type AcknowledgementStore,
  type StoredAcknowledgement,
} from "./acknowledgement.js";

export {
  ACK_STATEMENTS,
  createSqlAcknowledgementStore,
  parseFrozenResponseBody,
  type AckSqlExecutor,
  type AckSqlQueryResult,
} from "./acknowledgement-sql.js";

// NODE_VERIFIED admission policy (ZTR-1301) — fail-closed ops.allow_node_verified.
export {
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
  admitVerificationMode,
  createSqlAllowNodeVerifiedPolicy,
  isNodeVerifiedAllowedByPolicy,
  parseAllowNodeVerifiedPolicyDocument,
  parseAllowNodeVerifiedPolicyStructure,
  refuseAllNodeVerifiedPolicy,
  resolveVerificationMode,
  serializeAllowNodeVerifiedPolicyDocument,
  InMemoryAllowNodeVerifiedPolicy,
  type AllowNodeVerifiedDisabledReason,
  type AllowNodeVerifiedImplementerEntry,
  type AllowNodeVerifiedPolicyDocument,
  type AllowNodeVerifiedPolicyPort,
  type AllowNodeVerifiedPolicySetMeta,
  type AllowNodeVerifiedSqlExecutor,
  type VerificationMode,
} from "./allow-node-verified-policy.js";
