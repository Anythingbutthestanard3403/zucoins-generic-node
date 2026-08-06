// the approval concern — Public surface of the approval concern (one approval → one exact external partial;
// the approval-tuple freeze). Concern-local barrel owned by the approval concern group; NOT the package index (src/index.ts
// owned by the concern-manifest registry).

export {
  type ApprovalPurpose,
  type ApprovalFieldType,
  type ApprovalFieldRole,
  type ApprovalFieldDescriptor,
  type ApprovalTupleManifest,
  type ApprovalOrderingPhase,
  APPROVAL_PURPOSE,
  APPROVAL_CANONICAL_VERSION,
  APPROVAL_PREIMAGE_CONSTRUCTION,
  APPROVAL_AUTH,
  APPROVAL_ORDERING,
  APPROVAL_FORMATION_TIME_FACTS,
  APPROVAL_FIELD_TYPES,
  APPROVAL_FIELD_ROLES,
  APPROVAL_TUPLE,
  SOURCE_SELECTOR_SIGNED_CLOSURE,
} from "./approval-tuple.contract.ts";

export {
  type FormationState,
  type SignIntentBoundInput,
  FORMATION_STATES,
  FORMATION_TRANSITIONS,
  APPROVAL_CARDINALITY,
  SIGN_INTENT_BOUND_INPUTS,
  SIGN_INTENT_FROZEN_AFTER_EXISTS,
  APPROVAL_CONSUMPTION,
  REDELIVERY_RULE,
  REPLACEMENT_RULE,
  TIMER_SEPARATION,
  CONSUMED_APPROVAL_PURPOSE,
  STRUCTURAL_UNIQUENESS,
} from "./sign-intent.contract.ts";

export {
  type CrashDurableState,
  type CrashMatrixRow,
  type CrashPoint,
  type RecoveryAction,
  type ForbiddenRecoveryAction,
  CRASH_DURABLE_STATES,
  RECOVERY_ACTIONS,
  FORBIDDEN_RECOVERY_ACTIONS,
  CRASH_MATRIX,
  CRASH_POINTS,
  DETERMINISTIC_RESIGN,
  INVARIANT_BREACH_PREDICATE,
  APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD,
} from "./crash-recovery.contract.ts";

export {
  type ApprovalEnvelope,
  type ApprovalDeviceVerificationCrypto,
  type ApprovalVerifyResult,
  type ApprovalVerifyRejectReason,
  type ApprovalConsumedNoSignIntentEvidence,
  APPROVAL_VERIFY_REJECT_REASONS,
  hasSuiteDomainPrefix,
  verifyApprovalPreimage,
  verifyApprovalDeviceSignature,
  recoveryActionFor,
  classifyApprovalConsumedNoSignIntent,
} from "./verify.ts";

export {
  APPROVAL_GOLDEN,
  APPROVAL_CONCERN_MANIFEST,
  buildApprovalManifest,
} from "./manifest.ts";
