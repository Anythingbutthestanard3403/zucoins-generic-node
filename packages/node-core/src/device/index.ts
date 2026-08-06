// Device enrollment, revocation, and break-glass recovery — public surface.

export type {
  EnrolledDeviceKey,
  DeviceEnrolmentTuple,
  DeviceEnrolmentResult,
  DeviceEnrolmentRejectionCode,
  DeviceSignatureVerificationResult,
  DeviceSignatureRejectionCode,
  EnrollmentChallenge,
  EnrollmentChallengeStatus,
  EnrollmentAuditEntry,
  EnrollmentAuditOutcome,
  BreakGlassAuthority,
  BreakGlassRatifyResult,
  BreakGlassTotpResetResult,
  BreakGlassAuditEntry,
  BreakGlassAuditOutcome,
  DeviceRevocationResult,
  DeviceRevocationAuditEntry,
  DeviceRevocationAuditOutcome,
} from "./types.js";
export { DEVICE_LIFECYCLE_FORBIDDEN_CUSTODY_FIELDS } from "./types.js";
export type { DeviceKeyStore } from "./store.js";
export { InMemoryDeviceKeyStore } from "./in-memory-store.js";
export { validateDeviceLabel, type LabelValidationResult } from "./label-validation.js";
export {
  verifyAndEnrolDevice,
  verifyAndEnrolGenesisDevice,
  type EnrolmentVerificationInput,
  type EnrolmentDeps,
  type GenesisEnrolmentInput,
} from "./enrollment.js";
export { verifyDeviceSignature, type DeviceSignatureInput } from "./verify.js";
export {
  issueEnrollmentChallenge,
  consumeEnrollmentChallenge,
  invalidateIssuedEnrollmentChallenges,
  InMemoryEnrollmentChallengeStore,
  DEVICE_ENROL_PURPOSE,
  ENROLLMENT_CHALLENGE_WINDOW_MS,
  type EnrollmentChallengeStore,
  type IssueEnrollmentChallengeInput,
  type IssueEnrollmentChallengeResult,
  type ConsumeChallengeResult,
} from "./challenge.js";
export {
  InMemoryEnrollmentAuditLog,
  type EnrollmentAuditLog,
} from "./audit.js";
export type { BreakGlassAuthorityStore } from "./break-glass-store.js";
export { InMemoryBreakGlassAuthorityStore } from "./break-glass-store.js";
export {
  ratifyBreakGlassAuthority,
  resetTotpUnderBreakGlass,
  buildBreakGlassTotpResetPreimage,
  BREAK_GLASS_TOTP_RESET_PURPOSE,
  InMemoryBreakGlassAuditLog,
  type BreakGlassAuditLog,
  type RatifyBreakGlassInput,
  type BreakGlassTotpResetInput,
  type TotpFactorResetPort,
} from "./break-glass.js";
export {
  revokeDevice,
  deviceRowStillPresent,
  NoopDeviceRevocationSideEffects,
  InMemoryDeviceRevocationAuditLog,
  type RevokeDeviceInput,
  type RevokeDeviceDeps,
  type DeviceRevocationSideEffects,
  type DeviceRevocationAuditLog,
} from "./revocation.js";

// destination bless device authorizer + SQL mounts.
export {
  createDeviceBlessingAuthorizer,
  type BlessingAuthorizeInput,
  type BlessingAuthorizeOk,
  type DeviceBlessingAuthorizer,
  type DeviceBlessingAuthorizerDeps,
  type LookUpActiveDevice,
  type PersistBlessingArtifact,
  type DestinationBlessingArtifactRow,
  type AppendBlessingAudit,
  type DestinationBlessAuditEntry,
} from "./blessing-authorizer.js";
export {
  createSqlActiveDeviceLookup,
  createSqlBlessingArtifactPersister,
  createSqlBlessingAuditAppender,
  createSqlDeviceKeyStore,
  createSqlEnrollmentChallengeStore,
  type DeviceSqlExecutor,
  type DeviceSqlQueryResult,
  type SqlDeviceKeyStore,
  type SqlEnrollmentChallengeStore,
} from "./sql-device-store.js";

// Second-device QR enrolment.
export {
  SECOND_DEVICE_QR_KEYS,
  SECOND_DEVICE_QR_FORBIDDEN_KEYS,
  InMemorySecondDeviceCeremonyStore,
  issueSecondDeviceCeremony,
  bindSecondDevicePublicKey,
  authorizeSecondDeviceEnrol,
  completeSecondDeviceEnrol,
  peekSecondDeviceCeremony,
  buildSecondDeviceQrPayload,
  assertSafeSecondDeviceQr,
  type SecondDeviceCeremony,
  type SecondDeviceCeremonyStatus,
  type SecondDeviceCeremonyStore,
  type SecondDeviceQrPayload,
  type SecondDeviceIssueResult,
  type SecondDeviceBindResult,
  type SecondDeviceAuthorizeResult,
  type SecondDeviceCompleteResult,
} from "./second-device-enrol.js";
