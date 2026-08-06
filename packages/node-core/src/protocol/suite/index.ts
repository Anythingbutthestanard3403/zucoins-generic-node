// Public surface of the canonical suite-tuple serializer. This barrel deliberately
// exposes only: the one serializer entrypoint (which returns a finished preimage, never an
// intermediate object a caller could re-stringify), the registry query/dispatch helpers, the field encoders (for
// composition and negative testing), the error types, and the census/prohibition datum. There is no
// exported path that yields an unfinished suite object — ad-hoc suite serialization is prohibited
// by the serializer contract, and this shape is the first line of that enforcement.
//
// extends this barrel with the per-purpose typed builders, strict parsers, and
// verifiers the serializer contract requires ("each tuple has one builder... and one
// parser/verifier"), plus the Ed25519 point-validation module the reporting-register PoP
// verifier depends on. Nothing above this point (own exports) is modified.

export {
  serializeSuiteTuple,
  SuiteSerializeError,
  type SuiteSerializeReason,
  type SuiteTuplePreimage,
  type SuiteTupleValues,
} from "./serialize.js";

export {
  type SuiteKeyClass,
  type SuiteFieldSpec,
  type SuitePurposeSpec,
  SUITE_PURPOSES,
  NEUTRAL_EVENT_TYPES,
  suitePurposeSpec,
  keyClassForPurpose,
  mayKeyClassSign,
} from "./registry.js";

export {
  type CanonicalEncoder,
  type CanonicalJson,
  type JsonObject,
  type JsonScalar,
  type FieldEncodingReason,
  InvalidFieldError,
  closedEnum,
  encodeAfterLanding,
  encodeAnchor,
  encodeCanonicalTimestamp,
  encodeCanonicalVersion,
  encodeEd25519Signature,
  encodeEmptyOrSignature,
  encodeExpiryUnixTimeSecs,
  encodeHttpMethod,
  encodeLabel,
  encodeOriginPath,
  encodePositiveDecimalSeq,
  encodePositiveZkzAmount,
  encodeSha256Hex,
  encodeSourceSelector,
  encodeUuid,
  encodeWalletPublicKey,
  encodeZkzBalance,
} from "./encoders.js";

export {
  type SuitePurposeCensus,
  type SuiteSerializerManifest,
  SUITE_SERIALIZER_ENTRYPOINT,
  EXTERNAL_SUITE_SERIALIZATION_PROHIBITED,
  buildSuiteSerializerManifest,
} from "./manifest.js";

export type { AfterLanding, NodeEventType, SourceSelector, WalletStateKind } from "./composites.js";

export { WeakEd25519KeyError, assertPrimeOrderEd25519PublicKey } from "./ed25519-point.js";

export {
  buildDestinationBless,
  buildDeviceEnrol,
  buildMoveInternalExpectedArtifact,
  buildNodeEvent,
  buildReceiveExpectedArtifact,
  buildReportRequest,
  buildReportingRegister,
  buildSendExternalApproval,
  buildSendExternalExpectedArtifact,
  buildWalletHeadFingerprint,
  type DestinationBlessInput,
  type DeviceEnrolInput,
  type MoveInternalExpectedInput,
  type NodeEventInput,
  type ReceiveExpectedInput,
  type ReportRequestInput,
  type ReportingRegisterInput,
  type SendExternalApprovalInput,
  type SendExternalExpectedInput,
  type WalletHeadFingerprintInput,
} from "./builders.js";

export {
  parseDestinationBless,
  parseDeviceEnrol,
  parseMoveInternalExpectedArtifact,
  parseNodeEvent,
  parseReceiveExpectedArtifact,
  parseReportRequest,
  parseReportingRegister,
  parseSendExternalApproval,
  parseSendExternalExpectedArtifact,
  parseWalletHeadFingerprint,
  SuiteParseError,
  type DestinationBlessPayload,
  type DeviceEnrolPayload,
  type MoveInternalExpectedPayload,
  type NodeEventPayload,
  type ParsedSuiteTuple,
  type ReceiveExpectedPayload,
  type ReportRequestPayload,
  type ReportingRegisterPayload,
  type SendExternalApprovalPayload,
  type SendExternalExpectedPayload,
  type SuiteParseReason,
  type WalletHeadFingerprintPayload,
} from "./parsers.js";

export {
  verifyDestinationBless,
  verifyDeviceEnrol,
  verifyMoveInternalExpectedArtifact,
  verifyNodeEvent,
  verifyReceiveExpectedArtifact,
  verifyReportRequest,
  verifyReportingRegisterProof,
  verifySendExternalApprovalDeviceSignature,
  verifySendExternalExpectedArtifact,
  SuiteVerifyError,
  type ReportingRegisterProof,
  type ResolvedSuiteVerificationKey,
  type SignedSuiteTupleEnvelope,
  type SuiteVerifyReason,
} from "./verify.js";
