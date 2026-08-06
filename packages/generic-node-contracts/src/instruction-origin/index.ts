// the presentation-scope concern — Public surface of the instruction-origin concern. Concern-local barrel owned by the
// the presentation-scope concern.1/.2/.3 slices; NOT the package index (src/index.ts, owned by the concern-manifest registry).

export {
  type OriginClass,
  type OriginClassClaims,
  ORIGIN_CLASSES,
  ORIGIN_CLASS_CLAIMS,
  claimsForOriginClass,
  isSubstitutionProof,
} from "./origin-classes.contract.ts";

export {
  type NodeIdentityPin,
  type NodePublishedIdentity,
  type PinRejectReason,
  type PinVerdict,
  type PublishedIdentityKeyEntry,
  DISCOVERY_PATH,
  PIN_REJECT_REASONS,
  identityKeyFingerprint,
  isRotationEvidenceChainCoherent,
  isRotationEvidenceChainMonotonic,
  verifyIdentityPin,
} from "./identity-pin.contract.ts";

export {
  type CapabilityDescriptor,
  type CapabilityId,
  type CapabilityStatus,
  type NonCapability,
  CAPABILITY_IDS,
  CAPABILITY_MANIFEST,
  CAPABILITY_STATUSES,
  NON_CAPABILITIES,
  capabilityDescriptor,
  isCapabilityId,
  isFrozenAvailable,
  isNonCapability,
} from "./capability-manifest.contract.ts";

export {
  type PresentationHandoff,
  type PresentationHandoffField,
  type SubstitutionThreatRow,
  PRESENTATION_HANDOFF_FIELDS,
  SUBSTITUTION_THREAT_TABLE,
  isThreatTableRowConsistent,
  isValidPresentationHandoffShape,
} from "./presentation-handoff.contract.ts";

export {
  type ConsumerRejectReason,
  type ConsumerVerdict,
  type ConsumerVerifyInput,
  CONSUMER_REJECT_REASONS,
  verifyPresentationHandoff,
} from "./consumer-boundary.ts";

export { INSTRUCTION_ORIGIN_CONCERN_MANIFEST } from "./manifest.ts";

export {
  type NodeIdentityKeyRecord,
  type NodeIdentityKeyStatus,
  ARTIFACT_KEY_ROLE,
  NODE_IDENTITY_KEY_STATUSES,
  isKeyAcceptedForVerification,
} from "../artifacts/signing-contract.ts";
