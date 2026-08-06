// node-identity-key pinning workflow.
//
// Import via `@zucoins/node-core/verifier/consumer/pinning`.
//
// Composes pin predicates with authenticateArtifact.
// No private keys; no signing; no hosted-platform pin source (relay-notice wire value).

export {
  DISCOVERY_PATH,
  PIN_SOURCE_CHANNELS,
  PINNING_REFUSE_REASONS,
  type ArtifactEnvelope,
  type BootstrapPinInput,
  type CachedIdentityPin,
  type DiscoveryIdentityWire,
  type DiscoveryKeyValidityWire,
  type DiscoveryKeyWireEntry,
  type NodeIdentityKeyRecord,
  type NodeIdentityKeyStatus,
  type NodeIdentityPin,
  type NodeVerificationKey,
  type OriginClass,
  type PinAndAuthenticateInput,
  type PinRejectReason,
  type PinningRefuseReason,
  type PinningVerdict,
  type PinSourceChannel,
} from "./types.js";

export {
  DEFAULT_PIN_REFRESH_AFTER_MS,
  assertOriginAuthorized,
  bootstrapIdentityPin,
  discoveryEntryToKeyRecord,
  fingerprintNodeIdentityKey,
  pinAndAuthenticateArtifact,
  pinRefreshDue,
  repinAfterRotation,
  resolvePinnedKeyFromCache,
  resolvePinnedKeyFromDiscovery,
} from "./workflow.js";

// Re-export the frozen primitives the workflow rests on so a consumer
// can pin-compare without a second import path.
export {
  identityKeyFingerprint,
  isSubstitutionProof,
  verifyIdentityPin,
  ORIGIN_CLASSES,
  ORIGIN_CLASS_CLAIMS,
} from "@zucoins/generic-node-contracts/instruction-origin";
