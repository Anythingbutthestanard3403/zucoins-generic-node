// Concern barrel for expected-artifact surfaces (the artifacts concern). Public frozen surface for
// the concern-manifest registry assembly and platform consumers that must verify expected-artifact
// material without re-declaring node shapes (the scan-scope freeze). This is NOT the package index
// (src/index.ts, the concern-manifest registry-owned) — it is the src/artifacts/ concern's own export sequence.
//
// expected-artifacts.contract.ts, signing-contract.ts, and verify.ts each export a SOURCE
// citation constant, so this barrel names every export explicitly instead of using
// `export *` — a bare star-export would collide on SOURCE.

export {
  EXPECTED_ARTIFACT_PURPOSES,
  CANONICAL_VERSION,
  ARTIFACT_SIGNING_KEY_ROLE,
  SUITE_PREIMAGE_CONSTRUCTION,
  ARTIFACT_FIELD_TYPES,
  ARTIFACT_FIELD_ROLES,
  RECEIVE_EXPECTED,
  MOVE_INTERNAL_EXPECTED,
  SEND_EXTERNAL_EXPECTED,
  EXPECTED_ARTIFACTS,
  type ExpectedArtifactPurpose,
  type ArtifactFieldType,
  type ArtifactFieldRole,
  type ArtifactFieldDescriptor,
  type ExpectedArtifactManifest,
} from "./expected-artifacts.contract.ts";

export {
  ARTIFACT_KEY_ROLE,
  NODE_IDENTITY_KEY_STATUSES,
  KEY_VALIDITY_RULES,
  KEY_REJECT_REASONS,
  isKeyAcceptedForVerification,
  isKeyAcceptedForNewSigning,
  type NodeIdentityKeyStatus,
  type NodeIdentityKeyRecord,
  type KeyRejectReason,
  type KeyVerdict,
} from "./signing-contract.ts";

export {
  VERIFY_REJECT_REASONS,
  verifyExpectedArtifact,
  type ArtifactVerificationCrypto,
  type ArtifactEnvelope,
  type VerifyInput,
  type VerifyRejectReason,
  type VerifyResult,
} from "./verify.ts";

export { ARTIFACTS_CONCERN_MANIFEST } from "./manifest.ts";
