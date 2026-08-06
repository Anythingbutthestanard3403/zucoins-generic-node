/**
 * Package entry surface for `@zucoins/generic-node-contracts`. The root barrel exposes the
 * package-wide concern registry — the closed assembly of every self-registered `ConcernManifest` —
 * the canonical manifest contract type, and testkit helpers for downstream freeze/assertion use.
 * Per-concern production surfaces are reached through their own subpath exports
 * (e.g. `@zucoins/generic-node-contracts/amounts`) so a consumer that needs a single concern does
 * not pull the whole package graph; the subpaths are declared in this package's `package.json`
 * `exports` map.
 *
 * Governing doc: `CONTRACT.md` (package contract).
 */

// --- Concern barrels (frozen by their own concerns). Required for any cross-package consumer (the node-core consumer / packages/node-core is
// the first) to import this package by name instead of reaching into its src/ directly. ---

export * from "./observation/index.ts";
export * from "./amounts/index.ts";

// Reporting rejection taxonomy (platform branches on `code`).
// Also available via `@zucoins/generic-node-contracts/auth-errors`.
export {
  type ReportingRejectionCode,
  REPORTING_REJECTION_CODES,
  REJECTION_STATUS,
} from "./auth-errors/reporting-rejection.ts";

// The four reporting concern barrels, consumed by the node-core runtime
// verification slice. reporting-tuples and reporting-behavior collide with nothing; the two
// explicit lists below dodge the three cross-concern name collisions without renames:
// `VerifyResult` (reporting-auth vs reporting-tuples) and `ReportingKeyState` /
// `REPORTING_KEY_STATES` (reporting-persistence vs reporting-auth, byte-identical twins).
export * from "./reporting-tuples/index.ts";
export * from "./reporting-behavior/index.ts";
export {
  type ReportingRegisterPayload,
  REPORTING_REGISTER_PURPOSE,
  REPORTING_REGISTER_CANONICAL_VERSION,
  REPORTING_KEY_ENROL_WINDOW_SECS,
  REGISTER_FIELD_ORDER,
  buildRegisterPreimage,
  REGISTER_GOLDEN_PAYLOAD,
  REGISTER_GOLDEN_PREIMAGE,
  type ReportingKeyClass,
  REPORTING_KEY_CLASSES,
  REPORTING_KEY_ALLOWED_PURPOSES,
  NODE_EVENT_KEY_ALLOWED_PURPOSES,
  REPORTING_CROSS_PURPOSE_FORBIDDEN,
  ALLOWED_CREDENTIAL_MECHANISMS,
  FORBIDDEN_CREDENTIAL_MECHANISMS,
  V2_REPORTING_PURPOSES,
  LEGACY_PUSH_PURPOSES,
  ED25519_SMALL_ORDER_ENCODINGS_HEX,
  type ReportingKeyBinding,
  type ReportingKeyState,
  type KeyStateTransition,
  REPORTING_KEY_STATES,
  REPORTING_KEY_TRANSITIONS,
  TERMINAL_KEY_STATES,
  REPORTING_VERIFIER_ORDER,
  ROTATION_MODEL,
  RESTORE_GUARD,
  BOOTSTRAP_TRUST_ROOT,
  type RegisterProofCallbacks,
  REGISTER_PROOF_VERIFICATION_STAGES,
  decodeCanonicalReportingPublicKey,
  decodeCanonicalEd25519Signature,
  verifyRegisterProofOfPossession,
  verifyRegisterPreimage,
  reportingKeyMaySign,
  isLegalReportingKeyTransition,
  requestTupleMatchesBinding,
  credentialMechanismAllowed,
  REGISTER_GOLDEN_PREIMAGE_SHA256,
  REGISTER_GOLDEN_POP_SIGNATURE,
  REGISTER_GOLDEN_REPORTING_PUBKEY,
  type ReportingAuthManifest,
  reportingAuthConcernManifest,
  buildReportingAuthManifest,
} from "./reporting-auth/index.ts";
export {
  type NonceClaim,
  type NonceClaimOutcome,
  type NonceClaimResult,
  type ReportingNoncePurpose,
  type RegistrationEvidenceMode,
  type ReportingRouteClass,
  type DownstreamResult,
  type BurnDecisionOutcome,
  type BurnDecision,
  type LifecycleCommitOutcome,
  type LifecycleCommitResult,
  type LifecycleHead,
  type LifecycleEvent,
  type LifecycleKeyTransition,
  type AuthoritativeKeyState,
  type ReportingLifecycleEventType,
  type ReportingKeyEligibilityState,
  type RegistrationEvidenceOutcome,
  type RegistrationCrossBinding,
  type RegistrationCrossBindingOutcome,
  type DurableRegistrationNonceEvidence,
  type DurableEnrolmentEvidence,
  type BootstrapEvidenceProjection,
  type RotationAuthorizerEvidence,
  type LogicalFingerprintInput,
  type PersistedExactResponse,
  type MutationBindingProjection,
  type MutationAtomicityOutcome,
  type RestoreMarkers,
  type ExternalRestoreAuthority,
  type RestoredReportingState,
  type GuardedFingerprintClaim,
  type CompletedIdempotencyResult,
  type PostBurnOutcome,
  type PostBurnDecision,
  NONCE_UNIQUENESS_FIELDS,
  NONCE_SCOPE_EXCLUDED_FIELDS,
  REPORTING_NONCE_PURPOSES,
  REPORTING_NONCE_FIELDS,
  REPORTING_KEY_ID_NULLABILITY,
  REPORTING_SIGNED_WINDOW_MS,
  PRE_BURN_CHECKS,
  BURN_TRANSACTION_STEPS,
  POST_BURN_STAGES,
  MUTATION_IDEMPOTENCY_UNIQUENESS_FIELDS,
  LOGICAL_FINGERPRINT_FIELDS,
  LOGICAL_FINGERPRINT_EXCLUDED_FIELDS,
  FINGERPRINT_GUARDED_ROUTE_IDS,
  GUARDED_FINGERPRINT_UNIQUENESS_FIELDS,
  GUARDED_FINGERPRINT_PARTIAL_UNIQUENESS,
  MUTATION_IDEMPOTENCY_FIELDS,
  MUTATION_IDEMPOTENCY_PERSISTENCE,
  MUTATION_EVIDENCE_BINDING_FIELDS,
  MUTATION_EVIDENCE_IMMUTABILITY,
  MUTATION_ROUTE_RETENTION,
  REPORTING_LIFECYCLE_HEAD_FIELDS,
  REPORTING_LIFECYCLE_EVENT_UNIQUENESS_FIELDS,
  REPORTING_LIFECYCLE_EVENT_FIELDS,
  REPORTING_LIFECYCLE_EVENT_TYPES,
  LEGAL_LIFECYCLE_KEY_TRANSITIONS,
  LIFECYCLE_EVENT_HASH_CHAIN,
  REPORTING_KEY_IDENTITY_ALLOWED_FIELDS,
  REPORTING_KEY_IDENTITY_FORBIDDEN_FIELDS,
  REPORTING_KEY_OVERLAP_MS,
  REGISTRATION_EVIDENCE_MODES,
  REGISTRATION_EVIDENCE_FIELDS,
  IDEMPOTENCY_KEY_CONTRACT,
  REPORTING_RETENTION,
  RESTORE_POLICY,
  nonceClaimHasValidKeySemantics,
  reportingSignedWindowIsValid,
  nonceRetentionForRoute,
  claimSharedNonce,
  decideReportingBurn,
  commitLifecycleHead,
  priorKeyEligible,
  evaluateRegistrationEvidence,
  evaluateRegistrationCrossBinding,
  sameLogicalFingerprint,
  persistExactResponse,
  replayExactResponse,
  decideMutationAtomicity,
  mutationEvidenceBindingsMatch,
  restoreRequiresAuthHold,
  reportingAdmissionAllowed,
  reportingKeyIdentityIsPublicOnly,
  idempotencyKeyIsValid,
  guardedFingerprintAlreadyClaimed,
  decidePostBurn,
  type ReportingPersistenceManifest,
  reportingPersistenceConcernManifest,
  buildReportingPersistenceManifest,
} from "./reporting-persistence/index.ts";

// --- ConcernManifest type and factory (the concern-manifest registry leave-behind shape) ---

export type { ConcernManifest } from "./testkit/concernManifest.ts";
export { defineConcernManifest } from "./testkit/concernManifest.ts";

// --- Registry assembly (the concern-manifest registry package entry surface) ---

export type { RegisteredConcern } from "./registry.ts";
export {
  CONCERN_REGISTRY,
  CONCERN_MANIFESTS,
  CONCERN_MANIFEST_COUNT,
  concernByDir,
} from "./registry.ts";

// --- Testkit helpers (for downstream freeze/assertion use) ---

// `testkit/freeze.ts` is deliberately NOT re-exported here: it imports `vitest` at module
// top level, and `vitest` is a devDependency. Re-exporting it put a test framework in the
// runtime import graph of every barrel consumer — including the custody entry point
// (`apps/generic-node/dist/main.js` -> node-core -> protocol/wallet-role.ts -> this barrel),
// which made the production image (built with `pnpm install --prod`, so no vitest) die at
// boot with ERR_MODULE_NOT_FOUND. Same principle as the zero-I/O leaf rule below. The freeze
// helpers are in-package test utilities; every consumer imports `./testkit/freeze.ts`
// relatively. Guarded by `index.test.ts` "root barrel reaches no test framework".
export { toSortedPlainObject } from "./testkit/serialize.ts";

// --- Fixture provenance registry (the fixture-provenance surface) — the pure assembly only. The disk-verification
// side (`fixture-provenance/verify.ts`, fs/crypto) is deliberately NOT re-exported here so
// the root barrel stays a zero-I/O leaf; tests and the fixture-provenance drift gate drift gate import it by
// path. ---

export type {
  FixtureByteClass,
  FixtureFileDigest,
  FixtureOriginKind,
  FixtureProvenance,
  FixtureProvenanceRecord,
} from "./fixture-provenance/types.ts";
export { FIXTURE_BYTE_CLASSES, FIXTURE_ORIGIN_KINDS } from "./fixture-provenance/types.ts";
export {
  FIXTURE_INDEX_PATHS,
  FIXTURE_PROVENANCE_COUNT,
  FIXTURE_PROVENANCE_REGISTRY,
  fixtureById,
  fixtureByIndexPath,
} from "./fixture-provenance/registry.ts";
export { validateFixtureRecord } from "./fixture-provenance/validate.ts";
export type { FixtureExpectation } from "./fixture-provenance/validate.ts";
