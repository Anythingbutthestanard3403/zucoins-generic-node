// Generic node core — the product-neutral protocol, persistence, and operation engine.
// This package must never gain
// product-specific vocabulary or a dependency on any product-implementer module; see the
// enforcement gate at packages/node-core/test/neutrality.test.ts.
export * from "./api/index.js";
export * from "./core/index.js";
export * from "./money-path-admission.js";
export * from "./assign-and-topup.js";
export * from "./operation-route-store.js";
export * from "./credential/index.js";
export * from "./implementer/index.js";
// Public Route-2 handshake module (ZTR-1239). Colliding store type/class names with the
// implementer operator inbox store (ZTR-1240) are aliased at the package boundary so both
// can ship from one barrel without TS2308 ambiguity.
export {
  CLAIM_TOKEN_PREFIX,
  INTEGRATION_REQUEST_INTAKE_SCOPES,
  INTEGRATION_REQUEST_PENDING_CAP,
  INTEGRATION_REQUEST_READ_GRACE_MS,
  INTEGRATION_REQUEST_TTL_MS,
  INTEGRATION_REQUEST_RATE_MAX_REQUESTS,
  INTEGRATION_REQUEST_RATE_WINDOW_MS,
  _resetIntegrationRequestRateLimitForTests,
  consumeIntegrationRequestAttempt,
  parseProposedIntegrationRule,
  serializeProposedRule,
  claimTokenHashesEqual,
  generateClaimToken,
  hashClaimToken,
  extractClaimToken,
  handleCreateIntegrationRequest,
  handleGetIntegrationRequest,
  createIntegrationRequestRouter,
  type ClaimOutcome,
  type IntegrationRequestIntakeInput,
  type IntegrationRequestIntakeResult,
  type IntegrationRequestIntakeScope,
  type IntegrationRequestRow,
  type IntegrationRequestStatus,
  type ProposedIntegrationRule,
  type IntegrationRequestHandlerDeps,
  type IntegrationRequestRouter,
  type IntegrationRequestRouterDeps,
  type IntegrationRequestTxFn,
  // Aliased — bare names belong to implementer/operator inbox store
  type IntegrationRequestStore as PublicIntegrationRequestStore,
  type IntegrationRequestSqlExecutor as PublicIntegrationRequestSqlExecutor,
  SqlIntegrationRequestStore as PublicSqlIntegrationRequestStore,
  InMemoryIntegrationRequestStore as PublicInMemoryIntegrationRequestStore,
} from "./integration-request/index.js";
export * from "./data/index.js";
export * from "./event-log/index.js";
export * from "./gateway/index.js";
export * from "./http/index.js";
export * from "./net/index.js";
export * from "./observability/index.js";
export * from "./observation/index.js";
export * from "./operator/index.js";
export * from "./push/index.js";
export * from "./cosign-persist/index.js";
export * from "./proof-body/index.js";
export * from "./protocol/index.js";
// MOVE_INTERNAL reconcile classification (the landing-path oracle), exported directly from the
// reconcile submodules rather than re-exported through protocol/index.ts: protocol/reconcile/
// is held out of the construction-scope ratchet, so any import
// edge from a protocol/ production file into reconcile/ is a violation regardless of directory.
export {
  classifyMoveReconcile,
  type MoveReconcileOutcome,
  type MoveReconcileInput,
} from "./protocol/reconcile/move.js";
export {
  type PathObservation as ReconcilePathObservation,
} from "./protocol/reconcile/observation-input.js";
// The reconcile-reason → closed `attention_reason` mapper. Exported for the same reason as the
// classifier above: the composition root builds the operation.needs_attention event payload and
// must name the SAME vocabulary member persistMoveOutcome writes to the column, not a second
// hand-maintained mapping that could drift from it.
export { toAttentionReason } from "./protocol/reconcile/types.js";
export * from "./reporting/index.js";
export * from "./send/index.js";
// MOVE_INTERNAL admission is mostly via "@zucoins/node-core/move" (not star-re-exported:
// IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS collides with send). Composition roots need
// the SQL store class on the main barrel (custody main; app shell may only import
// @zucoins/node-core — see boundaries.test.ts).
export {
  SqlMoveCreateStore,
  type SqlMoveCreateStoreConfig,
  type MoveSqlExecutor,
  type MoveSqlTxFn,
  type MoveCreatedEventAppender,
  createDualChainMoveCreatedEventAppender,
  buildInternalMoveCreatedEventData,
  createInternalMove,
  MOVE_ADMISSION_EVENTS_DDL,
  // money workers — dual-lease for MOVE_INTERNAL.
  acquireMoveLeases,
  moveLeaseRejectionCode,
  MOVE_SOURCE_LEASE_ROLE,
  MOVE_DESTINATION_LEASE_ROLE,
  type HeldMoveLease,
  type MoveLeaseRequest,
  type MoveLeaseOutcome,
  type MoveLeaseTxFn,
  createChildMoveWithContinuousSourceTransfer,
  type ContinuousHandoffParams,
  type ContinuousHandoffResult,
} from "./move/index.js";
export * from "./vault/index.js";
export * from "./verifier/index.js";
export * from "./workers/index.js";

// Re-export the zod surface so the generic-node application shell depends on this
// package alone (packages/node-core/test/boundaries.test.ts: the shell's only
// external import must be @zucoins/node-core). The shell uses the `z` namespace —
// schemas, coercions, and the z.infer / z.ZodType types — and re-exporting the
// binding preserves both its value and type meanings. `zod` is a neutral,
// product-agnostic dependency, so this trips no node-core boundary or vocabulary gate.
export { z } from "zod";

// Disambiguate `sha256Hex`: both./gateway and./reporting export an
// identical `(bytes: Uint8Array): string` SHA-256 hex helper, so the two star re-exports above
// are ambiguous (TS2308). Pin the barrel's `sha256Hex` to the pre-existing gateway export; the
// two implementations are byte-identical, and every module imports its own copy directly, so this
// changes no runtime behavior and no signing/verification byte.
export { sha256Hex } from "./gateway/index.js";

// Disambiguate `sha256HexUtf8`: both./reporting and./send (landing-verify)
// export an identical `(text: string): string` SHA-256-of-UTF-8 helper. Pin to the pre-existing
// reporting export; landing-verify's copy hashes the same bytes (`update(text, "utf8")` vs
// `update(UTF8.encode(text))`), and landing-commit imports it from "./landing-verify.js" directly,
// so this changes no runtime behavior and no signing/verification byte.
export { sha256HexUtf8 } from "./reporting/index.js";

// Disambiguate `DEFAULT_MAX_BODY_BYTES`: both./api (strict-json) and./reporting
// (request-verifier) export the same 1 MiB constant. Pin to the pre-existing reporting
// export; the api module uses its own copy internally.
export { DEFAULT_MAX_BODY_BYTES } from "./reporting/index.js";

// Disambiguate `IndeterminateReason` / `PathManifestEntry`: both./api (
// action-routes wire types) and./observation/verification (verification-material
// material) export identical closed vocabularies / field shapes. Pin the
// package barrel to the verification-material definitions (the canonical surface);
// action-route modules import their own copies via ./api/routes.
export type {
  IndeterminateReason,
  PathManifestEntry,
} from "./observation/verification/index.js";

// Disambiguate `ExternalSendResponse`: both the operation-routes HTTP contract
// (./api/routes) and./send (create-time response builder) export the name. The
// shapes are not identical — routes is the general operation-route surface (transfer_code may
// be non-null post approval); send's create builder freezes the CREATED-state nulls.
// Pin the package barrel to the routes HTTP contract. ./api/index intentionally withholds
// this name so it does not collide with./send under `export *`. Create callers
// import the narrower type from the create module (or via the function return type).
export type { ExternalSendResponse } from "./api/routes/index.js";

export const NODE_CORE_VERSION = "0.0.0";

export {
  CUSTODY_SCHEMA_FILE,
  CUSTODY_SCHEMA_INVARIANTS,
  CUSTODY_SCHEMA_SOURCE,
  SCHEMA_EXECUTION_OBLIGATIONS,
  type CustodySchemaInvariant,
} from "./schema/custody-eligibility.contract.js";

export {
  SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS,
  TRANSACTION_MATERIAL_INVARIANTS,
  TRANSACTION_MATERIAL_MUTABILITY_REGIMES,
  TRANSACTION_MATERIAL_PHASE_VOCABULARY,
  TRANSACTION_MATERIAL_SCHEMA_FILE,
  TRANSACTION_MATERIAL_SOURCE,
  type TransactionMaterialInvariant,
} from "./schema/transaction-material.contract.js";

export {
  SCHEMA_SUBMIT_ATTEMPTS_OBLIGATIONS,
  SUBMIT_ATTEMPTS_INVARIANTS,
  SUBMIT_ATTEMPTS_MUTABILITY_REGIMES,
  SUBMIT_ATTEMPTS_SCHEMA_FILE,
  SUBMIT_ATTEMPTS_SOURCE,
  type SubmitAttemptsInvariant,
} from "./schema/submit-attempts.contract.js";

export {
  SCHEMA_OBSERVATION_LEDGER_OBLIGATIONS,
  OBSERVATION_LEDGER_INVARIANTS,
  OBSERVATION_LEDGER_SCHEMA_FILE,
  OBSERVATION_LEDGER_SOURCE,
  type ObservationLedgerInvariant,
} from "./schema/observation-ledger.contract.js";

export {
  SCHEMA_OBSERVATION_STORES_OBLIGATIONS,
  OBSERVATION_STORES_INVARIANTS,
  OBSERVATION_STORES_SCHEMA_FILE,
  OBSERVATION_STORES_SOURCE,
  type ObservationStoresInvariant,
} from "./schema/observation-stores.contract.js";

export {
  SEND_EXTERNAL_CREATE_GN3_OBLIGATIONS,
  SEND_EXTERNAL_CREATE_INVARIANTS,
  SEND_EXTERNAL_CREATE_SCHEMA_FILE,
  type SendExternalCreateInvariant,
} from "./schema/send-external-create.contract.js";

export {
  EVENT_LEDGER_INVARIANTS,
  EVENT_LEDGER_SCHEMA_FILE,
  EVENT_LEDGER_SOURCE,
  SCHEMA_EVENT_LEDGER_OBLIGATIONS,
  type EventLedgerInvariant,
} from "./schema/event-ledger.contract.js";

export {
  SCHEMA_PROOF_BODY_STORE_OBLIGATIONS,
  PROOF_BODY_STORE_FORBIDDEN_AUTHORITY_TOKENS,
  PROOF_BODY_STORE_INVARIANTS,
  PROOF_BODY_STORE_MUTABILITY_REGIMES,
  PROOF_BODY_STORE_SCHEMA_FILE,
  PROOF_BODY_STORE_SOURCE,
  type ProofBodyStoreInvariant,
} from "./schema/proof-body-store.contract.js";

export {
  AUDIT_LOG_ACTOR_KINDS,
  AUDIT_LOG_FORBIDDEN_SECRET_TOKENS,
  AUDIT_LOG_INVARIANTS,
  AUDIT_LOG_MUTABILITY_REGIMES,
  AUDIT_LOG_SCHEMA_FILE,
  AUDIT_LOG_SOURCE,
  SCHEMA_AUDIT_LOG_OBLIGATIONS,
  type AuditLogInvariant,
} from "./schema/audit-log.contract.js";

// verification-material access-window durable shape.
export {
  SCHEMA_VERIFICATION_ACCESS_WINDOWS_OBLIGATIONS,
  VERIFICATION_ACCESS_WINDOWS_INVARIANTS,
  VERIFICATION_ACCESS_WINDOWS_MUTABILITY_REGIMES,
  VERIFICATION_ACCESS_WINDOWS_SCHEMA_FILE,
  type VerificationAccessWindowsInvariant,
} from "./schema/verification-access-windows.contract.js";

// The node-side outbox delivery table (outbox_messages) is deliberately NOT built: reporting-key enrolment ceremony /
// B-07 remove every node-initiated callback/push/delivery surface (zero non-gateway node
// egress HTTP; no backend delivery table exists), leaving the signed pull event stream signed pull event stream +
// SSE + snapshot as the sole delivery channel. The read-only events read-service (reporting
// module) and the append-only audit writer (core module) are the sanctioned replacements.

// residual: reporting private key, webhook signing secret, and push-receiver
// secrets are EXCLUDED_BY_CANON from the v2 generic-node SEALED_STORES set; the
// product-layer webhook secret encrypted at rest stays on the v1 platform's own census.
// See sealed-store-exclusions.contract.ts.
export {
  NON_NODE_SEALED_SECRETS,
  NON_NODE_SEALED_SECRET_IDS,
  SEALED_STORE_EXCLUSIONS_SOURCE,
  admitNonNodeSealedSecret,
  excludedSealSiteHits,
  type NonNodeSealedDisposition,
  type NonNodeSealedSecretClass,
  type NonNodeSealedSecretDescriptor,
} from "./schema/sealed-store-exclusions.contract.js";

// sealed-store registry + seal-site census surface.
export {
  REGISTERED_SEAL_SITES,
  REGISTERED_SEAL_SITE_PATHS,
  ROOT_KEY_MATERIAL,
  SEALED_STORES,
  SEALED_STORE_IDS,
  SEALED_STORE_REGISTRY_SOURCE,
  sealSiteCensus,
  sealedStore,
  type BackupCoverage,
  type HkdfLabelState,
  type RegisteredSealSite,
  type RewrapStatus,
  type RootKeyMaterialDescriptor,
  type SealSiteKind,
  type SealedStoreAccessPattern,
  type SealedStoreDescriptor,
  type SealedStoreEncryption,
  type SealedStoreId,
  type SealedStoreStorage,
  type TableState,
} from "./schema/sealed-store-registry.contract.js";

export {
  SCHEMA_PRIVILEGES_OBLIGATIONS,
  PRIVILEGES_SCHEMA_FILE,
  PRIVILEGES_SCHEMA_INVARIANTS,
  PRIVILEGES_SCHEMA_SOURCE,
  type PrivilegesSchemaInvariant,
} from "./schema/privileges.contract.js";

export {
  LEASE_FOUNDATION_INVARIANTS,
  LEASE_FOUNDATION_MUTABILITY_REGIMES,
  LEASE_FOUNDATION_SCHEMA_FILE,
  LEASE_FOUNDATION_SCHEMA_SOURCE,
  LEASE_FOUNDATION_SCHEMA_VERSION,
  LEASE_FOUNDATION_TABLES,
  SCHEMA_LEASE_FOUNDATION_OBLIGATIONS,
  type LeaseFoundationInvariant,
} from "./schema/lease-foundation.contract.js";

export {
  LeaseError,
  acquireGroupDestinationLeases,
  acquireLeases,
  assertLeaseFoundationReady,
  assertSignCapability,
  completeGroupOperation,
  createLeaseGroup,
  joinLeaseGroupOperation,
  LANDED_PROOF_KIND_BY_OPERATION_KIND,
  migrateLeaseFoundation,
  mintReleaseProof,
  releaseLease,
  renewLeaseHeartbeat,
  transferLeaseWithinGroup,
  sortWalletIdsAscending,
  STATEMENTS as LEASE_STATEMENTS,
  type LeaseErrorReason,
  type AcquireGroupDestinationLeasesParams,
  type AcquireLeasesParams,
  type AcquiredLease,
  type CompleteGroupOperationParams,
  type CreateLeaseGroupParams,
  type JoinLeaseGroupParams,
  type LeaseGroupChildDisposition,
  type MintReleaseProofParams,
  type ReleaseLeaseParams,
  type TerminalPositiveProofKind,
  type TransferLeaseWithinGroupParams,
  type TransferredLease,
  type SqlExecutor as LeaseSqlExecutor,
} from "./leases/index.js";

// Receive arm barrier — wallet-lock gate + SQL composition.
export {
  ARM_SQL_STATEMENTS,
  type SqlArmInsertEnvelope,
  activeArmTx,
  assertMemoryArmCommitSession,
  assertSqlArmCommitSession,
  buildArmSuccessResponse,
  commitArmUnderWalletLock,
  createArmMutationService,
  createFailClosedArmHandler,
  createSqlArmStore,
  createSqlArmWalletGate,
  createSqlTxBoundOperationState,
  expiresAtFromUnixSecs,
  isArmableWalletStanding,
  isReceiveUnexpired,
  requireActiveArmSqlTx,
  type ArmAuditEntry,
  type ArmAuditLog,
  type ArmClock,
  type ArmCommitSession,
  type ArmMutationService,
  type ArmOperationGateSnapshot,
  type ArmOperationState,
  type ArmOutcome,
  type ArmRecord,
  type ArmReleasePayload,
  type ArmRequest,
  type ArmSignatureVerifier,
  type ArmSqlQueryResult,
  type ArmSqlTxExecutor,
  type ArmSqlTxFactory,
  type ArmSqlTxRef,
  type ArmStore,
  type ArmWalletGate,
  type ArmWalletLockHandle,
  type ArmWalletStanding,
  type ArmWalletState,
  type T0Projection as ArmT0Projection,
  // arm pre-open binding
  ARM_REQUEST_BINDING_FIELDS,
  ARM_ROUTE_ID,
  assertArmReportingCredential,
  comparisonImportsConsumerObservation,
  isVerifiedReportRequest,
  operationIdFromArmTarget,
  parseArmRequestBinding,
  prepareArmT0Comparison,
  runArmPreopen,
  type ArmBindingParseFailureCode,
  type ArmBindingParseResult,
  type ArmCredentialRejectCode,
  type ArmPreopenDurableT0Port,
  type ArmPreopenRejectCode,
  type ArmPreopenResult,
  type ArmVerifiedReportingRequest,
  type ArmRequestBinding,
  type ArmRequestBindingField,
  type ArmT0ComparePrepResult,
  type ArmT0ComparisonShape,
  type ConsumerT0Projection,
  type NodeDurableT0,
} from "./receive/index.js";

// The receive landing commit and its
// PostgreSQL store. Surfaced on the root barrel so the generic-node composition root (the
// only layer that links a driver) can bind the DB-TX; node-core itself stays driver-free.
export {
  RECEIVE_LANDED_EVENT,
  RECEIVE_LANDED_STATUS,
  RECEIVE_LANDED_VERIFIED_PHASE,
  RECEIVE_READY_STATUS,
  RECEIVE_SETTLED_BODY_PERSISTED_PHASE,
  RECEIVER_PATH_ROLE,
  SqlReceiveLandingStore,
  InMemoryReceiveLandingStore,
  classifyReceiveLandingError,
  commitReceiveLanding,
  verifyAndCommitReceiveLanding,
  type CommitReceiveLandingCommand,
  type CommitReceiveLandingInput,
  type CommitReceiveLandingOutcome,
  type ReceiveLandedEvent,
  type ReceiveLandingConflictReason,
  type ReceiveLandingPathBody,
  type ReceiveLandingProofRecord,
  type ReceiveLandingRejectReason,
  type ReceiveLandingStore,
} from "./receive/index.js";

// Candidate intake (pre-co-sign gate).
export {
  CANDIDATE_CAPTURE_FIELDS,
  CANDIDATE_INTAKE_PHASE,
  CandidateIntakeError,
  RECEIVE_SENDER_PREFLIGHT_ROLE,
  createCandidateIntakeService,
  createFixedClock,
  createInMemoryCandidatePersistPort,
  createInMemoryRawCapturePort,
  type CandidateIntakeClock,
  type CandidateIntakeDeps,
  type CandidateIntakeRejectionReason,
  type CandidateIntakeRequest,
  type CandidateIntakeResult,
  type CandidateIntakeService,
  type CandidateIntakeSignerProbe,
  type CandidateIntakeSuccess,
  type CandidateLocateKeys,
  type CandidatePersistPort,
  type CandidateRawCapture,
  type CandidateRawCapturePort,
  type CandidateValidationManifest,
  type InMemoryCaptureRecord,
  type InMemoryPersistedCandidate,
  type LocatedReceive,
  type LocateReceivePort,
  type PersistWinningCandidateInput,
  type PersistWinningCandidateResult,
  type ReceiverT0Projection,
  type SenderPreflightObservation,
  type SenderPreflightObserver,
} from "./receive/index.js";

// receive admission + idempotency (distinct from pool-allocator admitReceive).
// Canonical transport is api/routes handleCreateReceive via operation-router.
export {
  RECEIVE_ADMISSION_IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
  RECEIVE_CANONICAL_ROUTE,
  RECEIVE_HTTP_METHOD,
  RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS,
  DEFAULT_EXPIRES_IN_SECONDS,
  admitReceiveExternal,
  canonicalReceiveRequestSha256,
  isMoveDestinationEligible,
  isReceiveEligible,
  validateAfterLanding,
  validateReceiveRequest,
  SqlReceiveAdmissionStore,
  type AfterLanding,
  type ReceiveAdmissionConfig,
  type ReceiveAdmissionOutcome,
  type ReceiveAdmissionStore,
  type ReceiveAdmissionSqlExecutor,
  type ReceiveAdmissionSqlQueryResult,
  type ReceiveAdmissionSqlTxFactory,
  type ReceiveDestinationRecord,
  type ReceiveDestinationState,
  type ReceiveInsertOutcome,
  type ReceiveOperation,
  type ReceiveOperationStatus,
  type ReceiveQueuedInsertOutcome,
  type ReceiveRejectionCode,
  type ReceiveRequest,
  type ReceiveWalletRecord,
  type ReceiveWalletState,
  type StoredReceiveOperation,
  RECEIVE_ADMISSION_STATEMENTS,
} from "./receive/index.js";

// bounded receive-pool allocator (queue cap / assignment). Kept as a second
// named export block so admitReceive (pool) and admitReceiveExternal (admission) cannot
// collide in a single list and force a rename at the import site.
export {
  RECEIVE_ADMISSION_LOCK_KEY,
  RECEIVE_ALLOCATOR_STATEMENTS,
  ReceiveAllocatorError,
  admitReceive,
  assignReceiveWallet,
  assignReceiveWalletThenObserve,
  countUnassignedReceives,
  promoteQueuedReceives,
  selectQueuedReceivesFifo,
  type AdmitReceiveOutcome,
  type AdmitReceiveParams,
  type AssignReceiveWalletOutcome,
  type AssignReceiveWalletParams,
  type PromoteQueuedReceivesResult,
  type ReceiveAllocatorErrorReason,
  type ReceiveLeasePort,
  type ReceiveQueueLimits,
  type ReceiveAllocatorSqlExecutor,
} from "./receive/index.js";

// pool scale-up + queue-age expiry (composition root money workers).
export {
  HEADROOM_DENOMINATOR,
  HEADROOM_NUMERATOR,
  MINT_BATCH_LIMIT,
  POOL_FLOOR,
  POOL_SCALER_STATEMENTS,
  POOL_SCALE_UP_LOCK_KEY,
  PoolScalerError,
  collectPoolPressureMetrics,
  computeMintCount,
  countOpenSessions,
  planPoolScaleUp,
  poolTargetTotal,
  runPoolScaleUp,
  expireQueueAgedReceives,
  selectQueueExpiredReceives,
  type EmitOperationExpired,
  type ExpireQueueAgedResult,
  type MintWallet,
  type PoolPressureMetrics,
  type PoolScaleUpPlan,
  type PoolScaleUpResult,
  type PoolScalerErrorReason,
  type PoolScalerLimits,
  type QueueExpiredReceive,
} from "./receive/index.js";

// The lease-fenced RECEIVE_T0 read and the not-verified branch.
export {
  RECEIVE_T0_EVIDENCE_ROLE,
  RECEIVE_T0_OBSERVATION_ROLE,
  RECEIVE_T0_STATEMENTS,
  captureReceiveT0,
  classifyReceiveT0Phase,
  type CaptureReceiveT0Params,
  type ReceiveT0Observation,
  type ReceiveT0Observer,
  type ReceiveT0Outcome,
  type ReceiveT0Phase,
  type ReceiveT0SqlExecutor,
} from "./receive/index.js";

// Transfer code, zp-receive-expected-v1, CREATED→READY.
export {
  RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
  RECEIVE_EXPECTED_CANONICAL_VERSION,
  RECEIVE_READY_STATEMENTS,
  assertWithheldTransferCode,
  buildReceiveReady201Body,
  buildReceiveReadyEventData,
  buildReceiverT0Fingerprint,
  classifyReceiveCodePhase,
  commitReceiveReady,
  completeReadyFromDurableCode,
  isNonEmptySubscriptionHandle,
  formReceiveCodeAndArtifact,
  type ArtifactEnvelope,
  type CommitReceiveReadyInput,
  type CommitReceiveReadyRejectionReason,
  type CommitReceiveReadyResult,
  type FormReceiveCodeInput,
  type FormReceiveCodeRejectionReason,
  type FormReceiveCodeResult,
  type FormedReceiveCode,
  type ReceiveAfterLanding,
  type ReceiveCodeFormationStore,
  type ReceiveCodeNodeIdentitySigner,
  type ReceiveCodePhase,
  type ReceiveReadyEventAppender,
  type ReceiveReadySqlExecutor,
} from "./receive/index.js";

// receive admission schema inventory (SQL contract; not a runtime module).
export {
  RECEIVE_ADMISSION_INVARIANTS,
  RECEIVE_ADMISSION_GN3_OBLIGATIONS,
  RECEIVE_ADMISSION_SCHEMA_FILE,
  type ReceiveAdmissionInvariant,
} from "./schema/receive-admission.contract.js";

// receive expiry/attention/release schema inventory.
export {
  SCHEMA_RECEIVE_EXPIRY_RELEASE_OBLIGATIONS,
  RECEIVE_EXPIRY_RELEASE_EXTENDS,
  RECEIVE_EXPIRY_RELEASE_INVARIANTS,
  RECEIVE_EXPIRY_RELEASE_MUTABILITY_REGIMES,
  RECEIVE_EXPIRY_RELEASE_SCHEMA_FILE,
  RECEIVE_EXPIRY_RELEASE_SOURCE,
  type ReceiveExpiryReleaseInvariant,
} from "./schema/receive-expiry-release.contract.js";

// verification_mode column + RELEASED_NODE_VERIFIED + policy home (ZTR-1300).
export {
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  DEFAULT_VERIFICATION_MODE,
  RELEASED_NODE_VERIFIED,
  VERIFICATION_MODES,
  VERIFICATION_MODE_SCHEMA_EXECUTION_OBLIGATIONS,
  VERIFICATION_MODE_SCHEMA_FILE,
  VERIFICATION_MODE_SCHEMA_INVARIANTS,
  VERIFICATION_MODE_SCHEMA_SOURCE,
  VERIFICATION_MODE_EXTENDS,
  type VerificationModeSchemaInvariant,
} from "./schema/verification-mode.contract.js";

// receive expiry, attention hold attention hold, and exact-T0 release.
export {
  LOAD_EXPIRED_RECEIVE_CANDIDATES,
  POST_EXPIRY_RECONCILING,
  RECEIVE_EXPIRED_EVENT,
  RECEIVE_EXPIRED_LEASE_PROOF_KIND,
  RECEIVE_EXPIRED_RELEASE_KIND,
  RECEIVE_EXPIRED_RELEASE_STATUS,
  RECEIVE_OPERATOR_ACCEPTED_RISK_LEASE_PROOF_KIND,
  RECEIVE_OPERATOR_ACCEPTED_RISK_RELEASE_KIND,
  RECEIVE_OPERATOR_ACCEPTED_RISK_RELEASE_STATUS,
  RECEIVE_EXPIRY_RELEASE_STATEMENTS,
  RECEIVE_EXPIRY_SAFETY_MARGIN_SECS,
  RECEIVE_NEEDS_ATTENTION_EVENT,
  RECEIVE_QUEUE_MAX_WAIT_MS,
  SAFE_TERMINAL_RELEASE_STATUS,
  SqlReceiveExpiryReleaseService,
  RECEIVE_RELEASE_PREDICATE_CAUSES,
  allReceiveReleasePredicatesHold,
  buildReceiveExpiryAttentionDetail,
  commitOperatorAcceptedRiskRelease,
  failedReceiveReleasePredicates,
  loadExpiredReceiveCandidates,
  serializeFreshReadOutcome,
  type ExpiredReceiveCandidate,
  type ExpireReceiveInput,
  type ExpireReceiveOutcome,
  type FreshReadOutcome,
  type OperatorAcceptedRiskReleaseInput,
  type OperatorAcceptedRiskReleaseOutcome,
  type ReceiveExpiryAttentionReason,
  type ReceiveExpiryDualChainEmitter,
  type ReceiveExpiryLeaseRepository,
  type ReceiveExpiryTxFactory,
  type ReceiveReleasePredicateName,
  type ReceiveReleasePredicates,
} from "./receive/index.js";

// Verification-complete acknowledgement barrier.
// `LeaseReleaseStatus` is already exported from ./api (action-routes' wire type); the
// predicate module's structurally identical union is aliased so both surfaces stay visible
// and neither shadows the other.
export {
  ACK_EVIDENCE_ROLES,
  ACK_STATEMENTS,
  ACK_VERDICTS,
  AcknowledgementError,
  AcknowledgementInsertConflict,
  InMemoryAllowNodeVerifiedPolicy,
  LEASE_RELEASE_STATUSES,
  REQUIRED_EVIDENCE_ROLES,
  admitVerificationMode,
  clampReleaseToVerdict,
  computeEvidenceSetSha256,
  createAcknowledgementService,
  createSqlAcknowledgementStore,
  createSqlAllowNodeVerifiedPolicy,
  isNodeVerifiedAllowedByPolicy,
  parseAllowNodeVerifiedPolicyDocument,
  parseAllowNodeVerifiedPolicyStructure,
  refuseAllNodeVerifiedPolicy,
  resolveVerificationMode,
  serializeAllowNodeVerifiedPolicyDocument,
  evaluateGroupRelease,
  expectedWalletsForOperation,
  isAckEvidenceRole,
  isAckVerdict,
  parseFrozenResponseBody,
  validateEvidenceIdentity,
  validateEvidenceSet,
  validateRoleSet,
  type AckEvidenceRole,
  type AckObservationRef,
  type AckOpenMembership,
  type AckOperationFacts,
  type AckSqlExecutor,
  type AckVerdict,
  type AckWalletEvidenceInput,
  type AcknowledgementDraft,
  type AcknowledgementFailureReason,
  type AcknowledgementInput,
  type AcknowledgementOutcome,
  type AcknowledgementResponseBody,
  type AcknowledgementService,
  type AcknowledgementStore,
  type DurableEvidenceFact,
  type EvidenceSetFailure,
  type GroupOperationFact,
  type GroupReleaseDecision,
  type GroupReleaseFacts,
  type GroupReleaseReason,
  type AllowNodeVerifiedDisabledReason,
  type AllowNodeVerifiedImplementerEntry,
  type AllowNodeVerifiedPolicyDocument,
  type AllowNodeVerifiedPolicyPort,
  type AllowNodeVerifiedPolicySetMeta,
  type AllowNodeVerifiedSqlExecutor,
  type OperationWalletAssignment,
  type StoredAcknowledgement,
} from "./verification/index.js";

// registry group: nodes/implementers + signing-key tables
// and read layer. Isolation/rotation scenario suite remains.
export {
  NODE_IMPLEMENTER_SCHEMA_FILE,
  NODE_IMPLEMENTER_SCHEMA_INVARIANTS,
  NODE_IMPLEMENTER_SCHEMA_SOURCE,
  type RegistrySchemaInvariant,
} from "./schema/node-implementer-registry.contract.js";

export {
  SIGNING_KEY_SCHEMA_FILE,
  SIGNING_KEY_SCHEMA_INVARIANTS,
  SIGNING_KEY_SCHEMA_SOURCE,
  type SigningKeySchemaInvariant,
} from "./schema/signing-key-registry.contract.js";

export {
  REGISTRY_GROUP_EXIT_CRITERION,
  REGISTRY_GROUP_INVARIANTS,
  REGISTRY_GROUP_SCHEMA_FILES,
  REGISTRY_GROUP_SOURCE,
  REGISTRY_GROUP_TABLES,
  type RegistryGroupSchemaFile,
  type RegistryGroupTable,
} from "./schema/registry-group.contract.js";

export {
  NODE_SIGNING_DEK_HKDF_LABEL,
  NODE_SIGNING_KEY_COLUMNS,
  NODE_SIGNING_KEY_ENSURE_LOCK_CLASS,
  NODE_SIGNING_KEY_PURPOSES,
  NODE_SIGNING_SECRET_AAD_DOMAIN,
  REPORTING_KEY_COLUMNS,
  SigningKeyRegistry,
  UnknownSigningKeyPurposeError,
  assertExactPurpose,
  buildNodeSigningDekInfo,
  buildNodeSigningSecretAad,
  ensureActiveNodeSigningKey,
  generateEd25519Seed,
  openNodeSigningSeed,
  publicKeyFromEd25519Seed,
  rewrapNodeSigningKeyStore,
  sealNodeSigningSeed,
  type EnsureActiveNodeSigningKeyInput,
  type NodeIdentityArtifactSigner,
  type NodeSigningKeyIdentity,
  type NodeSigningKeyPurpose,
  type NodeSigningKeyRewrapInput,
  type NodeSigningKeyRewrapRow,
  type NodeSigningKeyRow,
  type NodeSigningKeySealedEnvelope,
  type NodeSigningKeySealedStoreRewrapResult,
  type ReportingKeyRow,
  type SqlExecutor as SigningKeySqlExecutor,
} from "./signing-keys/index.js";

// destination bless device authorizer + SQL device/enrol mounts.
// Selective (device/ is not star-exported — shell bound to this barrel only).
export {
  createDeviceBlessingAuthorizer,
  createSqlActiveDeviceLookup,
  createSqlBlessingArtifactPersister,
  createSqlBlessingAuditAppender,
  createSqlDeviceKeyStore,
  createSqlEnrollmentChallengeStore,
  createSqlEnrollmentAuditLog,
  createSqlDeviceRevocationAuditLog,
  InMemoryDeviceKeyStore,
  InMemoryEnrollmentChallengeStore,
  InMemoryEnrollmentAuditLog,
  InMemoryDeviceRevocationAuditLog,
  NoopDeviceRevocationSideEffects,
  issueEnrollmentChallenge,
  verifyAndEnrolDevice,
  verifyAndEnrolGenesisDevice,
  revokeDevice,
  verifyDeviceSignature,
  ENROLLMENT_CHALLENGE_WINDOW_MS,
  // Second-device QR enrolment
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
  type BlessingAuthorizeInput,
  type DeviceBlessingAuthorizer,
  type DeviceKeyStore,
  type DeviceSignatureInput,
  type DeviceSqlExecutor,
  type EnrolledDeviceKey,
  type EnrollmentChallengeStore,
  type EnrollmentAuditLog,
  type EnrolmentDeps,
  type GenesisEnrolmentInput,
  type SecondDeviceCeremony,
  type SecondDeviceCeremonyStore,
  type SecondDeviceQrPayload,
  type LookUpActiveDevice,
  type PersistBlessingArtifact,
  type SqlDeviceKeyStore,
  type SqlEnrollmentChallengeStore,
  type DeviceRevocationAuditLog,
  type DeviceRevocationSideEffects,
  type BreakGlassAuthorityStore,
} from "./device/index.js";
export { buildDeviceEnrol, buildDestinationBless } from "./protocol/suite/builders.js";
