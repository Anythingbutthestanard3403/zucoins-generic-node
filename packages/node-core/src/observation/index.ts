// Evidence storage budgets, usage metrics, and fail-closed admission.
// Permanent evidence is never deleted: budgets reject new
// admission when exceeded, and the retention window governs proof access only.
export {
  DEFAULT_EVIDENCE_RETENTION_DAYS,
  DEFAULT_MAX_EVIDENCE_BYTES_PER_WALLET,
  DEFAULT_MAX_EVIDENCE_BYTES_TOTAL,
  DEFAULT_WRITE_LATENCY_P99_BASELINE_DELTA_MS,
  DEFAULT_WRITE_LATENCY_P99_PRESSURE_MS,
  DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD,
  EVIDENCE_ADMISSION_REJECTION_REASONS,
  EvidenceStorageBudgetError,
  WRITE_LATENCY_PRESSURE_UTILIZATION,
  applyWriteLatencyPressureFromCollector,
  computeEvidenceDiskHeadroom,
  computeEvidenceGrowthRate,
  computeEvidenceStorageMetrics,
  createStubEvidenceRuntimeMetricsCollector,
  createWriteLatencyPressureRefresh,
  evaluateEvidenceAccess,
  evaluateEvidenceAdmission,
  evaluateWriteLatencyPressure,
  growthSampleFromMetrics,
  resolveEvidenceStorageBudget,
  utilizationFromEvidenceSnapshot,
  utilizationFromWriteLatencyPressure,
  type EvidenceAccessStatus,
  type EvidenceAdmissionRejectionReason,
  type EvidenceAdmissionRequest,
  type EvidenceAdmissionResult,
  type EvidenceDiskHeadroom,
  type EvidenceGrowthRate,
  type EvidenceGrowthSample,
  type EvidenceRuntimeMetricsCollector,
  type EvidenceRuntimeStorageSignals,
  type EvidenceStorageBudget,
  type EvidenceStorageBudgetOverrides,
  type EvidenceStorageMetrics,
  type EvidenceStorageSnapshot,
  type EvidenceWalletMetrics,
  type EvidenceWalletUsage,
  type WriteLatencyPercentiles,
  type WriteLatencyPressureRefreshOptions,
  type WriteLatencyPressureThreshold,
} from "./storage-budget.js";

// live host disk + write-latency probes (production fail-closed seam).
export {
  createHostEvidenceRuntimeMetricsCollector,
  createStatfsDiskUtilization,
  isLiveEvidenceRuntimeCollector,
  probeStatfsDiskReading,
  probeStatfsDiskUtilization,
  type DiscriminatedEvidenceRuntimeMetricsCollector,
  type EvidenceRuntimeSignalKind,
  type HostDiskReading,
  type HostEvidenceRuntimeMetricsCollector,
  type HostEvidenceRuntimeMetricsCollectorOptions,
} from "./host-runtime-metrics.js";

export {
  HEAD_FINGERPRINT_DRIFT_VERDICTS,
  OBSERVATION_HEAD_FINGERPRINT_FIELDS,
  OBSERVATION_HEAD_FINGERPRINT_PURPOSE,
  ObservationHeadFingerprintError,
  buildObservationHeadFingerprintPreimage,
  compareObservationHeadFingerprints,
  computeObservationHeadFingerprint,
  type HeadFingerprintDriftVerdict,
  type ObservationHeadFingerprintReason,
  type ObservationHeadState,
  type WalletHeadStateEntry,
} from "./head-fingerprint.js";

export {
  ExactRepeatService,
  InMemoryExactRepeatStore,
  type AnomalyAppendEntry,
  type ExactRepeatCandidate,
  type ExactRepeatCursorState,
  type ExactRepeatDecision,
  type ExactRepeatStore,
  type ObservationAppendEntry,
} from "./dedup.js";

export {
  createSerializedStreamWriter,
  planCapture,
  type CaptureWritePlan,
  type CaptureWriteResult,
  type CursorAppendUpdate,
  type CursorSightingUpdate,
  type ObservationStreamKey,
  type PlannedObservationRow,
  type SerializedStreamWriter,
  type StreamWriterEffects,
} from "./capture-writer.js";

export {
  createSqlStreamWriterEffects,
  CrossObserverCursorError,
  STREAM_WRITER_SQL,
  type ObservationRowProjection,
  type SqlExecutor as StreamWriterSqlExecutor,
  type SqlQueryResult as StreamWriterSqlQueryResult,
  type SqlStreamWriterEffectsOptions,
} from "./stream-writer-sql.js";

export {
  inboundReceiverLinkMatchesBaselineS,
  projectGenesisState,
  projectRoleState,
  reconstructInnerPreimageText,
  toWalletStateProjection,
  type GenesisStateProjection,
  type ProjectRoleStateResult,
  type RoleStateProjection,
  type WalletObservationRole,
  type WalletStateProjection,
} from "./projection.js";


// pure relationship classifier over verified semantic projections.
export {
  CLASSIFIER_RELATIONSHIPS,
  classifyRelationship,
  establishesOrdinaryHead,
  isAnomalousRelationship,
  verifiedStateFromGenesisProjection,
  verifiedStateFromHeadProjection,
  type ClassificationComparison,
  type RelationshipClassifierInput,
  type RelationshipEvidence,
  type RelationshipResult,
  type VerifiedSemanticState,
} from "./classifier.js";

// residual / landing-path oracle — SUCCESSOR under lease without attribution → INVARIANT_BREACH.
export {
  assessSuccessorCustodyAuthority,
  type SuccessorCustodyGateInput,
  type SuccessorCustodyGateResult,
} from "./custody-authority.js";

// fail-closed anomaly quarantine actions (plan + apply + in-memory store).
export {
  ANOMALY_ACTION_INVARIANTS,
  CLASSIFIER_ANOMALY_KINDS,
  InMemoryAnomalyQuarantineStore,
  OBS15_ANOMALY_KINDS,
  QUARANTINE_AUDIT_ACTIONS,
  applyAnomalyAction,
  canAcquireNewLease,
  isSigningHalted,
  planActionForRelationship,
  planAnomalyAction,
  resolveAttentionStatus,
  type AnomalyActionInvariants,
  type AnomalyActionPlan,
  type AnomalyQuarantineStore,
  type ApplyAnomalyActionInput,
  type ApplyAnomalyActionResult,
  type ClassifierAnomalyKind,
  type EvidenceRow,
  type NeedsAttentionEvent,
  type Obs15AnomalyKind,
  type OperationPlanEffect,
  type PlanAnomalyActionInput,
  type QuarantineAuditAction,
  type QuarantineAuditEntry,
  type QuarantineOperationSnapshot,
  type QuarantineTrackedStatus,
  type QuarantineWalletSnapshot,
  type WalletPlanEffect,
  type WalletState,
} from "./quarantine.js";


// PURPOSE/FIELDS constants live in fingerprint.js but are intentionally not
// re-exported from this barrel: verifier already exports the same A.7 literals as
// WALLET_HEAD_FINGERPRINT_PURPOSE / WALLET_HEAD_FINGERPRINT_FIELDS, and the package
// root star-exports both modules (TS2308). Import the builders here; import the
// literals from `./fingerprint.js` or `../verifier/transaction-verify.js` directly.
export {
  buildGenesisWalletHeadFingerprint,
  buildWalletHeadFingerprintFromProjection,
  fingerprintsSemanticallyEqual,
  type FingerprintBuildRejection,
  type FingerprintBuildResult,
  type WalletHeadFingerprintResult,
  type WalletHeadStateKind,
} from "./fingerprint.js";

export {
  InMemoryRetainedBodyIndex,
  retainedBodiesExactEqual,
  verifyRetainedBodyOnRead,
  type BodyIndexFailureReason,
  type BodyIndexResolveResult,
  type BodyIndexVerifyResult,
  type ResolvedRetainedBody,
  type RetainedBodyIndex,
  type RetainedBodyRecord,
} from "./body-index.js";

export {
  ANCESTOR_CLASSIFICATIONS,
  EVIDENCE_ROLES,
  FORBIDDEN_MATERIAL_MARKERS,
  INDETERMINATE_REASONS,
  asVerificationMaterialFields,
  assembleVerificationMaterial,
  assembleVerificationMaterialFromTables,
  assessAncestorProofCompleteness,
  computePathManifestSha256,
  containsForbiddenMaterial,
  transactionBodySha256,
  createInMemoryVerificationMaterialTables,
  classifyAttemptFromLandingFacts,
  createSqlVerificationMaterialTablePort,
  mapLineageBodiesToManifest,
  mapLineagePath,
  mapLineageVerdictToClassification,
  serializePathManifest,
  type AncestorClassification,
  type AncestorProofInput,
  type AncestorProofMaterial,
  type AssembleFromTablesResult,
  type AssembledVerificationMaterial,
  type AttemptMaterial,
  type AttemptTransactionMaterial,
  type DurableAttemptRow,
  type DurableExpectedArtifactRow,
  type DurableLineageBodyRow,
  type DurableLineagePathRow,
  type DurableObservationEvidenceRow,
  type DurableObservationRow,
  type DurableOperationHeader,
  type EvidenceRole,
  type ExpectedArtifactMaterial,
  type InMemoryVerificationMaterialTables,
  type IndeterminateReason,
  type ObservationEvidenceMaterial,
  type ObservationProjection,
  type PathManifestEntry,
  type StateProjection,
  type TransactionBodyMaterial,
  type VerificationMaterialInput,
  type VerificationMaterialPayload,
  type VerificationMaterialTablePort,
} from "./verification/index.js";
