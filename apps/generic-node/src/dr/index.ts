// Generic-node disaster-recovery surface.

export {
  HEADER_LENGTH,
  KDF_ITERATIONS,
  KDF_HASH,
  KEY_LENGTH,
  IV_LENGTH,
  SALT_LENGTH,
  AUTH_TAG_LENGTH,
  SHA256_LENGTH,
  WRAPPED_DEK_LENGTH,
  OFF_VERSION,
  OFF_SALT,
  OFF_WRAPPED_DEK,
  OFF_DATA_IV,
  OFF_AUTH_TAG,
  OFF_SHA256,
  deriveKek,
  deriveWrapIv,
  assembleEnvelope,
  parseEnvelope,
  wrapDek,
  unwrapDek,
  encryptBuffer,
  decryptBuffer,
  exportEncryptedBackup,
  restoreEncryptedBackup,
  awaitCleanExit,
  buildRestorePsqlArgs,
  buildPgDumpArgs,
  type BackupResult,
  type DecryptedBackup,
  type ExportEncryptedBackupOptions,
  type ParsedEnvelope,
} from "./encrypted-backup.js";

export { rotateBackupKey, type RotationResult } from "./key-rotation.js";
export { runDrill, type DrillResult } from "./drill.js";
export {
  probePgClientBinaries,
  EXPECTED_PG_CLIENT_MAJOR_VERSION,
  type PgClientProbeResult,
} from "./client-probe.js";

export {
  BACKUP_RPO_TARGET_MS,
  BACKUP_RTO_TARGET_MS,
  BACKUP_RETENTION_DEFAULT_DAYS,
  BACKUP_RETENTION_MIN_DAYS,
  BACKUP_RETENTION_MAX_DAYS,
  BACKUP_SCHEDULE_INTERVAL_DEFAULT_MS,
  BACKUP_SCHEDULE_INTERVAL_MIN_MS,
  BACKUP_SCHEDULE_INTERVAL_MAX_MS,
  BACKUP_ENVELOPE_EXTENSION,
  DEFAULT_BACKUP_POLICY,
  isRpoBreached,
  isRtoBreached,
  type BackupPolicy,
} from "./policy.js";

export {
  CONTINUITY_MARKER_FORMAT,
  parseContinuityMarkers,
  loadContinuityMarkers,
  writeContinuityMarkers,
  compareContinuityMarkers,
  hashHoldReleaseEvidence,
  buildScheduledBackupMarkers,
  deriveContinuitySnapshot,
  deriveContinuitySnapshotOnClient,
  type ContinuityMarkers,
  type LocalContinuitySnapshot,
  type MarkerLoadResult,
  type MarkerCompareResult,
} from "./markers.js";

export {
  evaluateRestoreHoldRelease,
  buildRestoreHoldReleaseUpdate,
  buildForceRestoreHoldUpsert,
  buildEnsureRestoreHoldInsert,
  forceRestoreHoldOnClient,
  applyForceRestoreHoldAfterRestore,
  type RestoreHoldDecision,
  type RestoreHoldRejectReason,
  type RestoreHoldEvaluationInput,
} from "./restore-hold.js";

export {
  applyForceAuthHoldAfterRestore,
  applyDualGateForceAfterRestore,
  releaseDualGatesWithTrustedMarkers,
  buildForceAuthHoldSetStatements,
  buildReleaseAuthHoldStatements,
  healLifecycleDeferredValidator,
  HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL,
  type ForceAuthHoldResult,
  type DualGateForceResult,
  type DualGateReleaseResult,
} from "./auth-hold.js";

export {
  withConnectedPgClient,
  runFailClosedPerNodeHold,
  DISCOVER_RESTORE_NODE_IDS_SQL,
  type HoldDbClient,
  type FailClosedPerNodeHoldInput,
  type FailClosedPerNodeHoldResult,
} from "./hold-db-orchestration.js";

export {
  createBackupScheduler,
  newestBackupArtifactMtimeMs,
  type BackupScheduleConfig,
  type BackupScheduleOwnership,
  type BackupScheduleStatus,
  type BackupSchedulerHandle,
  type ScheduledBackupPairingInput,
  type ScheduledBackupSuccess,
} from "./schedule.js";

export { pruneRetainedBackups, type RetentionInput, type RetentionReport } from "./retention.js";

export {
  verifyProviderBackups,
  type ProviderArtifactReport,
  type ProviderVerifyReport,
} from "./provider-verify.js";

export { runDrCli, type CliEnv, type CliIo } from "./cli.js";
