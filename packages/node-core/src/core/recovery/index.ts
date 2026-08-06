// Restore / recovery-verification and vault master-key rotation ceremonies.
// Both are node-origin, offline, and key-free at this boundary: every private-key operation
// happens inside a caller-held seam, so nothing here ever holds a key (the key-custody rule).
export {
  RECOVERY_PROBE_FIELD_SEQUENCE,
  RECOVERY_VERIFICATION_PURPOSE,
  buildRecoveryProbePayload,
  buildRecoveryProbePreimageText,
  type RecoveryProbeInputs,
  type RecoveryProbePayload,
  type RecoveryVerificationPurpose,
} from "./probe.js";
export { runRestoreRecoveryCeremony } from "./restore.js";
export { rotateVaultMasterKey } from "./rotation.js";
export {
  createSqlRecoveryLiveDatabase,
  RECOVERY_STAMP_SQL,
  type RecoverySqlExecutor,
  type SqlRecoveryLiveDatabaseDeps,
} from "./sql-live-database.js";
export type {
  NodeSigningInterlock,
  RecoveryCeremonySummary,
  RecoveryLiveDatabase,
  RecoveryStampInput,
  RecoveryWalletRow,
  RestoreAbortReason,
  RestoreCeremonyInput,
  RestoreCeremonyResult,
  RestoredInstance,
  RestoredVaultAccess,
  RotateVaultMasterKeyInput,
  RotationAbortReason,
  RotationCrypto,
  RotationResult,
  RotationSecretHandle,
  RotationState,
  RotationVaultRow,
  RotationWallet,
  WalletCeremonyOutcome,
} from "./types.js";
