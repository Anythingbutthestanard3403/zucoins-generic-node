// Launch DR policy for the generic node. Frozen operator-facing numbers.

/** Target maximum age of the newest successful encrypted backup. */
export const BACKUP_RPO_TARGET_MS = 24 * 60 * 60 * 1000; // 24h

/** Target wall-clock budget for a full greenfield restore drill. */
export const BACKUP_RTO_TARGET_MS = 60 * 60 * 1000; // 1h

/** Default on-disk retention for successful backup artifacts. */
export const BACKUP_RETENTION_DEFAULT_DAYS = 14;

export const BACKUP_RETENTION_MIN_DAYS = 1;
export const BACKUP_RETENTION_MAX_DAYS = 90;

/** Default schedule interval when the operator enables the scheduler. */
export const BACKUP_SCHEDULE_INTERVAL_DEFAULT_MS = 24 * 60 * 60 * 1000; // 24h

export const BACKUP_SCHEDULE_INTERVAL_MIN_MS = 60 * 60 * 1000; // 1h
export const BACKUP_SCHEDULE_INTERVAL_MAX_MS = BACKUP_RPO_TARGET_MS;

export const BACKUP_ENVELOPE_EXTENSION = ".zbkp" as const;

export interface BackupPolicy {
  readonly rpoTargetMs: number;
  readonly rtoTargetMs: number;
  readonly retentionDays: number;
  readonly scheduleIntervalMs: number;
}

export const DEFAULT_BACKUP_POLICY: BackupPolicy = Object.freeze({
  rpoTargetMs: BACKUP_RPO_TARGET_MS,
  rtoTargetMs: BACKUP_RTO_TARGET_MS,
  retentionDays: BACKUP_RETENTION_DEFAULT_DAYS,
  scheduleIntervalMs: BACKUP_SCHEDULE_INTERVAL_DEFAULT_MS,
});

export function isRpoBreached(
  newestBackupAtMs: number | null,
  nowMs: number,
  policy: BackupPolicy = DEFAULT_BACKUP_POLICY,
): boolean {
  if (newestBackupAtMs === null) return true;
  if (!Number.isFinite(newestBackupAtMs) || newestBackupAtMs > nowMs) return true;
  return nowMs - newestBackupAtMs > policy.rpoTargetMs;
}

export function isRtoBreached(
  durationMs: number,
  policy: BackupPolicy = DEFAULT_BACKUP_POLICY,
): boolean {
  if (!Number.isFinite(durationMs) || durationMs < 0) return true;
  return durationMs > policy.rtoTargetMs;
}
