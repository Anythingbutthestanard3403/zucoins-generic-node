// Stage-1 configuration (zero-custody compose root).
// Production reference requires the encrypted-backup KEK + durable sink.

import {
  BACKUP_RETENTION_DEFAULT_DAYS,
  BACKUP_SCHEDULE_INTERVAL_DEFAULT_MS,
  BACKUP_SCHEDULE_INTERVAL_MAX_MS,
  BACKUP_SCHEDULE_INTERVAL_MIN_MS,
  BACKUP_RETENTION_MAX_DAYS,
  BACKUP_RETENTION_MIN_DAYS,
} from "./dr/policy.js";

export interface Stage1BackupConfig {
  readonly enabled: true;
  readonly masterKey: string;
  readonly outputDir: string;
  readonly continuityMarkersPath: string | undefined;
  readonly retentionDays: number;
  readonly scheduleIntervalMs: number;
}

export interface Stage1Config {
  readonly bindHost: string;
  readonly databaseUrl: string;
  readonly port: number;
  readonly nodeEnv: "development" | "test" | "production";
  /** Present only when BACKUP_SCHEDULE_ENABLED=true (required under production). */
  readonly backup: Stage1BackupConfig | undefined;
}

function parseBool(raw: string | undefined, name: string): boolean | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`Invalid Stage-1 configuration: ${name} must be 'true' or 'false'`);
}

function parseIntInRange(
  raw: string | undefined,
  name: string,
  min: number,
  max: number,
  fallback: number,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(
      `Invalid Stage-1 configuration: ${name} must be an integer from ${min} to ${max}`,
    );
  }
  return n;
}

export function loadStage1Config(
  source: Readonly<Record<string, string | undefined>> = process.env,
): Stage1Config {
  const databaseUrl = source.DATABASE_URL?.trim();
  if (!databaseUrl || !/^postgres(ql)?:\/\//.test(databaseUrl)) {
    throw new Error("Invalid Stage-1 configuration: DATABASE_URL must be a postgres URL");
  }
  const bindHost = source.BIND_HOST?.trim() || "::";
  const port = source.PORT === undefined ? 8080 : Number(source.PORT);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("Invalid Stage-1 configuration: PORT must be an integer from 1 to 65535");
  }

  const nodeEnvRaw = source.NODE_ENV?.trim() || "development";
  if (nodeEnvRaw !== "development" && nodeEnvRaw !== "test" && nodeEnvRaw !== "production") {
    throw new Error(
      "Invalid Stage-1 configuration: NODE_ENV must be development, test, or production",
    );
  }
  const nodeEnv = nodeEnvRaw;

  const scheduleFlag = parseBool(source.BACKUP_SCHEDULE_ENABLED, "BACKUP_SCHEDULE_ENABLED");
  // Production reference policy: scheduled encrypted backups are
  // required. Non-production stays opt-in so local/dev boots remain light.
  const enabled =
    scheduleFlag === true || (scheduleFlag === undefined && nodeEnv === "production");
  if (nodeEnv === "production" && scheduleFlag === false) {
    throw new Error(
      "Invalid Stage-1 configuration: BACKUP_SCHEDULE_ENABLED=false is forbidden under NODE_ENV=production (durable backup policy)",
    );
  }

  let backup: Stage1BackupConfig | undefined;
  if (enabled) {
    const masterKey = source.BACKUP_MASTER_KEY?.trim();
    if (!masterKey || masterKey.length < 32) {
      throw new Error(
        "Invalid Stage-1 configuration: BACKUP_MASTER_KEY (≥32 chars, dedicated KEK) is required when scheduled backups are enabled",
      );
    }
    const outputDir = source.BACKUP_OUTPUT_DIR?.trim();
    if (!outputDir) {
      throw new Error(
        "Invalid Stage-1 configuration: BACKUP_OUTPUT_DIR is required when scheduled backups are enabled (durable sink; not emptyDir /tmp)",
      );
    }
    if (outputDir === "/tmp" || outputDir.startsWith("/tmp/")) {
      throw new Error(
        "Invalid Stage-1 configuration: BACKUP_OUTPUT_DIR must not be under /tmp (ephemeral; pod replace destroys RPO evidence)",
      );
    }
    const continuityMarkersPath = source.BACKUP_CONTINUITY_MARKERS_PATH?.trim() || undefined;
    backup = Object.freeze({
      enabled: true as const,
      masterKey,
      outputDir,
      continuityMarkersPath,
      retentionDays: parseIntInRange(
        source.BACKUP_RETENTION_DAYS,
        "BACKUP_RETENTION_DAYS",
        BACKUP_RETENTION_MIN_DAYS,
        BACKUP_RETENTION_MAX_DAYS,
        BACKUP_RETENTION_DEFAULT_DAYS,
      ),
      scheduleIntervalMs: parseIntInRange(
        source.BACKUP_SCHEDULE_INTERVAL_MS,
        "BACKUP_SCHEDULE_INTERVAL_MS",
        BACKUP_SCHEDULE_INTERVAL_MIN_MS,
        BACKUP_SCHEDULE_INTERVAL_MAX_MS,
        BACKUP_SCHEDULE_INTERVAL_DEFAULT_MS,
      ),
    });
  }

  return Object.freeze({
    bindHost,
    databaseUrl,
    port,
    nodeEnv,
    backup,
  });
}
