// Scheduled encrypted-backup job for generic-node (opt-in).

import { mkdir, readdir, rename, rm, stat } from "node:fs/promises";
import { join } from "node:path";

import { exportEncryptedBackup, type BackupResult } from "./encrypted-backup.js";
import {
  BACKUP_ENVELOPE_EXTENSION,
  DEFAULT_BACKUP_POLICY,
  isRpoBreached,
  type BackupPolicy,
} from "./policy.js";
import { pruneRetainedBackups, type RetentionReport } from "./retention.js";

export interface BackupScheduleConfig {
  readonly enabled: boolean;
  readonly databaseUrl: string;
  readonly masterKey: string;
  readonly outputDir: string;
  readonly intervalMs: number;
  readonly policy?: BackupPolicy;
  readonly nowMs?: () => number;
  /**
   * Injectable inter-run delay. `signal.stopped()` is true after {@link BackupSchedulerHandle.stop};
   * implementations must resolve early when stopped so graceful stop is not blocked by intervalMs.
   */
  readonly sleep?: (ms: number, signal: { readonly stopped: () => boolean }) => Promise<void>;
  /**
   * Optional hook so the process shutdown registry can track each export
   * . Invoked with the in-flight run promise before it is awaited.
   */
  readonly trackInflight?: <T>(work: Promise<T>) => Promise<T>;
  readonly afterSuccess?: (result: ScheduledBackupSuccess) => Promise<void> | void;
  /**
   * Leadership / ownership gate (ZTR-1183). When provided, start() and each
   * loop iteration consult it; followers must not beginTrackedRun backups.
   * Omitted = single-writer composition (Stage 1) that has no leadership latch.
   */
  readonly isLeader?: () => boolean;
  readonly logger?: {
    info(message: string): void;
    error(message: string, err?: unknown): void;
  };
}

export interface ScheduledBackupSuccess {
  readonly result: BackupResult;
  readonly startedAtMs: number;
  readonly finishedAtMs: number;
  readonly retention: RetentionReport;
}

/**
 * Ownership of the scheduled-backup duty on this process (ZTR-1183).
 * - owner: this process holds leadership (or no leadership gate is wired) and may run dumps
 * - standby: schedule is configured but this process is not the backup owner
 * - disabled: BACKUP_SCHEDULE_ENABLED=false / config.enabled=false
 */
export type BackupScheduleOwnership = "owner" | "standby" | "disabled";

export interface BackupScheduleStatus {
  readonly enabled: boolean;
  /** Who owns scheduled dumps on this process — never confuse standby with RPO failure. */
  readonly ownership: BackupScheduleOwnership;
  readonly running: boolean;
  readonly lastSuccessAtMs: number | null;
  readonly lastFailureAtMs: number | null;
  readonly lastError: string | null;
  readonly newestArtifactAtMs: number | null;
  /**
   * RPO breach is only meaningful for the owner. Standby/disabled always report
   * false so a non-leader replica cannot raise backup_age from empty local state.
   */
  readonly rpoBreached: boolean;
  readonly consecutiveFailures: number;
}

export interface BackupSchedulerHandle {
  /**
   * Begin the loop (no-op when config.enabled is false, or when
   * {@link BackupScheduleConfig.isLeader} is provided and returns false).
   */
  start(): void;
  /**
   * Synchronous ENGINE_QUIESCE step: stop accepting new runs and
   * interrupt the inter-run sleep. In-flight export is NOT cancelled — await
   * {@link drain} / let the tracked promise settle inside flushInFlight. // contract-allow:drain:frozen structural vocabulary
   */
  stop(): void;
  /**
   * Await the currently running export (if any). Resolves immediately when
   * idle. Bound for graceful-stop INFLIGHT_SIGNING_COMPLETE / deploy drain. // contract-allow:drain:frozen structural vocabulary
   */
  drain(): Promise<void>; // contract-allow:drain:frozen structural vocabulary
  runOnce(): Promise<ScheduledBackupSuccess>;
  status(): BackupScheduleStatus;
}

/**
 * Sleep that resolves early when `wake` is invoked (scheduler.stop).
 */
export function interruptibleSleep(
  ms: number,
  registerWake: (wake: () => void) => void,
): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(handle);
      resolve();
    };
    const handle = setTimeout(finish, ms);
    registerWake(finish);
  });
}

function backupFilename(nowMs: number): string {
  const iso = new Date(nowMs).toISOString().replace(/[:.]/g, "-");
  return `generic-node-${iso}${BACKUP_ENVELOPE_EXTENSION}`;
}

export async function newestBackupArtifactMtimeMs(outputDir: string): Promise<number | null> {
  let entries: string[];
  try {
    entries = await readdir(outputDir);
  } catch {
    return null;
  }
  let newest: number | null = null;
  for (const name of entries) {
    if (!name.endsWith(BACKUP_ENVELOPE_EXTENSION)) continue;
    try {
      const s = await stat(join(outputDir, name));
      if (!s.isFile()) continue;
      if (newest === null || s.mtimeMs > newest) newest = s.mtimeMs;
    } catch {
      /* skip */
    }
  }
  return newest;
}

export function createBackupScheduler(config: BackupScheduleConfig): BackupSchedulerHandle {
  const policy = config.policy ?? DEFAULT_BACKUP_POLICY;
  const nowMs = config.nowMs ?? (() => Date.now());
  const log = config.logger ?? {
    info: (m: string) => console.log(m),
    error: (m: string, err?: unknown) => {
      if (err === undefined) console.error(m);
      else console.error(m, err);
    },
  };

  let stopped = true;
  let lastSuccessAtMs: number | null = null;
  let lastFailureAtMs: number | null = null;
  let lastError: string | null = null;
  let newestArtifactAtMs: number | null = null;
  let consecutiveFailures = 0;
  let running = false;
  /** Active export promise (settled or rejected both clear the slot). */
  let activeRun: Promise<unknown> | null = null;
  /** Interrupts inter-run sleep so stop() does not wait full intervalMs. */
  let wakeSleep: (() => void) | undefined;

  async function runOnce(): Promise<ScheduledBackupSuccess> {
    if (!config.masterKey || config.masterKey.trim() === "") {
      throw new Error("BACKUP_MASTER_KEY is required to run an encrypted backup");
    }
    await mkdir(config.outputDir, { recursive: true });
    const startedAtMs = nowMs();
    const finalPath = join(config.outputDir, backupFilename(startedAtMs));
    const tmpPath = `${finalPath}.partial`;

    try {
      const result = await exportEncryptedBackup(config.databaseUrl, tmpPath, config.masterKey);
      await rename(tmpPath, finalPath);
      const published: BackupResult = { ...result, outputPath: finalPath };
      const retention = await pruneRetainedBackups({
        directory: config.outputDir,
        retentionDays: policy.retentionDays,
        nowMs: nowMs(),
      });
      const finishedAtMs = nowMs();
      lastSuccessAtMs = finishedAtMs;
      newestArtifactAtMs = finishedAtMs;
      lastError = null;
      consecutiveFailures = 0;
      const success: ScheduledBackupSuccess = {
        result: published,
        startedAtMs,
        finishedAtMs,
        retention,
      };
      log.info(
        `dr: backup ok path=${finalPath} bytes=${published.bytesWritten} sha256=${published.sha256} pruned=${retention.pruned.length}`,
      );
      await config.afterSuccess?.(success);
      return success;
    } catch (err) {
      consecutiveFailures += 1;
      lastFailureAtMs = nowMs();
      lastError = err instanceof Error ? err.message : String(err);
      await rm(tmpPath, { force: true }).catch(() => undefined);
      log.error(`dr: backup failed: ${lastError}`, err);
      throw err;
    }
  }

  function beginTrackedRun(): Promise<void> {
    const work = (async (): Promise<void> => {
      running = true;
      try {
        await runOnce();
      } catch {
        /* logged in runOnce */
      } finally {
        running = false;
      }
    })();
    const tracked: Promise<void> =
      config.trackInflight !== undefined
        ? config.trackInflight(work).then(
            () => undefined,
            () => undefined,
          )
        : work;
    activeRun = tracked.finally(() => {
      if (activeRun === tracked) activeRun = null;
    });
    return tracked;
  }

  async function sleepBetweenRuns(): Promise<void> {
    if (stopped) return;
    if (config.sleep !== undefined) {
      await config.sleep(config.intervalMs, { stopped: () => stopped });
      return;
    }
    await interruptibleSleep(config.intervalMs, (wake) => {
      wakeSleep = wake;
    });
    wakeSleep = undefined;
  }

  function leadershipAllowsRun(): boolean {
    // No gate wired (Stage 1 / unit tests) → single-writer assumption.
    if (config.isLeader === undefined) return true;
    try {
      return config.isLeader() === true;
    } catch (err) {
      log.error("dr: isLeader probe failed — treating as non-leader (fail-closed)", err);
      return false;
    }
  }

  function ownershipNow(): BackupScheduleOwnership {
    if (!config.enabled) return "disabled";
    return leadershipAllowsRun() ? "owner" : "standby";
  }

  async function loop(): Promise<void> {
    while (!stopped) {
      // Re-check ownership every iteration so a lost leadership latch stops
      // further pg_dump runs without waiting for process exit (ZTR-1183).
      if (!leadershipAllowsRun()) {
        log.info("dr: scheduler skipping run — this process is not the backup owner (leadership not held)");
        if (stopped) return;
        await sleepBetweenRuns();
        continue;
      }
      await beginTrackedRun();
      if (stopped) return;
      await sleepBetweenRuns();
    }
  }

  return {
    start() {
      if (!config.enabled) {
        log.info("dr: scheduler disabled (BACKUP_SCHEDULE_ENABLED=false)");
        return;
      }
      if (!leadershipAllowsRun()) {
        log.info(
          "dr: scheduler not started — this process is not the backup owner (leadership not held)",
        );
        return;
      }
      if (!stopped) return;
      stopped = false;
      void loop();
      log.info(`dr: scheduler started intervalMs=${config.intervalMs}`);
    },
    stop() {
      stopped = true;
      wakeSleep?.();
      wakeSleep = undefined;
    },
    async drain() { // contract-allow:drain:frozen structural vocabulary
      const current = activeRun;
      if (current === null) return;
      await current.then(
        () => undefined,
        () => undefined,
      );
    },
    runOnce,
    status() {
      const ownership = ownershipNow();
      const anchor = newestArtifactAtMs ?? lastSuccessAtMs;
      // Standby/disabled must not surface RPO breach — that alarm is owner-only.
      const rpoBreached =
        ownership === "owner"
          ? isRpoBreached(anchor, nowMs(), policy)
          : false;
      return {
        enabled: config.enabled,
        ownership,
        running,
        lastSuccessAtMs,
        lastFailureAtMs,
        lastError,
        newestArtifactAtMs,
        rpoBreached,
        consecutiveFailures,
      };
    },
  };
}
