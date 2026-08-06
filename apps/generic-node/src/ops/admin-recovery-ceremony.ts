// In-process recovery-verification ceremony for the Mode A admin API.
//
// Reuses the same composeRestoreRecoveryCeremony core as the CLI break-glass path.
// Master key enters only as a function argument (POST body upstream); never logged,
// never written to DB/audit, never returned. Root buffers are zeroed in finally.
//
// Progress is digests/counts only. Ceremony remains the sole writer of recovery_verified_at
//. CLI `run-recovery-ceremony.js` stays supported break-glass.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Pool } from "pg";

import {
  deriveRootKey,
  type RestoreCeremonyResult,
} from "@zucoins/node-core";

import { exportLiveBackupArchive } from "./export-live-backup-archive.js";
import {
  composeRestoreRecoveryCeremony,
  deriveLiveConnectionParams,
} from "./run-recovery-ceremony.js";
import { createSqlRestoredInstance } from "./sql-restored-instance.js";

const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
export const MIN_MASTER_KEY_CHARS = 32;

export type CeremonyStage =
  | "accepted"
  | "exporting_archive"
  | "restoring_throwaway"
  | "verifying_wallets"
  | "stamping"
  | "summarising"
  | "complete"
  | "failed";

export interface CeremonyProgressEvent {
  readonly stage: CeremonyStage;
  readonly detail?: string;
  readonly at: string;
}

export interface CeremonyDigestSummary {
  readonly ok: boolean;
  readonly ceremony_id: string;
  readonly export_id: string | null;
  readonly archive_sha256: string | null;
  readonly accepted: boolean;
  readonly stamped: number;
  readonly failed_closed: number;
  readonly skipped: number;
  readonly born_blocked: number;
  readonly abort_reasons: readonly string[];
  readonly instance_destroyed: boolean;
  readonly recovery_verified_on_live: number;
}

export interface CeremonyJobSnapshot {
  readonly ceremony_id: string;
  readonly status: "running" | "complete" | "failed";
  readonly stage: CeremonyStage;
  readonly progress: readonly CeremonyProgressEvent[];
  readonly summary: CeremonyDigestSummary | null;
  readonly error: { readonly code: string; readonly message: string } | null;
  readonly started_at: string;
  readonly finished_at: string | null;
}

export interface RunInProcessCeremonyInput {
  readonly databaseUrl: string;
  readonly liveSql: Pool;
  readonly nodeId: string;
  readonly vaultMasterKey: string;
  readonly archiveEpochMasterKey?: string;
  readonly verifierIdentity: string;
  readonly now?: () => Date;
  readonly newId?: () => string;
  readonly onProgress?: (event: CeremonyProgressEvent) => void;
}

function b64urlNonce(): string {
  const raw = randomBytes(16);
  const unpadded = raw.toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function outcomeCounts(result: RestoreCeremonyResult): {
  stamped: number;
  failedClosed: number;
  skipped: number;
} {
  let stamped = 0;
  let failedClosed = 0;
  let skipped = 0;
  for (const outcome of result.outcomes.values()) {
    if (outcome === "stamped") stamped += 1;
    else if (outcome === "failed_closed") failedClosed += 1;
    else skipped += 1;
  }
  return { stamped, failedClosed, skipped };
}

function wipeBuffer(buf: Uint8Array | Buffer | undefined): void {
  if (buf === undefined) return;
  buf.fill(0);
}

function wipeStringHolder(holder: { value: string }): void {
  // Best-effort: overwrite the JS string slot with empty. JS strings are immutable;
  // callers must drop all references after return. We never log/store the value.
  holder.value = "";
}

async function createThrowawayProvider(input: {
  readonly databaseUrl: string;
  readonly rootKey: Uint8Array;
  readonly archiveRootKey?: Uint8Array;
  readonly nodeId: string;
}): Promise<() => Promise<{
  readonly instance: import("@zucoins/node-core").RestoredInstance;
  readonly restoredVault: import("@zucoins/node-core").RestoredVaultAccess;
  readonly destroy: () => Promise<void>;
}>> {
  const adminConnectionString = deriveLiveConnectionParams(input.databaseUrl, "postgres");
  const { Client } = await import("pg");
  const adminClient = new Client({ connectionString: adminConnectionString });
  await adminClient.connect();
  const throwawayName = `admin_recovery_restore_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  await adminClient.query(`CREATE DATABASE ${throwawayName}`);
  const { Pool: PgPool } = await import("pg");
  const throwawayPool = new PgPool({
    connectionString: deriveLiveConnectionParams(input.databaseUrl, throwawayName),
  });
  const { runMigrationsOnPool } = await import("../db/migrate.js");
  await runMigrationsOnPool(throwawayPool);
  const { migrateLeaseFoundation } = await import("@zucoins/node-core");
  await migrateLeaseFoundation({
    query: async <R>(text: string, params?: readonly unknown[]) => {
      const r = await throwawayPool.query(text, params as never);
      return { rows: r.rows as R[], rowCount: r.rowCount };
    },
  });
  const drop = async () => {
    await throwawayPool.end().catch(() => {});
    await adminClient
      .query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [throwawayName],
      )
      .catch(() => {});
    await adminClient.query(`DROP DATABASE IF EXISTS ${throwawayName}`).catch(() => {});
    await adminClient.end().catch(() => {});
  };
  return async () => {
    const r = await createSqlRestoredInstance({
      createThrowawayDatabase: async () => ({
        pool: throwawayPool,
        databaseName: throwawayName,
        drop,
      }),
      rootKey: input.rootKey,
      archiveRootKey: input.archiveRootKey,
      nodeId: input.nodeId,
    });
    return { instance: r.instance, restoredVault: r.vaultAccess, destroy: r.destroy };
  };
}

/**
 * Run the full restore ceremony in-process. Caller must already have burned a fresh TOTP.
 * Never logs or returns the master key. Zeroizes derived root keys on every exit path.
 */
export async function runInProcessRecoveryCeremony(
  input: RunInProcessCeremonyInput,
): Promise<CeremonyDigestSummary> {
  const masterHolder = { value: input.vaultMasterKey };
  const archiveHolder =
    input.archiveEpochMasterKey !== undefined
      ? { value: input.archiveEpochMasterKey }
      : null;

  if (masterHolder.value.length < MIN_MASTER_KEY_CHARS) {
    throw new CeremonyValidationError(
      "vault_master_key_too_short",
      `vault_master_key must be at least ${MIN_MASTER_KEY_CHARS} characters`,
    );
  }
  if (archiveHolder !== null && archiveHolder.value.length < MIN_MASTER_KEY_CHARS) {
    throw new CeremonyValidationError(
      "archive_epoch_master_key_too_short",
      `archive_epoch_master_key must be at least ${MIN_MASTER_KEY_CHARS} characters`,
    );
  }

  const emit = (stage: CeremonyStage, detail?: string) => {
    input.onProgress?.({
      stage,
      detail,
      at: (input.now ?? (() => new Date()))().toISOString(),
    });
  };

  const ceremonyId = input.newId?.() ?? randomUUID();
  const ceremonyNonce = b64urlNonce();
  const issuedAt = (input.now ?? (() => new Date()))().toISOString();

  let rootKey: Buffer | undefined;
  let archiveRootKey: Buffer | undefined;

  try {
    emit("accepted");
    rootKey = deriveRootKey(masterHolder.value, VAULT_ROOT_KDF_SALT);
    if (archiveHolder !== null) {
      archiveRootKey = deriveRootKey(archiveHolder.value, VAULT_ROOT_KDF_SALT);
    }

    emit("exporting_archive");
    const exported = await exportLiveBackupArchive({
      sql: input.liveSql,
      rootKey,
      nodeId: input.nodeId,
      exportId: ceremonyId,
      exportedAt: issuedAt,
    });
    const archiveText = exported.archiveText;
    const exportId = exported.exportId;
    const archiveSha = sha256HexUtf8(archiveText);

    emit("restoring_throwaway");
    const restoredInstanceProvider = await createThrowawayProvider({
      databaseUrl: input.databaseUrl,
      rootKey,
      archiveRootKey,
      nodeId: input.nodeId,
    });

    emit("verifying_wallets");
    const { result, destroyCalls } = await composeRestoreRecoveryCeremony({
      archiveText,
      rootKey,
      archiveRootKey,
      nodeId: input.nodeId,
      liveSql: input.liveSql,
      verifierIdentity: input.verifierIdentity,
      ceremonyId,
      ceremonyNonce,
      issuedAt,
      now: input.now,
      newId: input.newId,
      restoredInstanceProvider,
    });

    emit("stamping");
    const counts = outcomeCounts(result);
    const verified = await input.liveSql.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM wallets
        WHERE node_id = $1::uuid AND recovery_verified_at IS NOT NULL`,
      [input.nodeId],
    );
    const verifiedOnLive = Number(verified.rows[0]?.n ?? "0");

    emit("summarising");
    const summary: CeremonyDigestSummary = {
      ok: result.accepted && counts.stamped + counts.skipped > 0 && verifiedOnLive > 0,
      ceremony_id: ceremonyId,
      export_id: exportId,
      archive_sha256: archiveSha,
      accepted: result.accepted,
      stamped: counts.stamped,
      failed_closed: counts.failedClosed,
      skipped: counts.skipped,
      born_blocked: result.bornBlocked.length,
      abort_reasons: result.abortReasons,
      instance_destroyed: result.instanceDestroyed && destroyCalls >= 1,
      recovery_verified_on_live: verifiedOnLive,
    };
    emit("complete");
    return summary;
  } catch (err) {
    emit("failed", err instanceof Error ? err.name : "error");
    throw err;
  } finally {
    wipeBuffer(rootKey);
    wipeBuffer(archiveRootKey);
    wipeStringHolder(masterHolder);
    if (archiveHolder !== null) wipeStringHolder(archiveHolder);
  }
}

export class CeremonyValidationError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CeremonyValidationError";
    this.code = code;
  }
}

// ── In-memory job registry (digests-only; never stores master key) ──────────

const CEREMONY_RATE_WINDOW_MS = 15 * 60 * 1000;
const CEREMONY_RATE_THRESHOLD = 5;
const CEREMONY_LOCKOUT_MS = 15 * 60 * 1000;

interface RateEntry {
  count: number;
  windowStartMs: number;
  lockedUntilMs: number | null;
}

const rateByUser = new Map<string, RateEntry>();
const jobs = new Map<string, CeremonyJobSnapshot>();
let runningCeremonyId: string | null = null;

/** Test helper — clear job + rate state. */
export function _resetCeremonyRegistryForTests(): void {
  rateByUser.clear();
  jobs.clear();
  runningCeremonyId = null;
}

export function isCeremonyUserLocked(userId: string, nowMs = Date.now()): boolean {
  const entry = rateByUser.get(userId);
  return entry?.lockedUntilMs != null && entry.lockedUntilMs > nowMs;
}

export function registerCeremonyAttempt(userId: string, nowMs = Date.now()): {
  tripped: boolean;
  count: number;
} {
  const entry = rateByUser.get(userId);
  if (entry?.lockedUntilMs != null && entry.lockedUntilMs > nowMs) {
    return { tripped: true, count: entry.count };
  }
  if (!entry || nowMs - entry.windowStartMs >= CEREMONY_RATE_WINDOW_MS) {
    const fresh: RateEntry = {
      count: 1,
      windowStartMs: nowMs,
      lockedUntilMs: CEREMONY_RATE_THRESHOLD <= 1 ? nowMs + CEREMONY_LOCKOUT_MS : null,
    };
    rateByUser.set(userId, fresh);
    return { tripped: fresh.lockedUntilMs != null, count: 1 };
  }
  entry.count += 1;
  const tripped = entry.count >= CEREMONY_RATE_THRESHOLD;
  if (tripped && entry.lockedUntilMs == null) {
    entry.lockedUntilMs = nowMs + CEREMONY_LOCKOUT_MS;
  }
  return { tripped, count: entry.count };
}

export function getCeremonyJob(ceremonyId: string): CeremonyJobSnapshot | null {
  return jobs.get(ceremonyId) ?? null;
}

export function getLatestCeremonyJob(): CeremonyJobSnapshot | null {
  let latest: CeremonyJobSnapshot | null = null;
  for (const job of jobs.values()) {
    if (latest === null || job.started_at > latest.started_at) latest = job;
  }
  return latest;
}

export function isCeremonyRunning(): boolean {
  return runningCeremonyId !== null;
}

/**
 * Start an async ceremony job. Returns the initial snapshot (status=running).
 * Master key is held only in the async closure until the run finishes, then dropped.
 */
export function startCeremonyJob(input: {
  readonly databaseUrl: string;
  readonly liveSql: Pool;
  readonly nodeId: string;
  readonly vaultMasterKey: string;
  readonly archiveEpochMasterKey?: string;
  readonly verifierIdentity: string;
  readonly userId: string;
  readonly now?: () => Date;
  readonly newId?: () => string;
}): CeremonyJobSnapshot {
  if (runningCeremonyId !== null) {
    throw new CeremonyValidationError(
      "ceremony_in_flight",
      "a recovery ceremony is already running on this node",
    );
  }

  const ceremonyId = input.newId?.() ?? randomUUID();
  const startedAt = (input.now ?? (() => new Date()))().toISOString();
  const progress: CeremonyProgressEvent[] = [];
  const snapshot: CeremonyJobSnapshot = {
    ceremony_id: ceremonyId,
    status: "running",
    stage: "accepted",
    progress,
    summary: null,
    error: null,
    started_at: startedAt,
    finished_at: null,
  };
  jobs.set(ceremonyId, snapshot);
  runningCeremonyId = ceremonyId;

  // Capture key into local only; never attach to snapshot/jobs map.
  const keyLocal = input.vaultMasterKey;
  const archiveLocal = input.archiveEpochMasterKey;

  void (async () => {
    try {
      const summary = await runInProcessRecoveryCeremony({
        databaseUrl: input.databaseUrl,
        liveSql: input.liveSql,
        nodeId: input.nodeId,
        vaultMasterKey: keyLocal,
        archiveEpochMasterKey: archiveLocal,
        verifierIdentity: input.verifierIdentity,
        now: input.now,
        newId: input.newId,
        onProgress: (event) => {
          progress.push(event);
          const cur = jobs.get(ceremonyId);
          if (cur !== undefined) {
            jobs.set(ceremonyId, { ...cur, stage: event.stage, progress: [...progress] });
          }
        },
      });
      const finishedAt = (input.now ?? (() => new Date()))().toISOString();
      jobs.set(ceremonyId, {
        ceremony_id: ceremonyId,
        status: summary.ok ? "complete" : "failed",
        stage: summary.ok ? "complete" : "failed",
        progress: [...progress],
        summary,
        error: summary.ok
          ? null
          : {
              code: "ceremony_not_accepted",
              message: summary.abort_reasons.join(",") || "ceremony did not stamp any wallet",
            },
        started_at: startedAt,
        finished_at: finishedAt,
      });
    } catch (err) {
      const finishedAt = (input.now ?? (() => new Date()))().toISOString();
      const code =
        err instanceof CeremonyValidationError
          ? err.code
          : err instanceof Error
            ? err.name
            : "ceremony_failed";
      // Prefer a short safe message for operators. Never surface values that could carry
      // master-key / seed / pack material; fall back to err.name when the message looks risky.
      const rawMessage = err instanceof Error ? err.message : "ceremony failed";
      const messageLooksSafe =
        rawMessage.length > 0 &&
        rawMessage.length <= 400 &&
        !/master|seed|private|passcode|secret|ik_|BEGIN |-----/i.test(rawMessage);
      const message =
        err instanceof CeremonyValidationError
          ? err.message
          : messageLooksSafe
            ? rawMessage
            : err instanceof Error
              ? err.name
              : "ceremony failed";
      jobs.set(ceremonyId, {
        ceremony_id: ceremonyId,
        status: "failed",
        stage: "failed",
        progress: [...progress],
        summary: null,
        error: { code, message },
        started_at: startedAt,
        finished_at: finishedAt,
      });
    } finally {
      if (runningCeremonyId === ceremonyId) runningCeremonyId = null;
    }
  })();

  return snapshot;
}

/** Wire shape for GET status — digests only. */
export function ceremonyJobToWire(job: CeremonyJobSnapshot): Record<string, unknown> {
  return {
    ceremony_id: job.ceremony_id,
    status: job.status,
    stage: job.stage,
    progress: job.progress.map((p) => ({
      stage: p.stage,
      detail: p.detail ?? null,
      at: p.at,
    })),
    summary: job.summary,
    error: job.error,
    started_at: job.started_at,
    finished_at: job.finished_at,
  };
}
