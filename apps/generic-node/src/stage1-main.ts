import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";

import { loadStage1Config, type Stage1Config } from "./stage1-config.js";
import {
  createBackupScheduler,
  DEFAULT_BACKUP_POLICY,
  newestBackupArtifactMtimeMs,
  isRpoBreached,
  probePgClientBinaries,
  type BackupSchedulerHandle,
  type PgClientProbeResult,
} from "./dr/index.js";
import { installFatalExceptionHandler } from "./boot/fatal-exception.js";
import { createSafeConsoleLogger } from "./boot/safe-logger.js";
import {
  installStage1GracefulStop,
  type InstallStage1GracefulStopOptions,
  type Stage1GracefulStop,
} from "./stage1-shutdown.js";

// Zero-custody or not, Stage 1 holds the backup master key and a database URL,
// and its errors come from the same drivers. Every log line goes through the
// central redactor — see boot/safe-logger.ts.
const logger = createSafeConsoleLogger();

export interface Stage1ServiceDependencies {
  readonly closeDatabase: () => Promise<void>;
  readonly pingDatabase: () => Promise<void>;
  readonly runMigrations: () => Promise<void>;
  /** Test seam — production constructs the real scheduler when config.backup is set. */
  readonly createScheduler?: (config: Stage1Config) => BackupSchedulerHandle | undefined;
  /**
   * Test seam — production probes the real pg_dump/psql binaries.
   * Only invoked when config.backup is set; a non-ok result is fail-closed
   * (startStage1Service rejects rather than starting the scheduler).
   */
  readonly probeBackupClient?: () => Promise<PgClientProbeResult>;
  /**
   * Signal wiring for the graceful stop installed before migrations. Production
   * (main) supplies exit/logger; a test supplies a fake emitter so no handler is
   * registered on the test process. Omitting it still installs the handler — on
   * the real `process` — because a missing handler is the defect this ordering
   * exists to close.
   */
  readonly shutdown?: Omit<InstallStage1GracefulStopOptions, "stop">;
}

export interface Stage1Service {
  readonly server: Server;
  readonly backupScheduler: BackupSchedulerHandle | undefined;
  /** Installed before migrations — see the boot ordering on startStage1Service. */
  readonly gracefulStop: Stage1GracefulStop;
  stop(): Promise<void>;
}

function json(
  response: import("node:http").ServerResponse,
  status: number,
  body: Readonly<Record<string, unknown>>,
): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "content-length": Buffer.byteLength(payload).toString(),
    "content-type": "application/json",
  });
  response.end(payload);
}

function defaultCreateScheduler(config: Stage1Config): BackupSchedulerHandle | undefined {
  if (config.backup === undefined) return undefined;
  return createBackupScheduler({
    enabled: true,
    databaseUrl: config.databaseUrl,
    masterKey: config.backup.masterKey,
    outputDir: config.backup.outputDir,
    intervalMs: config.backup.scheduleIntervalMs,
    policy: {
      ...DEFAULT_BACKUP_POLICY,
      retentionDays: config.backup.retentionDays,
      scheduleIntervalMs: config.backup.scheduleIntervalMs,
    },
    logger,
  });
}

/**
 * Stage 1 is deliberately a distinct zero-custody composition root. Its only
 * boot dependencies are the greenfield migrations and a live DB probe.
 * Vault, signer leadership, recovery, gateway reads and operation workers are
 * Stage-2 custody surfaces and are neither constructed nor marked successful.
 *
 * When production (or explicitly enabled) backup policy is present,
 * the encrypted-backup scheduler is constructed here so the Dockerfile's
 * stage1-main entrypoint actually produces durable RPO artifacts.
 *
 * Boot sequencing mirrors the custody boot lane (boot/boot-lane.ts:1-54, rule at
 * :12-13 — migrations run with the health surface already answering):
 * listen → install the graceful stop → migrate → open readiness. Migrating first
 * left nothing bound for the whole migration, so a supervisor probe got
 * ECONNREFUSED ("container dead", restart the pod) instead of a 503 ("alive, not
 * ready"), and a SIGTERM arriving before the handler existed was an uncatchable
 * kill. A migration failure stays fatal: the surface is torn back down and the
 * error rethrown.
 */
export async function startStage1Service(
  config: Stage1Config,
  dependencies: Stage1ServiceDependencies,
): Promise<Stage1Service> {
  let stopping = false;
  // Readiness gate: false until migrations (and the backup wiring behind them)
  // complete, so /health/ready answers 503 while the schema is being applied.
  let migrationsComplete = false;
  let backupScheduler: BackupSchedulerHandle | undefined;
  let rpoTimer: ReturnType<typeof setInterval> | undefined;

  const server = createServer((request, response) => {
    const path = (request.url ?? "").split(/[?#]/, 1)[0];
    if (request.method === "GET" && path === "/health") {
      json(response, 200, { status: "live" });
      return;
    }
    if (request.method === "GET" && path === "/health/ready") {
      if (!migrationsComplete || stopping) {
        // Bound but not ready. Liveness above stays unconditional — it must never
        // depend on the database (readiness-state.ts:49-51 for the custody path).
        json(response, 503, {
          status: "not_ready",
          stage: "zero-custody",
          checks: { migrations: migrationsComplete, database: false },
        });
        return;
      }
      void dependencies.pingDatabase().then(
        () =>
          json(response, 200, {
            status: "ready",
            stage: "zero-custody",
            checks: { migrations: true, database: true },
          }),
        () =>
          json(response, 503, {
            status: "not_ready",
            stage: "zero-custody",
            checks: { migrations: true, database: false },
          }),
      );
      return;
    }
    // No operation/auth/gateway adapter is mounted in the Stage-1 process.
    // Backup bytes are never served over HTTP.
    json(response, 503, { error: "stage_1_zero_custody" });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.bindHost, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const stop = async (): Promise<void> => {
    if (stopping) return;
    stopping = true;
    if (rpoTimer !== undefined) clearInterval(rpoTimer);
    backupScheduler?.stop();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
      if (typeof server.closeIdleConnections === "function") {
        server.closeIdleConnections();
      }
    });
    await dependencies.closeDatabase();
  };

  // Installed BEFORE the migration, not after it. Chosen posture on a SIGTERM
  // that lands mid-migration: stop rather than wait. The migration owns a
  // separate pool (db/migrate.ts runMigrations builds its own), so `stop` only
  // closes the HTTP surface and the service pool; the migration's pinned
  // connection dies with the process, and Postgres rolls back its open
  // transaction and drops the migrator advisory lock on disconnect
  // (db/migrate.ts:87-90). Waiting instead would risk outliving the platform's
  // SIGTERM→SIGKILL grace and losing the log line entirely; every migration is
  // idempotent and additive (boot-lane.ts:43-48), so the retry converges.
  const gracefulStop = installStage1GracefulStop({ ...dependencies.shutdown, stop });

  try {
    await dependencies.runMigrations();

    if (config.backup !== undefined) {
      const probeBackupClient = dependencies.probeBackupClient ?? probePgClientBinaries;
      const probe = await probeBackupClient();
      if (!probe.ok) {
        throw new Error(
          `postgresql-client probe failed — refusing to start with backup schedule enabled ` +
            `: ${probe.reason}`,
        );
      }
    }

    const createScheduler = dependencies.createScheduler ?? defaultCreateScheduler;
    backupScheduler = createScheduler(config);
    backupScheduler?.start();

    // RPO monitor: poll newest artifact age without serving backup bytes over HTTP.
    if (config.backup !== undefined) {
      const outputDir = config.backup.outputDir;
      const intervalMs = Math.min(config.backup.scheduleIntervalMs, 60 * 60 * 1000);
      const check = async (): Promise<void> => {
        try {
          const newest = await newestBackupArtifactMtimeMs(outputDir);
          const status = backupScheduler?.status();
          if (isRpoBreached(newest, Date.now()) || status?.rpoBreached === true) {
            logger.error(
              `dr: RPO BREACHED newestArtifactAtMs=${newest ?? "none"} consecutiveFailures=${status?.consecutiveFailures ?? "n/a"} — run \`node dist/dr/cli.js status\` / restore drill`,
            );
          }
        } catch (err) {
          logger.error("dr: RPO monitor probe failed", err);
        }
      };
      void check();
      rpoTimer = setInterval(() => {
        void check();
      }, intervalMs);
      // Do not keep the process alive solely for monitoring.
      rpoTimer.unref?.();
    }
  } catch (error) {
    // Still fatal — only later than before. The port is already bound, so tear
    // it back down (best effort; the boot error is what the operator needs).
    await stop().catch(() => {});
    throw error;
  }

  migrationsComplete = true;
  return Object.freeze({ server, backupScheduler, gracefulStop, stop });
}

async function main(): Promise<void> {
  // Before config, before any listener: an unguarded synchronous throw in a
  // request path must not be able to kill the process.
  const fatal = installFatalExceptionHandler({ logger });

  // Validation is intentionally first. The dynamic imports prevent either DB
  // pool construction or migration work before the Stage-1 schema succeeds.
  const config = loadStage1Config();
  const [{ createPool }, { runMigrations }] = await Promise.all([
    import("./db/client.js"),
    import("./db/migrate.js"),
  ]);
  const pool = createPool(config.databaseUrl);
  const service = await startStage1Service(config, {
    // Config.databaseUrl is already validated by loadStage1Config above —
    // migrations must run against that same value, not a second env read.
    runMigrations: () => runMigrations(config.databaseUrl),
    pingDatabase: async () => {
      await pool.query("SELECT 1");
    },
    closeDatabase: async () => {
      await pool.end();
    },
    // Installed inside startStage1Service, before migrations — see its boot
    // sequencing note. Registered on the real `process` by default.
    shutdown: {
      // A fatal left the process in unknown state — even a clean stop exits non-zero.
      exit: (code) => process.exit(fatal.tripped() ? 1 : code),
      logger,
    },
  });
  if (config.backup !== undefined) {
    logger.info(
      `generic-node Stage 1 backup scheduler enabled intervalMs=${config.backup.scheduleIntervalMs} dir=${config.backup.outputDir}`,
    );
  } else {
    logger.info(
      "generic-node Stage 1 backup scheduler disabled — set BACKUP_SCHEDULE_ENABLED=true (required in production)",
    );
  }
  fatal.wire(() => service.gracefulStop.handleSignal("uncaughtException"));
  logger.info(`generic-node Stage 1 listening on ${config.bindHost}:${config.port}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error: unknown) => {
    logger.error(
      "generic-node Stage 1 could not start and is not serving traffic. Inspect configuration validation, database connectivity, migration status, and bind-address availability before restarting.",
      error,
    );
    process.exit(1);
  });
}
