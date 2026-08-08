// The v2 node process entry point (Stage-2 custody composition).
//
// Boot sequence (enforced structurally — see boot/boot-lane.ts):
//
//   0. loadNodeConfig — the frozen schema. Fail-fast: invalid,
//      missing, or blank critical configuration exits 1 with a diagnosable,
//      secret-free error BEFORE the HTTP server starts and BEFORE any
//      migration can run (review indicator 2).
//   1. Health server starts — liveness 200 immediately, readiness 503 until
// the readiness gating checks pass (schema ∧ DB ∧ vault ∧ observation;
// leadership is reported non-gating by the readiness rule).
//   2. Graceful stop installed — a SIGTERM at ANY later phase is clean.
//   3. runBootLane — migrations → privilege readiness → genesis bootstrap →
//      vault unlock → signer leadership → boot recovery → validated gateway
//      read → readiness → money workers.
//
// Stage-2 money-surface wiring (this ticket):
//   - Live DB adapter + privilege readiness (assertPrivilegeReadiness).
//   - Vault unlock via VaultSqlStore + EncryptedWalletKeyStore (master key
//     only from process.env, not Stage-1 config schema — stage1-production census).
//   - Signer leadership: acquireSignerLeadership bounded retry (fail-closed at
//     SIGNER_LEADERSHIP_RETRY_MAX_MS, well inside the Railway healthcheck window) on
//     shutdownRegistry.authority (sole acquire margin).
//  - runDeterministicBootRecovery with real SQL-backed inventory (greenfield
//     ready when no nonterminal ops / leases; populated recovery classifies durable state).
//   - Validated observation gateway read via readGatewayAction.
//   - SqlCredentialStore + implementer_bearer (no permissive auth).
//   - Live OperationRouteStore over SQL admission stores + three-ops engines
//     under implementer_bearer only (composition gate).
//  - Live SqlDestinationStore + node_generated wallet mint.
//  - NODE_IDENTITY sealed-store ensure + SendArtifactSigner from sealed seed.
//   - Money workers armMoneySurface only after recovery authorizes (never
//     optional-omit MoneyPathSignerGates).

import {
  generateKeyPairSync,
  randomUUID,
} from "node:crypto";
import { createServer } from "node:http";
import type { Pool, PoolClient } from "pg";

import {
  assertPrivilegeReadiness,
  assertSchemaCompleteness,
  CachedDbProbe,
  createDestinationService,
  createDeviceBlessingAuthorizer,
  createHostEvidenceRuntimeMetricsCollector,
  createImplementerBearerAuthFromService,
  createMoneyPathAdmissionPortsFromRuntime,
  createNodeMetrics,
  createMetricsHooks,
  createSafetyAlertEvaluator,
  createSqlActiveDeviceLookup,
  createSqlBlessingArtifactPersister,
  createSqlBlessingAuditAppender,
  createSqlDestinationStore,
  createGatewayExchangeTransport,
  type DeviceSqlExecutor,
  createSqlDeviceKeyStore,
  createSqlOperationRouteStore,
  createStatfsDiskUtilization,
  CredentialService,
  deriveRootKey,
  EncryptedWalletKeyStore,
  ensureActiveNodeSigningKey,
  SqlProofBodyStore,
  type LeadershipLockClient,
  type LeadershipLockPool,
  migrateLeaseFoundation,
  type NodeEventSigner,
  readGatewayAction,
  runDeterministicBootRecovery,
  SIGNER_LEADERSHIP_LOCK_ID,
  SqlCredentialStore,
  SqlMoveCreateStore,
  SqlReceiveAdmissionStore,
  SqlSendCreateStore,
  type SendArtifactSigner,
  SendAdmissionError,
  toBase64UrlPadded,
  type MoneyPathAdmissionPorts,
  type Uuid,
  type WalletPublicKey,
  VaultSqlStore,
  createHaltGate,
  createNodeSettingsHaltStore,
  createNodeSettingsHaltEvidenceRecorder,
  restoreHaltState,
  type OperatorHaltStore,
  type HaltEvidenceRecorder,
  type HaltGate,
  NODE_CORE_VERSION,
} from "@zucoins/node-core";

import {
  loadCustodyNodeConfig,
  NodeConfigurationError,
  receiveQueueCap,
} from "./config/index.js";
import {
  createEventSignerAuthority,
  createShutdownRegistry,
  dispositionForIncompleteBoot,
  installEventSigner,
  installFatalExceptionHandler,
  installGracefulStop,
  NodeReadiness,
  runBootLane,
  type BootLogger,
  type SignerLeadershipHandle,
  type StampedLeadershipHandle,
} from "./boot/index.js";
import { createSqlBootRecovery } from "./boot/sql-boot-recovery.js";
import { acquireSignerLeadershipWithBoundedRetry } from "./boot/signer-leadership-retry.js";
import { PlaceholderSecretError } from "./config/placeholders.js";
import {
  createNodeRuntimeListener,
  type RuntimeListenerLogger,
} from "./runtime-listener.js";
import { createProductionRouteSurface, applyLabTotpBinding, resolveLabTotp } from "./full-http-mount.js";
import { createPool, withPostgresDeadline } from "./db/client.js";
import { createProductionStoragePressureWiring } from "./storage-pressure.js";
import { createBackupScheduler, probePgClientBinaries } from "./dr/index.js";
import { createProductionMetricsSnapshotSource } from "./metrics/snapshot-source.js";
import {
  CUSTODY_ALERT_COOLDOWN_MS,
  evaluateAndDispatchCustodyAlerts,
} from "./metrics/custody-alerts.js";
import {
  generateEphemeralIdentityPublicKey,
  parseNodeIdentitySeed,
  publicKeyFromEd25519Seed,
  runGenesisBootstrap,
} from "./bootstrap/genesis.js";
import { composePush, type PushComposition } from "./push/compose.js";
import { createPoolVaultSigner } from "./money-workers/send-vault-signer.js";
import {
  SqlReportingRateLimiter,
  SqlVerificationAccessStore,
  SqlVaultAccessAuditLog,
  createPoolSqlExecutor,
  createPoolSqlTransactionRunner,
} from "./reporting/durable-security-ports.js";
// Sourced from the app's own relay producer, NOT from @zucoins/generic-node-contracts:
// apps/generic-node does not declare that package as a dependency, so a direct import
// resolves via pnpm hoisting locally and then fails at runtime in the prod-slim image
// (ERR_MODULE_NOT_FOUND). The relay producer already owns these two literals.
import {
  RECEIVER_CHANNEL_ACTION_DATA_FIELD,
  RECEIVER_CHANNEL_ACTION_NAME,
} from "./money-workers/receiver-channel-producer.js";

/** Push API base. Overridable via ZUCOINS_PUSH_API_BASE for staging. */
const DEFAULT_PUSH_API_BASE = "https://wallet.zucoins.com/api__v1/";
import {
  createCandidateIntakeInbox,
  createSqlSendPartialLoader,
  enqueueReceiverChannelDeposit,
  startMoneyWorkers,
  type MoneyWorkersHandle,
} from "./money-workers/index.js";
import { createMoveAdvancedPorts } from "./money-workers/move-advanced-ports.js";
import { createSafeConsoleLogger, safeJsonLine } from "./boot/safe-logger.js";

// Every log line this entry point writes goes through the central redactor.
// Raw console calls here are what let vault, driver and gateway values reach
// the platform log store unfiltered — see boot/safe-logger.ts.
const logger: BootLogger = createSafeConsoleLogger();

const runtimeListenerLogger: RuntimeListenerLogger = {
  error(event) {
    logger.error(safeJsonLine({ ...event }));
  },
};

const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const DEFERRED_SIGNING_KEY_ID = "00000000-0000-4000-8000-000000000001";

function adaptPoolClientForLeadership(client: PoolClient): LeadershipLockClient {
  return {
    query: (sql, values) => client.query(sql, values as never),
    on: (event, listener) => {
      client.on(event, listener as never);
    },
    removeListener: (event, listener) => {
      client.removeListener(event, listener as never);
    },
    release: () => {
      client.release();
    },
    end: () => {
      client.release(true);
    },
  };
}

function createLeadershipPool(pool: Pool): LeadershipLockPool {
  return {
    connect: async () => adaptPoolClientForLeadership(await pool.connect()),
  };
}

function createNodeGeneratedWalletKeyGenerator(deps: {
  readonly pool: Pool;
  readonly vault: EncryptedWalletKeyStore;
}): {
  generate(nodeId: Uuid): Promise<{ readonly walletId: Uuid; readonly publicKey: WalletPublicKey }>;
} {
  return {
    async generate(nodeId) {
      const { privateKey, publicKey: pubObj } = generateKeyPairSync("ed25519");
      const spki = pubObj.export({ format: "der", type: "spki" });
      const publicKey = toBase64UrlPadded(Buffer.from(spki).subarray(-32)) as WalletPublicKey;
      const jwk = privateKey.export({ format: "jwk" });
      const d = typeof jwk.d === "string" ? jwk.d : "";
      const seed = Buffer.from(d, "base64url");
      const secret64 = Buffer.concat([seed, Buffer.from(spki).subarray(-32)]);
      const walletId = randomUUID() as Uuid;
      try {
        // Commit wallet on the pool so vault.seal (separate connection) can see FK target.
        await deps.pool.query(
          `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
          [walletId, nodeId, publicKey],
        );
        await deps.vault.seal(
          {
            nodeId,
            walletId,
            keyVersion: 1,
            publicKey,
            keyOrigin: "node_generated",
          },
          secret64,
        );
        return { walletId, publicKey };
      } catch (err) {
        try {
          await deps.pool.query(`DELETE FROM wallets WHERE id = $1::uuid`, [walletId]);
        } catch {
          // best-effort compensate
        }
        throw err;
      } finally {
        secret64.fill(0);
      }
    },
  };
}

async function main(): Promise<void> {
  // Before config, before any listener: an unguarded synchronous throw in a
  // request path must not be able to kill a node holding signer leadership.
  const fatal = installFatalExceptionHandler({ logger });

  let config;
  try {
    config = loadCustodyNodeConfig();
  } catch (err) {
    if (err instanceof NodeConfigurationError || err instanceof PlaceholderSecretError) {
      logger.error(`fatal: ${err.message}`);
      process.exit(1);
    }
    throw err;
  }

  const pool = createPool(config.DATABASE_URL);
  // Hoisted above its other call sites (destination/device stores, metrics snapshot):
  // a plain query adapter over `pool`, no state of its own.
  const poolSql = {
    query: async <R>(text: string, params?: readonly unknown[]) => {
      const result = await pool.query(text, params as never);
      return { rows: result.rows as R[] };
    },
  };
  let databaseReachableForMoney = false;
  const pingDb = async (): Promise<void> => {
    // Finish server-side cancellation before CachedDbProbe's 5s client-side fail-safe wins.
    await withPostgresDeadline(pool, 4_500, async (db) => {
      await db.query("SELECT 1");
    });
    databaseReachableForMoney = true;
  };
  // Shared with the health route so /health/ready and /metrics agree on DB
  // reachability within one TTL window instead of probing (and potentially disagreeing)
  // independently.
  const dbProbe = new CachedDbProbe(pingDb);

  const readiness = new NodeReadiness(config.GATEWAY_READ_FAILURE_BUDGET);

  const storageProbePath = process.cwd();
  const hostStorageCollector = createHostEvidenceRuntimeMetricsCollector({
    path: storageProbePath,
  });
  const storagePressure = createProductionStoragePressureWiring({
    readiness,
    collector: hostStorageCollector,
    diskUtilization: createStatfsDiskUtilization(storageProbePath),
    onEarlyAlert: (event) => {
      logger.error(
        `node: storage-pressure early alert reason=${event.reason} util=${event.utilization} pressure=${event.pressure}`,
      );
    },
  });

  // Operator halt — fail-closed gate until restore completes.
  const haltGate: HaltGate = createHaltGate("HALTED");
  const haltSqlExecutor = {
    query: async <R>(text: string, params: readonly unknown[]) => {
      const result = await pool.query(text, [...params]);
      return { rows: result.rows as R[] };
    },
  };
  const haltStore: OperatorHaltStore = createNodeSettingsHaltStore(haltSqlExecutor);
  const haltEvidence: HaltEvidenceRecorder =
    createNodeSettingsHaltEvidenceRecorder(haltSqlExecutor);
  const applyHaltStamp = (engaged: boolean): void => {
    readiness.setHalted(engaged);
  };

  const moneyPathPorts: MoneyPathAdmissionPorts = createMoneyPathAdmissionPortsFromRuntime({
    snapshotReadiness: () => readiness.core.snapshot(),
    isDatabaseReachable: () => databaseReachableForMoney,
    backpressure: storagePressure.storageBackpressure,
    haltGate,
  });

  const metrics = createNodeMetrics();
  const metricsHooks = createMetricsHooks(metrics);
  let moneyWorkers: MoneyWorkersHandle | undefined;
  let backupScheduler: ReturnType<typeof createBackupScheduler> | undefined;
  // safety-alert rule set (lease_age/queue_caps/signer_loss P0/P1 with spec-cited
  // postures), fed truthful readings below — never fabricated ones — from this scrape's
  // DB-truth snapshot. Log-only delivery: advisory, never gates admission or a lease.
  const custodyAlertEvaluator = createSafetyAlertEvaluator({
    backupMaxAgeMs: 24 * 60 * 60 * 1000,
    channels: {
      log: {
        kind: "log",
        deliver: async (notification) => {
          logger.error(
            `node: safety-alert signal=${notification.signal} severity=${notification.severity} ` +
              `${notification.message}`,
          );
        },
      },
    },
    cooldownMs: CUSTODY_ALERT_COOLDOWN_MS,
  });
  // Real readiness verdict (schema ∧ db ∧ vault ∧ observation, the SAME
  // evaluator + probe /health/ready uses) and real DB-truth counters, replacing the prior
  // hard-coded `readinessReady: 0` and emptyOperationalSnapshot() stub. Fail-safe to a
  // stamps-only snapshot on DB outage so a scrape never 500s or hangs.
  const metricsSnapshotSource = createProductionMetricsSnapshotSource({
    getState: () => readiness.core.snapshot(),
    dbProbe,
    db: poolSql,
    withinDbDeadline: (remainingBudgetMs, work) =>
      withPostgresDeadline(pool, remainingBudgetMs, work),
    poolCapTotal: config.POOL_CAP_TOTAL,
    workerHealth: () => {
      const workersHealthy = moneyWorkers?.healthy() === true ? 1 : 0;
      return {
        reconciler: workersHealthy,
        receive_queue_expiry: workersHealthy,
        pool_scaler: workersHealthy,
        send_completion_monitor: workersHealthy,
        observation: workersHealthy,
        leadership: readiness.core.snapshot().leadershipLockHeld ? 1 : 0,
      };
    },
    workerHealthAvailable: () => ({
      reconciler: moneyWorkers === undefined ? 0 : 1,
      receive_queue_expiry: moneyWorkers === undefined ? 0 : 1,
      pool_scaler: moneyWorkers === undefined ? 0 : 1,
      send_completion_monitor: moneyWorkers === undefined ? 0 : 1,
      observation: moneyWorkers === undefined ? 0 : 1,
      leadership: 1,
    }),
    backupStatus: () => backupScheduler?.status() ?? null,
    onSnapshot: (snapshot, databaseTruthAvailable) => {
      void evaluateAndDispatchCustodyAlerts(custodyAlertEvaluator, snapshot, databaseTruthAvailable);
    },
  });

  const credentialStore = new SqlCredentialStore(pool, config.NODE_ID);

  const identitySeedRaw = process.env.NODE_IDENTITY_SEED?.trim();
  const identitySeed =
    identitySeedRaw !== undefined && identitySeedRaw.length > 0
      ? parseNodeIdentitySeed(identitySeedRaw)
      : null;
  if (identitySeedRaw !== undefined && identitySeedRaw.length > 0 && identitySeed === null) {
    logger.error(
      "fatal: NODE_IDENTITY_SEED must be ≥32 bytes as hex (≥64 hex chars) or base64/base64url",
    );
    process.exit(1);
  }

  // Fail-closed stub until leadership ensure seals/loads NODE_IDENTITY.
  // Never arms a seed-only in-process signer without a durable sealed row.
  let identityPublicKey: string =
    identitySeed !== null
      ? publicKeyFromEd25519Seed(identitySeed)
      : generateEphemeralIdentityPublicKey();
  let identityEnsured = false;
  // Sealed EVENT_SIGNING signer, held from boot so the money path can append the
  // durable receive.ready event on both continuity chains. Null until ensure succeeds.
  const eventSignerHolder: { current: NodeEventSigner | null } = { current: null };
  const sendSignerHolder: { current: SendArtifactSigner } = {
    current: {
      signingKeyId: DEFERRED_SIGNING_KEY_ID,
      sign(): never {
        throw new SendAdmissionError(
          "signing_key_unavailable",
          "NODE_IDENTITY sealed-store runtime not yet provisioned",
        );
      },
    },
  };

  if (identitySeed !== null) {
    logger.info(
      "boot: NODE_IDENTITY_SEED set — ceremony/override for first sealed mint only (signer loads from sealed store after ensure)",
    );
  } else {
    logger.info(
      "boot: no NODE_IDENTITY_SEED — leadership ensure will mint+seal a fresh NODE_IDENTITY if none active",
    );
  }

  const sendSigner: SendArtifactSigner = {
    get signingKeyId() {
      return sendSignerHolder.current.signingKeyId;
    },
    sign(preimageBytes: Uint8Array) {
      return sendSignerHolder.current.sign(preimageBytes);
    },
  };

  const withPgTransaction = async <T>(
    fn: (tx: { query: <R>(text: string, params?: readonly unknown[]) => Promise<{ rows: R[] }> }) => Promise<T>,
  ): Promise<T> => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const tx = {
        query: async <R>(text: string, params?: readonly unknown[]) => {
          const result = await client.query(text, params as never);
          return { rows: result.rows as R[] };
        },
      };
      const out = await fn(tx);
      await client.query("COMMIT");
      return out;
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // surface the original error
      }
      throw err;
    } finally {
      client.release();
    }
  };
  const receiveStore = new SqlReceiveAdmissionStore(poolSql, {
    withTransaction: withPgTransaction,
  });
  const moveStore = new SqlMoveCreateStore({
    sql: poolSql,
    withTransaction: withPgTransaction,
  });
  const sendStore = new SqlSendCreateStore(poolSql);
  const operationStore = createSqlOperationRouteStore({
    nodeId: config.NODE_ID,
    queueCap: receiveQueueCap(config),
    receive: receiveStore,
    move: moveStore,
    send: sendStore,
    sendSigner,
    // GET /v1/external-sends at AWAITING_REDEMPTION returns code fingerprint.
    sendPartials: createSqlSendPartialLoader(pool),
    // late-bound push gate — push is composed below, so the closure captures
    // the mutable `push` ref. EXTERNAL send path calls this before committing.
    requireActiveSubscription: async (walletId: string) => {
      if (push) { await push.service.requireActiveSubscription(walletId); }
    },
  });
  const operationAuth = createImplementerBearerAuthFromService(
    new CredentialService(credentialStore),
  );

  const rootKey = deriveRootKey(config.VAULT_MASTER_KEY, VAULT_ROOT_KDF_SALT);
  const reportingRateLimiter = new SqlReportingRateLimiter(pool, 60_000, 600);
  const proofBodyStore = new SqlProofBodyStore(
    createPoolSqlExecutor(pool),
    createPoolSqlTransactionRunner(pool),
  );
  const verificationAccessStore = new SqlVerificationAccessStore(pool);
  const vaultAccessAuditLog = new SqlVaultAccessAuditLog(pool, config.NODE_ID);
  const vaultKeyStore = new EncryptedWalletKeyStore({
    rootKey,
    store: new VaultSqlStore(pool),
    auditLog: vaultAccessAuditLog,
  });

  const destinationKeyGenerator = createNodeGeneratedWalletKeyGenerator({
    pool,
    vault: vaultKeyStore,
  });
  // Live device dual-control bless (A.4.2). operator_device_keys +
  // destination_blessing_artifacts + audit_log; public keys only (never private).
  // authorize's artifact-insert + audit-append must land on the SAME
  // connection as store.bless(), so the authorizer is rebound per sql executor —
  // pool-bound for the boot service, tx-client-bound inside destinationServiceForSql.
  // A single pool-bound authorizer would auto-commit the single-use nonce artifact
  // before store.bless() runs on the tx client; a post-action rollback then orphans
  // that artifact and a same-nonce retry is permanently stuck on nonce_reused.
  const blessingAuthorizerForSql = (sql: DeviceSqlExecutor) =>
    createDeviceBlessingAuthorizer({
      lookupDevice: createSqlActiveDeviceLookup(sql),
      persistArtifact: createSqlBlessingArtifactPersister(sql),
      appendAudit: createSqlBlessingAuditAppender(sql),
    });
  const destinationClock = { now: () => new Date().toISOString() };
  const destinationIds = { destinationId: () => randomUUID() as Uuid };

  const destinationService = createDestinationService({
    store: createSqlDestinationStore(pool),
    keyGenerator: destinationKeyGenerator,
    blessingAuthorizer: blessingAuthorizerForSql(poolSql),
    clock: destinationClock,
    ids: destinationIds,
  });

  // Eager device-key index for dual-control send approve (optional when routes bind).
  // Tables are migrated with the money pack; empty greenfield until enrolment.
  const deviceKeyStore = createSqlDeviceKeyStore(poolSql);
  void deviceKeyStore.refreshNode(config.NODE_ID).catch(() => {
    // Best-effort boot refresh — miss leaves approve without device dual-control until retry.
  });

  // GATEWAY_TLS_CERT_SHA256_PINS: absent/empty falls through to createGatewayExchangeTransport's
  // own default (standard TLS trust, no pinning) via tlsCertSha256Pins being undefined.
  // Hoisted above createProductionRouteSurface: the recovery-action confirm-read
  // reader needs it, and it depends only on config, not on anything boot-lane produces later.
  const gatewayExchange = createGatewayExchangeTransport({
    limits: {
      readTimeoutMs: 10_000,
      maxRequestBytes: 1_048_576,
      maxResponseBytes: 4_194_304,
    },
    tlsCertSha256Pins: config.GATEWAY_TLS_CERT_SHA256_PINS,
  });

  // Full ROUTE_POLICIES production surface (24 routes + health + optional metrics).
  // Engines not yet live mount fail-closed after correct auth classes.
  // Mutable holder so readinessProbe.backupStatus can read the scheduler after late boot create.
  const backupSchedulerHolder: {
    current: ReturnType<typeof createBackupScheduler> | undefined;
  } = { current: undefined };
  // Mutable ref so GET /admin/v1/settings reflects push composition after this block.
  const pushConfiguredRef = { current: false };

  // Late-bound reporting handle: createProductionRouteSurface owns the handler;
  // lab receive needs it after the surface returns — holder fills the gap.
  const reportingHandleHolder: {
    current: null | ((captured: {
      readonly method: string;
      readonly rawTarget: string;
      readonly rawHeaders: readonly string[];
      readonly bodyBytes: Uint8Array;
      readonly receivedAtMs: number;
    }) => Promise<{
      readonly status: number;
      readonly headers: Readonly<Record<string, string>>;
      readonly bodyBytes: Uint8Array;
    }>);
  } = { current: null };

  const routeSurface = createProductionRouteSurface({
    nodeId: config.NODE_ID,
    pool,
    databaseUrl: config.DATABASE_URL,
    // Env vault key ⇒ configured (no re-generate); backup KEK for ≠ check only.
    vaultMasterKey: config.VAULT_MASTER_KEY,
    backupMasterKey: config.BACKUP_MASTER_KEY ?? null,
    newRequestId: (): string => randomUUID(),
    metricsScrapeToken: config.METRICS_SCRAPE_TOKEN,
    destinationService,
    deviceStore: deviceKeyStore,
    readinessProbe: {
      nodeStatus: () => (readiness.snapshot().ready ? "ready" : "not_ready"),
      backupStatus: () => {
        const st = backupSchedulerHolder.current?.status() ?? null;
        if (st === null) return null;
        return {
          enabled: st.enabled,
          rpoBreached: st.rpoBreached,
          lastSuccessAt:
            st.lastSuccessAtMs === null ? null : new Date(st.lastSuccessAtMs).toISOString(),
          consecutiveFailures: st.consecutiveFailures,
        };
      },
    },
    labReceive: {
      operationStore,
      reportingHandle: async (captured) => {
        const h = reportingHandleHolder.current;
        if (h === null) {
          return {
            status: 503,
            headers: { "content-type": "application/json" },
            bodyBytes: new TextEncoder().encode(
              JSON.stringify({ error: { code: "service_unavailable", message: "reporting not ready" } }),
            ),
          };
        }
        return h(captured);
      },
    },
    // Route A confirm-read (createSqlFreshHeadReader) for RELEASE_EXPIRED_RECEIVE.
    gatewayUrls: config.SPLITCHAIN_GATEWAY_URLS,
    gatewayExchange,
    // bless/retire run inside the admin idempotency transaction; the
    // atomic executor needs a destination service bound to that tx client, not
    // the pool-bound instance above (else it falls back to fail-closed → 503).
    destinationServiceForSql: (client) =>
      createDestinationService({
        store: createSqlDestinationStore(client),
        keyGenerator: destinationKeyGenerator,
        // per-client authorizer so authorize's artifact-insert + audit-append
        // run on the tx `client` too — bless is now one transaction, not two connections.
        blessingAuthorizer: blessingAuthorizerForSql(client),
        clock: destinationClock,
        ids: destinationIds,
      }),
    rateLimiter: reportingRateLimiter,
    proofBodyStore,
    verificationAccessStore,
    vaultAccessAuditLog,
    // same-origin SPA + optional Vite/proxy extras for CSRF Origin checks
    publicBaseUrl: config.PUBLIC_BASE_URL,
    adminAllowedOrigins: config.ADMIN_CORS_ALLOWED_ORIGINS,
    halt: {
      gate: haltGate,
      store: haltStore,
      evidence: haltEvidence,
      onToggle: applyHaltStamp,
    },
    // Secret-safe Settings read model. push_configured starts false and
    // flips true once composePush succeeds below (same process; route reads live).
    effectiveConfig: () => ({
      publicBaseUrl: config.PUBLIC_BASE_URL,
      nodeId: config.NODE_ID,
      gatewayUrls: config.SPLITCHAIN_GATEWAY_URLS,
      version: NODE_CORE_VERSION,
      backupScheduleEnabled: config.BACKUP_SCHEDULE_ENABLED,
      pushConfigured: pushConfiguredRef.current,
    }),
  });

  reportingHandleHolder.current = routeSurface.reportingHandle;

  // Shared candidate inbox lives for the process lifetime. HTTP receiver
  // channel enqueues here; money workers drain under leadership. Handle retained // contract-allow:drain:frozen structural vocabulary
  // so stop + enqueue🎚 paths are not GC-dropped after armMoneySurface.
  const candidateIntake = createCandidateIntakeInbox();
  // the Web Push slices — push composition is built after the vault root exists (below) and
  // held here so the listener, money workers and shutdown can all reach it.
  let push: PushComposition | null = null;

  // ── Delivery channel 1: Web Push ────────────────────────────────────────
  // Composed here because it needs the vault root (to seal per-wallet push secrets) and
  // the wallet signer (to prove key ownership in the subscribe id-proof). PUBLIC_BASE_URL
  // is required: the push service delivers to a URL we publish, so without a reachable
  // base there is nothing to subscribe and push stays unavailable rather than silently
  // registering an endpoint nobody can reach.
  const pushApiBase = process.env.ZUCOINS_PUSH_API_BASE?.trim() || DEFAULT_PUSH_API_BASE;
  const publicBaseUrl = config.PUBLIC_BASE_URL?.trim() ?? "";
  if (publicBaseUrl.length === 0) {
    logger.info(
      "push: PUBLIC_BASE_URL unset — Web Push not composed; EXTERNAL receives will refuse " +
        "(internal transfers unaffected)",
    );
  } else {
    const pushSigner = createPoolVaultSigner({
      pool,
      vault: vaultKeyStore,
      nodeId: config.NODE_ID,
    });
    push = composePush({
      pool,
      nodeId: config.NODE_ID,
      rootKey,
      pushApiBase,
      nodePublicUrl: publicBaseUrl,
      sign: (walletId, preimage) => pushSigner.sign(walletId, preimage),
      // Same inbox the origin relay feeds — one intake path, two producers.
      sink: (transferCodeEncoded) => {
        const result = enqueueReceiverChannelDeposit(candidateIntake, {
          action_name: RECEIVER_CHANNEL_ACTION_NAME,
          action_data: { [RECEIVER_CHANNEL_ACTION_DATA_FIELD]: transferCodeEncoded },
        });
        if (result.enqueued) {
          logger.info("push: delivery enqueued for candidate intake");
        } else {
          logger.info(`push: delivery not enqueued reason=${result.reason}`);
        }
      },
      logger,
    });
    logger.info(`push: composed (api=${pushApiBase}, endpoint base=${publicBaseUrl})`);
    pushConfiguredRef.current = true;
  }

  const server = createServer(
    createNodeRuntimeListener({
      readiness,
      pingDb,
      dbProbe,
      operationStore,
      operationAuth,
      newRequestId: (): string => randomUUID(),
      onBeforeEvaluate: storagePressure.onBeforeEvaluate,
      storageBackpressure: storagePressure.storageBackpressure,
      metricsScrapeToken: config.METRICS_SCRAPE_TOKEN,
      metrics,
      metricsHooks,
      metricsSnapshotSource,
      logger: runtimeListenerLogger,
      destinationService: routeSurface.destinationService,
      nodeId: config.NODE_ID,
      adminRouteDeps: routeSurface.adminRouteDeps,
      discoveryDocument: routeSurface.discoveryDocument,
      reportingListener: routeSurface.reportingListener,
      subscribeDeps: routeSurface.subscribeDeps,
      onReceiverChannelDeposit: (rawBody) => {
        const result = enqueueReceiverChannelDeposit(candidateIntake, rawBody);
        if (result.enqueued) {
          logger.info("node: receiver-channel deposit enqueued for candidate intake");
        }
      },
      // Channel-1 Web Push. Absent until the vault root is derived, so a delivery that beats
      // composition is discarded rather than half-handled; the push service retries.
      onPushDelivery: async (endpointId, body) => {
        await push?.onPushDelivery(endpointId, body);
      },
    }),
  );
  server.listen(config.PORT, config.BIND_HOST);
  logger.info(`node: http surface listening on ${config.BIND_HOST}:${config.PORT}`);
  logger.info(
    `node: ROUTE_POLICIES full mount (${routeSurface.mountedRouteKeys.length} required keys; halt live: ${routeSurface.liveHaltRoutes.map((r) => `${r.method} ${r.path}`).join(", ")})`,
  );
  // no secrets: store kind + ticket only (never keys / Authorization).
  logger.info(
    `node: reporting store ${routeSurface.reportingStoreKind.kind} (${routeSurface.reportingStoreKind.ticket})`,
  );
  // Engine names + ticket only; never a transfer_code, key, or Authorization value.
  for (const engine of routeSurface.liveReportingEngines) {
    logger.info(`node: reporting route ${engine.routeId} LIVE (${engine.ticket})`);
  }
  logger.info(
    routeSurface.adminTotpLabBound
      ? "node: admin money engines LIVE (lab TOTP mode; recovery-action still deferred)"
      : "node: admin money engines LIVE (enrol TOTP via POST /admin/v1/enrol-totp + confirm-totp; recovery-action still deferred)",
  );
  // Device dual-control bless is live on DestinationService (no private keys logged).
  logger.info(
    "node: destination bless LIVE (device authorizer + operator_device_keys + blessing artifacts)",
  );
  if (config.METRICS_SCRAPE_TOKEN !== undefined) {
    logger.info("node: /metrics mounted (bearer-gated)");
  }

  const shutdownRegistry = createShutdownRegistry();
  const registryHooks = shutdownRegistry.hooks();
  // EVENT_SIGNING availability is an authority, not a residual. Arms the
  // readiness conjunct at boot; a runtime signing failure withdraws authority and
  // quiesces the money surface before any further transition can commit (Byte-exact).
  const eventSignerAuthority = createEventSignerAuthority({
    readiness,
    withdrawSignerAuthority: registryHooks.withdrawSignerAuthority,
    stopWorkers: registryHooks.stopWorkers,
    logger,
  });
  const stop = installGracefulStop({
    server,
    readiness,
    logger,
    // A fatal left the process in unknown state — even a clean stop exits non-zero.
    exit: (code) => process.exit(fatal.tripped() ? 1 : code),
    withdrawSignerAuthority: registryHooks.withdrawSignerAuthority,
    stopWorkers: () => {
      registryHooks.stopWorkers();
      backupScheduler?.stop();
    },
    flushInFlight: async () => {
      await registryHooks.flushInFlight();
      await backupScheduler?.drain(); // contract-allow:drain:frozen structural vocabulary
    },
    releaseLeadership: registryHooks.releaseLeadership,
  });
  fatal.wire(() => stop.handleSignal("uncaughtException"));

  const leadershipPool = createLeadershipPool(pool);

  // SQL-backed boot recovery store + actions (real inventory, not greenfield-only).
  const { store: bootStore, actions: bootActions } = createSqlBootRecovery(
    pool,
    logger,
    vaultKeyStore,
  );

  const result = await runBootLane({
    readiness,
    logger,
    runMigrations: async () => {
      const { runMigrations } = await import("./db/migrate.js");
      // Config.DATABASE_URL is already validated by loadNodeConfig above —
      // migrations must run against that same value, not a second env read.
      await runMigrations(config.DATABASE_URL);
      // Money-pack DDL creates lease foundation tables but does not stamp
      // lease_schema_fence. Enroll fence + first-episode guard environment before workers.
      const leaseSql = {
        query: async <R>(text: string, params?: readonly unknown[]) => {
          const result = await pool.query(text, params as never);
          return { rows: result.rows as R[], rowCount: result.rowCount };
        },
      };
      const lease = await migrateLeaseFoundation(leaseSql);
      logger.info(`boot: lease foundation migrate status=${lease.status} v=${lease.schemaVersion}`);
    },
    assertPostMigrationReadiness: async () => {
      // Fail closed if the runtime-owned tables/columns migrated by
      // migrate.ts don't exist yet — readiness must not flip before schema is complete.
      await assertSchemaCompleteness(pool);
      await assertPrivilegeReadiness(pool);
      // Money workers read isDatabaseReachable before any external health probe
      // may have called pingDb — arm the path once the pool is proven writable.
      await pingDb();
      // Restore durable halt BEFORE money engines (fail-closed default).
      const restored = await restoreHaltState(haltStore, haltGate);
      applyHaltStamp(haltGate.isHalted());
      logger.info(
        `boot: operator halt restored state=${restored} engaged=${haltGate.isHalted()}`,
      );
      await routeSurface.ensureAdminOperators();
      await runGenesisBootstrap(
        {
          pool,
          adminUserStore: routeSurface.adminUserStore,
          credentialStore,
          logger,
        },
        {
          nodeId: config.NODE_ID,
          identityPublicKey,
          isProduction: config.NODE_ENV === "production",
          initialAdminPassword: config.INITIAL_ADMIN_PASSWORD,
          bootstrapImplementerName: process.env.BOOTSTRAP_IMPLEMENTER_NAME,
          implementerCredentialOut: process.env.IMPLEMENTER_CREDENTIAL_OUT,
          reportingKeyOut: process.env.REPORTING_KEY_OUT,
          recoverLostReportingKeyId: process.env.REPORTING_KEY_RECOVER,
        },
      );
      const labTotp = resolveLabTotp({ env: process.env });
      const labBind = await applyLabTotpBinding(
        routeSurface.adminUserStore,
        labTotp,
        process.env,
      );
      if (labBind.bound) {
        logger.info(
          "boot: ADMIN_TOTP_LAB_MODE process TOTP armed (undurable; not written to admin_operators; lab-only)",
        );
      }
    },
    unlockVault: async () => {
      if (vaultKeyStore === undefined) {
        throw new Error("vault key store failed to initialise");
      }
      logger.info("boot: vault sealed store initialised (root key derived)");
    },
    acquireSignerLeadership: async (): Promise<SignerLeadershipHandle> => {
      // The outgoing container during a rolling deploy still holds
      // the advisory lock for a brief overlap; wait it out with bounded
      // backoff instead of failing on the first try. Still fails closed
      // exactly as the prior one-shot try-lock did once the cap is hit (e.g.
      // the old holder never releases).
      const held = await acquireSignerLeadershipWithBoundedRetry({
        pool: leadershipPool,
        latch: shutdownRegistry.authority,
        lockId: SIGNER_LEADERSHIP_LOCK_ID,
        maxWaitMs: config.SIGNER_LEADERSHIP_RETRY_MAX_MS,
        logger,
      });
      if (held === null) {
        throw new Error("signer leadership lock held by another instance");
      }
      return {
        release: () => held.release(),
      };
    },
    onLeadershipAcquired: (handle) => shutdownRegistry.stampLeadership(handle),
    onBootPhaseComplete: () => shutdownRegistry.completeBootPhase(),
    runBootRecovery: async () => {
      // Under leadership + vault root, ensure durable NODE_IDENTITY (and EVENT_SIGNING).
      // This await is an authority gate: any active-row open/signing failure
      // rejects boot recovery, keeps readiness closed, and prevents worker arm.
      const withTx = async <T>(
        work: (sql: {
          query: <R>(text: string, params?: readonly unknown[]) => Promise<{ rows: R[] }>;
        }) => Promise<T>,
      ): Promise<T> => {
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const sql = {
            query: async <R>(text: string, params?: readonly unknown[]) => {
              const result = await client.query(text, params as never);
              return { rows: result.rows as R[] };
            },
          };
          const out = await work(sql);
          await client.query("COMMIT");
          return out;
        } catch (err) {
          try {
            await client.query("ROLLBACK");
          } catch {
            // surface original
          }
          throw err;
        } finally {
          client.release();
        }
      };

      const identity = await withTx((sql) =>
        ensureActiveNodeSigningKey({
          sql,
          rootKey,
          nodeId: config.NODE_ID,
          purpose: "NODE_IDENTITY",
          seedOverride: identitySeed ?? undefined,
        }),
      );
      // Prove the returned authority can reopen and sign before installing it.
      // The boot-local signature is discarded and never persisted or logged.
      identity.sign(new Uint8Array());
      sendSignerHolder.current = {
        signingKeyId: identity.signingKeyId,
        sign: (preimageBytes: Uint8Array) => identity.sign(preimageBytes),
      };
      identityPublicKey = identity.publicKey;
      identityEnsured = true;
      logger.info(
        `boot: NODE_IDENTITY active signingKeyId=${identity.signingKeyId} (sealed-store; public only logged)`,
      );

      // EVENT_SIGNING is a boot prerequisite, not a preferred
      // sibling. ensure → correspondence probe → arm lives in installEventSigner so
      // it is executable in a test; any failure in it propagates out of boot recovery
      // exactly like NODE_IDENTITY above, so readiness stays closed and money workers
      // never start. A node that cannot sign events must not run engines that commit
      // the custody transitions those events are supposed to evidence (Byte-exact).
      eventSignerHolder.current = await installEventSigner({
        openSigner: async () => {
          const eventKey = await withTx((sql) =>
            ensureActiveNodeSigningKey({
              sql,
              rootKey,
              nodeId: config.NODE_ID,
              purpose: "EVENT_SIGNING",
            }),
          );
          return {
            signingKeyId: eventKey.signingKeyId,
            sign: (preimageBytes: Uint8Array) =>
              toBase64UrlPadded(Buffer.from(eventKey.sign(preimageBytes))),
          };
        },
        authority: eventSignerAuthority,
        logger,
      });

      const report = await runDeterministicBootRecovery({
        leadership: shutdownRegistry.authority,
        store: bootStore,
        actions: bootActions,
      });
      return {
        ready: report.ready,
        invariantBreach: report.invariantBreach,
      };
    },
    performValidatedGatewayRead: async () => {
      // Smoke probe: prove observation-capability against configured endpoints
      // via the typed read path (get_transaction__v1 — never submit). Empty id
      // is a valid form body; gateway may 4xx; transport/protocol errors throw
      // and keep readiness false (fail-closed).
      await readGatewayAction(
        "get_transaction__v1",
        { transaction_id: "" },
        {
          endpoints: config.SPLITCHAIN_GATEWAY_URLS,
          limits: {
            readTimeoutMs: 10_000,
            maxRequestBytes: 1_048_576,
            maxResponseBytes: 4_194_304,
          },
          recorder: {
            recordObservation: async () => {},
          },
          exchange: gatewayExchange,
          maxAttempts: config.GATEWAY_READ_RETRY_MAX_ATTEMPTS,
          backoffMaxMs: config.GATEWAY_READ_BACKOFF_MAX_MS,
        },
      );
      // Push action-vocabulary probe (ZTR-1152 Option B). The push host dispatches on
      // opaque suffixed action names transcribed from the wallet bundle; a wallet
      // release can rotate them, and the rejection otherwise masquerades as a
      // transport failure mid-money-path. Only deterministic vocabulary drift throws
      // (PushActionVocabularyRejectedError — named, distinct); a plain push-host
      // outage logs and proceeds, because availability has never gated boot (the boot
      // reconcile and periodic pass repair it later).
      if (push !== null) {
        await push.probeActionVocabulary();
      }
    },
    startMoneyWorkers: (leadership: SignerLeadershipHandle) => {
      // boot-lane already gated via shouldStartMoneyWorkersAfterRecovery.
      const stamped = leadership as StampedLeadershipHandle;
      if (typeof stamped.armMoneySurface !== "function") {
        throw new Error("startMoneyWorkers requires stamped leadership handle (armMoneySurface)");
      }
      if (vaultKeyStore === undefined) {
        throw new Error("startMoneyWorkers requires vault key store");
      }
      // Fail closed rather than arming the settle step with an empty endpoint: a defined-but-
      // empty submitGateway would burn the one-shot claim against a non-endpoint. env-schema
      // already enforces .min(1), so this only ever fires if that guarantee is weakened.
      const submitEndpoint = config.SPLITCHAIN_GATEWAY_URLS[0];
      if (submitEndpoint === undefined) {
        throw new Error("startMoneyWorkers requires at least one configured gateway endpoint");
      }

      // Real loops (pool scale → assign → T0/form/READY). Gates are live binders —
      // never voided away. Tick + formation drain under the leadership shutdown hooks. // contract-allow:drain:frozen structural vocabulary
      // "money workers started" is logged only inside startMoneyWorkers after setInterval.
      // Inject the process-wide inlet so receiver-channel deposits drain here. // contract-allow:drain:frozen structural vocabulary
      moneyWorkers = startMoneyWorkers({
        pool,
        vault: vaultKeyStore,
        config: {
          nodeId: config.NODE_ID,
          ownerInstanceId: config.NODE_ID,
          poolCapTotal: config.POOL_CAP_TOTAL,
          receiveQueueCap: receiveQueueCap(config),
          receiveQueueMaxWaitSecs: config.RECEIVE_QUEUE_MAX_WAIT,
          receiveTtlDefaultSecs: config.RECEIVE_TTL_DEFAULT_SECS,
          receiveTtlMinSecs: config.RECEIVE_TTL_MIN_SECS,
          receiveTtlMaxSecs: config.RECEIVE_TTL_MAX_SECS,
          tickIntervalMs: 2_000,
          // Money path OBSERVE uses real get_transaction__v1 when URLs set.
          gatewayUrls: config.SPLITCHAIN_GATEWAY_URLS,
        },
        logger,
        // Subscribe every freshly minted wallet, post-commit.
        onWalletsMinted: (walletIds) => push?.onWalletsMinted(walletIds),
        // Hard gate for EXTERNAL receive — wallet must hold ACTIVE push subscription.
        requireActivePushSubscription: async (walletId: string) => {
          if (push) { await push.service.requireActiveSubscription(walletId); }
        },
        moneyPathGates: moneyPathPorts,
        // The settle step co-signs under this latch and submits to
        // the first configured gateway. Submit is never spread across the endpoint list.
        leadership: shutdownRegistry.authority,
        submitGateway: {
          endpoint: submitEndpoint,
          limits: {
            readTimeoutMs: 10_000,
            maxRequestBytes: 1_048_576,
            maxResponseBytes: 4_194_304,
          },
        },
        gatewayExchange,
        gatewayMaxAttempts: config.GATEWAY_READ_RETRY_MAX_ATTEMPTS,
        gatewayBackoffMaxMs: config.GATEWAY_READ_BACKOFF_MAX_MS,
        runUnderLeadership: (work) => stamped.runUnderLeadership(work),
        trackSigningInflight: (work) =>
          shutdownRegistry.authority.trackSigningInflight(work),
        // SEND form/sign lamps leadership latch from the shutdown-registry authority.
        signerLeadership: shutdownRegistry.authority,
        candidateIntakeInbox: candidateIntake,
        // Durable receive.ready append on node_events + implementer_events.
        eventSigner: () => eventSignerHolder.current,
        // SEND landing device-signature verification (B5).
        deviceKeyStore,
        metricsHooks,
        nodeIdentitySigner: () => {
          const held = sendSignerHolder.current;
          if (
            !identityEnsured ||
            held.signingKeyId === DEFERRED_SIGNING_KEY_ID
          ) {
            return null;
          }
          return {
            signingKeyId: held.signingKeyId,
            sign(preimageBytes: Uint8Array): string {
              return toBase64UrlPadded(Buffer.from(held.sign(preimageBytes)));
            },
          };
        },
        // MOVE_INTERNAL advanced ports (baseline/form/sign/submit/land).
        // Bound only when leadership + submitGateway are configured (same gate as settle).
        ...(submitEndpoint !== undefined && shutdownRegistry.authority.held
          ? {
              moveInternalPorts: createMoveAdvancedPorts({
                pool,
                vault: vaultKeyStore,
                nodeId: config.NODE_ID,
                ownerInstanceId: config.NODE_ID,
                leadership: shutdownRegistry.authority,
                moneyPathGates: moneyPathPorts,
                submitGateway: {
                  endpoint: submitEndpoint,
                  limits: {
                    readTimeoutMs: 10_000,
                    maxRequestBytes: 1_048_576,
                    maxResponseBytes: 4_194_304,
                  },
                },
                gatewayExchange,
                gatewayMaxAttempts: config.GATEWAY_READ_RETRY_MAX_ATTEMPTS,
                gatewayBackoffMaxMs: config.GATEWAY_READ_BACKOFF_MAX_MS,
                gatewayUrls: config.SPLITCHAIN_GATEWAY_URLS,
                nodeIdentitySigner: () => {
                  const held = sendSignerHolder.current;
                  if (!identityEnsured || held.signingKeyId === DEFERRED_SIGNING_KEY_ID) {
                    return null;
                  }
                  return {
                    signingKeyId: held.signingKeyId,
                    sign(preimageBytes: Uint8Array): string {
                      return toBase64UrlPadded(Buffer.from(held.sign(preimageBytes)));
                    },
                  };
                },
                logger,
              }),
            }
          : {}),
      });

      // The always-subscribed invariant, under leadership only so two replicas
      // never drive the subscribe path for the same wallets. The boot pass is deliberately
      // NOT awaited: it calls a third-party push API, and boot must not stall on someone
      // else's availability. The sweep repairs whatever the pass misses; its first run is // contract-allow:sweep:frozen structural vocabulary
      // one interval away so it does not duplicate this one.
      const pushSweep = push === null ? null : push.startSweep();
      if (push !== null) {
        void push.reconcileNow();
      }

      stamped.armMoneySurface(() => {
        moneyWorkers?.stop();
        pushSweep?.stop();
      });
      // Retain handle for the process lifetime (enqueue path via candidateIntake;
      // workers linger until ENGINE_QUIESCE). No void of moneyWorkers.
      void moneyWorkers.candidateIntake;
      logger.info(
        identityEnsured
          ? "boot: money surface armed under leadership (NODE_IDENTITY sealed signer live; candidate intake enqueued)"
          : "boot: money surface armed under leadership (NODE_IDENTITY signer unavailable — SEND artifact signing fail-closed; candidate intake enqueued)",
      );

    },

  });

  if (result.leadership !== undefined && shutdownRegistry.leadership === undefined) {
    shutdownRegistry.stampLeadership(result.leadership);
    shutdownRegistry.completeBootPhase();
  }

  if (!result.ready) {
    const disposition = dispositionForIncompleteBoot(result);
    if (disposition === "quarantine") {
      logger.error(
        `node: boot incomplete at step "${result.failedStep ?? "unknown"}" — quarantine (leadership retained); serving liveness only, readiness stays false`,
      );
      return;
    }
    if (disposition === "exit-for-reacquire") {
      logger.error(
        `node: boot incomplete at step "${result.failedStep ?? "unknown"}" — retryable recovery released leadership; exiting so a replacement can recover`,
      );
      process.exit(1);
    }
    logger.error(
      `node: boot incomplete at step "${result.failedStep ?? "unknown"}" — serving liveness only, readiness stays false`,
    );
  }

  if (config.BACKUP_SCHEDULE_ENABLED) {
    // Fail closed: a missing/wrong-major-version pg_dump or psql
    // must be caught here, once, at boot — never discovered for the first
    // time inside the scheduler's first scheduled run.
    const clientProbe = await probePgClientBinaries();
    if (!clientProbe.ok) {
      logger.error(
        `node: FATAL — postgresql-client probe failed, refusing to start with backup schedule enabled: ${clientProbe.reason}`,
      );
      process.exit(1);
    }
    backupScheduler = createBackupScheduler({
      enabled: true,
      databaseUrl: config.DATABASE_URL,
      masterKey: config.BACKUP_MASTER_KEY ?? "",
      outputDir: config.BACKUP_OUTPUT_DIR ?? "",
      intervalMs: config.BACKUP_SCHEDULE_INTERVAL_MS,
      policy: {
        rpoTargetMs: 24 * 60 * 60 * 1000,
        rtoTargetMs: 60 * 60 * 1000,
        retentionDays: config.BACKUP_RETENTION_DAYS,
        scheduleIntervalMs: config.BACKUP_SCHEDULE_INTERVAL_MS,
      },
      trackInflight: (work) => shutdownRegistry.trackInflight(work),
      logger,
    });
    backupScheduler.start();
    backupSchedulerHolder.current = backupScheduler;
    logger.info(
      `node: backup scheduler enabled intervalMs=${config.BACKUP_SCHEDULE_INTERVAL_MS} dir=${config.BACKUP_OUTPUT_DIR}`,
    );
  } else {
    logger.info(
      "node: backup scheduler disabled (BACKUP_SCHEDULE_ENABLED=false) — use `node dist/dr/cli.js` for manual backup/restore/drill",
    );
  }
}

main().catch((err: unknown) => {
  logger.error("fatal: unexpected boot failure", err);
  process.exit(1);
});
