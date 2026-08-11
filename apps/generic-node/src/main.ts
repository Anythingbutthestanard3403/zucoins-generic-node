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
// leadership + EVENT_SIGNING are reported/money-only, non-gating — ZPAY-252).
//   2. Graceful stop installed — a SIGTERM at ANY later phase is clean.
//   3. runBootLane — migrations → privilege readiness → genesis bootstrap →
//      vault unlock → validated gateway read (deploy-ready) → signer
//      leadership (wait-for-handover) → boot recovery → money workers.
//
// Stage-2 money-surface wiring (this ticket):
//   - Live DB adapter + privilege readiness (assertPrivilegeReadiness).
//   - Vault unlock via VaultSqlStore + EncryptedWalletKeyStore (master key
//     only from process.env, not Stage-1 config schema — stage1-production census).
//   - Signer leadership: acquire after deploy-ready (ZPAY-252 / D8.102 class),
//     wait-for-handover on shutdownRegistry.authority until prior holder
//     releases or SIGTERM aborts; prolonged-wait log at
//     SIGNER_LEADERSHIP_RETRY_MAX_MS (warn only, not a hard fail).
//  - runDeterministicBootRecovery with real SQL-backed inventory (greenfield
//     ready when no nonterminal ops / leases; populated recovery classifies durable state).
//   - Validated observation gateway read via readGatewayAction (before leadership).
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
  DEFAULT_DB_PING_TTL_MS,
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
  migrateTotpSecretsAtRest,
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
  HARDENED_HTTP_SERVER_OPTIONS,
  type RuntimeListenerLogger,
} from "./runtime-listener.js";
import { createProductionRouteSurface, applyLabTotpBinding, resolveLabTotp } from "./full-http-mount.js";
import {
  applyMoneyPathStatementTimeout,
  createPool,
  withPostgresDeadline,
} from "./db/client.js";
import { createProductionStoragePressureWiring } from "./storage-pressure.js";
import {
  buildScheduledBackupMarkers,
  createBackupScheduler,
  probePgClientBinaries,
  writeContinuityMarkers,
} from "./dr/index.js";
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
import {
  composePush,
  requireActivePushSubscriptionOrRefuse,
  type PushComposition,
} from "./push/compose.js";
import {
  assertRootKeyOpensSealedEnvelope,
  reconcileRootKdfSalt,
  resolveConfiguredRootKdfSalt,
} from "./vault/root-kdf-salt.js";
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

/**
 * Shared DB-probe refresh cadence. Half the probe's own TTL so idle age stays well inside
 * one TTL under normal ping cost (refresh() re-dates unconditionally — a probe() timer is
 * swallowed by its own TTL and cannot keep the verdict warm at any cadence).
 *
 * Production ping budget (DB_PING_DEADLINE_MS ≤ probe timeoutMs) can exceed this half-TTL
 * slack under pool pressure. That is not a composition bug: CachedDbProbe.cachedReachable()
 * sticky-opens while a refresh is in flight on a last-true verdict, so mid-flight age past
 * TTL does not refuse money on a healthy node. Fail-closed still applies on completed
 * failure, idle stale, and unknown (ZTR-1178).
 */
const DB_PROBE_KEEP_WARM_MS = DEFAULT_DB_PING_TTL_MS / 2;
/** Server-side cancel budget for pingDb; must stay ≤ CachedDbProbe's client-side timeoutMs. */
const DB_PING_DEADLINE_MS = 4_500;
import {
  createCandidateIntakeInbox,
  createSqlSendPartialLoader,
  enqueueReceiverChannelDeposit,
  startMoneyWorkers,
  type CandidateIntakeSource,
  type MoneyWorkersHandle,
} from "./money-workers/index.js";
import { createMoveAdvancedPorts } from "./money-workers/move-advanced-ports.js";
import { createSafeConsoleLogger, safeJsonLine } from "./boot/safe-logger.js";
import { assertNoGoldenFixtureKeysAtBoot } from "./boot/refuse-golden-fixture-keys.js";

// Every log line this entry point writes goes through the central redactor.
// Raw console calls here are what let vault, driver and gateway values reach
// the platform log store unfiltered — see boot/safe-logger.ts.
const logger: BootLogger = createSafeConsoleLogger();

const runtimeListenerLogger: RuntimeListenerLogger = {
  error(event) {
    logger.error(safeJsonLine({ ...event }));
  },
};

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

  const pool = createPool(config.DATABASE_URL, {
    max: config.DB_POOL_MAX,
    connectionTimeoutMillis: config.DB_POOL_CONNECTION_TIMEOUT_MS,
    idleTimeoutMillis: config.DB_POOL_IDLE_TIMEOUT_MS,
    keepAlive: true,
    keepAliveInitialDelayMillis: config.DB_POOL_KEEPALIVE_INITIAL_DELAY_MS,
  });
  const moneyPathStatementTimeoutMs = config.MONEY_PATH_STATEMENT_TIMEOUT_MS;
  // Hoisted above its other call sites (destination/device stores, metrics snapshot):
  // a plain query adapter over `pool`, no state of its own.
  const poolSql = {
    query: async <R>(text: string, params?: readonly unknown[]) => {
      const result = await pool.query(text, params as never);
      return { rows: result.rows as R[] };
    },
  };
  const pingDb = async (): Promise<void> => {
    // Finish server-side cancellation before CachedDbProbe's 5s client-side fail-safe wins.
    await withPostgresDeadline(pool, DB_PING_DEADLINE_MS, async (db) => {
      await db.query("SELECT 1");
    });
  };
  // Shared with the health route so /health/ready, /metrics and money admission agree on
  // DB reachability within one TTL window instead of probing (and potentially disagreeing)
  // independently. It is the ONLY DB-reachability state in this process — a second copy
  // held in the shell latched open at the first successful ping and never re-closed
  // (ZTR-1178).
  const dbProbe = new CachedDbProbe(pingDb);
  // /health/ready and /metrics refresh the probe when something calls them; the money
  // workers call neither, and a cached verdict nobody refreshes reads stale-closed. This
  // keeps the shared verdict inside its own TTL without any external caller. refresh(),
  // not probe(): probe() would short-circuit on its own cache and leave cachedAtMs where
  // it was, so the verdict would still age out between ticks. One `SELECT 1` per cadence.
  const dbProbeKeepWarm = setInterval(() => {
    // refresh() resolves false on failure rather than rejecting; the catch is only so a
    // future change there cannot become an unhandled rejection on this timer.
    void dbProbe.refresh().catch(() => {});
  }, DB_PROBE_KEEP_WARM_MS);
  // unref only — deliberately NOT cleared from graceful stop's stopWorkers hook, which
  // runs before flushInFlight: killing the refresh there would let the shared verdict age
  // out while in-flight money work is still being flushed, and refuse the very work the
  // flush exists to finish. unref already keeps it from holding the process open, so there
  // is nothing left to reclaim.
  dbProbeKeepWarm.unref();

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
    // The same probe that answers /health/ready, read synchronously: admission issues no
    // query of its own and acts on a verdict up to one probe TTL old (deliberate — see
    // CachedDbProbe.cachedReachable). Stale or never-probed reads false, so the database
    // conjunct re-closes on loss instead of staying satisfied for the life of the process.
    isDatabaseReachable: () => dbProbe.cachedReachable(),
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
    // Fail closed before leadership/signing: a published A.8 seed must never become node identity.
    assertNoGoldenFixtureKeysAtBoot([
      { publicKey: identityPublicKey, role: "NODE_IDENTITY_SEED" },
    ]);
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
      // Transaction-local bound — dies with COMMIT/ROLLBACK; never a pool default
      // (migrations use a longer session-level SET on their own client).
      await applyMoneyPathStatementTimeout(client, moneyPathStatementTimeoutMs);
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
    // Fail closed when push was not composed (PUBLIC_BASE_URL unset) — matches
    // the boot log claim that EXTERNAL paths refuse (ZTR-1181).
    requireActiveSubscription: async (walletId: string) => {
      await requireActivePushSubscriptionOrRefuse(push, walletId);
    },
  });
  const operationAuth = createImplementerBearerAuthFromService(
    new CredentialService(credentialStore),
  );

  // Vault root key. Derived here from configuration alone, because composition runs before
  // the boot lane and therefore before migrations — there is no `vault_root_kdf_salt` table
  // to consult yet. `unlockVault` binds this to the salt persisted beside the envelopes and
  // re-derives IN PLACE if the two differ, which is only ever the case on a node whose salt
  // was minted at genesis while VAULT_ROOT_SALT_B64 stays unset. Every downstream holder
  // (EncryptedWalletKeyStore, composePush, the sealed signing-key store, SqlAdminUserStore)
  // keeps this reference rather than a copy. Holders MAY retain the buffer before the vault
  // gate opens; seal-on-write (TOTP factors) MUST NOT run until unlock arms the store under
  // the final root — provisional composition-time bytes must never seal durable rows.
  const configuredRootSalt = resolveConfiguredRootKdfSalt(config);
  const rootKey = deriveRootKey(config.VAULT_MASTER_KEY, configuredRootSalt.salt);
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
    moneyPathStatementTimeoutMs,
    // Env vault key ⇒ configured (no re-generate); backup KEK for ≠ check only.
    vaultMasterKey: config.VAULT_MASTER_KEY,
    backupMasterKey: config.BACKUP_MASTER_KEY ?? null,
    // Same root buffer EncryptedWalletKeyStore holds; unlock may rederive in place.
    vaultRootKey: rootKey,
    newRequestId: (): string => randomUUID(),
    metricsScrapeToken: config.METRICS_SCRAPE_TOKEN,
    destinationService,
    deviceStore: deviceKeyStore,
    dualControlMode: config.DUAL_CONTROL_MODE,
    readinessProbe: {
      nodeStatus: () => (readiness.snapshot().ready ? "ready" : "not_ready"),
      backupStatus: () => {
        const st = backupSchedulerHolder.current?.status() ?? null;
        if (st === null) return null;
        return {
          enabled: st.enabled,
          ownership: st.ownership,
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
  // Per-lane cap = RECEIVE_QUEUE_CAP (= POOL_CAP_TOTAL): a deposit is only useful if it
  // matches a live receive, so the pool cap is the ceiling on genuinely distinct backlog.
  const candidateIntake = createCandidateIntakeInbox(receiveQueueCap(config));
  // Single accounting seam for both producers: enqueue, count, log. A refusal is never
  // silent — an uncounted one is a lost credit notification presenting as slowness.
  // Refusals are counted on every event but logged only on the leading edge of a
  // refusing run per lane, so a flood cannot trade a memory-exhaustion DoS for a
  // log-volume one. The counter is the continuous signal; the log names the reason.
  // Returns the verdict so a producer that keeps a per-deposit record (push) can audit the
  // refusal truthfully rather than reporting an enqueue that never happened.
  const refusingIntakeSources = new Set<CandidateIntakeSource>();
  const depositToCandidateIntake = (source: CandidateIntakeSource, rawBody: unknown): boolean => {
    const result = enqueueReceiverChannelDeposit(candidateIntake, rawBody, source);
    if (result.enqueued) {
      refusingIntakeSources.delete(source);
      logger.info(`node: candidate intake deposit enqueued source=${source}`);
      return true;
    }
    const reason = result.reason ?? "malformed_body";
    metricsHooks.onCandidateIntakeRefused(source, reason);
    if (!refusingIntakeSources.has(source)) {
      refusingIntakeSources.add(source);
      logger.info(`node: candidate intake deposit refused source=${source} reason=${reason}`);
    }
    return false;
  };
  // the Web Push slices — push composition is built after the vault root exists (below) and
  // held here so the listener, money workers and shutdown can all reach it.
  let push: PushComposition | null = null;

  // ── Delivery channel 1: Web Push ────────────────────────────────────────
  // Composed here because it needs the vault root (to seal per-wallet push secrets) and
  // the wallet signer (to prove key ownership in the subscribe id-proof). PUBLIC_BASE_URL
  // is required: the push service delivers to a URL we publish, so without a reachable
  // base there is nothing to subscribe and push stays unavailable rather than silently
  // registering an endpoint nobody can reach.
  const pushApiBase = config.ZUCOINS_PUSH_API_BASE;
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
      // Same inbox the origin relay feeds — one intake path, two producers, but the
      // authenticated lane has its own capacity and is served first.
      sink: (transferCodeEncoded) =>
        depositToCandidateIntake("push", {
          action_name: RECEIVER_CHANNEL_ACTION_NAME,
          action_data: { [RECEIVER_CHANNEL_ACTION_DATA_FIELD]: transferCodeEncoded },
        }),
      logger,
    });
    logger.info(`push: composed (api=${pushApiBase}, endpoint base=${publicBaseUrl})`);
    pushConfiguredRef.current = true;
  }

  // Options first, listener second: without them node's defaults hold a socket and a request
  // slot for 300 s on a request that never finishes arriving.
  const server = createServer(
    HARDENED_HTTP_SERVER_OPTIONS,
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
      // Anonymous lane. Capped at RECEIVE_QUEUE_CAP and served only with the budget the
      // authenticated lane leaves; the route answers 204 either way (non-oracular).
      onReceiverChannelDeposit: (rawBody) => {
        depositToCandidateIntake("relay", rawBody);
      },
      // Channel-1 Web Push. Absent until the vault root is derived, so a delivery that beats
      // composition is discarded rather than half-handled. The route answers 204 regardless
      // (non-oracular), so nothing upstream retries — the discard is final and is why the
      // window is closed inside the boot lane rather than tolerated.
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
      // Money workers read isDatabaseReachable before any external health probe may have
      // refreshed the shared verdict — arm it once the pool is proven writable. refresh(),
      // not probe(): the keep-warm timer is already running by now, so a single failed tick
      // during boot would otherwise be served back from cache here and fail the boot the
      // pool has just proven healthy. The arm must be a real ping. refresh() collapses a
      // ping failure to `false` rather than throwing, so the boot lane still has to fail
      // closed on it explicitly.
      if (!(await dbProbe.refresh())) {
        // The driver's reason was collapsed to `false`; re-issue once, on the failure path
        // only, so the crash carries it instead of a bare sentence.
        const cause = await pingDb().then(
          () => undefined,
          (err: unknown) => err,
        );
        throw new Error("boot: database probe failed after migrations", { cause });
      }
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
      // Bind the configured salt to the durable one (ZTR-1159). First sight of this node
      // writes the row: the operator's VAULT_ROOT_SALT_B64 when set, the pre-ZTR-1159
      // literal when the node has already sealed material, and a fresh per-deployment
      // CSPRNG salt when it has sealed nothing. A configured salt that disagrees with an
      // existing row throws VaultRootSaltError here, before anything opens an envelope.
      const rootSalt = await reconcileRootKdfSalt({
        sql: poolSql,
        nodeId: config.NODE_ID,
        configured: configuredRootSalt,
        // The row is insert-only: on a node that has already sealed something, reconcile
        // proves the candidate salt opens that material and refuses (writing nothing)
        // when it does not, rather than committing a salt that can never be corrected.
        deriveRootKey: (salt) => deriveRootKey(config.VAULT_MASTER_KEY, salt),
      });
      if (rootSalt.rederive) {
        // Only reachable when the durable salt is not the configured one, which the
        // reconcile above permits only while VAULT_ROOT_SALT_B64 is unset. TOTP seal-on-write
        // stays disarmed until after this rederive + sealed census, so no durable TOTP
        // envelope can exist under the composition-time provisional bytes. Holders read
        // this buffer by reference; set() replaces bytes in place for the final root.
        const rederived = deriveRootKey(config.VAULT_MASTER_KEY, rootSalt.salt);
        rootKey.set(rederived);
        rederived.fill(0);
      }
      // Derivation self-check. Prove the root key opens something this node actually
      // sealed BEFORE readiness opens the vault gate — a salt or master-key mismatch is a
      // named refusal in the first second rather than a decrypt failure under load.
      const proof = await assertRootKeyOpensSealedEnvelope({
        sql: poolSql,
        nodeId: config.NODE_ID,
        rootKey,
        saltSource: rootSalt.source,
      });
      logger.info(
        `boot: vault root salt source=${rootSalt.source} persisted=${rootSalt.persisted} ` +
          `rederived=${rootSalt.rederive} ` +
          `self-check=${proof.checked ? `opened:${proof.provenAgainst}` : "nothing-sealed"}`,
      );
      // ZTR-1134: seal residual plaintext TOTP secrets and drop totp_secret_base32.
      // Needs the unlocked root; drizzle 0007/0008 only add/conditionally drop the column.
      const totpMigrate = await migrateTotpSecretsAtRest({
        db: {
          query: async <T extends Record<string, unknown>>(
            sql: string,
            params?: readonly unknown[],
          ) => {
            const result = await pool.query(sql, params === undefined ? undefined : [...params]);
            return { rows: result.rows as T[] };
          },
        },
        rootKey,
      });
      logger.info(
        `boot: TOTP seal migration migrated=${totpMigrate.migrated} ` +
          `already_sealed=${totpMigrate.alreadySealed} ` +
          `plaintext_dropped=${totpMigrate.plaintextColumnDropped}`,
      );
      // Arm TOTP seal-on-write only after final root is bound + sealed census passed.
      // Pre-unlock enrol cannot create durable sealed rows under provisional bytes.
      const adminUsers = routeSurface.adminUserStore as unknown as {
        armVaultRoot?: () => void;
      };
      if (typeof adminUsers.armVaultRoot === "function") {
        adminUsers.armVaultRoot();
      }
      logger.info("boot: vault sealed store initialised (root key derived; TOTP sealing armed)");
    },
    acquireSignerLeadership: async (): Promise<SignerLeadershipHandle> => {
      // Deploy-ready already passed (gateway before this step). Wait for the
      // prior holder to release — never a short hard timeout that would leave
      // a ready non-signer stranded (ZPAY-252). SIGTERM aborts the wait so
      // graceful stop can complete; prolonged-wait is log-only.
      const leadershipAbort = new AbortController();
      const onStopSignal = (): void => {
        leadershipAbort.abort();
      };
      process.once("SIGTERM", onStopSignal);
      process.once("SIGINT", onStopSignal);
      try {
        const held = await acquireSignerLeadershipWithBoundedRetry({
          pool: leadershipPool,
          latch: shutdownRegistry.authority,
          lockId: SIGNER_LEADERSHIP_LOCK_ID,
          signal: leadershipAbort.signal,
          prolongedWaitMs: config.SIGNER_LEADERSHIP_RETRY_MAX_MS,
          ownershipAssertIntervalMs: config.SIGNER_LEADERSHIP_OWNERSHIP_ASSERT_INTERVAL_MS,
          logger,
        });
        if (held === null) {
          throw new Error(
            "signer leadership acquire aborted (shutdown during handover wait)",
          );
        }
        return {
          release: () => held.release(),
        };
      } finally {
        process.removeListener("SIGTERM", onStopSignal);
        process.removeListener("SIGINT", onStopSignal);
      }
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
          await applyMoneyPathStatementTimeout(client, moneyPathStatementTimeoutMs);
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
      assertNoGoldenFixtureKeysAtBoot([
        {
          keyId: identity.signingKeyId,
          publicKey: identity.publicKey,
          role: "NODE_IDENTITY",
        },
      ]);
      // Wallet custody public keys — refuse any A.8 golden fixture key held as a wallet.
      {
        const walletRows = await pool.query<{ public_key: string; id: string }>(
          `SELECT id::text AS id, public_key FROM wallets WHERE node_id = $1::uuid`,
          [config.NODE_ID],
        );
        assertNoGoldenFixtureKeysAtBoot(
          walletRows.rows.map((r) => ({
            publicKey: r.public_key,
            role: `wallet custody ${r.id}`,
          })),
        );
      }
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
          // Boot readiness smoke only — not a money-workers custody path. No wallet key
          // is known here (empty transaction_id probe), so there is nothing to attribute
          // a TRANSPORT_ERROR pair to. Money-path readers all route through
          // persistSqlObservation (see inert-recorder gate test).
          recorder: {
            recordObservation: async () => {
              /* readiness smoke: intentionally non-durable */
            },
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
        moneyPathStatementTimeoutMs: moneyPathStatementTimeoutMs,
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
        // Fail closed when push was not composed (PUBLIC_BASE_URL unset) — matches
        // the boot log claim that EXTERNAL paths refuse (ZTR-1181).
        requireActivePushSubscription: async (walletId: string) => {
          await requireActivePushSubscriptionOrRefuse(push, walletId);
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
                moneyPathStatementTimeoutMs,
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
      // ZTR-1183: incomplete boot never starts the backup scheduler (even with
      // leadership retained for quarantine). A half-migrated / unready node must
      // not author restore artifacts into the shared sink.
      return;
    }
    if (disposition === "exit-for-reacquire") {
      logger.error(
        `node: boot incomplete at step "${result.failedStep ?? "unknown"}" — retryable recovery released leadership; exiting so a replacement can recover`,
      );
      process.exit(1);
    }
    // liveness-only (migrations/vault/gateway failure, aborted leadership
    // wait, etc.). Explicit return — do NOT fall through to the backup
    // scheduler start. Only the ready leadership holder runs scheduled
    // pg_dump (ZTR-1183). A replica still waiting on handover never reaches
    // this branch while healthy — it is blocked inside the boot lane after
    // deploy-ready already answers 200.
    logger.error(
      `node: boot incomplete at step "${result.failedStep ?? "unknown"}" — serving liveness only, readiness stays false`,
    );
    if (config.BACKUP_SCHEDULE_ENABLED) {
      logger.info(
        "node: backup scheduler withheld — boot incomplete (liveness-only); only the ready leadership holder runs scheduled backups",
      );
    }
    return;
  }

  // Full boot only: leadership held, recovery ready, money workers started.
  // Mirrors the money-worker leadership gate — multi-replica safe (ZTR-1183).
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
      // Same latch family money workers consult — lost leadership stops further dumps.
      isLeader: () => shutdownRegistry.authority.held,
      trackInflight: (work) => shutdownRegistry.trackInflight(work),
      // Bind marker values to the dump snapshot inside exportEncryptedBackup.
      continuityNodeId: config.NODE_ID,
      afterSuccess: async (success) => {
        const markerPath = config.BACKUP_CONTINUITY_MARKERS_PATH;
        if (markerPath === undefined) {
          throw new Error("BACKUP_CONTINUITY_MARKERS_PATH is required for scheduled backup continuity");
        }
        const snapshot = success.result.continuitySnapshot;
        if (snapshot === undefined) {
          throw new Error(
            "scheduled backup missing dump-bound continuitySnapshot — refusing unpaired artifact",
          );
        }
        await writeContinuityMarkers(
          markerPath,
          buildScheduledBackupMarkers(snapshot, {
            backupArtifactSha256: success.result.sha256,
            backupOutputPath: success.result.outputPath,
            observedAt: new Date(success.finishedAtMs),
          }),
        );
      },
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
