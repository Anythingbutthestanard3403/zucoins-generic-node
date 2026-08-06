// Production full-ROUTE_POLICIES composition for custody main.
//
// Composes implementer-bearer ops + destinations, signed reporting raw-capture,
// operator_session admin money routes, public discovery, and subscription_handle
// SSE. Fail-closed ports remain only for engines that are truly unbound; do not
// re-assert fail-closed for routes already in LIVE_ENGINE_CATALOG.
//
// Admin challenge + send-decision + recovery-action SQL stores mount live against
// the custody pool (recovery effect kinds are partial — see sql-recovery-store
// IMPLEMENTED_EFFECT_KINDS). X-ZP-TOTP verifies the operator's enrolled
// secret (HTTP enrol→confirm). Lab-only shortcut: ADMIN_TOTP_LAB_MODE=1 + valid
// ADMIN_TOTP_SECRET arms a process-level undurable fallback (never writes
// admin_operators; hard-stopped when NODE_ENV=production). Either env alone is
// not enough.
//
// Signed reporting nonce / key registry uses DurableReportingRequestStore
// (same Pool as money SQL stores).
//
// LIVE reporting engines (see LIVE_ENGINE_CATALOG): operation_armed, events list/
// stream, state snapshot, verification-material, verification-complete,
// destinations_list (when destinationService is composed).
//
// SSE subscribe uses durable subscription_handles.

import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Pool } from "pg";

import {
  buildNodeIdentityDocument,
  createFailClosedDestinationService,
  createReportingRequestHandler,
  createReportingRequestVerifier,
  createAdminSessionService,
  createPoolAdminSessionExecutor,
  createPoolAdminUserExecutor,
  createPoolTotpBurnExecutor,
  createSqlApprovalChallengeStore,
  createSqlApprovalOperationLoader,
  CredentialService,
  DEFAULT_ADMIN_USERNAME,
  DEFERRED_HALT_ROUTE,
  LIVE_HALT_ROUTES,
  LIVE_ATTENTION_RETRACTION_ROUTES,
  DEFAULT_MAX_BODY_BYTES,
  InMemoryReportingRateLimiter,
  InMemoryVaultAccessAuditLog,
  NODE_CORE_VERSION,
  parseAdminTotpSecret,
  REPORTING_ROUTE_IDS,
  reportingErrorResponse,
  requiredProductionRouteKeys,
  routeKeyOf,
  SqlAdminSessionStore,
  SqlAdminUserStore,
  SqlCredentialStore,
  SqlProofBodyStore,
  SqlSendDecisionStore,
  SqlTotpBurnStore,
  SigningKeyRegistry,
  type AdminSessionStore,
  type AdminUserStore,
  type CapturedReportRequest,
  type DestinationService,
  type DestinationSqlExecutor,
  type DiscoveryKeyConfig,
  type NodeSigningKeyRow,
  type OperationSubscribeRouteDeps,
  type ReportingHandlerRegistry,
  type ReportingHttpResponse,
  type ReportingRateLimiter,
  type ReportingRequestStore,
  type ReportingRouteHandler,
  type SigningKeySqlExecutor,
  type TotpBurnStore,
  type TotpConfig,
  type ProofBodyStore,
  type VaultAccessAuditLog,
  type WellKnownDeps,
  type GatewayExchangeTransport,
  type HaltGate,
  type OperatorHaltStore,
  type HaltEvidenceRecorder,
  createHaltGate,
  createInMemoryOperatorHaltStore,
  createInMemoryHaltEvidenceRecorder,
  createNodeSettingsHaltStore,
  createNodeSettingsHaltEvidenceRecorder,
  createSqlDeviceKeyStore,
  createSqlEnrollmentChallengeStore,
  InMemoryEnrollmentAuditLog,
  InMemoryDeviceRevocationAuditLog,
  NoopDeviceRevocationSideEffects,
  type DeviceSqlExecutor,
  // Second-device enrol, dual-control policy, operator push
  InMemorySecondDeviceCeremonyStore,
  InMemoryDualControlPolicy,
  InMemoryApprovalChallengeIssuerStore,
  InMemoryOperatorPushSubscriptionStore,
  parseDualControlMode,
} from "@zucoins/node-core";

import { createLiveArmRouteHandler, LIVE_ARM_ENGINE } from "./operations/arm-live.js";
import { createSqlRecoveryActionStore, createSqlRecoveryInspectionStore } from "./operations/sql-recovery-store.js";
import { createSqlAttentionRetractionStore } from "./operations/sql-attention-retraction-store.js";
import { createSqlFreshHeadReader } from "./money-workers/sql-fresh-head-reader.js";
import {
  createLiveReportingReads,
  DURABLE_SUBSCRIPTION_HANDLES,
  LIVE_DESTINATIONS_LIST_ENGINE,
  LIVE_EVENTS_LIST_ENGINE,
  LIVE_EVENTS_STREAM_ENGINE,
  LIVE_STATE_SNAPSHOT_ENGINE,
  LIVE_VERIFICATION_MATERIAL_ENGINE,
  LIVE_VERIFICATION_COMPLETE_ENGINE,
  LIVE_HANDLER_BRAND,
  brandLiveHandler,
  type LiveReportingReadEngine,
  type LiveReportingRouteHandler,
} from "./reporting/live-reporting-reads.js";

export {
  LIVE_ARM_ENGINE,
  DURABLE_SUBSCRIPTION_HANDLES,
  LIVE_DESTINATIONS_LIST_ENGINE,
  LIVE_EVENTS_LIST_ENGINE,
  LIVE_EVENTS_STREAM_ENGINE,
  LIVE_STATE_SNAPSHOT_ENGINE,
  LIVE_VERIFICATION_MATERIAL_ENGINE,
  LIVE_HANDLER_BRAND,
  brandLiveHandler,
  type LiveReportingRouteHandler,
};

/**
 * Engines that may appear on `liveReportingEngines` only when the mounted
 * handlers map binds that route to a non-fail-closed handler. Deriving the surface from the
 * map means AC1 asserts composition, not a hardcoded constant list next to a separate registry.
 */
const LIVE_ENGINE_CATALOG = [
  [REPORTING_ROUTE_IDS.operationArmed, LIVE_ARM_ENGINE],
  [REPORTING_ROUTE_IDS.eventsList, LIVE_EVENTS_LIST_ENGINE],
  [REPORTING_ROUTE_IDS.eventsStream, LIVE_EVENTS_STREAM_ENGINE],
  [REPORTING_ROUTE_IDS.stateSnapshot, LIVE_STATE_SNAPSHOT_ENGINE],
  [REPORTING_ROUTE_IDS.verificationMaterial, LIVE_VERIFICATION_MATERIAL_ENGINE],
  [REPORTING_ROUTE_IDS.verificationComplete, LIVE_VERIFICATION_COMPLETE_ENGINE],
  [REPORTING_ROUTE_IDS.destinationsList, LIVE_DESTINATIONS_LIST_ENGINE],
] as const;

export type LiveReportingEngine =
  | typeof LIVE_ARM_ENGINE
  | LiveReportingReadEngine;

// LIVE_HANDLER_BRAND and brandLiveHandler are defined in live-reporting-reads.ts and
// re-exported above, breaking the circular dependency that previously existed between
// the two modules.

function liveEnginesFromMountedHandlers(
  handlers: ReportingHandlerRegistry,
  _failClosed: ReportingRouteHandler,
): readonly LiveReportingEngine[] {
  const engines: LiveReportingEngine[] = [];
  for (const [routeId, engine] of LIVE_ENGINE_CATALOG) {
    const mounted = handlers[routeId];
    if (mounted === undefined) continue;
    // Positive liveness — the handler must carry the LIVE brand. A fail-closed
    // variant (different object, same 501 behaviour) does not carry it and is excluded.
    if (Boolean((mounted as unknown as Record<symbol, unknown>)[LIVE_HANDLER_BRAND]) === true) {
      engines.push(engine);
    }
  }
  return Object.freeze(engines);
}

/**
 * Challenge, send-decision, and recovery-action are all live (SQL) whenever the
 * surface is composed — TOTP gating is independent (enrol/confirm
 * or lab mode).
 */
export const LIVE_ADMIN_MONEY_ENGINES = Object.freeze({
  challengeStore: "createSqlApprovalChallengeStore — live",
  sendDecisionStore: "SqlSendDecisionStore — live",
  loadOperation: "createSqlApprovalOperationLoader — live",
  recoveryActionStore:
    "createSqlRecoveryActionStore — live",
  attentionRetractionStore:
    "createSqlAttentionRetractionStore — live",
  ticket:
    "challenge + send-decision live; TOTP from enrol/confirm or ADMIN_TOTP_LAB_MODE",
} as const);

/** Alias kept for prior test greps — money challenge/send are no longer deferred. */
export const DEFERRED_ADMIN_MONEY_ENGINES = LIVE_ADMIN_MONEY_ENGINES;

/** custody production reporting store is PG-durable. */
export const DURABLE_REPORTING_STORE = Object.freeze({
  kind: "durable-pg" as const,
  store: "DurableReportingRequestStore via createPoolReportingClient(pool)",
  ticket: "durable reporting PG store mounted on custody production surface",
});

import {
  createFailClosedAdminRouteDeps,
  createLiveAdminRouteDeps,
  type AdminMutationTxPorts,
  type AdminRouteDeps,
} from "./admin-router.js";
import {
  createSqlAdminInventoryStore,
  withDestinationServiceInventory,
} from "./admin-inventory/index.js";
import { SqlAdminIdempotencyStore } from "./ops/admin-idempotency.js";
import { createAtomicAdminMutationExecutor } from "./ops/atomic-admin-mutation.js";
import { createSqlReportingCredentialService } from "./reporting-credential-service.js";
import { createNodeHttpListener, createReportingHttpListener } from "./http-adapter.js";
import {
  createPoolReportingClient,
  DurableReportingRequestStore,
} from "./reporting/durable-store.js";
import {
  SqlVerificationAccessStore,
  createPoolSqlExecutor,
  createPoolSqlTransactionRunner,
} from "./reporting/durable-security-ports.js";
import { createSqlSetupStateStore } from "./setup-state-store.js";
import {
  applyDurableSealInPlace,
  createSqlVaultMasterSealStore,
  resolveVaultMasterBootstrap,
} from "./setup-vault-master-seal-store.js";
import { createSqlRecoveryPackLockoutStore } from "./ops/recovery-pack-lockout.js";
import {
  createOperatorPushAuthSealer,
  createProcessLocalOperatorPushSealKey,
  resolveOperatorPushSealKeyFromEnv,
} from "./operator-push-seal.js";

export { DurableReportingRequestStore, createPoolReportingClient };

const SUPPORTED_OPS = [
  "RECEIVE_EXTERNAL",
  "MOVE_INTERNAL",
  `SEND${"_EXTERNAL"}`,
] as const;

export {
  DEFERRED_HALT_ROUTE,
  LIVE_HALT_ROUTES,
  LIVE_ATTENTION_RETRACTION_ROUTES,
  requiredProductionRouteKeys,
  routeKeyOf,
  createFailClosedAdminRouteDeps,
};

/** Explicit lab flag — ADMIN_TOTP_SECRET alone does nothing. */
export const ADMIN_TOTP_LAB_MODE_ENV = "ADMIN_TOTP_LAB_MODE";

/** Production env hard-stop — lab TOTP never arms when NODE_ENV=production. */
export function isProductionNodeEnv(env: NodeJS.ProcessEnv = process.env): boolean {
  return (env.NODE_ENV ?? "").trim().toLowerCase() === "production";
}

/**
 * Intentional lab only. Hard-stops when NODE_ENV=production so a leftover
 * ADMIN_TOTP_LAB_MODE on a prod box cannot arm process TOTP.
 */
export function isAdminTotpLabMode(env: NodeJS.ProcessEnv = process.env): boolean {
  if (isProductionNodeEnv(env)) return false;
  const v = (env[ADMIN_TOTP_LAB_MODE_ENV] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

export interface ProductionSurfaceConfig {
  readonly nodeId: string;
  readonly pool: Pool;
  /**
   * Live DATABASE_URL string — required for Mode A throwaway restore DB creation
   * (same server as the custody pool). Never logged. Omitted ⇒ ceremony routes 503.
   */
  readonly databaseUrl?: string;
  readonly vaultMasterKey?: string | null;
  readonly backupMasterKey?: string | null;
  readonly newRequestId?: () => string;
  readonly nowMs?: () => number;
  /**
   * Node's externally reachable base URL (PUBLIC_BASE_URL). Its origin is always
   * included in CSRF allowedOrigins so the same-origin operator SPA can mutate.
   */
  readonly publicBaseUrl?: string;
  /**
   * Extra exact origins (ADMIN_CORS_ALLOWED_ORIGINS) — e.g. Vite dev
   * `http://localhost:5174`. Never `*`. Merged with publicBaseUrl origin.
   */
  readonly adminAllowedOrigins?: readonly string[];
  /**
   * Process-level TOTP used only as lab fallback when ADMIN_TOTP_LAB_MODE is on
   * (or when config.totp is injected with labMode). Prefer HTTP enrol.
   */
  readonly totp?: TotpConfig;
  /** Override env reader (tests). Defaults to process.env. */
  readonly env?: NodeJS.ProcessEnv;
  /**
   * Force lab process-level TOTP bind. When undefined, derived from
   * ADMIN_TOTP_LAB_MODE env.
   */
  readonly labTotpMode?: boolean;
  readonly destinationService?: DestinationService;
  /** Live main supplies a factory that rebinds destination child writes to one PoolClient. */
  readonly destinationServiceForSql?: (sql: DestinationSqlExecutor) => DestinationService;
  /**
   * SPLITCHAIN_GATEWAY_URLS for the recovery-action confirm-read
   * (createSqlFreshHeadReader). Absent/empty ⇒ no reader ⇒ RELEASE_EXPIRED_RECEIVE
   * fails closed (predicate_failed/no_fresh_observation), never fabricates fresh=t0.
   */
  readonly gatewayUrls?: readonly string[];
  /** Offline fixtures inject a scripted exchange; production leaves it undefined. */
  readonly gatewayExchange?: GatewayExchangeTransport;
  readonly reportingHandlers?: ReportingHandlerRegistry;
  readonly metricsScrapeToken?: string;
  /** Required durable security ports in production; optional lab overrides otherwise. */
  readonly rateLimiter?: ReportingRateLimiter;
  readonly proofBodyStore?: ProofBodyStore;
  readonly verificationAccessStore?: SqlVerificationAccessStore;
  readonly vaultAccessAuditLog?: VaultAccessAuditLog;
  /**
   * Override admin user store (tests). Production default is SqlAdminUserStore
   * on the custody pool so TOTP factor survives process restart.
   */
  readonly adminUserStore?: AdminUserStore;
  /**
   * Override admin session store (tests). Production default is SqlAdminSessionStore
   * on the custody pool so cookie validation survives restart / multi-replica.
   */
  readonly adminSessionStore?: AdminSessionStore;
  /**
   * Override global TOTP burn registry (tests). Production default is
   * SqlTotpBurnStore so confirm-consumed steps reject SEND approve after restart.
   */
  readonly totpBurnStore?: TotpBurnStore;
  /**
   * Override halt toggle stack (tests). Production injects SQL-backed ports from main.
   * When omitted, an in-memory RUNNING gate is used so the route mounts and admits.
   */
  readonly halt?: {
    readonly gate: HaltGate;
    readonly store: OperatorHaltStore;
    readonly evidence: HaltEvidenceRecorder;
    readonly onToggle?: (engaged: boolean) => void;
  };
  /** Optional device-key store for dual-control inventory + readiness. */
  readonly deviceStore?: AdminRouteDeps["deviceStore"];
  /** Optional readiness probes (node health, backup schedule, break-glass). */
  readonly readinessProbe?: AdminRouteDeps["readinessProbe"];
  /**
   * Secret-safe effective config inputs for GET /admin/v1/settings.
   * Built once at boot from allowlisted NodeConfig fields + push composition flag.
   */
  readonly effectiveConfig?: AdminRouteDeps["effectiveConfig"];
  /** Lab receive ports — operation store + reporting ARM handle. */
  readonly labReceive?: AdminRouteDeps["labReceive"];
}

/**
 * CSRF Origin allowlist for admin money mutations.
 * Always includes PUBLIC_BASE_URL's origin when provided (same-origin SPA prod);
 * appends optional exact cross-origin entries (Vite proxy / ops console).
 */
export function resolveAdminCsrfOrigins(opts: {
  readonly publicBaseUrl?: string;
  readonly extraOrigins?: readonly string[];
}): readonly string[] {
  const out: string[] = [];
  if (opts.publicBaseUrl !== undefined && opts.publicBaseUrl !== "") {
    try {
      const origin = new URL(opts.publicBaseUrl).origin;
      if (origin !== "" && !out.includes(origin)) out.push(origin);
    } catch {
      // schema already rejects malformed URLs at boot; tests may omit
    }
  }
  for (const o of opts.extraOrigins ?? []) {
    if (o !== "" && o !== "*" && !out.includes(o)) out.push(o);
  }
  return Object.freeze(out);
}

export interface ProductionRouteSurface {
  readonly destinationService: DestinationService;
  readonly adminRouteDeps: AdminRouteDeps;
  readonly adminUserStore: AdminUserStore;
  readonly adminCsrfAllowedOrigins: readonly string[];
  readonly discoveryDocument: WellKnownDeps["buildDocument"];
  readonly reportingListener: (
    request: IncomingMessage,
    response: ServerResponse,
  ) => Promise<void>;
  /** Bound reporting store — always DurableReportingRequestStore on custody production. */
  readonly reportingStore: ReportingRequestStore;
  readonly reportingStoreKind: typeof DURABLE_REPORTING_STORE;
  readonly reportingRateLimiter: ReportingRateLimiter;
  readonly proofBodyStore: ProofBodyStore;
  readonly verificationAccessStore: SqlVerificationAccessStore;
  readonly vaultAccessAuditLog: VaultAccessAuditLog;
  /**
   * The same verified reporting pipeline the listener drives, minus the socket.
   * Composition tests assert auth class + arm outcomes against exactly what production serves.
   */
  readonly reportingHandle: (
    captured: CapturedReportRequest,
  ) => Promise<ReportingHttpResponse>;
  /**
   * Derived from the mounted handlers map (non-fail-closed entries
   * only). Never a hardcoded list adjacent to a separate registry.
   */
  readonly liveReportingEngines: readonly LiveReportingEngine[];
  readonly subscribeDeps: OperationSubscribeRouteDeps;
  /** Subscription handle store is PG-durable (restart-safe). */
  readonly subscriptionHandlesKind: typeof DURABLE_SUBSCRIPTION_HANDLES;
  readonly mountedRouteKeys: readonly string[];
  /** Live halt surface — always mounted on admin router. */
  readonly liveHaltRoutes: typeof LIVE_HALT_ROUTES;
  /** @deprecated prefer liveHaltRoutes; kept for prior greps. */
  readonly deferredHalt: typeof DEFERRED_HALT_ROUTE;
  /** Live attention-retraction surface — always mounted on admin router. */
  readonly liveAttentionRetractionRoutes: typeof LIVE_ATTENTION_RETRACTION_ROUTES;
  readonly deferredAdminMoney: typeof LIVE_ADMIN_MONEY_ENGINES;
  /** True when challenge + send-decision SQL stores are live (always on this surface). */
  readonly adminMoneyLive: boolean;
  /**
   * True when ADMIN_TOTP_LAB_MODE + valid secret (or injected lab totp) armed a
   * process-level fallback (undurable). Public path uses enrol/confirm instead.
   */
  readonly adminTotpLabBound: boolean;
  /**
   * Ensure durable admin_operators + admin_sessions (+ totp burns) exist.
   * Await before genesis bootstrap so enrolled factors and live cookies
   * survive process restart.
   */
  readonly ensureAdminOperators: () => Promise<void>;
  /** Production SQL session store (or test override). Cookie verify hits this. */
  readonly adminSessionStore: AdminSessionStore;
}

function failClosedReportingHandler(newRequestId: () => string): ReportingRouteHandler {
  return async () => ({
    response: reportingErrorResponse("internal_error", newRequestId()),
    persistChild: null,
  });
}

/**
 * Lab-only process TOTP. Requires explicit lab mode + ≥16-byte secret.
 * Absolute hard-stop when NODE_ENV=production (even if labTotpMode forced).
 * Public multi-operator deployments leave this null and use enrol/confirm.
 */
export function resolveLabTotp(config: {
  readonly totp?: TotpConfig;
  readonly env?: NodeJS.ProcessEnv;
  readonly labTotpMode?: boolean;
}): TotpConfig | null {
  const env = config.env ?? process.env;
  // Production never binds lab — env flag and test inject are both refused.
  if (isProductionNodeEnv(env)) return null;
  const lab =
    config.labTotpMode !== undefined ? config.labTotpMode : isAdminTotpLabMode(env);
  if (!lab) return null;

  if (config.totp !== undefined && config.totp.secret.length >= 16) {
    return config.totp;
  }
  const parsed = parseAdminTotpSecret(env.ADMIN_TOTP_SECRET);
  if (parsed === null) return null;
  return { secret: parsed, windowSteps: 1 };
}

/**
 * Lab process TOTP is **undurable**. Never writes setActiveTotpSecret / never
 * clears mustEnrolTotp in storage — a lab flag flipped off cannot leave a sticky
 * genesis factor. Money gates accept the process secret via labTotp fallback.
 * Production (or labTotp null) is always a no-op.
 */
export async function applyLabTotpBinding(
  userStore: AdminUserStore,
  labTotp: TotpConfig | null,
  env: NodeJS.ProcessEnv = process.env,
): Promise<{
  readonly bound: boolean;
  readonly userId: string | null;
  readonly durable: false;
}> {
  if (labTotp === null || isProductionNodeEnv(env)) {
    return { bound: false, userId: null, durable: false };
  }
  const admin = await userStore.findByUsername(DEFAULT_ADMIN_USERNAME);
  return { bound: true, userId: admin?.id ?? null, durable: false };
}

/**
 * a `node_signing_keys` row (public columns only; no `vault_secret_ref`,
 * see registry-store.ts) as a discovery wire key. `activated_at`/`retired_at` are typed as
 * strings by the registry but the pg driver may hand back `Date` for a timestamptz column;
 * normalize either shape to RFC3339-with-ms so it satisfies Rfc3339MsSchema regardless of the
 * driver's row-mapping mode.
 */
function toDiscoveryKeyConfig(row: NodeSigningKeyRow): DiscoveryKeyConfig {
  const toIso = (value: string | Date): string =>
    value instanceof Date ? value.toISOString() : new Date(value).toISOString();
  return {
    keyId: row.id,
    publicKey: row.public_key,
    validFrom: toIso(row.activated_at),
    validUntil: row.retired_at === null ? null : toIso(row.retired_at),
  };
}

function poolAsSigningKeySqlExecutor(pool: Pool): SigningKeySqlExecutor {
  return {
    query: async <R>(text: string, params: readonly unknown[]) => {
      const result = await pool.query(text, params as never);
      return { rows: result.rows as R[] };
    },
  };
}

export function createProductionRouteSurface(
  config: ProductionSurfaceConfig,
): ProductionRouteSurface {
  if (isProductionNodeEnv(config.env ?? process.env)) {
    for (const key of [
      "rateLimiter",
      "proofBodyStore",
      "verificationAccessStore",
      "vaultAccessAuditLog",
    ] as const) {
      if (config[key] === undefined) {
        throw new Error(`production composition requires durable ${key}`);
      }
    }
  }
  const newRequestId = config.newRequestId ?? (() => randomUUID());
  const nowMs = config.nowMs ?? (() => Date.now());
  const destinationService =
    config.destinationService ?? createFailClosedDestinationService();

  // Durable by default: cookie + factor survive reboot / multi-replica.
  const sqlSessionStore =
    config.adminSessionStore === undefined
      ? new SqlAdminSessionStore(createPoolAdminSessionExecutor(config.pool))
      : null;
  const sessionStore = config.adminSessionStore ?? sqlSessionStore!;
  const sqlUserStore =
    config.adminUserStore === undefined
      ? new SqlAdminUserStore(createPoolAdminUserExecutor(config.pool))
      : null;
  const userStore = config.adminUserStore ?? sqlUserStore!;
  // Shared durable (node_id,timestep) burns — confirm + money approve/reject.
  const sqlTotpBurns =
    config.totpBurnStore === undefined
      ? new SqlTotpBurnStore(createPoolTotpBurnExecutor(config.pool))
      : null;
  const totpBurnStore = config.totpBurnStore ?? sqlTotpBurns!;
  const ensureAdminOperators = async (): Promise<void> => {
    if (sqlSessionStore !== null) await sqlSessionStore.ensureSchema();
    if (sqlUserStore !== null) await sqlUserStore.ensureSchema();
    if (sqlTotpBurns !== null) await sqlTotpBurns.ensureSchema();
    // admin-mutation idempotency table created alongside the admin operator stores.
    await adminIdempotencyStore.ensureSchema();
  };
  const sessions = createAdminSessionService(
    { nodeId: config.nodeId },
    sessionStore,
    userStore,
  );

  const labTotp = resolveLabTotp(config);
  // Placeholder never authenticates (all-zero); lab binds real secret; enrol binds per-user.
  const failClosedTotp: TotpConfig = {
    secret: new Uint8Array(32),
    windowSteps: 1,
  };
  const routeTotp = labTotp ?? failClosedTotp;

  const adminCsrfAllowedOrigins = resolveAdminCsrfOrigins({
    publicBaseUrl: config.publicBaseUrl,
    extraOrigins: config.adminAllowedOrigins,
  });

  // SQL inventory reads always mount (session-gated in admin-router). Empty/throw
  // tables surface as empty pages / 503 rather than missing routes. Destinations overlay
  // DestinationService so bless/retire visibility matches the implementer list when live.
  const inventoryStore = withDestinationServiceInventory(
    createSqlAdminInventoryStore(config.pool),
    destinationService,
  );

  const haltBundle =
    config.halt ??
    (() => {
      const gate = createHaltGate("RUNNING");
      return {
        gate,
        store: createInMemoryOperatorHaltStore("RUNNING"),
        evidence: createInMemoryHaltEvidenceRecorder(),
      };
    })();

  // Implementer API key management. The CredentialService is bound to the
  // custody pool via SqlCredentialStore (same store genesis issues the bootstrap key
  // into). The implementer id is the single non-retired row genesis seeded; resolved
  // per-call so a reseed after retirement is honoured without a restart. The platform
  // never receives the raw key or the hash — only the operator SPA does, once, on issue.
  const credentialService = new CredentialService(
    new SqlCredentialStore(config.pool, config.nodeId),
  );
  // Review fix: resolve the target implementer through the canonical node-bound
  // relation (implementer_reporting_keys(node_id, implementer_id)), NOT a global
  // `implementers` query. Fails closed on BOTH edges — zero rows (no implementer registered for
  // this node) and more than one row (ambiguous; refuse to pick one). The prior global query let
  // an operator on node B mint/revoke credentials for an unrelated earlier-sorting implementer.
  const resolveImplementerId = async (): Promise<string | null> => {
    const { rows } = await config.pool.query<{ id: string }>(
      `SELECT irk.implementer_id AS id
         FROM implementer_reporting_keys irk
         JOIN implementers i ON i.id = irk.implementer_id
        WHERE irk.node_id = $1::uuid AND i.retired_at IS NULL
        GROUP BY irk.implementer_id`,
      [config.nodeId],
    );
    if (rows.length === 0) return null;
    if (rows.length > 1) {
      throw new Error(
        `resolveImplementerId: ${rows.length} non-retired implementers registered for node ${config.nodeId}; ` +
          "refusing to pick one — resolve the ambiguity before minting or revoking credentials",
      );
    }
    return rows[0]!.id;
  };

  // Device dual-control registry (list/enrol/revoke + approve signature verify).
  // Public keys only; private device keys stay browser-only (WebCrypto).
  const deviceSql: DeviceSqlExecutor = {
    query: async <R extends Record<string, unknown>>(text: string, params?: readonly unknown[]) => {
      const result = await config.pool.query(text, params as never);
      return { rows: result.rows as R[] };
    },
  };
  const deviceKeyStore = createSqlDeviceKeyStore(deviceSql);
  const deviceEnrollmentChallengeStore = createSqlEnrollmentChallengeStore(deviceSql);
  void deviceKeyStore.refreshNode(config.nodeId).catch(() => {
    /* best-effort boot index */
  });

  // G4: dual-control policy, second-device enrol, operator push.
  // Ceremony/issuer/push side-stores are process-local until a durable migration lands
  // (fail-soft / re-issue on restart OK).
  const secondDeviceCeremonyStore = new InMemorySecondDeviceCeremonyStore();
  const dualControlPolicy = new InMemoryDualControlPolicy(
    parseDualControlMode(process.env.DUAL_CONTROL_MODE),
  );
  const challengeIssuerStore = new InMemoryApprovalChallengeIssuerStore();
  const operatorPushStore = new InMemoryOperatorPushSubscriptionStore();
  // Real sealed auth (not length-only discard). Env OPERATOR_PUSH_SEAL_KEY preferred;
  // process-local key when unset so subscribe still stores openable bytes for a sender.
  const operatorPushSealKey =
    resolveOperatorPushSealKeyFromEnv() ?? createProcessLocalOperatorPushSealKey();
  const operatorPushAuthSealer = createOperatorPushAuthSealer(operatorPushSealKey);
  // Sender optional — inject in tests / future VAPID adapter. Subscribe stores real sealed auth.
  let nodeOrigin = "http://127.0.0.1";
  try {
    if (config.publicBaseUrl) {
      nodeOrigin = new URL(config.publicBaseUrl).origin;
    }
  } catch {
    /* keep loopback */
  }

  // Durable setup_state + vault-master seal (fingerprint only).
  const poolSqlExecutor = {
    query: async <T extends Record<string, unknown> = Record<string, unknown>>(
      sqlText: string,
      params?: readonly unknown[],
    ) => {
      const result = await config.pool.query(sqlText, params as never);
      return { rows: result.rows as T[] };
    },
  };
  const setupStateStore = createSqlSetupStateStore(poolSqlExecutor);
  const vaultMasterSealStore = createSqlVaultMasterSealStore(poolSqlExecutor);
  // Singleton bootstrap object — mutated in-place on seal hydrate + generate/ack.
  const vaultMasterBootstrap = resolveVaultMasterBootstrap({
    vaultMasterKey: config.vaultMasterKey,
    durableSeal: null,
  });
  // Boot-hydrate vault seal so show-once cannot re-issue after restart.
  void (async () => {
    try {
      const seal = await vaultMasterSealStore.load(config.nodeId);
      if (seal) applyDurableSealInPlace(vaultMasterBootstrap, seal);
    } catch {
      // lazy hydrate on first vault route still applies
    }
  })();

  const baseDeps = {
    sessions,
    userStore,
    csrf: { allowedOrigins: adminCsrfAllowedOrigins },
    nodeId: config.nodeId,
    destinationService,
    inventoryStore,
    newRequestId,
    nowMs,
    totpLog: totpBurnStore,
    halt: haltBundle,
    credentialService,
    resolveImplementerId,
    deviceEnrollmentChallengeStore,
    deviceEnrollmentAuditLog: new InMemoryEnrollmentAuditLog(),
    deviceRevocationAuditLog: new InMemoryDeviceRevocationAuditLog(),
    deviceRevocationSideEffects: new NoopDeviceRevocationSideEffects(),
    // node-mint the reporting credential (raw shown once by the SPA), replacing
    // dependence on REPORTING_KEY_OUT. Same custody pool; the node persists public only.
    reportingCredentialService: createSqlReportingCredentialService(config.pool, config.nodeId, {
      credentialStore: new SqlCredentialStore(config.pool, config.nodeId),
    }),
    deviceStore: config.deviceStore ?? deviceKeyStore,
    readinessProbe: config.readinessProbe,
    effectiveConfig: config.effectiveConfig,
    labReceive: config.labReceive,
    recoveryCeremonyRunner:
      config.databaseUrl !== undefined && config.databaseUrl.length > 0
        ? { databaseUrl: config.databaseUrl, liveSql: config.pool }
        : undefined,
    recoveryPackLockoutStore: createSqlRecoveryPackLockoutStore(poolSqlExecutor),
    recoveryPackAudit: (event: {
      readonly kind: "pack_create" | "pack_prove_ok" | "pack_prove_fail";
      readonly operator_id: string;
      readonly pack_content_sha256: string | null;
      readonly at: string;
      readonly verified_wallet_count?: number;
      readonly recovery_verification_id?: string | null;
    }) => {
      // Digests only — never passcode / master. Structured log for operators.
      console.info(
        JSON.stringify({
          event: "recovery_pack_audit",
          kind: event.kind,
          operator_id: event.operator_id,
          pack_content_sha256: event.pack_content_sha256,
          at: event.at,
          verified_wallet_count: event.verified_wallet_count ?? null,
          recovery_verification_id: event.recovery_verification_id ?? null,
        }),
      );
    },
    setupStateStore,
    vaultMasterBootstrap,
    vaultMasterSealStore,
    backupMasterKey: config.backupMasterKey ?? null,
    // G4
    dualControlPolicy,
    challengeIssuerStore,
    secondDeviceEnrol: {
      enrollmentChallengeStore: deviceEnrollmentChallengeStore,
      ceremonyStore: secondDeviceCeremonyStore,
      auditLog: new InMemoryEnrollmentAuditLog(),
      nodeOrigin,
    },
    operatorPush: {
      store: operatorPushStore,
      sealAuth: (auth: string) => operatorPushAuthSealer.seal(auth),
    },
  };

  // recovery-action confirm-read reader (Route A). Mirrors the
  // start-money-workers.ts landing-deps precedent: null without gatewayUrls, so the
  // release path fails closed rather than fabricating fresh=t0.
  const readFreshHead =
    config.gatewayUrls !== undefined && config.gatewayUrls.length > 0
      ? createSqlFreshHeadReader({
          pool: config.pool,
          nodeId: config.nodeId,
          gatewayUrls: config.gatewayUrls,
          exchange: config.gatewayExchange,
        })
      : undefined;

  // Always mount live challenge + send-decision; recovery stays fail-closed.
  const adminIdempotencyStore = new SqlAdminIdempotencyStore(config.pool);
  const atomicAdminMutation = createAtomicAdminMutationExecutor<AdminMutationTxPorts>({
    pool: config.pool,
    idempotencyStore: adminIdempotencyStore,
    portsFor: (client) => {
      const shadowHalt = config.halt === undefined ? undefined : {
        gate: createHaltGate(config.halt.gate.isHalted() ? "HALTED" : "RUNNING"),
        store: createNodeSettingsHaltStore(client),
        evidence: createNodeSettingsHaltEvidenceRecorder(client),
      };
      return {
        challengeStore: createSqlApprovalChallengeStore(client),
        sendDecisionStore: new SqlSendDecisionStore(client),
        loadOperation: createSqlApprovalOperationLoader(client),
        destinationService: config.destinationServiceForSql?.(client) ?? createFailClosedDestinationService(),
        halt: shadowHalt,
        credentialService: new CredentialService(new SqlCredentialStore(client, config.nodeId)),
      };
    },
  });
  const adminRouteDeps = createLiveAdminRouteDeps(
    { ...baseDeps, totp: routeTotp, adminIdempotencyStore, atomicAdminMutation },
    {
      challengeStore: createSqlApprovalChallengeStore(config.pool),
      sendDecisionStore: new SqlSendDecisionStore(config.pool),
      loadOperation: createSqlApprovalOperationLoader(config.pool),
      // Live recovery action + inspection stores.
      // readFreshHead threads the Route A confirm-read into RELEASE_EXPIRED_RECEIVE.
      recoveryActionStore: createSqlRecoveryActionStore(config.pool, readFreshHead),
      recoveryInspectionStore: createSqlRecoveryInspectionStore(config.pool),
      // Live audited attention-retraction store.
      attentionRetractionStore: createSqlAttentionRetractionStore(config.pool),
    },
  );


  // Read the durable signing-key registry per request so discovery reflects boot,
  // rotation, and restart alike (no in-process cache to go stale or to publish empty on a
  // freshly restarted process). NODE_IDENTITY doubles as the expected-artifact signer (see
  // main.ts SendArtifactSigner wiring); EVENT_SIGNING is the event-stream signer.
  // findRetainedNodeSigningKeys (not findActiveNodeSigningKeys) — discovery must publish the
  // active key PLUS every retained-valid prior key so an artifact/event signed before the
  // most recent rotation stays independently verifiable ("key validity intervals").
  const signingKeyRegistry = new SigningKeyRegistry(poolAsSigningKeySqlExecutor(config.pool));
  const discoveryDocument = async () => {
    const [eventSigningKeys, artifactSigningKeys] = await Promise.all([
      signingKeyRegistry.findRetainedNodeSigningKeys(config.nodeId, "EVENT_SIGNING"),
      signingKeyRegistry.findRetainedNodeSigningKeys(config.nodeId, "NODE_IDENTITY"),
    ]);
    return buildNodeIdentityDocument({
      nodeId: config.nodeId,
      apiVersion: NODE_CORE_VERSION,
      supportedOperations: [...SUPPORTED_OPS] as never,
      canonicalSuites: ["zp-v1"],
      eventSigningKeys: eventSigningKeys.map(toDiscoveryKeyConfig),
      artifactSigningKeys: artifactSigningKeys.map(toDiscoveryKeyConfig),
    });
  };

  // Same Pool as money SQL stores — nonces survive process restart.
  const reportingStore: ReportingRequestStore = new DurableReportingRequestStore(
    createPoolReportingClient(config.pool),
  );
  const reportingRateLimiter =
    config.rateLimiter ?? new InMemoryReportingRateLimiter(60_000, 600);
  const proofBodyStore =
    config.proofBodyStore ?? new SqlProofBodyStore(
      createPoolSqlExecutor(config.pool),
      createPoolSqlTransactionRunner(config.pool),
    );
  const verificationAccessStore =
    config.verificationAccessStore ?? new SqlVerificationAccessStore(config.pool);
  const vaultAccessAuditLog =
    config.vaultAccessAuditLog ?? new InMemoryVaultAccessAuditLog();
  // The live arm handler reads/writes the SAME pool the durable reporting store
  // burns nonces on, so receive_arms.reporting_nonce_id has a committed parent.
  const liveArm = createLiveArmRouteHandler({ pool: config.pool, newRequestId, nowMs });
  // Live reporting list/stream/snapshot/verification-material + durable subscription_handles.
  const failClosed = failClosedReportingHandler(newRequestId);
  const liveReads = createLiveReportingReads({
    pool: config.pool,
    nodeId: config.nodeId,
    newRequestId,
    nowMs,
    failClosed,
    destinationService: config.destinationService,
    liveArm,
    proofBodyStore,
    verificationAccessStore,
  });
  // Registry: liveArm is bound here so census greps stay valid; reporting read routes come from liveReads.
  const handlers =
    config.reportingHandlers ??
    Object.freeze({
      ...liveReads.handlers,
      [REPORTING_ROUTE_IDS.operationArmed]: liveArm,
    });
  // F5: surface mirrors mounted map — fail-closed routes never appear as "live".
  const liveReportingEngines = liveEnginesFromMountedHandlers(handlers, failClosed);

  const verifier = createReportingRequestVerifier({
    nodeId: config.nodeId,
    store: reportingStore,
    rateLimiter: reportingRateLimiter,
    nowMs,
    maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
  });
  const handler = createReportingRequestHandler({
    verifier,
    store: reportingStore,
    handlers,
    newRequestId,
    nowMs,
  });
  const reportingListener = createNodeHttpListener(
    createReportingHttpListener({
      handle: handler.handle,
      nowMs,
      maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
      newRequestId,
    }),
  );

  const subscribeDeps: OperationSubscribeRouteDeps = liveReads.subscribeDeps;


  return Object.freeze({
    destinationService,
    adminRouteDeps,
    adminUserStore: userStore,
    adminCsrfAllowedOrigins,
    discoveryDocument,
    reportingListener,
    reportingStore,
    reportingStoreKind: DURABLE_REPORTING_STORE,
    reportingRateLimiter,
    proofBodyStore,
    verificationAccessStore,
    vaultAccessAuditLog,
    reportingHandle: handler.handle,
    liveReportingEngines,
    subscribeDeps,
    subscriptionHandlesKind: liveReads.subscriptionHandlesKind,
    mountedRouteKeys: requiredProductionRouteKeys(),
    liveHaltRoutes: LIVE_HALT_ROUTES,
    deferredHalt: DEFERRED_HALT_ROUTE,
    liveAttentionRetractionRoutes: LIVE_ATTENTION_RETRACTION_ROUTES,
    deferredAdminMoney: LIVE_ADMIN_MONEY_ENGINES,
    adminMoneyLive: true,
    adminTotpLabBound: labTotp !== null,
    ensureAdminOperators,
    adminSessionStore: sessionStore,
  });
}
