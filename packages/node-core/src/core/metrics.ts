/**
 * Operational metrics for the generic node (Layer 1).
 *
 * Zero-dependency Prometheus text exposition: counters, gauges, and a coarse
 * histogram with closed label cardinality. Per-scrape gauges are fed by a
 * composition-root snapshot source (DB-truth, restart-safe); event counters and
 * the gateway-duration histogram are instrumented at call seams.
 *
 * Closed vocabulary only (Layer-1 operation kinds/statuses,
 * wallet_active_leases.lease_role) — never product-layer labels.
 *
 * Metrics slice for host-runtime signals.
 */

import { OPERATION_KINDS } from "@zucoins/generic-node-contracts/operations";

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

export interface CounterMetric {
  readonly name: string;
  readonly help: string;
  readonly labelNames: readonly string[];
  inc(labels: Record<string, string>, value?: number): void;
  get(labels: Record<string, string>): number;
  reset(): void;
  series(): ReadonlyArray<[Record<string, string>, number]>;
}

export interface GaugeMetric {
  readonly name: string;
  readonly help: string;
  readonly labelNames: readonly string[];
  set(labels: Record<string, string>, value: number): void;
  inc(labels: Record<string, string>, value?: number): void;
  dec(labels: Record<string, string>, value?: number): void;
  get(labels: Record<string, string>): number;
  reset(): void;
  series(): ReadonlyArray<[Record<string, string>, number]>;
}

export interface HistogramMetric {
  readonly name: string;
  readonly help: string;
  readonly labelNames: readonly string[];
  readonly buckets: readonly number[];
  observe(labels: Record<string, string>, valueSeconds: number): void;
  reset(): void;
  /** Render-ready series including `_bucket`, `_sum`, `_count`. */
  series(): ReadonlyArray<[string, Record<string, string>, number]>;
}

function labelKey(labels: Record<string, string>): string {
  return Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${v}"`)
    .join(",");
}

function createCounter(
  name: string,
  help: string,
  labelNames: readonly string[],
): CounterMetric {
  const store = new Map<string, { labels: Record<string, string>; value: number }>();
  return {
    name,
    help,
    labelNames,
    inc(labels, value = 1) {
      const key = labelKey(labels);
      const existing = store.get(key);
      if (existing) existing.value += value;
      else store.set(key, { labels: { ...labels }, value });
    },
    get(labels) {
      return store.get(labelKey(labels))?.value ?? 0;
    },
    reset() {
      store.clear();
    },
    series() {
      return [...store.values()].map(({ labels, value }) => [labels, value] as const);
    },
  };
}

function createGauge(
  name: string,
  help: string,
  labelNames: readonly string[],
): GaugeMetric {
  const store = new Map<string, { labels: Record<string, string>; value: number }>();
  return {
    name,
    help,
    labelNames,
    set(labels, value) {
      store.set(labelKey(labels), { labels: { ...labels }, value });
    },
    inc(labels, value = 1) {
      const key = labelKey(labels);
      const existing = store.get(key);
      if (existing) existing.value += value;
      else store.set(key, { labels: { ...labels }, value });
    },
    dec(labels, value = 1) {
      const key = labelKey(labels);
      const existing = store.get(key);
      if (existing) existing.value -= value;
      else store.set(key, { labels: { ...labels }, value: -value });
    },
    get(labels) {
      return store.get(labelKey(labels))?.value ?? 0;
    },
    reset() {
      store.clear();
    },
    series() {
      return [...store.values()].map(({ labels, value }) => [labels, value] as const);
    },
  };
}

function createHistogram(
  name: string,
  help: string,
  labelNames: readonly string[],
  buckets: readonly number[],
): HistogramMetric {
  const sorted = [...buckets].sort((a, b) => a - b);
  type Series = {
    labels: Record<string, string>;
    counts: number[];
    sum: number;
    count: number;
  };
  const store = new Map<string, Series>();

  function seriesFor(labels: Record<string, string>): Series {
    const key = labelKey(labels);
    let s = store.get(key);
    if (!s) {
      s = { labels: { ...labels }, counts: sorted.map(() => 0), sum: 0, count: 0 };
      store.set(key, s);
    }
    return s;
  }

  return {
    name,
    help,
    labelNames,
    buckets: sorted,
    observe(labels, valueSeconds) {
      const s = seriesFor(labels);
      s.sum += valueSeconds;
      s.count += 1;
      for (let i = 0; i < sorted.length; i++) {
        if (valueSeconds <= sorted[i]!) s.counts[i]! += 1;
      }
    },
    reset() {
      store.clear();
    },
    series() {
      const out: Array<[string, Record<string, string>, number]> = [];
      for (const s of store.values()) {
        for (let i = 0; i < sorted.length; i++) {
          out.push([
            `${name}_bucket`,
            { ...s.labels, le: String(sorted[i]) },
            s.counts[i]!,
          ]);
        }
        out.push([`${name}_bucket`, { ...s.labels, le: "+Inf" }, s.count]);
        out.push([`${name}_sum`, s.labels, s.sum]);
        out.push([`${name}_count`, s.labels, s.count]);
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------
// Closed label domains (Layer-1 only)
// ---------------------------------------------------------------------------

export const METRIC_OPERATION_KINDS = OPERATION_KINDS;
export type MetricOperationKind = (typeof METRIC_OPERATION_KINDS)[number];

export const METRIC_OPERATION_STATUSES = [
  "CREATED",
  "READY",
  "RECEIVE_LANDED",
  "INTERNAL_MOVE_LANDED",
  "APPROVED",
  "AWAITING_REDEMPTION",
  "EXTERNAL_SEND_LANDED",
  "EXPIRED",
  "REJECTED",
  "NEEDS_ATTENTION",
] as const;
export type MetricOperationStatus = (typeof METRIC_OPERATION_STATUSES)[number];

/** wallet_active_leases.lease_role closed set. */
export const METRIC_LEASE_ROLES = [
  "RECEIVE_WINDOW",
  "MOVE_DESTINATION",
  "SEND_SOURCE",
  "MOVE_SOURCE",
  "RECONCILIATION",
] as const;
export type MetricLeaseRole = (typeof METRIC_LEASE_ROLES)[number];

export const METRIC_WALLET_STATES = [
  "AVAILABLE",
  "PINNED",
  "QUARANTINED",
  "RETIRED",
] as const;
export type MetricWalletState = (typeof METRIC_WALLET_STATES)[number];

/** Submit outcomes observed at the submitter seam (Layer-1 outcomes only). */
export const METRIC_SUBMIT_OUTCOMES = [
  "accepted",
  "rejected",
  "ambiguous",
  "error",
] as const;
export type MetricSubmitOutcome = (typeof METRIC_SUBMIT_OUTCOMES)[number];

export const METRIC_GATEWAY_RPCS = [
  "get_transaction__v1",
  "submit_transaction__v1",
] as const;
export type MetricGatewayRpc = (typeof METRIC_GATEWAY_RPCS)[number];

export const METRIC_GATEWAY_OUTCOMES = ["ok", "error"] as const;
export type MetricGatewayOutcome = (typeof METRIC_GATEWAY_OUTCOMES)[number];

export const METRIC_AUTH_OUTCOMES = ["authorized", "rejected", "error"] as const;
export type MetricAuthOutcome = (typeof METRIC_AUTH_OUTCOMES)[number];

export const METRIC_IDEMPOTENCY_OUTCOMES = ["first", "replay", "conflict", "invalid"] as const;
export type MetricIdempotencyOutcome = (typeof METRIC_IDEMPOTENCY_OUTCOMES)[number];

/**
 * Candidate-intake producer lanes. `push` is the Web Push delivery channel
 * (authenticated by the ECE auth secret + endpoint id); `relay` is the anonymous
 * origin-relay POST. Held apart so an anonymous flood can neither consume the
 * authenticated lane's headroom nor queue ahead of it.
 */
export const METRIC_CANDIDATE_INTAKE_SOURCES = ["push", "relay"] as const;
export type MetricCandidateIntakeSource = (typeof METRIC_CANDIDATE_INTAKE_SOURCES)[number];

/**
 * Closed refusal reasons for a candidate-intake deposit. Coarse by design — a
 * refusal reason is rendered on a public scrape and must never echo signed material.
 * Sole source of truth for the app-side unions in
 * apps/generic-node/src/money-workers/receiver-channel-producer.ts.
 */
export const METRIC_CANDIDATE_INTAKE_REFUSALS = [
  "inbox_full",
  "malformed_body",
  "wrong_action",
  "decode_failed",
  "not_armed",
] as const;
export type MetricCandidateIntakeRefusal = (typeof METRIC_CANDIDATE_INTAKE_REFUSALS)[number];

/**
 * Inbound Web Push VAPID gate outcomes (ZTR-1161).
 * `verified` — RFC 8292 ES256 ok against stored app-server key.
 * `rejected` — header present but failed verify.
 * `absent` — no Authorization header.
 * `no_key` — row has no stored app_server_public_key (or node origin unset).
 */
export const METRIC_PUSH_VAPID_OUTCOMES = [
  "verified",
  "rejected",
  "absent",
  "no_key",
] as const;
export type MetricPushVapidOutcome = (typeof METRIC_PUSH_VAPID_OUTCOMES)[number];

/**
 * Push-receive money-path outcomes (ZTR-1154). Coarse closed set rendered on the
 * public scrape — never echoes envelope bytes or transfer codes.
 * `enqueued` / `no_transfer_code` / `decrypt_failed` only; refused/unknown stay audit-only.
 */
export const METRIC_PUSH_RECEIVE_OUTCOMES = [
  "enqueued",
  "no_transfer_code",
  "decrypt_failed",
] as const;
export type MetricPushReceiveOutcome = (typeof METRIC_PUSH_RECEIVE_OUTCOMES)[number];

/**
 * Delivered-envelope shape label on the enqueued path. `none` is used for
 * no_transfer_code / decrypt_failed so the series stays fully labelled.
 */
export const METRIC_PUSH_RECEIVE_SHAPES = [
  "aps",
  "data",
  "send_side_fallback",
  "none",
] as const;
export type MetricPushReceiveShape = (typeof METRIC_PUSH_RECEIVE_SHAPES)[number];

/** Observation anomaly classification (closed; relationship/parse kinds). */
export const METRIC_ANOMALY_KINDS = [
  "REGRESSION",
  "GENESIS_AFTER_HISTORY",
  "UNEXPLAINED_JUMP",
  "SIGNATURE_COLLISION",
  "TRANSPORT_ERROR",
  "MALFORMED_ENVELOPE",
  "MALFORMED_TRANSACTION",
  "UNVERIFIED_SIGNATURE",
  "WALLET_ROLE_INVALID",
  "other",
] as const;
export type MetricAnomalyKind = (typeof METRIC_ANOMALY_KINDS)[number];

/** Coarse gateway histogram buckets (seconds) — same ladder as v1 operator surface. */
export const GATEWAY_HISTOGRAM_BUCKETS = [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10] as const;

// ---------------------------------------------------------------------------
// Per-scrape snapshot (DB + process stamps; composition root supplies)
// ---------------------------------------------------------------------------

/**
 * Point-in-time operational signal set the node is required to publish.
 * All counts are non-negative integers; ratios are integer floor percents.
 * Supplied fresh on every scrape so gauges cannot drift after restart.
 */
export interface OperationalMetricsSnapshot {
  readonly availableWallets: number;
  readonly totalWallets: number;
  readonly walletsByState: Readonly<Partial<Record<MetricWalletState, number>>>;
  /** Active leases grouped by lease_role (wallet_active_leases). */
  readonly activeLeasesByRole: Readonly<Partial<Record<MetricLeaseRole, number>>>;
  /** Wallets currently PINNED (state projection). */
  readonly pinnedWallets: number;
  readonly queueDepth: number;
  readonly queueOldestAgeSecs: number;
  /** Integer floor percent of pool cap consumed. */
  readonly capUtilizationPercent: number;
  readonly poolCapTotal: number;
  /** Oldest active lease age (any role), seconds. */
  readonly oldestLeaseAgeSecs: number;
  /**
   * Wallets quarantined by unexpected head movement
   * (quarantine_reason ∈ {GENESIS_AFTER_HISTORY, REGRESSION}).
   */
  readonly quarantinedUnexpectedHead: number;
  /**
   * External-send operations parked at NEEDS_ATTENTION. Each one holds a source-wallet
   * lease against the pool cap, and the cap never recovers capacity, so this is the level
   * that makes a stuck send visible before it is a wall.
   */
  readonly parkedExternalSends: number;
  /** Non-terminal / all ops by status (closed OPERATION_STATUS). */
  readonly operationsByStatus: Readonly<Partial<Record<MetricOperationStatus, number>>>;
  /** Oldest non-terminal operation age by status, seconds (optional series). */
  readonly operationsOldestAgeSecsByStatus: Readonly<
    Partial<Record<MetricOperationStatus, number>>
  >;
  /** 1 when storage/disk pressure band is engaged, else 0. */
  readonly storagePressure: 0 | 1;
  /** 1 when this process holds signer leadership, else 0. */
  readonly signerLeadershipHeld: 0 | 1;
  /** 1 when operator halt is engaged, else 0. */
  readonly haltEngaged: 0 | 1;
  /** 1 when readiness conjunction is open, else 0. */
  readonly readinessReady: 0 | 1;
  /** 1 when observation gate is degraded, else 0. */
  readonly observationDegraded: 0 | 1;
  /**
   * Worker/reconciler health by closed name. Missing names render as 0.
   * Values: 1 = healthy/running, 0 = stopped/unhealthy/unwired.
   */
  readonly workerHealth: Readonly<Partial<Record<MetricWorkerName, 0 | 1>>>;
  /** Availability is separate from values so unknown never masquerades as healthy/down. */
  readonly databaseTruthAvailable?: 0 | 1;
  readonly workerHealthAvailable?: Readonly<Partial<Record<MetricWorkerName, 0 | 1>>>;
  readonly backupEnabled?: 0 | 1;
  readonly backupRunning?: 0 | 1;
  readonly backupStatusAvailable?: 0 | 1;
  readonly backupLastSuccessAgeSecs?: number;
  readonly backupLastSuccessAvailable?: 0 | 1;
  readonly backupRpoBreached?: 0 | 1;
}

export const METRIC_WORKER_NAMES = [
  "reconciler",
  "receive_queue_expiry",
  "pool_scaler",
  "send_completion_monitor",
  "observation",
  "leadership",
] as const;
export type MetricWorkerName = (typeof METRIC_WORKER_NAMES)[number];

export type MetricsSnapshotSource = () =>
  | OperationalMetricsSnapshot
  | Promise<OperationalMetricsSnapshot>;

export function emptyOperationalSnapshot(): OperationalMetricsSnapshot {
  return {
    availableWallets: 0,
    totalWallets: 0,
    walletsByState: {},
    activeLeasesByRole: {},
    pinnedWallets: 0,
    queueDepth: 0,
    queueOldestAgeSecs: 0,
    capUtilizationPercent: 0,
    poolCapTotal: 0,
    oldestLeaseAgeSecs: 0,
    quarantinedUnexpectedHead: 0,
    parkedExternalSends: 0,
    operationsByStatus: {},
    operationsOldestAgeSecsByStatus: {},
    storagePressure: 0,
    signerLeadershipHeld: 0,
    haltEngaged: 0,
    readinessReady: 0,
    observationDegraded: 0,
    workerHealth: {},
    databaseTruthAvailable: 0,
    workerHealthAvailable: {},
    backupEnabled: 0,
    backupRunning: 0,
    backupStatusAvailable: 0,
    backupLastSuccessAgeSecs: 0,
    backupLastSuccessAvailable: 0,
    backupRpoBreached: 0,
  };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export interface NodeMetrics {
  // --- event counters (instrumented at seams) ---
  readonly operationsCreated: CounterMetric;
  readonly operationsCompleted: CounterMetric;
  readonly operationsFailed: CounterMetric;
  readonly submitTotal: CounterMetric;
  readonly t0ReadFailures: CounterMetric;
  readonly observationAnomalies: CounterMetric;
  readonly proofBudgetExhaustion: CounterMetric;
  readonly gatewayRequestDuration: HistogramMetric;
  readonly authTotal: CounterMetric;
  readonly idempotencyTotal: CounterMetric;
  readonly candidateIntakeRefused: CounterMetric;
  /** Inbound Web Push VAPID gate outcomes (ZTR-1161). */
  readonly pushVapid: CounterMetric;
  /**
   * Inbound Web Push receive outcomes (ZTR-1154). Labels: outcome, shape.
   * shape is meaningful on enqueued; "none" otherwise.
   */
  readonly pushReceiveTotal: CounterMetric;
  /**
   * Current consecutive no_transfer_code count with no intervening enqueued
   * (process-local; resets on enqueue or process restart).
   */
  readonly pushNoTransferCodeStreak: GaugeMetric;

  // --- per-scrape gauges (filled from snapshot on render) ---
  readonly availableWallets: GaugeMetric;
  readonly totalWallets: GaugeMetric;
  readonly walletsByState: GaugeMetric;
  readonly activeLeasesByRole: GaugeMetric;
  readonly pinnedWallets: GaugeMetric;
  readonly queueDepth: GaugeMetric;
  readonly queueOldestAgeSecs: GaugeMetric;
  readonly capUtilizationPercent: GaugeMetric;
  readonly poolCapTotal: GaugeMetric;
  readonly oldestLeaseAgeSecs: GaugeMetric;
  readonly quarantinedUnexpectedHead: GaugeMetric;
  readonly parkedExternalSends: GaugeMetric;
  readonly operationsByStatus: GaugeMetric;
  readonly operationsOldestAgeSecs: GaugeMetric;
  readonly storagePressure: GaugeMetric;
  readonly signerLeadershipHeld: GaugeMetric;
  readonly haltEngaged: GaugeMetric;
  readonly readinessReady: GaugeMetric;
  readonly observationDegraded: GaugeMetric;
  readonly workerHealth: GaugeMetric;
  readonly databaseTruthAvailable: GaugeMetric;
  readonly workerHealthAvailable: GaugeMetric;
  readonly backupEnabled: GaugeMetric;
  readonly backupRunning: GaugeMetric;
  readonly backupStatusAvailable: GaugeMetric;
  readonly backupLastSuccessAgeSecs: GaugeMetric;
  readonly backupLastSuccessAvailable: GaugeMetric;
  readonly backupRpoBreached: GaugeMetric;

  // --- process defaults (collected at render) ---
  readonly processResidentMemoryBytes: GaugeMetric;
  readonly processHeapUsedBytes: GaugeMetric;
  readonly processCpuUserSeconds: CounterMetric;
  readonly processCpuSystemSeconds: CounterMetric;

  /** Optional snapshot source; when set, renderMetrics awaits it before exposition. */
  setSnapshotSource(source: MetricsSnapshotSource | undefined): void;
  getSnapshotSource(): MetricsSnapshotSource | undefined;
  /** Apply a snapshot onto the per-scrape gauges (test helper / render path). */
  applySnapshot(snapshot: OperationalMetricsSnapshot): void;
  /** Refresh process CPU/memory gauges from `process`. */
  collectProcessDefaults(nowMs?: () => number): void;
  resetAll(): void;
}

export function createNodeMetrics(): NodeMetrics {
  const operationsCreated = createCounter(
    "gn_operations_created_total",
    "Operations created by kind.",
    ["kind"],
  );
  const operationsCompleted = createCounter(
    "gn_operations_completed_total",
    "Operations reaching a terminal landed state by kind.",
    ["kind"],
  );
  const operationsFailed = createCounter(
    "gn_operations_failed_total",
    "Operations that failed (REJECTED or EXPIRED) by kind.",
    ["kind"],
  );
  const submitTotal = createCounter(
    "gn_submit_total",
    "Gateway submit attempts by outcome.",
    ["outcome"],
  );
  const t0ReadFailures = createCounter(
    "gn_t0_read_failures_total",
    "T0 / gateway-read failures observed at the observation seam.",
    [],
  );
  const observationAnomalies = createCounter(
    "gn_observation_anomalies_total",
    "Observation anomalies by closed kind.",
    ["kind"],
  );
  const proofBudgetExhaustion = createCounter(
    "gn_proof_budget_exhaustion_total",
    "Any-depth verification path-depth or proof-budget exhaustion events.",
    [],
  );
  const gatewayRequestDuration = createHistogram(
    "gn_gateway_request_duration_seconds",
    "Gateway request duration in seconds at the observation/submit seam.",
    ["rpc", "outcome"],
    GATEWAY_HISTOGRAM_BUCKETS,
  );
  const authTotal = createCounter("gn_auth_total", "Operation API authentication outcomes.", ["outcome"]);
  const idempotencyTotal = createCounter("gn_idempotency_total", "Operation API idempotency outcomes.", ["outcome"]);
  const candidateIntakeRefused = createCounter(
    "gn_candidate_intake_refused_total",
    "Candidate-intake deposits refused before enqueue, by producer lane and reason.",
    ["source", "reason"],
  );
  const pushVapid = createCounter(
    "gn_push_vapid_total",
    "Inbound Web Push VAPID verification outcomes (verified|rejected|absent|no_key).",
    ["outcome"],
  );
  const pushReceiveTotal = createCounter(
    "gn_push_receive_total",
    "Inbound Web Push receive outcomes by closed outcome and envelope shape (ZTR-1154).",
    ["outcome", "shape"],
  );
  const pushNoTransferCodeStreak = createGauge(
    "gn_push_no_transfer_code_streak",
    "Consecutive no_transfer_code push receives since the last enqueued delivery (shape-break detector).",
    [],
  );

  const availableWallets = createGauge(
    "gn_available_wallets",
    "Recovery-verified AVAILABLE wallets eligible for receive assignment.",
    [],
  );
  const totalWallets = createGauge(
    "gn_total_wallets",
    "Total wallets counted against the pool cap (all states).",
    [],
  );
  const walletsByState = createGauge(
    "gn_wallets",
    "Wallet count by closed wallet state.",
    ["state"],
  );
  const activeLeasesByRole = createGauge(
    "gn_active_leases",
    "Active wallet_active_leases rows by lease_role.",
    ["lease_role"],
  );
  const pinnedWallets = createGauge(
    "gn_pinned_wallets",
    "Wallets currently in PINNED state.",
    [],
  );
  const queueDepth = createGauge(
    "gn_receive_queue_depth",
    "Receive-admission queue depth (unassigned RECEIVE_EXTERNAL CREATED).",
    [],
  );
  const queueOldestAgeSecs = createGauge(
    "gn_receive_queue_oldest_age_seconds",
    "Age in seconds of the oldest queued receive.",
    [],
  );
  const capUtilizationPercent = createGauge(
    "gn_pool_cap_utilization_percent",
    "Integer floor percent of pool cap consumed.",
    [],
  );
  const poolCapTotal = createGauge(
    "gn_pool_cap_total",
    "Configured pool cap (total wallets ceiling).",
    [],
  );
  const oldestLeaseAgeSecs = createGauge(
    "gn_oldest_lease_age_seconds",
    "Age in seconds of the oldest active lease (any role).",
    [],
  );
  const quarantinedUnexpectedHead = createGauge(
    "gn_wallets_quarantined_unexpected_head",
    "Wallets quarantined for unexpected head movement (GENESIS_AFTER_HISTORY or REGRESSION).",
    [],
  );
  const parkedExternalSends = createGauge(
    "gn_send_external_parked",
    "External-send operations parked at NEEDS_ATTENTION after partial delivery (post-expiry hold or head anomaly), each still holding its source-wallet lease against the pool cap.",
    [],
  );
  const operationsByStatus = createGauge(
    "gn_operations",
    "Operation count by closed status.",
    ["status"],
  );
  const operationsOldestAgeSecs = createGauge(
    "gn_operations_oldest_age_seconds",
    "Oldest operation age in seconds by status.",
    ["status"],
  );
  const storagePressure = createGauge(
    "gn_storage_pressure",
    "1 when storage/disk pressure band is engaged, else 0.",
    [],
  );
  const signerLeadershipHeld = createGauge(
    "gn_signer_leadership_held",
    "1 when this process holds signer leadership, else 0.",
    [],
  );
  const haltEngaged = createGauge(
    "gn_halt_engaged",
    "1 when the operator halt is engaged, else 0.",
    [],
  );
  const readinessReady = createGauge(
    "gn_readiness_ready",
    "1 when the readiness conjunction is open, else 0.",
    [],
  );
  const observationDegraded = createGauge(
    "gn_observation_degraded",
    "1 when observation is degraded after exceeding the gateway-read failure budget.",
    [],
  );
  const workerHealth = createGauge(
    "gn_worker_healthy",
    "Worker/reconciler health by closed name (consult availability; 0 may mean down).",
    ["worker"],
  );
  const databaseTruthAvailable = createGauge("gn_database_truth_available", "1 when DB-backed scrape gauges are truthful; 0 means unknown.", []);
  const workerHealthAvailable = createGauge("gn_worker_health_available", "1 when the named worker state is observed; 0 means unknown, not down.", ["worker"]);
  const backupEnabled = createGauge("gn_backup_enabled", "1 when scheduled backups are configured.", []);
  const backupRunning = createGauge("gn_backup_running", "1 while a scheduled backup export is running.", []);
  const backupStatusAvailable = createGauge("gn_backup_status_available", "1 when backup scheduler state is available.", []);
  const backupLastSuccessAgeSecs = createGauge("gn_backup_last_success_age_seconds", "Age of last successful backup; consult availability.", []);
  const backupLastSuccessAvailable = createGauge("gn_backup_last_success_available", "1 when a successful backup timestamp exists.", []);
  const backupRpoBreached = createGauge("gn_backup_rpo_breached", "1 when configured backup RPO is breached.", []);

  const processResidentMemoryBytes = createGauge(
    "gn_process_resident_memory_bytes",
    "Resident set size of the node process in bytes.",
    [],
  );
  const processHeapUsedBytes = createGauge(
    "gn_process_heap_used_bytes",
    "V8 heap used bytes.",
    [],
  );
  const processCpuUserSeconds = createCounter(
    "gn_process_cpu_user_seconds_total",
    "Cumulative user CPU time of the node process in seconds.",
    [],
  );
  const processCpuSystemSeconds = createCounter(
    "gn_process_cpu_system_seconds_total",
    "Cumulative system CPU time of the node process in seconds.",
    [],
  );

  let snapshotSource: MetricsSnapshotSource | undefined;
  // CPU counters are cumulative absolute values from process.cpuUsage — store last
  // absolute so we can set (not delta) via counter store overwrite path.
  // We expose absolute seconds by resetting then inc'ing the absolute value each collect.

  const metrics: NodeMetrics = {
    operationsCreated,
    operationsCompleted,
    operationsFailed,
    submitTotal,
    t0ReadFailures,
    observationAnomalies,
    proofBudgetExhaustion,
    gatewayRequestDuration,
    authTotal,
    idempotencyTotal,
    candidateIntakeRefused,
    pushVapid,
    pushReceiveTotal,
    pushNoTransferCodeStreak,
    availableWallets,
    totalWallets,
    walletsByState,
    activeLeasesByRole,
    pinnedWallets,
    queueDepth,
    queueOldestAgeSecs,
    capUtilizationPercent,
    poolCapTotal,
    oldestLeaseAgeSecs,
    quarantinedUnexpectedHead,
    parkedExternalSends,
    operationsByStatus,
    operationsOldestAgeSecs,
    storagePressure,
    signerLeadershipHeld,
    haltEngaged,
    readinessReady,
    observationDegraded,
    workerHealth,
    databaseTruthAvailable,
    workerHealthAvailable,
    backupEnabled,
    backupRunning,
    backupStatusAvailable,
    backupLastSuccessAgeSecs,
    backupLastSuccessAvailable,
    backupRpoBreached,
    processResidentMemoryBytes,
    processHeapUsedBytes,
    processCpuUserSeconds,
    processCpuSystemSeconds,
    setSnapshotSource(source) {
      snapshotSource = source;
    },
    getSnapshotSource() {
      return snapshotSource;
    },
    applySnapshot(snapshot) {
      availableWallets.set({}, snapshot.availableWallets);
      totalWallets.set({}, snapshot.totalWallets);
      for (const state of METRIC_WALLET_STATES) {
        walletsByState.set({ state }, snapshot.walletsByState[state] ?? 0);
      }
      for (const role of METRIC_LEASE_ROLES) {
        activeLeasesByRole.set({ lease_role: role }, snapshot.activeLeasesByRole[role] ?? 0);
      }
      pinnedWallets.set({}, snapshot.pinnedWallets);
      queueDepth.set({}, snapshot.queueDepth);
      queueOldestAgeSecs.set({}, snapshot.queueOldestAgeSecs);
      capUtilizationPercent.set({}, snapshot.capUtilizationPercent);
      poolCapTotal.set({}, snapshot.poolCapTotal);
      oldestLeaseAgeSecs.set({}, snapshot.oldestLeaseAgeSecs);
      quarantinedUnexpectedHead.set({}, snapshot.quarantinedUnexpectedHead);
      parkedExternalSends.set({}, snapshot.parkedExternalSends);
      for (const status of METRIC_OPERATION_STATUSES) {
        operationsByStatus.set({ status }, snapshot.operationsByStatus[status] ?? 0);
        operationsOldestAgeSecs.set(
          { status },
          snapshot.operationsOldestAgeSecsByStatus[status] ?? 0,
        );
      }
      storagePressure.set({}, snapshot.storagePressure);
      signerLeadershipHeld.set({}, snapshot.signerLeadershipHeld);
      haltEngaged.set({}, snapshot.haltEngaged);
      readinessReady.set({}, snapshot.readinessReady);
      observationDegraded.set({}, snapshot.observationDegraded);
      for (const worker of METRIC_WORKER_NAMES) {
        workerHealth.set({ worker }, snapshot.workerHealth[worker] ?? 0);
        workerHealthAvailable.set({ worker }, snapshot.workerHealthAvailable?.[worker] ?? 0);
      }
      databaseTruthAvailable.set({}, snapshot.databaseTruthAvailable ?? 0);
      backupEnabled.set({}, snapshot.backupEnabled ?? 0);
      backupRunning.set({}, snapshot.backupRunning ?? 0);
      backupStatusAvailable.set({}, snapshot.backupStatusAvailable ?? 0);
      backupLastSuccessAgeSecs.set({}, snapshot.backupLastSuccessAgeSecs ?? 0);
      backupLastSuccessAvailable.set({}, snapshot.backupLastSuccessAvailable ?? 0);
      backupRpoBreached.set({}, snapshot.backupRpoBreached ?? 0);
    },
    collectProcessDefaults() {
      const mem = process.memoryUsage();
      processResidentMemoryBytes.set({}, mem.rss);
      processHeapUsedBytes.set({}, mem.heapUsed);
      const cpu = process.cpuUsage();
      // Absolute cumulative seconds (microseconds → seconds). Counter store is
      // reset then set to the absolute so scrape shows process lifetime totals.
      processCpuUserSeconds.reset();
      processCpuSystemSeconds.reset();
      processCpuUserSeconds.inc({}, cpu.user / 1e6);
      processCpuSystemSeconds.inc({}, cpu.system / 1e6);
    },
    resetAll() {
      operationsCreated.reset();
      operationsCompleted.reset();
      operationsFailed.reset();
      submitTotal.reset();
      t0ReadFailures.reset();
      observationAnomalies.reset();
      proofBudgetExhaustion.reset();
      gatewayRequestDuration.reset();
      authTotal.reset();
      idempotencyTotal.reset();
      candidateIntakeRefused.reset();
      pushVapid.reset();
      pushReceiveTotal.reset();
      pushNoTransferCodeStreak.reset();
      availableWallets.reset();
      totalWallets.reset();
      walletsByState.reset();
      activeLeasesByRole.reset();
      pinnedWallets.reset();
      queueDepth.reset();
      queueOldestAgeSecs.reset();
      capUtilizationPercent.reset();
      poolCapTotal.reset();
      oldestLeaseAgeSecs.reset();
      quarantinedUnexpectedHead.reset();
      parkedExternalSends.reset();
      operationsByStatus.reset();
      operationsOldestAgeSecs.reset();
      storagePressure.reset();
      signerLeadershipHeld.reset();
      haltEngaged.reset();
      readinessReady.reset();
      observationDegraded.reset();
      workerHealth.reset();
      databaseTruthAvailable.reset();
      workerHealthAvailable.reset();
      backupEnabled.reset();
      backupRunning.reset();
      backupStatusAvailable.reset();
      backupLastSuccessAgeSecs.reset();
      backupLastSuccessAvailable.reset();
      backupRpoBreached.reset();
      processResidentMemoryBytes.reset();
      processHeapUsedBytes.reset();
      processCpuUserSeconds.reset();
      processCpuSystemSeconds.reset();
    },
  };

  return Object.freeze(metrics);
}

// ---------------------------------------------------------------------------
// Prometheus text exposition
// ---------------------------------------------------------------------------

function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

function formatLabels(labels: Record<string, string>): string {
  const entries = Object.entries(labels);
  if (entries.length === 0) return "";
  const inner = entries
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${escapeLabelValue(v)}"`)
    .join(",");
  return `{${inner}}`;
}

function renderCounter(metric: CounterMetric): string {
  const lines: string[] = [
    `# HELP ${metric.name} ${metric.help}`,
    `# TYPE ${metric.name} counter`,
  ];
  for (const [labels, value] of metric.series()) {
    lines.push(`${metric.name}${formatLabels(labels)} ${value}`);
  }
  // Always emit TYPE/HELP even with zero series so scrapers discover the metric.
  if (metric.series().length === 0) {
    lines.push(`${metric.name} 0`);
  }
  return lines.join("\n");
}

function renderGauge(metric: GaugeMetric): string {
  const lines: string[] = [
    `# HELP ${metric.name} ${metric.help}`,
    `# TYPE ${metric.name} gauge`,
  ];
  const series = metric.series();
  if (series.length === 0) {
    lines.push(`${metric.name} 0`);
  } else {
    for (const [labels, value] of series) {
      lines.push(`${metric.name}${formatLabels(labels)} ${value}`);
    }
  }
  return lines.join("\n");
}

function renderHistogram(metric: HistogramMetric): string {
  const lines: string[] = [
    `# HELP ${metric.name} ${metric.help}`,
    `# TYPE ${metric.name} histogram`,
  ];
  for (const [seriesName, labels, value] of metric.series()) {
    lines.push(`${seriesName}${formatLabels(labels)} ${value}`);
  }
  return lines.join("\n");
}

/**
 * Apply snapshot (if configured), collect process defaults, and render Prometheus
 * text exposition. Suitable for GET /metrics with
 * Content-Type: text/plain; version=0.0.4; charset=utf-8.
 */
export async function renderMetrics(metrics: NodeMetrics): Promise<string> {
  const source = metrics.getSnapshotSource();
  if (source) {
    metrics.applySnapshot(await source());
  }
  metrics.collectProcessDefaults();

  const blocks = [
    renderCounter(metrics.operationsCreated),
    renderCounter(metrics.operationsCompleted),
    renderCounter(metrics.operationsFailed),
    renderCounter(metrics.submitTotal),
    renderCounter(metrics.t0ReadFailures),
    renderCounter(metrics.observationAnomalies),
    renderCounter(metrics.proofBudgetExhaustion),
    renderHistogram(metrics.gatewayRequestDuration),
    renderCounter(metrics.authTotal),
    renderCounter(metrics.idempotencyTotal),
    renderCounter(metrics.candidateIntakeRefused),
    renderCounter(metrics.pushVapid),
    renderCounter(metrics.pushReceiveTotal),
    renderGauge(metrics.pushNoTransferCodeStreak),
    renderGauge(metrics.availableWallets),
    renderGauge(metrics.totalWallets),
    renderGauge(metrics.walletsByState),
    renderGauge(metrics.activeLeasesByRole),
    renderGauge(metrics.pinnedWallets),
    renderGauge(metrics.queueDepth),
    renderGauge(metrics.queueOldestAgeSecs),
    renderGauge(metrics.capUtilizationPercent),
    renderGauge(metrics.poolCapTotal),
    renderGauge(metrics.oldestLeaseAgeSecs),
    renderGauge(metrics.quarantinedUnexpectedHead),
    renderGauge(metrics.parkedExternalSends),
    renderGauge(metrics.operationsByStatus),
    renderGauge(metrics.operationsOldestAgeSecs),
    renderGauge(metrics.storagePressure),
    renderGauge(metrics.signerLeadershipHeld),
    renderGauge(metrics.haltEngaged),
    renderGauge(metrics.readinessReady),
    renderGauge(metrics.observationDegraded),
    renderGauge(metrics.workerHealth),
    renderGauge(metrics.databaseTruthAvailable),
    renderGauge(metrics.workerHealthAvailable),
    renderGauge(metrics.backupEnabled),
    renderGauge(metrics.backupRunning),
    renderGauge(metrics.backupStatusAvailable),
    renderGauge(metrics.backupLastSuccessAgeSecs),
    renderGauge(metrics.backupLastSuccessAvailable),
    renderGauge(metrics.backupRpoBreached),
    renderGauge(metrics.processResidentMemoryBytes),
    renderGauge(metrics.processHeapUsedBytes),
    renderCounter(metrics.processCpuUserSeconds),
    renderCounter(metrics.processCpuSystemSeconds),
  ];
  return blocks.join("\n\n") + "\n";
}

// ---------------------------------------------------------------------------
// Lifecycle hooks — call-seam instrumentation
// ---------------------------------------------------------------------------

export interface MetricsHooks {
  onOperationCreated(kind: MetricOperationKind): void;
  onOperationCompleted(kind: MetricOperationKind): void;
  onOperationFailed(kind: MetricOperationKind): void;
  onSubmit(outcome: MetricSubmitOutcome): void;
  onT0ReadFailure(): void;
  onObservationAnomaly(kind: MetricAnomalyKind): void;
  onProofBudgetExhaustion(): void;
  onAuth(outcome: MetricAuthOutcome): void;
  onIdempotency(outcome: MetricIdempotencyOutcome): void;
  /** A candidate-intake deposit that never reached the inbox, by producer lane. */
  onCandidateIntakeRefused(
    source: MetricCandidateIntakeSource,
    reason: MetricCandidateIntakeRefusal,
  ): void;
  /** Inbound push VAPID gate outcome (ZTR-1161). */
  onPushVapid(outcome: MetricPushVapidOutcome): void;
  /**
   * Inbound Web Push receive outcome (ZTR-1154). `shape` is the envelope nest that
   * yielded the code on enqueued; pass `"none"` for no_transfer_code / decrypt_failed.
   */
  onPushReceive(outcome: MetricPushReceiveOutcome, shape: MetricPushReceiveShape): void;
  /** Publish the current consecutive no_transfer_code streak gauge. */
  setPushNoTransferCodeStreak(streak: number): void;
  /**
   * Observe a gateway call duration. `rpc` is a closed action name;
   * `outcome` is ok on any non-throwing response (including app-level reject).
   */
  observeGateway(
    rpc: MetricGatewayRpc,
    outcome: MetricGatewayOutcome,
    durationSeconds: number,
  ): void;
  /** Wrap an async gateway call: records duration + outcome without altering bytes. */
  timeGateway<T>(
    rpc: MetricGatewayRpc,
    fn: () => Promise<T>,
  ): Promise<T>;
}

export function createMetricsHooks(metrics: NodeMetrics): MetricsHooks {
  return {
    onOperationCreated(kind) {
      metrics.operationsCreated.inc({ kind });
    },
    onOperationCompleted(kind) {
      metrics.operationsCompleted.inc({ kind });
    },
    onOperationFailed(kind) {
      metrics.operationsFailed.inc({ kind });
    },
    onSubmit(outcome) {
      metrics.submitTotal.inc({ outcome });
    },
    onT0ReadFailure() {
      metrics.t0ReadFailures.inc({});
    },
    onObservationAnomaly(kind) {
      metrics.observationAnomalies.inc({ kind });
    },
    onProofBudgetExhaustion() {
      metrics.proofBudgetExhaustion.inc({});
    },
    onAuth(outcome) {
      metrics.authTotal.inc({ outcome });
    },
    onIdempotency(outcome) {
      metrics.idempotencyTotal.inc({ outcome });
    },
    onCandidateIntakeRefused(source, reason) {
      metrics.candidateIntakeRefused.inc({ source, reason });
    },
    onPushVapid(outcome) {
      metrics.pushVapid.inc({ outcome });
    },
    onPushReceive(outcome, shape) {
      metrics.pushReceiveTotal.inc({ outcome, shape });
    },
    setPushNoTransferCodeStreak(streak) {
      metrics.pushNoTransferCodeStreak.set({}, streak);
    },
    observeGateway(rpc, outcome, durationSeconds) {
      metrics.gatewayRequestDuration.observe({ rpc, outcome }, durationSeconds);
    },
    async timeGateway(rpc, fn) {
      const start = process.hrtime.bigint();
      try {
        const result = await fn();
        const seconds = Number(process.hrtime.bigint() - start) / 1e9;
        metrics.gatewayRequestDuration.observe({ rpc, outcome: "ok" }, seconds);
        return result;
      } catch (err) {
        const seconds = Number(process.hrtime.bigint() - start) / 1e9;
        metrics.gatewayRequestDuration.observe({ rpc, outcome: "error" }, seconds);
        throw err;
      }
    },
  };
}
