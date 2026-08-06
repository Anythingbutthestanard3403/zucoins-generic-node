// Evidence storage budgets, usage metrics, and fail-closed admission.
//
// Governing spec: (Retention);
// (retention and mutability matrix) and mandatory tests #18
// (resource-budget exhaustion can never create a landed verdict) and #20 (retention jobs
// revoke proof access without deleting any permanent row)
// (serialized capture — per-read cost model), (verification-material access and
// retention) and (fail-closed actions); (backpressure) and
// (incident severity — pinned-cap exhaustion pattern).
// Canonical override: landing-path oracle (non-authority).
//
// Invariants this module encodes:
// - Permanent evidence is never deleted. Canonical containers, signature preimages,
// byte-changed observations, and anomaly rows are retained verbatim forever. Neither a
// budget nor a retention window removes a permanent row.
// - Budget exhaustion fails closed: when admitting a new evidence record would push a wallet
// past its per-wallet cap or the node past its node-wide cap, admission is rejected. The
// node surfaces the pressure; it never silently drops or prunes evidence.
// - The retention period governs proof ACCESS only (default: terminal plus 30 days). When the
// window lapses the access surface reports expiry; the underlying bytes remain.
// - Metrics never parse or re-serialize authoritative raw bytes. Collectors feed
// pre-measured byte counts and sizes; this module only aggregates numbers.
//
// Pure logic over abstract usage snapshots. This module asserts no durability and touches no
// store; the durable observer store owns the real byte counts and feeds them in. It sets no
// verdict, releases no lease, and authorizes no retry (non-authority).

const MEBIBYTE = 1024 * 1024;
const GIBIBYTE = 1024 * MEBIBYTE;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

export const DEFAULT_MAX_EVIDENCE_BYTES_PER_WALLET = 256 * MEBIBYTE;
export const DEFAULT_MAX_EVIDENCE_BYTES_TOTAL = 10 * GIBIBYTE;
export const DEFAULT_EVIDENCE_RETENTION_DAYS = 30;

export interface EvidenceStorageBudget {
  readonly maxBytesPerWallet: number;
  readonly maxBytesTotal: number;
  readonly retentionDays: number;
}

export interface EvidenceStorageBudgetOverrides {
  readonly maxBytesPerWallet?: number;
  readonly maxBytesTotal?: number;
  readonly retentionDays?: number;
}

export class EvidenceStorageBudgetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceStorageBudgetError";
  }
}

export function resolveEvidenceStorageBudget(
  overrides: EvidenceStorageBudgetOverrides = {},
): EvidenceStorageBudget {
  const maxBytesPerWallet = overrides.maxBytesPerWallet ?? DEFAULT_MAX_EVIDENCE_BYTES_PER_WALLET;
  const maxBytesTotal = overrides.maxBytesTotal ?? DEFAULT_MAX_EVIDENCE_BYTES_TOTAL;
  const retentionDays = overrides.retentionDays ?? DEFAULT_EVIDENCE_RETENTION_DAYS;

  if (!Number.isFinite(maxBytesPerWallet) || maxBytesPerWallet <= 0) {
    throw new EvidenceStorageBudgetError("maxBytesPerWallet must be a positive finite byte count");
  }
  if (!Number.isFinite(maxBytesTotal) || maxBytesTotal <= 0) {
    throw new EvidenceStorageBudgetError("maxBytesTotal must be a positive finite byte count");
  }
  if (!Number.isFinite(retentionDays) || retentionDays < 0) {
    throw new EvidenceStorageBudgetError("retentionDays must be a non-negative finite number");
  }
  // A single wallet may not be allowed more than the whole node: keep the per-wallet cap the
  // tighter (or equal) bound so the per-wallet check is always the more specific cause.
  if (maxBytesPerWallet > maxBytesTotal) {
    throw new EvidenceStorageBudgetError("maxBytesPerWallet cannot exceed maxBytesTotal");
  }

  return { maxBytesPerWallet, maxBytesTotal, retentionDays };
}

// ── Usage snapshot ────────────────────────────────────────────────────────────
// Breakdown mirrors the per-read cost model in gateway_observations rows (raw bytes),
// observation_anomalies rows (always append), exact retained bodies (lineage_path_bodies /
// retained proof bodies), and consecutive-repeat suppressions (cursor increments that did NOT
// append a row — the cheap path that must be measured separately from appended-row volume).

export interface EvidenceWalletUsage {
  readonly walletId: string;
  /** Total attributed evidence bytes for this wallet (observations + anomalies + bodies). */
  readonly evidenceBytes: number;
  /** Total appended rows (observations + anomalies). Backward-compatible aggregate. */
  readonly recordCount: number;
  readonly observationCount?: number;
  readonly observationBytes?: number;
  readonly anomalyCount?: number;
  readonly anomalyBytes?: number;
  readonly exactBodyCount?: number;
  readonly exactBodyBytes?: number;
  /**
   * Bytes that would have been written had consecutive-repeat dedup not suppressed the write.
   * Measured separately from appended-row volume (consecutive-only dedup key).
   */
  readonly consecutiveRepeatSuppressedCount?: number;
  readonly consecutiveRepeatSuppressedBytes?: number;
}

export interface EvidenceStorageSnapshot {
  readonly wallets: readonly EvidenceWalletUsage[];
  /** Optional index footprint (bytes) — table uniqueness / body indexes. */
  readonly indexBytes?: number;
  /**
   * Epoch-ms of the oldest anomaly or gap not yet resolved by operator action
   * Absent when no unresolved evidence exists.
   */
  readonly oldestUnverifiedEvidenceAtMillis?: number | null;
}

export interface EvidenceWalletMetrics {
  readonly walletId: string;
  readonly evidenceBytes: number;
  readonly recordCount: number;
  readonly observationCount: number;
  readonly observationBytes: number;
  readonly anomalyCount: number;
  readonly anomalyBytes: number;
  readonly exactBodyCount: number;
  readonly exactBodyBytes: number;
  readonly consecutiveRepeatSuppressedCount: number;
  readonly consecutiveRepeatSuppressedBytes: number;
  /** Appended-row volume (observations + anomalies + exact bodies) in bytes. */
  readonly appendedRowBytes: number;
  readonly utilization: number;
  readonly withinBudget: boolean;
}

export interface EvidenceStorageMetrics {
  readonly totalBytes: number;
  readonly totalRecordCount: number;
  readonly totalObservationCount: number;
  readonly totalObservationBytes: number;
  readonly totalAnomalyCount: number;
  readonly totalAnomalyBytes: number;
  readonly totalExactBodyCount: number;
  readonly totalExactBodyBytes: number;
  readonly totalConsecutiveRepeatSuppressedCount: number;
  readonly totalConsecutiveRepeatSuppressedBytes: number;
  /** Sum of observation + anomaly + exact-body bytes (actual storage driver). */
  readonly totalAppendedRowBytes: number;
  readonly indexBytes: number;
  readonly walletCount: number;
  readonly totalUtilization: number;
  readonly withinTotalBudget: boolean;
  readonly perWallet: readonly EvidenceWalletMetrics[];
  /**
   * Age in milliseconds of the oldest unresolved evidence at `nowMillis`, or null when
   * none is reported. Distinct from raw disk usage as a capacity-planning signal.
   */
  readonly oldestUnverifiedEvidenceAgeMs: number | null;
}

function nonNeg(value: number | undefined, label: string): number {
  if (value === undefined) {
    return 0;
  }
  if (!Number.isFinite(value) || value < 0) {
    throw new EvidenceStorageBudgetError(`${label} must be a non-negative finite number`);
  }
  return value;
}

/**
 * Single byte-attribution path shared by metrics and admission so the two never disagree.
 *
 * - Every supplied byte field must be finite and ≥ 0 (fail-closed; NaN / negative throw).
 * - Prefer explicit `evidenceBytes` when > 0.
 * - When `evidenceBytes === 0` but observation/anomaly/exact-body breakdown is present,
 * fall back to the component sum (partial snapshots from collectors that only emit
 * breakdown fields).
 */
function attributedWalletEvidenceBytes(usage: EvidenceWalletUsage): {
  readonly evidenceBytes: number;
  readonly observationBytes: number;
  readonly anomalyBytes: number;
  readonly exactBodyBytes: number;
  readonly componentBytes: number;
} {
  const evidenceBytes = nonNeg(usage.evidenceBytes, "evidenceBytes");
  const observationBytes = nonNeg(usage.observationBytes, "observationBytes");
  const anomalyBytes = nonNeg(usage.anomalyBytes, "anomalyBytes");
  const exactBodyBytes = nonNeg(usage.exactBodyBytes, "exactBodyBytes");
  const componentBytes = observationBytes + anomalyBytes + exactBodyBytes;
  const attributed =
    evidenceBytes > 0 || componentBytes === 0 ? evidenceBytes : componentBytes;
  return {
    evidenceBytes: attributed,
    observationBytes,
    anomalyBytes,
    exactBodyBytes,
    componentBytes,
  };
}

function walletMetricsFromUsage(
  usage: EvidenceWalletUsage,
  budget: EvidenceStorageBudget,
): EvidenceWalletMetrics {
  const observationCount = nonNeg(usage.observationCount, "observationCount");
  const anomalyCount = nonNeg(usage.anomalyCount, "anomalyCount");
  const exactBodyCount = nonNeg(usage.exactBodyCount, "exactBodyCount");
  const consecutiveRepeatSuppressedCount = nonNeg(
    usage.consecutiveRepeatSuppressedCount,
    "consecutiveRepeatSuppressedCount",
  );
  const consecutiveRepeatSuppressedBytes = nonNeg(
    usage.consecutiveRepeatSuppressedBytes,
    "consecutiveRepeatSuppressedBytes",
  );

  const {
    evidenceBytes,
    observationBytes,
    anomalyBytes,
    exactBodyBytes,
  } = attributedWalletEvidenceBytes(usage);

  const recordCount =
    usage.recordCount > 0 || observationCount + anomalyCount === 0
      ? usage.recordCount
      : observationCount + anomalyCount;
  if (!Number.isFinite(recordCount) || recordCount < 0) {
    throw new EvidenceStorageBudgetError("recordCount must be a non-negative finite number");
  }

  return {
    walletId: usage.walletId,
    evidenceBytes,
    recordCount,
    observationCount,
    observationBytes,
    anomalyCount,
    anomalyBytes,
    exactBodyCount,
    exactBodyBytes,
    consecutiveRepeatSuppressedCount,
    consecutiveRepeatSuppressedBytes,
    appendedRowBytes: observationBytes + anomalyBytes + exactBodyBytes,
    utilization: evidenceBytes / budget.maxBytesPerWallet,
    withinBudget: evidenceBytes <= budget.maxBytesPerWallet,
  };
}

export function computeEvidenceStorageMetrics(
  budget: EvidenceStorageBudget,
  snapshot: EvidenceStorageSnapshot,
  nowMillis: number = Date.now(),
): EvidenceStorageMetrics {
  if (!Number.isFinite(nowMillis)) {
    throw new EvidenceStorageBudgetError("nowMillis must be a finite epoch-millisecond value");
  }

  const perWallet = snapshot.wallets.map((usage) => walletMetricsFromUsage(usage, budget));

  const totalBytes = perWallet.reduce((sum, w) => sum + w.evidenceBytes, 0);
  const totalRecordCount = perWallet.reduce((sum, w) => sum + w.recordCount, 0);
  const totalObservationCount = perWallet.reduce((sum, w) => sum + w.observationCount, 0);
  const totalObservationBytes = perWallet.reduce((sum, w) => sum + w.observationBytes, 0);
  const totalAnomalyCount = perWallet.reduce((sum, w) => sum + w.anomalyCount, 0);
  const totalAnomalyBytes = perWallet.reduce((sum, w) => sum + w.anomalyBytes, 0);
  const totalExactBodyCount = perWallet.reduce((sum, w) => sum + w.exactBodyCount, 0);
  const totalExactBodyBytes = perWallet.reduce((sum, w) => sum + w.exactBodyBytes, 0);
  const totalConsecutiveRepeatSuppressedCount = perWallet.reduce(
    (sum, w) => sum + w.consecutiveRepeatSuppressedCount,
    0,
  );
  const totalConsecutiveRepeatSuppressedBytes = perWallet.reduce(
    (sum, w) => sum + w.consecutiveRepeatSuppressedBytes,
    0,
  );
  const totalAppendedRowBytes = perWallet.reduce((sum, w) => sum + w.appendedRowBytes, 0);
  const indexBytes = nonNeg(snapshot.indexBytes, "indexBytes");

  let oldestUnverifiedEvidenceAgeMs: number | null = null;
  const oldestAt = snapshot.oldestUnverifiedEvidenceAtMillis;
  if (oldestAt !== undefined && oldestAt !== null) {
    if (!Number.isFinite(oldestAt)) {
      throw new EvidenceStorageBudgetError(
        "oldestUnverifiedEvidenceAtMillis must be a finite epoch-millisecond value",
      );
    }
    oldestUnverifiedEvidenceAgeMs = Math.max(0, nowMillis - oldestAt);
  }

  // Index footprint is load-bearing storage: totalUtilization and withinTotalBudget
  // include indexBytes so /3 backpressure can consume the production metrics
  // field directly (not a test-local totalBytes+indexBytes sum).
  const accountedBytes = totalBytes + indexBytes;
  return {
    totalBytes,
    totalRecordCount,
    totalObservationCount,
    totalObservationBytes,
    totalAnomalyCount,
    totalAnomalyBytes,
    totalExactBodyCount,
    totalExactBodyBytes,
    totalConsecutiveRepeatSuppressedCount,
    totalConsecutiveRepeatSuppressedBytes,
    totalAppendedRowBytes,
    indexBytes,
    walletCount: snapshot.wallets.length,
    totalUtilization: accountedBytes / budget.maxBytesTotal,
    withinTotalBudget: accountedBytes <= budget.maxBytesTotal,
    perWallet,
    oldestUnverifiedEvidenceAgeMs,
  };
}

// ── Windowed growth rate ──────────────────────────────────────────────────────
// Two ordered snapshots yield a rate (bytes/ms, observations/ms) and a projected
// time-to-capacity. Single-point snapshots cannot produce a rate — callers must supply a
// window. Zero or negative elapsed time fails closed.

export interface EvidenceGrowthSample {
  readonly atMillis: number;
  /**
   * Accounted storage bytes for growth / time-to-capacity projections.
   * Must match load-bearing totalUtilization accounting: evidence rows + indexBytes.
   */
  readonly totalBytes: number;
  readonly totalObservationCount: number;
  readonly totalAnomalyCount: number;
  readonly totalAppendedRowBytes: number;
  /** Index footprint included in totalBytes when built via growthSampleFromMetrics. */
  readonly indexBytes?: number;
}

export interface EvidenceGrowthRate {
  /** Elapsed window in milliseconds (strictly positive). */
  readonly windowMs: number;
  readonly bytesPerMs: number;
  readonly observationsPerMs: number;
  readonly anomaliesPerMs: number;
  readonly appendedRowBytesPerMs: number;
  /**
   * Milliseconds until `maxBytesTotal` is reached at the observed byte rate, or null when
   * the rate is non-positive (no projected exhaustion) or remaining capacity is already ≤ 0
   * (already at/over capacity — reported as 0).
   *
   * Remaining capacity uses the same accounted footprint as totalUtilization
   * (later.totalBytes already includes index when built from growthSampleFromMetrics).
   */
  readonly projectedTimeToCapacityMs: number | null;
}

export function computeEvidenceGrowthRate(
  earlier: EvidenceGrowthSample,
  later: EvidenceGrowthSample,
  budget: EvidenceStorageBudget,
): EvidenceGrowthRate {
  for (const [label, sample] of [
    ["earlier", earlier],
    ["later", later],
  ] as const) {
    if (!Number.isFinite(sample.atMillis)) {
      throw new EvidenceStorageBudgetError(`${label}.atMillis must be finite`);
    }
    if (!Number.isFinite(sample.totalBytes) || sample.totalBytes < 0) {
      throw new EvidenceStorageBudgetError(`${label}.totalBytes must be a non-negative finite number`);
    }
    if (!Number.isFinite(sample.totalObservationCount) || sample.totalObservationCount < 0) {
      throw new EvidenceStorageBudgetError(
        `${label}.totalObservationCount must be a non-negative finite number`,
      );
    }
    if (!Number.isFinite(sample.totalAnomalyCount) || sample.totalAnomalyCount < 0) {
      throw new EvidenceStorageBudgetError(
        `${label}.totalAnomalyCount must be a non-negative finite number`,
      );
    }
    if (!Number.isFinite(sample.totalAppendedRowBytes) || sample.totalAppendedRowBytes < 0) {
      throw new EvidenceStorageBudgetError(
        `${label}.totalAppendedRowBytes must be a non-negative finite number`,
      );
    }
    if (
      sample.indexBytes !== undefined &&
      (!Number.isFinite(sample.indexBytes) || sample.indexBytes < 0)
    ) {
      throw new EvidenceStorageBudgetError(
        `${label}.indexBytes must be a non-negative finite number when provided`,
      );
    }
  }

  const windowMs = later.atMillis - earlier.atMillis;
  if (!(windowMs > 0)) {
    throw new EvidenceStorageBudgetError(
      "growth-rate window requires later.atMillis strictly greater than earlier.atMillis",
    );
  }

  const bytesPerMs = (later.totalBytes - earlier.totalBytes) / windowMs;
  const observationsPerMs =
    (later.totalObservationCount - earlier.totalObservationCount) / windowMs;
  const anomaliesPerMs = (later.totalAnomalyCount - earlier.totalAnomalyCount) / windowMs;
  const appendedRowBytesPerMs =
    (later.totalAppendedRowBytes - earlier.totalAppendedRowBytes) / windowMs;

  let projectedTimeToCapacityMs: number | null;
  // later.totalBytes is the accounted footprint (evidence + index when from metrics).
  const remaining = budget.maxBytesTotal - later.totalBytes;
  if (remaining <= 0) {
    projectedTimeToCapacityMs = 0;
  } else if (!(bytesPerMs > 0)) {
    projectedTimeToCapacityMs = null;
  } else {
    projectedTimeToCapacityMs = remaining / bytesPerMs;
  }

  return {
    windowMs,
    bytesPerMs,
    observationsPerMs,
    anomaliesPerMs,
    appendedRowBytesPerMs,
    projectedTimeToCapacityMs,
  };
}

/**
 * Build a growth sample from already-computed metrics at a known timestamp.
 * totalBytes here is the load-bearing accounted footprint (evidence + index),
 * matching totalUtilization — so time-to-capacity cannot report headroom while
 * index bloat has already exhausted the budget.
 */
export function growthSampleFromMetrics(
  metrics: EvidenceStorageMetrics,
  atMillis: number,
): EvidenceGrowthSample {
  const accountedBytes = metrics.totalBytes + metrics.indexBytes;
  return {
    atMillis,
    totalBytes: accountedBytes,
    totalObservationCount: metrics.totalObservationCount,
    totalAnomalyCount: metrics.totalAnomalyCount,
    totalAppendedRowBytes: metrics.totalAppendedRowBytes,
    indexBytes: metrics.indexBytes,
  };
}

// ── Runtime collector interface (disk / index / write-latency) ────────────────
// These signals require OS or store instrumentation. Layer 1 exposes the typed seam so
// /3 (backpressure / exhaustion tests) can consume a single shape; production
// adapters live outside this pure module. A documented stub returns indeterminate zeros /
// empty percentiles so pure-logic consumers stay testable without a live disk.

export interface WriteLatencyPercentiles {
  readonly p50Ms: number;
  readonly p99Ms: number;
  readonly sampleCount: number;
}

export interface EvidenceRuntimeStorageSignals {
  /** Bytes free on the volume holding the evidence store. */
  readonly diskFreeBytes: number;
  /**
   * Estimated free bytes after accounting for WAL / replication overhead. Must be ≤
   * diskFreeBytes when both are known; collectors that cannot estimate overhead may set
   * this equal to diskFreeBytes.
   */
  readonly diskFreeBytesAfterWalOverhead: number;
  /** Total size of evidence-related indexes (bytes). */
  readonly indexBytes: number;
  readonly writeLatency: WriteLatencyPercentiles;
  /** Collector clock for composing with growth-rate projections. */
  readonly observedAtMillis: number;
}

export interface EvidenceDiskHeadroom {
  readonly diskFreeBytes: number;
  readonly diskFreeBytesAfterWalOverhead: number;
  /**
   * Milliseconds until free-after-WAL is exhausted at the supplied growth rate, or null when
   * the rate is non-positive. 0 when already exhausted.
   */
  readonly projectedTimeToDiskExhaustionMs: number | null;
}

export function computeEvidenceDiskHeadroom(
  signals: EvidenceRuntimeStorageSignals,
  growth: Pick<EvidenceGrowthRate, "bytesPerMs">,
): EvidenceDiskHeadroom {
  const free = signals.diskFreeBytes;
  const freeAfterWal = signals.diskFreeBytesAfterWalOverhead;
  if (!Number.isFinite(free) || free < 0) {
    throw new EvidenceStorageBudgetError("diskFreeBytes must be a non-negative finite number");
  }
  if (!Number.isFinite(freeAfterWal) || freeAfterWal < 0) {
    throw new EvidenceStorageBudgetError(
      "diskFreeBytesAfterWalOverhead must be a non-negative finite number",
    );
  }
  if (freeAfterWal > free) {
    throw new EvidenceStorageBudgetError(
      "diskFreeBytesAfterWalOverhead cannot exceed diskFreeBytes",
    );
  }

  let projectedTimeToDiskExhaustionMs: number | null;
  if (freeAfterWal === 0) {
    projectedTimeToDiskExhaustionMs = 0;
  } else if (!(growth.bytesPerMs > 0)) {
    projectedTimeToDiskExhaustionMs = null;
  } else {
    projectedTimeToDiskExhaustionMs = freeAfterWal / growth.bytesPerMs;
  }

  return {
    diskFreeBytes: free,
    diskFreeBytesAfterWalOverhead: freeAfterWal,
    projectedTimeToDiskExhaustionMs,
  };
}

/**
 * Collector seam for runtime/OS metrics that pure snapshot math cannot produce.
 * Implementations must not parse or re-serialize authoritative raw evidence bytes.
 *
 * `signalKind` provenance:
 * - `"stub"` — zero/empty samples; not a live disk signal.
 * - `"host"` / `"live"` / omitted — latency-window collector provenance only.
 * Production `createProductionStoragePressureWiring` treats a collector alone as
 * non-live for money BP (empty latency ⇒ util 0 under fill). A BP-consumed
 * `diskUtilization` probe is required for a permissive path.
 */
export interface EvidenceRuntimeMetricsCollector {
  collect(): Promise<EvidenceRuntimeStorageSignals>;
  readonly signalKind?: "stub" | "host" | "live";
}

/** Deterministic stub collector for unit tests. Production must not mount this alone. */
export function createStubEvidenceRuntimeMetricsCollector(
  signals: Partial<EvidenceRuntimeStorageSignals> = {},
): EvidenceRuntimeMetricsCollector {
  const baseline: EvidenceRuntimeStorageSignals = {
    diskFreeBytes: signals.diskFreeBytes ?? 0,
    diskFreeBytesAfterWalOverhead:
      signals.diskFreeBytesAfterWalOverhead ?? signals.diskFreeBytes ?? 0,
    indexBytes: signals.indexBytes ?? 0,
    writeLatency: signals.writeLatency ?? { p50Ms: 0, p99Ms: 0, sampleCount: 0 },
    observedAtMillis: signals.observedAtMillis ?? 0,
  };
  return {
    signalKind: "stub",
    collect: async () => baseline,
  };
}

// ── Write-latency → storage-pressure contract (scenario 4) ──────────
// shipped WriteLatencyPercentiles on the collector seam only (no operator
// pressure threshold). This module owns the operator-facing defaults that map
// those percentiles into readiness storage_pressure + money-path backpressure.
// Callers supply the stamp function; this module never imports readiness-state
// (observation ↛ core boundary). Production generic-node mounts
// createWriteLatencyPressureRefresh via createProductionStoragePressureWiring →
// createNodeRuntimeListener.onBeforeEvaluate → readinessHttp.

/**
 * Default absolute p99 (ms) at which write latency is considered pressured.
 * Operator-facing observation default — not a value defined by.
 */
export const DEFAULT_WRITE_LATENCY_P99_PRESSURE_MS = 20;

/**
 * Minimum p99 elevation over a measured baseline (ms) that also trips pressure.
 * Used when a pre-fault baseline is available so slow-path degradation is caught
 * even if absolute p99 stays under the absolute threshold on a fast disk.
 */
export const DEFAULT_WRITE_LATENCY_P99_BASELINE_DELTA_MS = 15;

/**
 * Utilization reading fed to StorageBackpressure when write-latency pressure is
 * active. 0.91 sits at/above the default pressure band (0.9) and below critical
 * (0.95), so refresh refuses new evidence while operations may still be draining.
 * Kept in this module so observation does not import the operator package.
 */
export const WRITE_LATENCY_PRESSURE_UTILIZATION = 0.91;

export interface WriteLatencyPressureThreshold {
  /** Absolute p99 ms that trips pressure when sampleCount > 0. */
  readonly absoluteP99Ms: number;
  /** p99 delta over baseline that trips pressure when both sides have samples. */
  readonly baselineDeltaMs: number;
}

export const DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD: WriteLatencyPressureThreshold = {
  absoluteP99Ms: DEFAULT_WRITE_LATENCY_P99_PRESSURE_MS,
  baselineDeltaMs: DEFAULT_WRITE_LATENCY_P99_BASELINE_DELTA_MS,
};

/**
 * Pure evaluation: does the collector's writeLatency exceed the operator-facing
 * write-latency pressure threshold (absolute p99 and/or baseline delta)?
 */
export function evaluateWriteLatencyPressure(
  current: WriteLatencyPercentiles,
  baseline: WriteLatencyPercentiles | null = null,
  threshold: WriteLatencyPressureThreshold = DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD,
): boolean {
  if (!Number.isFinite(current.p99Ms) || !Number.isFinite(current.p50Ms)) {
    // Indeterminate latency fails closed to pressure.
    return true;
  }
  if (!(current.sampleCount > 0)) {
    return false;
  }
  if (current.p99Ms >= threshold.absoluteP99Ms) {
    return true;
  }
  if (
    baseline !== null &&
    baseline.sampleCount > 0 &&
    Number.isFinite(baseline.p99Ms) &&
    current.p99Ms > baseline.p99Ms + threshold.baselineDeltaMs
  ) {
    return true;
  }
  return false;
}

/**
 * Production adapter: collect write-latency signals and stamp storage pressure via the
 * supplied callback (typically `readiness.setStoragePressure.bind(readiness)`). Returns
 * the pressure boolean the seam computed — callers must not re-derive it.
 */
export async function applyWriteLatencyPressureFromCollector(
  collector: EvidenceRuntimeMetricsCollector,
  setStoragePressure: (pressure: boolean) => void,
  baseline: WriteLatencyPercentiles | null = null,
  threshold: WriteLatencyPressureThreshold = DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD,
): Promise<{ readonly pressure: boolean; readonly signals: EvidenceRuntimeStorageSignals }> {
  const signals = await collector.collect();
  const pressure = evaluateWriteLatencyPressure(signals.writeLatency, baseline, threshold);
  setStoragePressure(pressure);
  return { pressure, signals };
}

export interface WriteLatencyPressureRefreshOptions {
  readonly collector: EvidenceRuntimeMetricsCollector;
  /** Typically `readiness.setStoragePressure.bind(readiness)`. */
  readonly setStoragePressure: (pressure: boolean) => void;
  readonly baseline?: WriteLatencyPercentiles | null;
  readonly threshold?: WriteLatencyPressureThreshold;
  /**
   * Optional side-effect after each stamp (e.g. latch a backpressure sample).
   * Receives the pressure boolean the seam computed — must not re-derive it.
   */
  readonly onPressure?: (pressure: boolean) => void;
}

/**
 * Production refresh handle for readiness / boot loops.
 * Pass the returned function as readinessHttp `onBeforeEvaluate` so every
 * /health/ready probe re-collects write latency and stamps storage_pressure
 * through the same seam tests exercise — not a test-only dead export.
 */
export function createWriteLatencyPressureRefresh(
  options: WriteLatencyPressureRefreshOptions,
): () => Promise<{ readonly pressure: boolean; readonly signals: EvidenceRuntimeStorageSignals }> {
  const baseline = options.baseline ?? null;
  const threshold = options.threshold ?? DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD;
  return async () => {
    const result = await applyWriteLatencyPressureFromCollector(
      options.collector,
      options.setStoragePressure,
      baseline,
      threshold,
    );
    options.onPressure?.(result.pressure);
    return result;
  };
}

/**
 * Map a write-latency pressure boolean into a utilization reading for
 * StorageUtilizationSource / createStorageBackpressure.refresh.
 * Pressured → WRITE_LATENCY_PRESSURE_UTILIZATION (evidence refused);
 * clear → 0 (NORMAL). Combine with disk/index util via Math.max at the call site.
 */
export function utilizationFromWriteLatencyPressure(pressure: boolean): number {
  return pressure ? WRITE_LATENCY_PRESSURE_UTILIZATION : 0;
}

/**
 * Utilization reading from production evidence metrics (includes indexBytes in
 * totalUtilization). Prefer this over hand-built totalBytes+indexBytes sums when
 * wiring StorageUtilizationSource.refresh.
 */
export function utilizationFromEvidenceSnapshot(
  budget: EvidenceStorageBudget,
  snapshot: EvidenceStorageSnapshot,
  nowMillis: number = Date.now(),
): number {
  return computeEvidenceStorageMetrics(budget, snapshot, nowMillis).totalUtilization;
}

// ── Admission ─────────────────────────────────────────────────────────────────

export const EVIDENCE_ADMISSION_REJECTION_REASONS = [
  "WALLET_BUDGET_EXCEEDED",
  "NODE_BUDGET_EXCEEDED",
] as const;

export type EvidenceAdmissionRejectionReason =
  (typeof EVIDENCE_ADMISSION_REJECTION_REASONS)[number];

export interface EvidenceAdmissionRequest {
  readonly walletId: string;
  readonly evidenceBytes: number;
}

export type EvidenceAdmissionResult =
  | { readonly admitted: true }
  | {
      readonly admitted: false;
      readonly reason: EvidenceAdmissionRejectionReason;
      readonly detail: string;
    };

// Fail-closed admission: project the wallet and node byte totals AFTER the incoming record and
// reject when either cap would be exceeded. Holding exactly the cap is still within budget;
// only a strict excess is rejected. This never deletes or prunes existing evidence — it only
// declines to admit new evidence (#18: budget exhaustion can never create
// a landed verdict; it surfaces pressure for operator attention).
export function evaluateEvidenceAdmission(
  budget: EvidenceStorageBudget,
  snapshot: EvidenceStorageSnapshot,
  request: EvidenceAdmissionRequest,
): EvidenceAdmissionResult {
  const incoming = nonNeg(request.evidenceBytes, "evidenceBytes");

  // Attribute every wallet through the same helper metrics uses. Malformed snapshot
  // bytes (NaN / negative / non-finite) throw — fail-closed, never admit on bad usage
  // (#18). Partial breakdown with evidenceBytes:0 falls back to
  // the component sum so admission and computeEvidenceStorageMetrics agree.
  let currentWalletBytes = 0;
  let totalBytes = 0;
  for (const usage of snapshot.wallets) {
    const { evidenceBytes } = attributedWalletEvidenceBytes(usage);
    totalBytes += evidenceBytes;
    if (usage.walletId === request.walletId) {
      currentWalletBytes = evidenceBytes;
    }
  }
  const indexBytes = nonNeg(snapshot.indexBytes, "indexBytes");
  // Node-wide cap accounts for index footprint the same way computeEvidenceStorageMetrics does.
  const accountedBytes = totalBytes + indexBytes;

  if (currentWalletBytes + incoming > budget.maxBytesPerWallet) {
    return {
      admitted: false,
      reason: "WALLET_BUDGET_EXCEEDED",
      detail: `wallet ${request.walletId} would hold ${currentWalletBytes + incoming} bytes, exceeding maxBytesPerWallet (${budget.maxBytesPerWallet})`,
    };
  }

  if (accountedBytes + incoming > budget.maxBytesTotal) {
    return {
      admitted: false,
      reason: "NODE_BUDGET_EXCEEDED",
      detail: `node would hold ${accountedBytes + incoming} bytes (evidence ${totalBytes + incoming} + index ${indexBytes}), exceeding maxBytesTotal (${budget.maxBytesTotal})`,
    };
  }

  return { admitted: true };
}

export interface EvidenceAccessStatus {
  readonly accessExpired: boolean;
  readonly ageDays: number;
}

// The retention window governs proof ACCESS only, never the bytes themselves: when it lapses the
// access surface reports expiry while the underlying evidence stays permanent.
// retentionDays === 0 means access expires immediately; a
// negative retentionDays is rejected at configuration time.
export function evaluateEvidenceAccess(
  budget: EvidenceStorageBudget,
  retainedAtMillis: number,
  nowMillis: number,
): EvidenceAccessStatus {
  if (!Number.isFinite(retainedAtMillis) || !Number.isFinite(nowMillis)) {
    throw new EvidenceStorageBudgetError(
      "retainedAtMillis and nowMillis must be finite epoch-millisecond values",
    );
  }
  const ageDays = (nowMillis - retainedAtMillis) / MS_PER_DAY;
  return {
    accessExpired: ageDays > budget.retentionDays,
    ageDays,
  };
}
