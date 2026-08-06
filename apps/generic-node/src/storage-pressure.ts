// Production write-latency → readiness + backpressure.
//
// Mount path (always-on):
//   main → createProductionStoragePressureWiring(readiness, live host probes)
//       → createNodeRuntimeListener({ onBeforeEvaluate, storageBackpressure })
//       → createHealthRouter({ onBeforeEvaluate })
//       → readinessHttp.onBeforeEvaluate (node-core)
//
// storage_pressure stays non-gating on the ready verdict. Money fail-closed
// is the StorageBackpressure gate, whose utilization source combines write-latency
// pressure with disk util via Math.max.
//
// Production must NOT mount a zero-signal path that looks healthy. Empty
// write-latency samples yield util 0 (NORMAL). A host/live/untagged collector alone
// is therefore NOT a permissive live signal — BP only treats an explicit
// `diskUtilization` probe (Math.max'd with latency) as live. Without that probe the
// BP source returns NaN → CRITICAL. main.ts wires statfs + host collector.

import {
  createStorageBackpressure,
  createStubEvidenceRuntimeMetricsCollector,
  createWriteLatencyPressureRefresh,
  utilizationFromWriteLatencyPressure,
  type EvidenceRuntimeMetricsCollector,
  type StorageBackpressure,
  type WriteLatencyPercentiles,
  type WriteLatencyPressureThreshold,
} from "@zucoins/node-core";

import type { NodeReadiness } from "./boot/readiness.js";

/** Early-alert reasons for storage-pressure operator signals. */
export type StoragePressureAlertReason =
  | "missing_live_signal"
  | "indeterminate_disk"
  | "pressure"
  | "critical";

export interface StoragePressureAlertEvent {
  readonly reason: StoragePressureAlertReason;
  readonly utilization: number;
  readonly pressure: boolean;
  readonly atMillis: number;
}

export interface ProductionStoragePressureWiringOptions {
  readonly readiness: NodeReadiness;
  /**
   * Runtime metrics collector (write-latency window). When omitted, a stub is used
   * only as a typed placeholder. Collector presence alone never opens admission —
   * production requires `diskUtilization` or the BP gate fails closed.
   */
  readonly collector?: EvidenceRuntimeMetricsCollector;
  /**
   * Live disk/index utilization reading (0..1+). Combined with write-latency
   * util via Math.max. Required for a permissive production path; omission
   * fails closed even when a host/live collector is mounted (host collect() disk
   * bytes are not consumed by the BP source unless promoted here).
   */
  readonly diskUtilization?: () => Promise<number>;
  readonly baseline?: WriteLatencyPercentiles | null;
  readonly threshold?: WriteLatencyPressureThreshold;
  /**
   * Early operator alert on missing live signal, indeterminate disk, or
   * pressure/critical bands (P1/P0 storage_pressure posture).
   */
  readonly onEarlyAlert?: (event: StoragePressureAlertEvent) => void;
}

export interface ProductionStoragePressureWiring {
  /**
   * Pass to createNodeRuntimeListener / createHealthRouter as onBeforeEvaluate.
   * Return type is void-compatible with HealthRouteDeps; pressure is stamped
   * onto readiness + BP as a side effect.
   */
  readonly onBeforeEvaluate: () => Promise<void>;
  /**
   * Same refresh, exposing the pressure boolean for tests / callers that need
   * the seam result without re-deriving it.
   */
  readonly refresh: () => Promise<{ readonly pressure: boolean }>;
  /** Live storage gate — money engines consult canAcceptEvidence / refresh. */
  readonly storageBackpressure: StorageBackpressure;
  readonly collector: EvidenceRuntimeMetricsCollector;
  /** True when a BP-consumed diskUtilization probe is mounted. */
  readonly hasLiveSignal: boolean;
}

function classifyAlert(
  utilization: number,
  pressure: boolean,
  hasLiveSignal: boolean,
): StoragePressureAlertReason | null {
  if (!hasLiveSignal) {
    return "missing_live_signal";
  }
  if (!Number.isFinite(utilization) || utilization < 0) {
    return "indeterminate_disk";
  }
  if (utilization >= 0.95) {
    return "critical";
  }
  if (pressure || utilization >= 0.9) {
    return "pressure";
  }
  return null;
}

/**
 * Production composition for write-latency + disk pressure.
 * Always constructs the readiness refresh + BP gate; callers must mount
 * `onBeforeEvaluate` on the health surface (createNodeRuntimeListener).
 *
 * Fail-closed without live signal: BP utilization = NaN → CRITICAL band.
 */
export function createProductionStoragePressureWiring(
  options: ProductionStoragePressureWiringOptions,
): ProductionStoragePressureWiring {
  const readiness = options.readiness;
  const collector = options.collector ?? createStubEvidenceRuntimeMetricsCollector();
  const diskUtilization = options.diskUtilization;
  const onEarlyAlert = options.onEarlyAlert;
  // Attack review: host/live/untagged collectors alone are NOT live for
  // money BP. Empty latency ⇒ util 0 ⇒ NORMAL under disk fill; collect() free
  // bytes are dead data unless diskUtilization is mounted and Math.max'd below.
  const hasLiveSignal = diskUtilization !== undefined;

  const emitAlert = (utilization: number, pressure: boolean): void => {
    if (onEarlyAlert === undefined) {
      return;
    }
    const reason = classifyAlert(utilization, pressure, hasLiveSignal);
    if (reason === null) {
      return;
    }
    onEarlyAlert({
      reason,
      utilization,
      pressure,
      atMillis: Date.now(),
    });
  };

  const storageBackpressure = createStorageBackpressure({
    source: {
      utilization: async () => {
        // no BP-consumed disk probe → indeterminate → NaN → CRITICAL.
        // Collector tags alone do not open (host/empty-latency was fail-open).
        if (diskUtilization === undefined) {
          return Number.NaN;
        }
        const latencyUtil = utilizationFromWriteLatencyPressure(
          readiness.core.snapshot().storagePressure,
        );
        let diskUtil = Number.NaN;
        try {
          diskUtil = await diskUtilization();
        } catch {
          diskUtil = Number.NaN;
        }
        return Math.max(latencyUtil, diskUtil);
      },
    },
  });

  const latencyRefresh = createWriteLatencyPressureRefresh({
    collector,
    setStoragePressure: (pressure) => {
      readiness.setStoragePressure(pressure);
    },
    baseline: options.baseline ?? null,
    threshold: options.threshold,
  });

  const refresh = async (): Promise<{ readonly pressure: boolean }> => {
    if (diskUtilization === undefined) {
      // Fail closed: stamp pressure + CRITICAL util so money engines refuse
      // before any irreversible boundary without a live metric source.
      readiness.setStoragePressure(true);
      storageBackpressure.recordGlobalSample(Number.NaN);
      emitAlert(Number.NaN, true);
      return { pressure: true };
    }
    const result = await latencyRefresh();
    let util = utilizationFromWriteLatencyPressure(result.pressure);
    try {
      const diskUtil = await diskUtilization();
      util = Math.max(util, diskUtil);
    } catch {
      util = Number.NaN;
    }
    // Combined latency × disk util drives the money BP gate (Math.max).
    storageBackpressure.recordGlobalSample(util);
    emitAlert(util, result.pressure || !Number.isFinite(util) || util >= 0.9);
    return { pressure: result.pressure };
  };

  return {
    onBeforeEvaluate: async () => {
      await refresh();
    },
    refresh,
    storageBackpressure,
    collector,
    hasLiveSignal,
  };
}
