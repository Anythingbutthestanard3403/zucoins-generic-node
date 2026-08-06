// Host / OS runtime metrics for evidence-storage pressure.
//
// Production storage-pressure wiring must not mount a zero-signal stub: empty
// write-latency samples yield no pressure, so evidence/signature writes would
// continue under real disk fill until hard I/O failure. This module supplies
// the live disk probe (statfs) and a host collector that pairs free-byte
// readings with an in-process write-latency window.
//
// (persist-before-irreversible); storage-backpressure fail-closed on
// indeterminate utilization (NaN → CRITICAL).

import { statfs } from "node:fs/promises";

import type {
  EvidenceRuntimeMetricsCollector,
  EvidenceRuntimeStorageSignals,
  WriteLatencyPercentiles,
} from "./storage-budget.js";

// Local copy of utilizationRatio so observation does not import the operator
// package (storage-budget boundary — WRITE_LATENCY_PRESSURE_UTILIZATION note).
function utilizationRatio(used: number, capacity: number): number {
  if (!Number.isFinite(used) || !Number.isFinite(capacity) || capacity <= 0) {
    return Number.NaN;
  }
  return used / capacity;
}

/** Collector provenance used by production fail-closed composition. */
export type EvidenceRuntimeSignalKind = "stub" | "host" | "live";

export interface DiscriminatedEvidenceRuntimeMetricsCollector
  extends EvidenceRuntimeMetricsCollector {
  readonly signalKind: EvidenceRuntimeSignalKind;
}

export function isLiveEvidenceRuntimeCollector(
  collector: EvidenceRuntimeMetricsCollector | null | undefined,
): boolean {
  if (collector === null || collector === undefined) {
    return false;
  }
  const kind = (collector as Partial<DiscriminatedEvidenceRuntimeMetricsCollector>).signalKind;
  // Explicit injectors without a kind tag are treated as live (test/harness).
  return kind !== "stub";
}

/**
 * Live disk utilization for `path` via statfs (blocks used / blocks total).
 * Returns NaN on probe failure so classification fails closed to CRITICAL.
 */
export async function probeStatfsDiskUtilization(path: string): Promise<number> {
  try {
    const stats = await statfs(path);
    const blocks = Number(stats.blocks);
    const bavail = Number(stats.bavail);
    if (!(blocks > 0) || !Number.isFinite(blocks) || !Number.isFinite(bavail) || bavail < 0) {
      return Number.NaN;
    }
    const used = Math.max(0, blocks - bavail);
    return utilizationRatio(used, blocks);
  } catch {
    return Number.NaN;
  }
}

/** Production/default disk-utilization source (statfs on a configured path). */
export function createStatfsDiskUtilization(path: string): () => Promise<number> {
  return () => probeStatfsDiskUtilization(path);
}

export interface HostDiskReading {
  readonly freeBytes: number;
  readonly capacityBytes: number;
  readonly utilization: number;
}

export async function probeStatfsDiskReading(path: string): Promise<HostDiskReading | null> {
  try {
    const stats = await statfs(path);
    const blocks = Number(stats.blocks);
    const bavail = Number(stats.bavail);
    const bsize = Number(stats.bsize);
    if (
      !(blocks > 0) ||
      !(bsize > 0) ||
      !Number.isFinite(blocks) ||
      !Number.isFinite(bavail) ||
      !Number.isFinite(bsize) ||
      bavail < 0
    ) {
      return null;
    }
    const capacityBytes = blocks * bsize;
    const freeBytes = bavail * bsize;
    const used = Math.max(0, blocks - bavail);
    return {
      freeBytes,
      capacityBytes,
      utilization: utilizationRatio(used, blocks),
    };
  } catch {
    return null;
  }
}

const DEFAULT_LATENCY_WINDOW = 256;

export interface HostEvidenceRuntimeMetricsCollectorOptions {
  /** Filesystem path whose volume backs evidence / durable state (statfs target). */
  readonly path: string;
  /** Max write-latency samples retained for p50/p99. */
  readonly latencyWindow?: number;
}

export interface HostEvidenceRuntimeMetricsCollector
  extends DiscriminatedEvidenceRuntimeMetricsCollector {
  readonly signalKind: "host";
  /** Record one durable-write duration (ms) into the rolling latency window. */
  recordWriteMs(ms: number): void;
  snapshotWriteLatency(): WriteLatencyPercentiles;
  readonly path: string;
}

function percentilesFromSamples(samples: readonly number[]): WriteLatencyPercentiles {
  if (samples.length === 0) {
    return { p50Ms: 0, p99Ms: 0, sampleCount: 0 };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const p50 = sorted[Math.floor(sorted.length * 0.5)]!;
  const p99 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.99))]!;
  return { p50Ms: p50, p99Ms: p99, sampleCount: samples.length };
}

/**
 * Live host collector: statfs free-bytes + rolling write-latency samples.
 * Call `recordWriteMs` from evidence/sign persist seams so latency pressure
 * has real samples; disk util remains live even before the first sample.
 */
export function createHostEvidenceRuntimeMetricsCollector(
  options: HostEvidenceRuntimeMetricsCollectorOptions,
): HostEvidenceRuntimeMetricsCollector {
  const path = options.path;
  const window = Math.max(1, options.latencyWindow ?? DEFAULT_LATENCY_WINDOW);
  const samples: number[] = [];

  return {
    signalKind: "host",
    path,
    recordWriteMs(ms: number): void {
      if (!Number.isFinite(ms) || ms < 0) {
        return;
      }
      samples.push(ms);
      if (samples.length > window) {
        samples.splice(0, samples.length - window);
      }
    },
    snapshotWriteLatency(): WriteLatencyPercentiles {
      return percentilesFromSamples(samples);
    },
    collect: async (): Promise<EvidenceRuntimeStorageSignals> => {
      const reading = await probeStatfsDiskReading(path);
      if (reading === null) {
        // Indeterminate disk — report zeros so pure helpers stay well-typed;
        // production diskUtilization path independently fails closed on NaN.
        return {
          diskFreeBytes: 0,
          diskFreeBytesAfterWalOverhead: 0,
          indexBytes: 0,
          writeLatency: percentilesFromSamples(samples),
          observedAtMillis: Date.now(),
        };
      }
      return {
        diskFreeBytes: reading.freeBytes,
        diskFreeBytesAfterWalOverhead: reading.freeBytes,
        indexBytes: 0,
        writeLatency: percentilesFromSamples(samples),
        observedAtMillis: Date.now(),
      };
    },
  };
}
