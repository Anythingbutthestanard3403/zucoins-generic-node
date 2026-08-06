// live host disk / write-latency collector seams.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  createHostEvidenceRuntimeMetricsCollector,
  createStatfsDiskUtilization,
  isLiveEvidenceRuntimeCollector,
  probeStatfsDiskReading,
  probeStatfsDiskUtilization,
} from "./host-runtime-metrics.js";
import { createStubEvidenceRuntimeMetricsCollector } from "./storage-budget.js";

describe("host-runtime-metrics", () => {
  it("stub is not live; host collector is live; untagged inject is live", () => {
    expect(isLiveEvidenceRuntimeCollector(createStubEvidenceRuntimeMetricsCollector())).toBe(
      false,
    );
    expect(
      isLiveEvidenceRuntimeCollector(
        createHostEvidenceRuntimeMetricsCollector({ path: process.cwd() }),
      ),
    ).toBe(true);
    expect(
      isLiveEvidenceRuntimeCollector({
        collect: async () => ({
          diskFreeBytes: 1,
          diskFreeBytesAfterWalOverhead: 1,
          indexBytes: 0,
          writeLatency: { p50Ms: 0, p99Ms: 0, sampleCount: 0 },
          observedAtMillis: 0,
        }),
      }),
    ).toBe(true);
    expect(isLiveEvidenceRuntimeCollector(undefined)).toBe(false);
  });

  it("statfs probe returns finite utilization for a real path", async () => {
    const dir = mkdtempSync(join(tmpdir(), "host-runtime-metrics-disk-"));
    try {
      const util = await probeStatfsDiskUtilization(dir);
      expect(Number.isFinite(util)).toBe(true);
      expect(util).toBeGreaterThanOrEqual(0);
      // Should not trip the pressure band on a normal temp volume in CI/dev.
      expect(util).toBeLessThan(1.5);

      const reading = await probeStatfsDiskReading(dir);
      expect(reading).not.toBeNull();
      expect(reading!.capacityBytes).toBeGreaterThan(0);
      expect(reading!.freeBytes).toBeGreaterThanOrEqual(0);
      // Internal consistency is exact-ish (same statfs call, float rounding only)…
      expect(reading!.utilization).toBeCloseTo(1 - reading!.freeBytes / reading!.capacityBytes, 12);
      // …but the pair of independent statfs calls races real disk activity, the same
      // reason the wired probe below is held to 5 dp.
      expect(reading!.utilization).toBeCloseTo(util, 5);

      const wired = createStatfsDiskUtilization(dir);
      // Second probe may differ slightly under concurrent FS activity; 5 dp is enough.
      await expect(wired()).resolves.toBeCloseTo(util, 5);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("statfs probe fails closed (NaN) on a nonsensical path", async () => {
    const util = await probeStatfsDiskUtilization(
      "/nonexistent/fixture-path-that-must-not-exist-" + Date.now(),
    );
    expect(Number.isNaN(util)).toBe(true);
    expect(await probeStatfsDiskReading("/nonexistent/fixture-" + Date.now())).toBeNull();
  });

  it("host collector exposes free bytes and rolling write-latency samples", async () => {
    const dir = mkdtempSync(join(tmpdir(), "host-runtime-metrics-host-"));
    try {
      const collector = createHostEvidenceRuntimeMetricsCollector({
        path: dir,
        latencyWindow: 8,
      });
      expect(collector.signalKind).toBe("host");
      expect(collector.snapshotWriteLatency().sampleCount).toBe(0);

      collector.recordWriteMs(2);
      collector.recordWriteMs(4);
      collector.recordWriteMs(40);
      expect(collector.snapshotWriteLatency().sampleCount).toBe(3);
      expect(collector.snapshotWriteLatency().p99Ms).toBe(40);

      const signals = await collector.collect();
      expect(signals.diskFreeBytes).toBeGreaterThan(0);
      expect(signals.writeLatency.sampleCount).toBe(3);
      expect(signals.writeLatency.p99Ms).toBe(40);
      expect(signals.observedAtMillis).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
