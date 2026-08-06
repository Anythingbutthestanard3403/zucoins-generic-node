import { describe, expect, it } from "vitest";

import {
  DEFAULT_EVIDENCE_RETENTION_DAYS,
  DEFAULT_MAX_EVIDENCE_BYTES_PER_WALLET,
  DEFAULT_MAX_EVIDENCE_BYTES_TOTAL,
  EvidenceStorageBudgetError,
  WRITE_LATENCY_PRESSURE_UTILIZATION,
  computeEvidenceDiskHeadroom,
  computeEvidenceGrowthRate,
  computeEvidenceStorageMetrics,
  applyWriteLatencyPressureFromCollector,
  createStubEvidenceRuntimeMetricsCollector,
  createWriteLatencyPressureRefresh,
  evaluateEvidenceAccess,
  evaluateEvidenceAdmission,
  evaluateWriteLatencyPressure,
  growthSampleFromMetrics,
  resolveEvidenceStorageBudget,
  utilizationFromEvidenceSnapshot,
  utilizationFromWriteLatencyPressure,
  type EvidenceStorageBudget,
  type EvidenceStorageSnapshot,
  type EvidenceWalletUsage,
} from "../src/observation/index.js";

// Evidence storage budget + metrics tests (node-core rules; the data model;
// the observation rules; the recovery rules).
// Permanent evidence is never deleted: budgets reject new admission when exceeded and the
// retention window governs proof access only. Metrics distinguish consecutive-repeat
// suppression from appended-row volume and never parse/re-serialize raw bytes.

const MS_PER_DAY = 24 * 60 * 60 * 1000;

function budget(overrides: Partial<EvidenceStorageBudget> = {}): EvidenceStorageBudget {
  return {
    maxBytesPerWallet: 100,
    maxBytesTotal: 250,
    retentionDays: 30,
    ...overrides,
  };
}

function snapshot(
  wallets: ReadonlyArray<EvidenceWalletUsage>,
  extras: Partial<Pick<EvidenceStorageSnapshot, "indexBytes" | "oldestUnverifiedEvidenceAtMillis">> = {},
): EvidenceStorageSnapshot {
  return { wallets, ...extras };
}

describe("resolveEvidenceStorageBudget", () => {
  it("fills documented defaults when no overrides are supplied", () => {
    const resolved = resolveEvidenceStorageBudget();
    expect(resolved.maxBytesPerWallet).toBe(DEFAULT_MAX_EVIDENCE_BYTES_PER_WALLET);
    expect(resolved.maxBytesTotal).toBe(DEFAULT_MAX_EVIDENCE_BYTES_TOTAL);
    expect(resolved.retentionDays).toBe(DEFAULT_EVIDENCE_RETENTION_DAYS);
  });

  it("applies supplied overrides", () => {
    const resolved = resolveEvidenceStorageBudget({
      maxBytesPerWallet: 1024,
      maxBytesTotal: 4096,
      retentionDays: 7,
    });
    expect(resolved).toEqual({ maxBytesPerWallet: 1024, maxBytesTotal: 4096, retentionDays: 7 });
  });

  it("accepts a per-wallet cap equal to the node cap", () => {
    expect(() =>
      resolveEvidenceStorageBudget({ maxBytesPerWallet: 500, maxBytesTotal: 500 }),
    ).not.toThrow();
  });

  it("rejects a per-wallet cap larger than the node cap", () => {
    expect(() =>
      resolveEvidenceStorageBudget({ maxBytesPerWallet: 1000, maxBytesTotal: 500 }),
    ).toThrow(EvidenceStorageBudgetError);
  });

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects a non-positive or non-finite maxBytesPerWallet (%s)",
    (value) => {
      expect(() => resolveEvidenceStorageBudget({ maxBytesPerWallet: value })).toThrow(
        EvidenceStorageBudgetError,
      );
    },
  );

  it.each([0, -1, Number.NaN, Number.NEGATIVE_INFINITY])(
    "rejects a non-positive or non-finite maxBytesTotal (%s)",
    (value) => {
      expect(() => resolveEvidenceStorageBudget({ maxBytesTotal: value })).toThrow(
        EvidenceStorageBudgetError,
      );
    },
  );

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects a negative or non-finite retentionDays (%s)",
    (value) => {
      expect(() => resolveEvidenceStorageBudget({ retentionDays: value })).toThrow(
        EvidenceStorageBudgetError,
      );
    },
  );
});

describe("computeEvidenceStorageMetrics", () => {
  it("reports zero usage for an empty snapshot", () => {
    const metrics = computeEvidenceStorageMetrics(budget(), snapshot([]), 0);
    expect(metrics.totalBytes).toBe(0);
    expect(metrics.totalRecordCount).toBe(0);
    expect(metrics.totalObservationCount).toBe(0);
    expect(metrics.totalAnomalyCount).toBe(0);
    expect(metrics.totalExactBodyBytes).toBe(0);
    expect(metrics.totalConsecutiveRepeatSuppressedBytes).toBe(0);
    expect(metrics.totalAppendedRowBytes).toBe(0);
    expect(metrics.indexBytes).toBe(0);
    expect(metrics.walletCount).toBe(0);
    expect(metrics.totalUtilization).toBe(0);
    expect(metrics.withinTotalBudget).toBe(true);
    expect(metrics.oldestUnverifiedEvidenceAgeMs).toBeNull();
    expect(metrics.perWallet).toEqual([]);
  });

  it("computes per-wallet and node-wide usage with utilization percentages", () => {
    const metrics = computeEvidenceStorageMetrics(
      budget({ maxBytesPerWallet: 1000, maxBytesTotal: 2000 }),
      snapshot([
        { walletId: "wallet-a", evidenceBytes: 250, recordCount: 3 },
        { walletId: "wallet-b", evidenceBytes: 500, recordCount: 5 },
      ]),
      0,
    );

    expect(metrics.totalBytes).toBe(750);
    expect(metrics.totalRecordCount).toBe(8);
    expect(metrics.walletCount).toBe(2);
    expect(metrics.totalUtilization).toBeCloseTo(0.375, 10);
    expect(metrics.withinTotalBudget).toBe(true);

    expect(metrics.perWallet[0]).toMatchObject({
      walletId: "wallet-a",
      evidenceBytes: 250,
      recordCount: 3,
      utilization: 0.25,
      withinBudget: true,
    });
    expect(metrics.perWallet[1]).toMatchObject({
      walletId: "wallet-b",
      evidenceBytes: 500,
      recordCount: 5,
      utilization: 0.5,
      withinBudget: true,
    });
  });

  it("separates observation, anomaly, and exact-body counters and byte volumes", () => {
    const metrics = computeEvidenceStorageMetrics(
      budget({ maxBytesPerWallet: 10_000, maxBytesTotal: 20_000 }),
      snapshot(
        [
          {
            walletId: "wallet-a",
            evidenceBytes: 1500,
            recordCount: 12,
            observationCount: 10,
            observationBytes: 1000,
            anomalyCount: 2,
            anomalyBytes: 200,
            exactBodyCount: 3,
            exactBodyBytes: 300,
            consecutiveRepeatSuppressedCount: 50,
            consecutiveRepeatSuppressedBytes: 5000,
          },
        ],
        { indexBytes: 4096 },
      ),
      0,
    );

    expect(metrics.totalObservationCount).toBe(10);
    expect(metrics.totalObservationBytes).toBe(1000);
    expect(metrics.totalAnomalyCount).toBe(2);
    expect(metrics.totalAnomalyBytes).toBe(200);
    expect(metrics.totalExactBodyCount).toBe(3);
    expect(metrics.totalExactBodyBytes).toBe(300);
    expect(metrics.totalAppendedRowBytes).toBe(1500);
    expect(metrics.totalConsecutiveRepeatSuppressedCount).toBe(50);
    expect(metrics.totalConsecutiveRepeatSuppressedBytes).toBe(5000);
    expect(metrics.indexBytes).toBe(4096);
    // totalUtilization includes indexBytes (production accounting, D1).
    expect(metrics.totalUtilization).toBeCloseTo((1500 + 4096) / 20_000, 10);
    expect(metrics.withinTotalBudget).toBe(true);
    expect(metrics.perWallet[0]?.appendedRowBytes).toBe(1500);
    // Suppressed volume is measured separately and does NOT inflate appended-row bytes.
    expect(metrics.totalConsecutiveRepeatSuppressedBytes).toBeGreaterThan(
      metrics.totalAppendedRowBytes,
    );
  });

  it("reports oldest unverified evidence age when a timestamp is supplied", () => {
    const now = 1_000_000;
    const metrics = computeEvidenceStorageMetrics(
      budget(),
      snapshot([], { oldestUnverifiedEvidenceAtMillis: now - 25_000 }),
      now,
    );
    expect(metrics.oldestUnverifiedEvidenceAgeMs).toBe(25_000);
  });

  it("flags a wallet over its per-wallet cap and a node over its total cap", () => {
    const metrics = computeEvidenceStorageMetrics(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 150 }),
      snapshot([
        { walletId: "wallet-a", evidenceBytes: 120, recordCount: 2 },
        { walletId: "wallet-b", evidenceBytes: 40, recordCount: 1 },
      ]),
      0,
    );

    expect(metrics.perWallet[0]?.withinBudget).toBe(false);
    expect(metrics.perWallet[1]?.withinBudget).toBe(true);
    expect(metrics.totalBytes).toBe(160);
    expect(metrics.withinTotalBudget).toBe(false);
  });
});

describe("consecutive-repeat suppressed vs appended-row volume", () => {
  // Exact raw-byte equality is only a consecutive dedup key. A flood of identical
  // responses that are consecutive is cheap (cursor increments only). A flood that varies
  // bytes non-adjacently defeats dedup and drives real storage growth. Metrics must diverge.

  it("diverges under a non-adjacent-repeat flood (appended grows; suppressed stays flat)", () => {
    // Model: each "tick" alternates two distinct payloads so no two consecutive reads match.
    // Every read appends a row (100 bytes). Consecutive-repeat suppressions remain 0.
    const ticks = 20;
    const payloadBytes = 100;
    const appended = ticks * payloadBytes;

    const metrics = computeEvidenceStorageMetrics(
      budget({ maxBytesPerWallet: 1_000_000, maxBytesTotal: 1_000_000 }),
      snapshot([
        {
          walletId: "wallet-a",
          evidenceBytes: appended,
          recordCount: ticks,
          observationCount: ticks,
          observationBytes: appended,
          anomalyCount: 0,
          anomalyBytes: 0,
          exactBodyCount: 0,
          exactBodyBytes: 0,
          consecutiveRepeatSuppressedCount: 0,
          consecutiveRepeatSuppressedBytes: 0,
        },
      ]),
      0,
    );

    expect(metrics.totalAppendedRowBytes).toBe(appended);
    expect(metrics.totalConsecutiveRepeatSuppressedBytes).toBe(0);
    expect(metrics.totalAppendedRowBytes).not.toBe(metrics.totalConsecutiveRepeatSuppressedBytes);
  });

  it("diverges under a consecutive-repeat flood (suppressed grows; appended stays flat)", () => {
    // First read appends 100 bytes; the next 19 identical consecutive reads only bump the
    // cursor (suppressed). Appended volume stays at one row; suppressed tracks the rest.
    const metrics = computeEvidenceStorageMetrics(
      budget({ maxBytesPerWallet: 1_000_000, maxBytesTotal: 1_000_000 }),
      snapshot([
        {
          walletId: "wallet-a",
          evidenceBytes: 100,
          recordCount: 1,
          observationCount: 1,
          observationBytes: 100,
          anomalyCount: 0,
          anomalyBytes: 0,
          exactBodyCount: 0,
          exactBodyBytes: 0,
          consecutiveRepeatSuppressedCount: 19,
          consecutiveRepeatSuppressedBytes: 1900,
        },
      ]),
      0,
    );

    expect(metrics.totalAppendedRowBytes).toBe(100);
    expect(metrics.totalConsecutiveRepeatSuppressedBytes).toBe(1900);
    expect(metrics.totalConsecutiveRepeatSuppressedBytes).toBeGreaterThan(
      metrics.totalAppendedRowBytes,
    );
  });
});

describe("computeEvidenceGrowthRate (windowed)", () => {
  const b = budget({ maxBytesPerWallet: 10_000, maxBytesTotal: 10_000 });

  it("computes bytes/observations per unit time over a window and projects time-to-capacity", () => {
    const earlier = {
      atMillis: 0,
      totalBytes: 1000,
      totalObservationCount: 10,
      totalAnomalyCount: 2,
      totalAppendedRowBytes: 1000,
    };
    const later = {
      atMillis: 1000,
      totalBytes: 3000,
      totalObservationCount: 30,
      totalAnomalyCount: 6,
      totalAppendedRowBytes: 3000,
    };

    const rate = computeEvidenceGrowthRate(earlier, later, b);
    expect(rate.windowMs).toBe(1000);
    expect(rate.bytesPerMs).toBe(2);
    expect(rate.observationsPerMs).toBe(0.02);
    expect(rate.anomaliesPerMs).toBe(0.004);
    expect(rate.appendedRowBytesPerMs).toBe(2);
    // remaining capacity = 10000 - 3000 = 7000; rate 2 bytes/ms → 3500 ms
    expect(rate.projectedTimeToCapacityMs).toBe(3500);
  });

  it("reports null projected time-to-capacity when growth is non-positive", () => {
    const rate = computeEvidenceGrowthRate(
      {
        atMillis: 0,
        totalBytes: 5000,
        totalObservationCount: 5,
        totalAnomalyCount: 0,
        totalAppendedRowBytes: 5000,
      },
      {
        atMillis: 1000,
        totalBytes: 5000,
        totalObservationCount: 5,
        totalAnomalyCount: 0,
        totalAppendedRowBytes: 5000,
      },
      b,
    );
    expect(rate.bytesPerMs).toBe(0);
    expect(rate.projectedTimeToCapacityMs).toBeNull();
  });

  it("reports 0 projected time-to-capacity when already at or over capacity", () => {
    const rate = computeEvidenceGrowthRate(
      {
        atMillis: 0,
        totalBytes: 9000,
        totalObservationCount: 1,
        totalAnomalyCount: 0,
        totalAppendedRowBytes: 9000,
      },
      {
        atMillis: 1000,
        totalBytes: 10_500,
        totalObservationCount: 2,
        totalAnomalyCount: 0,
        totalAppendedRowBytes: 10_500,
      },
      b,
    );
    expect(rate.projectedTimeToCapacityMs).toBe(0);
  });

  it("rejects a non-positive window (single-point is not a growth rate)", () => {
    const sample = {
      atMillis: 100,
      totalBytes: 1,
      totalObservationCount: 1,
      totalAnomalyCount: 0,
      totalAppendedRowBytes: 1,
    };
    expect(() => computeEvidenceGrowthRate(sample, sample, b)).toThrow(EvidenceStorageBudgetError);
  });

  it("builds a growth sample from computed metrics with index-inclusive accounted bytes", () => {
    const metrics = computeEvidenceStorageMetrics(
      b,
      snapshot(
        [
          {
            walletId: "w",
            evidenceBytes: 400,
            recordCount: 4,
            observationCount: 3,
            observationBytes: 300,
            anomalyCount: 1,
            anomalyBytes: 100,
            exactBodyCount: 0,
            exactBodyBytes: 0,
          },
        ],
        { indexBytes: 150 },
      ),
      0,
    );
    expect(growthSampleFromMetrics(metrics, 42)).toEqual({
      atMillis: 42,
      // totalBytes is accounted footprint (evidence + index), matching totalUtilization.
      totalBytes: 550,
      totalObservationCount: 3,
      totalAnomalyCount: 1,
      totalAppendedRowBytes: 400,
      indexBytes: 150,
    });
  });

  it("projects time-to-capacity from index-inclusive remaining (no false headroom)", () => {
    const tight = budget({ maxBytesPerWallet: 1_000, maxBytesTotal: 1_000 });
    const earlier = growthSampleFromMetrics(
      computeEvidenceStorageMetrics(
        tight,
        snapshot([{ walletId: "w", evidenceBytes: 100, recordCount: 1 }], { indexBytes: 100 }),
        0,
      ),
      0,
    );
    const later = growthSampleFromMetrics(
      computeEvidenceStorageMetrics(
        tight,
        snapshot([{ walletId: "w", evidenceBytes: 100, recordCount: 1 }], { indexBytes: 950 }),
        0,
      ),
      1_000,
    );
    // accounted later = 1050 > maxBytesTotal 1000 → already over capacity
    expect(later.totalBytes).toBe(1_050);
    const rate = computeEvidenceGrowthRate(earlier, later, tight);
    expect(rate.projectedTimeToCapacityMs).toBe(0);
  });
});

describe("runtime collector seam (disk headroom, index, write latency)", () => {
  it("exposes a stub collector with disk / index / write-latency signals", async () => {
    const collector = createStubEvidenceRuntimeMetricsCollector({
      diskFreeBytes: 8_000,
      diskFreeBytesAfterWalOverhead: 6_000,
      indexBytes: 512,
      writeLatency: { p50Ms: 2, p99Ms: 15, sampleCount: 100 },
      observedAtMillis: 999,
    });
    const signals = await collector.collect();
    expect(signals.diskFreeBytes).toBe(8_000);
    expect(signals.diskFreeBytesAfterWalOverhead).toBe(6_000);
    expect(signals.indexBytes).toBe(512);
    expect(signals.writeLatency).toEqual({ p50Ms: 2, p99Ms: 15, sampleCount: 100 });
    expect(signals.observedAtMillis).toBe(999);
  });

  it("projects disk headroom against a windowed growth rate (WAL-aware)", () => {
    const headroom = computeEvidenceDiskHeadroom(
      {
        diskFreeBytes: 10_000,
        diskFreeBytesAfterWalOverhead: 8_000,
        indexBytes: 0,
        writeLatency: { p50Ms: 0, p99Ms: 0, sampleCount: 0 },
        observedAtMillis: 0,
      },
      { bytesPerMs: 2 },
    );
    expect(headroom.diskFreeBytes).toBe(10_000);
    expect(headroom.diskFreeBytesAfterWalOverhead).toBe(8_000);
    // 8000 free-after-WAL / 2 bytes/ms = 4000 ms
    expect(headroom.projectedTimeToDiskExhaustionMs).toBe(4000);
  });

  it("reports null disk-exhaustion projection when growth is non-positive", () => {
    const headroom = computeEvidenceDiskHeadroom(
      {
        diskFreeBytes: 1000,
        diskFreeBytesAfterWalOverhead: 1000,
        indexBytes: 0,
        writeLatency: { p50Ms: 0, p99Ms: 0, sampleCount: 0 },
        observedAtMillis: 0,
      },
      { bytesPerMs: 0 },
    );
    expect(headroom.projectedTimeToDiskExhaustionMs).toBeNull();
  });

  it("rejects WAL overhead exceeding free bytes", () => {
    expect(() =>
      computeEvidenceDiskHeadroom(
        {
          diskFreeBytes: 100,
          diskFreeBytesAfterWalOverhead: 200,
          indexBytes: 0,
          writeLatency: { p50Ms: 0, p99Ms: 0, sampleCount: 0 },
          observedAtMillis: 0,
        },
        { bytesPerMs: 1 },
      ),
    ).toThrow(EvidenceStorageBudgetError);
  });
});

describe("evaluateEvidenceAdmission (fail closed)", () => {
  it("admits evidence that fits both the per-wallet and node-wide caps", () => {
    const result = evaluateEvidenceAdmission(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
      snapshot([{ walletId: "wallet-a", evidenceBytes: 50, recordCount: 1 }]),
      { walletId: "wallet-a", evidenceBytes: 40 },
    );
    expect(result).toEqual({ admitted: true });
  });

  it("admits evidence that brings a wallet exactly to its cap", () => {
    const result = evaluateEvidenceAdmission(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
      snapshot([{ walletId: "wallet-a", evidenceBytes: 80, recordCount: 1 }]),
      { walletId: "wallet-a", evidenceBytes: 20 },
    );
    expect(result).toEqual({ admitted: true });
  });

  it("admits evidence for a wallet with no prior usage", () => {
    const result = evaluateEvidenceAdmission(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
      snapshot([{ walletId: "wallet-a", evidenceBytes: 10, recordCount: 1 }]),
      { walletId: "wallet-b", evidenceBytes: 90 },
    );
    expect(result).toEqual({ admitted: true });
  });

  it("rejects with WALLET_BUDGET_EXCEEDED when the per-wallet cap would be exceeded", () => {
    const result = evaluateEvidenceAdmission(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
      snapshot([{ walletId: "wallet-a", evidenceBytes: 90, recordCount: 1 }]),
      { walletId: "wallet-a", evidenceBytes: 20 },
    );
    expect(result.admitted).toBe(false);
    if (!result.admitted) {
      expect(result.reason).toBe("WALLET_BUDGET_EXCEEDED");
      expect(result.detail).toContain("wallet-a");
    }
  });

  it("rejects with NODE_BUDGET_EXCEEDED when only the node-wide cap would be exceeded", () => {
    // Per-wallet cap (100) holds for each wallet, but the node cap (150) is the binding bound.
    const result = evaluateEvidenceAdmission(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 150 }),
      snapshot([
        { walletId: "wallet-a", evidenceBytes: 70, recordCount: 1 },
        { walletId: "wallet-b", evidenceBytes: 70, recordCount: 1 },
      ]),
      { walletId: "wallet-a", evidenceBytes: 20 },
    );
    expect(result.admitted).toBe(false);
    if (!result.admitted) {
      expect(result.reason).toBe("NODE_BUDGET_EXCEEDED");
    }
  });

  it("never mutates the snapshot when rejecting (evidence is never deleted)", () => {
    const usage = snapshot([
      { walletId: "wallet-a", evidenceBytes: 90, recordCount: 1 },
      { walletId: "wallet-b", evidenceBytes: 90, recordCount: 1 },
    ]);
    const before = JSON.stringify(usage);
    evaluateEvidenceAdmission(budget({ maxBytesPerWallet: 100, maxBytesTotal: 150 }), usage, {
      walletId: "wallet-a",
      evidenceBytes: 50,
    });
    expect(JSON.stringify(usage)).toBe(before);
  });

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY])(
    "fails closed on a non-finite or negative incoming size (%s)",
    (value) => {
      expect(() =>
        evaluateEvidenceAdmission(budget(), snapshot([]), {
          walletId: "wallet-a",
          evidenceBytes: value,
        }),
      ).toThrow(EvidenceStorageBudgetError);
    },
  );

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY])(
    "fails closed on non-finite or negative snapshot wallet evidenceBytes (%s)",
    (value) => {
      expect(() =>
        evaluateEvidenceAdmission(
          budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
          snapshot([{ walletId: "wallet-a", evidenceBytes: value, recordCount: 1 }]),
          { walletId: "wallet-a", evidenceBytes: 10 },
        ),
      ).toThrow(EvidenceStorageBudgetError);
    },
  );

  it("rejects when partial breakdown under-reports evidenceBytes:0 but components exceed cap", () => {
    // Metrics path falls back to observation+anomaly+exactBody sum; admission must too.
    const usage = snapshot([
      {
        walletId: "wallet-a",
        evidenceBytes: 0,
        recordCount: 0,
        observationBytes: 5000,
        observationCount: 1,
      },
    ]);
    const metrics = computeEvidenceStorageMetrics(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
      usage,
    );
    expect(metrics.totalBytes).toBe(5000);
    expect(metrics.withinTotalBudget).toBe(false);

    const result = evaluateEvidenceAdmission(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
      usage,
      { walletId: "wallet-a", evidenceBytes: 50 },
    );
    expect(result.admitted).toBe(false);
    if (!result.admitted) {
      expect(result.reason).toBe("WALLET_BUDGET_EXCEEDED");
    }
  });

  it("rejects zero-byte admit when wallet is already over cap via breakdown fallback", () => {
    const result = evaluateEvidenceAdmission(
      budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
      snapshot([
        {
          walletId: "wallet-a",
          evidenceBytes: 0,
          recordCount: 0,
          observationBytes: 150,
          observationCount: 1,
        },
      ]),
      { walletId: "wallet-a", evidenceBytes: 0 },
    );
    expect(result.admitted).toBe(false);
  });

  it("fails closed when a peer wallet in the snapshot has non-finite bytes", () => {
    expect(() =>
      evaluateEvidenceAdmission(
        budget({ maxBytesPerWallet: 100, maxBytesTotal: 250 }),
        snapshot([
          { walletId: "wallet-a", evidenceBytes: 10, recordCount: 1 },
          { walletId: "wallet-b", evidenceBytes: Number.NaN, recordCount: 1 },
        ]),
        { walletId: "wallet-a", evidenceBytes: 5 },
      ),
    ).toThrow(EvidenceStorageBudgetError);
  });
});

describe("evaluateEvidenceAccess (retention governs access only)", () => {
  const now = 100 * MS_PER_DAY;

  it("reports access open within the retention window", () => {
    const status = evaluateEvidenceAccess(budget({ retentionDays: 30 }), now - 10 * MS_PER_DAY, now);
    expect(status.accessExpired).toBe(false);
    expect(status.ageDays).toBeCloseTo(10, 10);
  });

  it("reports access expired beyond the retention window", () => {
    const status = evaluateEvidenceAccess(budget({ retentionDays: 30 }), now - 31 * MS_PER_DAY, now);
    expect(status.accessExpired).toBe(true);
    expect(status.ageDays).toBeCloseTo(31, 10);
  });

  it("treats retentionDays === 0 as immediate access expiry for any positive age", () => {
    const status = evaluateEvidenceAccess(budget({ retentionDays: 0 }), now - 1, now);
    expect(status.accessExpired).toBe(true);
  });

  it("keeps access open at exactly the retention boundary", () => {
    const status = evaluateEvidenceAccess(
      budget({ retentionDays: 30 }),
      now - 30 * MS_PER_DAY,
      now,
    );
    expect(status.accessExpired).toBe(false);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects non-finite timestamps (%s)",
    (value) => {
      expect(() => evaluateEvidenceAccess(budget(), value, now)).toThrow(
        EvidenceStorageBudgetError,
      );
    },
  );
});


describe("write-latency pressure contract (operator thresholds → readiness + BP)", () => {
  it("trips on absolute p99 threshold", () => {
    expect(
      evaluateWriteLatencyPressure({ p50Ms: 5, p99Ms: 25, sampleCount: 20 }),
    ).toBe(true);
    expect(
      evaluateWriteLatencyPressure({ p50Ms: 1, p99Ms: 5, sampleCount: 20 }),
    ).toBe(false);
  });

  it("trips on baseline delta even when absolute p99 is under threshold", () => {
    const baseline = { p50Ms: 1, p99Ms: 2, sampleCount: 10 };
    const elevated = { p50Ms: 2, p99Ms: 18, sampleCount: 10 }; // <20 absolute, >2+15 delta
    expect(evaluateWriteLatencyPressure(elevated, baseline)).toBe(true);
    expect(
      evaluateWriteLatencyPressure({ p50Ms: 1, p99Ms: 10, sampleCount: 10 }, baseline),
    ).toBe(false);
  });

  it("fails closed on non-finite latency; ignores empty samples", () => {
    expect(
      evaluateWriteLatencyPressure({ p50Ms: 1, p99Ms: Number.NaN, sampleCount: 5 }),
    ).toBe(true);
    expect(
      evaluateWriteLatencyPressure({ p50Ms: 1, p99Ms: 100, sampleCount: 0 }),
    ).toBe(false);
  });

  it("applyWriteLatencyPressureFromCollector stamps via production callback", async () => {
    const stamps: boolean[] = [];
    const collector = createStubEvidenceRuntimeMetricsCollector({
      writeLatency: { p50Ms: 5, p99Ms: 40, sampleCount: 12 },
    });
    const result = await applyWriteLatencyPressureFromCollector(
      collector,
      (p) => {
        stamps.push(p);
      },
    );
    expect(result.pressure).toBe(true);
    expect(stamps).toEqual([true]);
    expect(result.signals.writeLatency.p99Ms).toBe(40);
  });

  it("createWriteLatencyPressureRefresh is the readiness onBeforeEvaluate seam", async () => {
    const stamps: boolean[] = [];
    const pressureEvents: boolean[] = [];
    const collector = createStubEvidenceRuntimeMetricsCollector({
      writeLatency: { p50Ms: 8, p99Ms: 50, sampleCount: 20 },
    });
    const refresh = createWriteLatencyPressureRefresh({
      collector,
      setStoragePressure: (p) => {
        stamps.push(p);
      },
      onPressure: (p) => {
        pressureEvents.push(p);
      },
    });
    const result = await refresh();
    expect(result.pressure).toBe(true);
    expect(stamps).toEqual([true]);
    expect(pressureEvents).toEqual([true]);
    expect(utilizationFromWriteLatencyPressure(true)).toBe(WRITE_LATENCY_PRESSURE_UTILIZATION);
    expect(utilizationFromWriteLatencyPressure(false)).toBe(0);
  });
});

describe("utilizationFromEvidenceSnapshot (index-inclusive)", () => {
  it("matches computeEvidenceStorageMetrics.totalUtilization including index", () => {
    const snap = snapshot(
      [{ walletId: "w", evidenceBytes: 100, recordCount: 1 }],
      { indexBytes: 900 },
    );
    const b = budget({ maxBytesTotal: 1000, maxBytesPerWallet: 1000 });
    const util = utilizationFromEvidenceSnapshot(b, snap, 0);
    expect(util).toBe(1);
    expect(computeEvidenceStorageMetrics(b, snap, 0).totalUtilization).toBe(util);
  });

  it("admission rejects when index pushes node over maxBytesTotal", () => {
    const result = evaluateEvidenceAdmission(
      budget({ maxBytesPerWallet: 10_000, maxBytesTotal: 1_000 }),
      snapshot(
        [{ walletId: "wallet-a", evidenceBytes: 100, recordCount: 1 }],
        { indexBytes: 900 },
      ),
      { walletId: "wallet-a", evidenceBytes: 50 },
    );
    expect(result.admitted).toBe(false);
    if (!result.admitted) {
      expect(result.reason).toBe("NODE_BUDGET_EXCEEDED");
      expect(result.detail).toMatch(/index/);
    }
  });
});
