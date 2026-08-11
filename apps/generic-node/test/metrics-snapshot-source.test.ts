// endpoint-transition tests for the production /metrics snapshot source.
//
// Covers the reported defect directly: readinessReady must reflect the real
// readiness verdict (schema ∧ db ∧ vault ∧ observation) instead of a
// hard-coded 0, DB-truth counters must come from the DB rather than
// emptyOperationalSnapshot(), and a DB outage must degrade to a stamps-only
// snapshot rather than throwing out of the scrape (createMetricsRoute's
// handler has no .catch — an unhandled rejection there would hang the
// response).

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CachedDbProbe,
  METRICS_SNAPSHOT_STATEMENTS,
  type MetricsSqlExecutor,
  type ReadinessStateInputs,
} from "@zucoins/node-core";

import { createProductionMetricsSnapshotSource } from "../src/metrics/snapshot-source.js";

const EMPTY_ROWS_DB: MetricsSqlExecutor = {
  async query(text) {
    if (text === METRICS_SNAPSHOT_STATEMENTS.QUEUE_DEPTH_AND_OLDEST_AGE) {
      return { rows: [{ depth: 0, oldest_age_secs: 0 }] };
    }
    if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_AVAILABLE_WALLETS) {
      return { rows: [{ available_count: 0 }] };
    }
    if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_QUARANTINED_UNEXPECTED_HEAD) {
      return { rows: [{ wallets: 0 }] };
    }
    return { rows: [] };
  },
};

function readyState(overrides: Partial<ReadinessStateInputs> = {}): ReadinessStateInputs {
  return {
    schemaMigrated: true,
    vaultKeyRingLoaded: true,
    vaultCensusVerified: true,
    observationReadCapable: true,
    restoreHoldClear: true,
    leadershipLockHeld: true,
    eventSignerAvailable: true,
    halted: false,
    storagePressure: false,
    stopping: false,
    observationDegraded: false,
    ...overrides,
  };
}

describe("createProductionMetricsSnapshotSource — readinessReady transitions", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("coalesces concurrent scrapes into one seven-query census", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    let queryCalls = 0;
    let releaseFirstQuery!: () => void;
    const firstQueryGate = new Promise<void>((resolve) => {
      releaseFirstQuery = resolve;
    });
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: {
        async query(text) {
          queryCalls += 1;
          if (queryCalls === 1) await firstQueryGate;
          return EMPTY_ROWS_DB.query(text);
        },
      },
      poolCapTotal: 10,
    });

    const first = source();
    const concurrent = source();
    await Promise.resolve();
    releaseFirstQuery();
    await Promise.all([first, concurrent]);
    expect(queryCalls).toBe(7);
  });

  it("uses monotonic elapsed time so wall-clock rollback cannot extend the scrape budget", async () => {
    let wallNow = 1_000;
    let monotonicNow = 0;
    vi.spyOn(Date, "now").mockImplementation(() => wallNow);
    const dbProbe = new CachedDbProbe(async () => {
      wallNow = 0;
      monotonicNow = 15;
    });
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: { query: () => new Promise(() => {}) },
      poolCapTotal: 10,
      queryTimeoutMs: 20,
      monotonicNowMs: () => monotonicNow,
    });

    const result = await Promise.race([
      source(),
      new Promise<"watchdog">((resolve) => setTimeout(() => resolve("watchdog"), 100)),
    ]);
    expect(result).not.toBe("watchdog");
    expect(result).toMatchObject({ databaseTruthAvailable: 0 });
  });

  it("a DB probe that never resolves returns unavailable within the scrape budget without running DB truth", async () => {
    const dbProbe = new CachedDbProbe(() => new Promise<void>(() => {}), 5_000, Date.now, 20);
    let dbQueries = 0;
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: {
        async query() {
          dbQueries += 1;
          return { rows: [] };
        },
      },
      poolCapTotal: 10,
      queryTimeoutMs: 20,
    });

    const result = await Promise.race([
      source(),
      new Promise<"watchdog">((resolve) => setTimeout(() => resolve("watchdog"), 500)),
    ]);
    expect(result).not.toBe("watchdog");
    expect(result).toMatchObject({ readinessReady: 0, databaseTruthAvailable: 0 });
    expect(dbQueries).toBe(0);
  });

  it("a late-resolving timed-out DB probe cannot fabricate success on the next scrape", async () => {
    let resolvePing!: () => void;
    let calls = 0;
    const dbProbe = new CachedDbProbe(
      () => {
        calls += 1;
        return new Promise<void>((resolve) => {
          resolvePing = resolve;
        });
      },
      5_000,
      Date.now,
      20,
    );
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: EMPTY_ROWS_DB,
      poolCapTotal: 10,
      queryTimeoutMs: 20,
    });

    expect(await source()).toMatchObject({ readinessReady: 0, databaseTruthAvailable: 0 });
    resolvePing();
    await Promise.resolve();
    expect(await source()).toMatchObject({ readinessReady: 0, databaseTruthAvailable: 0 });
    expect(calls).toBe(1);
  });

  it("reports readinessReady: 1 once schema/db/vault/gateway are all live (AC1)", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: EMPTY_ROWS_DB,
      poolCapTotal: 10,
    });
    const snapshot = await source();
    expect(snapshot.readinessReady).toBe(1);
  });

  it("reports readinessReady: 0 (not 1) while any gating check is still incomplete", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState({ vaultCensusVerified: false }),
      dbProbe,
      db: EMPTY_ROWS_DB,
      poolCapTotal: 10,
    });
    const snapshot = await source();
    expect(snapshot.readinessReady).toBe(0);
  });

  it("degrades to readinessReady: 0 when the gateway-read failure budget is exceeded, and reports observationDegraded (AC2)", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState({ observationReadCapable: false, observationDegraded: true }),
      dbProbe,
      db: EMPTY_ROWS_DB,
      poolCapTotal: 10,
    });
    const snapshot = await source();
    expect(snapshot.readinessReady).toBe(0);
    expect(snapshot.observationDegraded).toBe(1);
  });

  it("simulated DB-unreachable: readinessReady: 0, no throw, DB-truth gauges default to 0 (AC3)", async () => {
    const dbProbe = new CachedDbProbe(async () => {
      throw new Error("connection refused");
    });
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: {
        async query() {
          throw new Error("must not be queried when the DB probe already failed");
        },
      },
      poolCapTotal: 10,
    });
    const snapshot = await source();
    expect(snapshot.readinessReady).toBe(0);
    expect(snapshot.availableWallets).toBe(0);
    expect(snapshot.totalWallets).toBe(0);
  });

  it("a DB-truth query that throws mid-scrape (DB blip after the probe succeeded) falls back instead of rejecting", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: {
        async query() {
          throw new Error("connection reset mid-query");
        },
      },
      poolCapTotal: 10,
    });
    await expect(source()).resolves.toMatchObject({ readinessReady: 1, availableWallets: 0 });
  });

  // REVIEW B item 3: /metrics now issues real pool.query calls with no bound — a stalled
  // (non-erroring, non-rejecting) query would hang the scrape indefinitely.
  it("a DB-truth query that never resolves (stalled) falls back within the query budget, not indefinitely", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: {
        query() {
          // Simulates a stalled query: neither resolves nor rejects.
          return new Promise(() => {});
        },
      },
      poolCapTotal: 10,
      queryTimeoutMs: 20,
    });
    const startedAt = Date.now();
    const snapshot = await source();
    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(snapshot.readinessReady).toBe(1);
    expect(snapshot.availableWallets).toBe(0);
  });

  it("reports databaseTruthAvailable=false to onSnapshot when the query stalls past budget", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    let truthAvailable: boolean | undefined;
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: { query: () => new Promise(() => {}) },
      poolCapTotal: 10,
      queryTimeoutMs: 20,
      onSnapshot: (_snapshot, databaseTruthAvailable) => {
        truthAvailable = databaseTruthAvailable;
      },
    });
    await source();
    expect(truthAvailable).toBe(false);
  });
});

describe("createProductionMetricsSnapshotSource — DB-truth counters (the 'drops runtime counters' defect)", () => {
  it("reflects live wallet/lease/queue/operation counts from the DB, not the empty stub", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    const db: MetricsSqlExecutor = {
      async query(text) {
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_WALLETS_BY_STATE) {
          return { rows: [{ state: "AVAILABLE", wallets: 3 }, { state: "PINNED", wallets: 1 }] };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_AVAILABLE_WALLETS) {
          return { rows: [{ available_count: 3 }] };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_ACTIVE_LEASES_BY_ROLE) {
          return { rows: [{ lease_role: "RECEIVE_WINDOW", leases: 2, oldest_age_secs: 45 }] };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.QUEUE_DEPTH_AND_OLDEST_AGE) {
          return { rows: [{ depth: 4, oldest_age_secs: 20 }] };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_QUARANTINED_UNEXPECTED_HEAD) {
          return { rows: [{ wallets: 0 }] };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_OPERATIONS_BY_STATUS) {
          return { rows: [{ status: "NEEDS_ATTENTION", ops: 2, oldest_age_secs: 500 }] };
        }
        return { rows: [] };
      },
    };
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db,
      poolCapTotal: 20,
    });
    const snapshot = await source();
    expect(snapshot.availableWallets).toBe(3);
    expect(snapshot.totalWallets).toBe(4);
    expect(snapshot.queueDepth).toBe(4);
    expect(snapshot.oldestLeaseAgeSecs).toBe(45);
    expect(snapshot.operationsByStatus.NEEDS_ATTENTION).toBe(2);
  });

  it("feeds workerHealth from the live callback (e.g. leadership) instead of leaving every worker unwired", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState({ leadershipLockHeld: true }),
      dbProbe,
      db: EMPTY_ROWS_DB,
      poolCapTotal: 10,
      workerHealth: () => ({ leadership: 1 }),
    });
    const snapshot = await source();
    expect(snapshot.workerHealth.leadership).toBe(1);
  });

  it("calls onSnapshot with the served snapshot (composition seam for alerting)", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    let seen: number | undefined;
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: EMPTY_ROWS_DB,
      poolCapTotal: 10,
      onSnapshot: (snapshot) => {
        seen = snapshot.readinessReady;
      },
    });
    await source();
    expect(seen).toBe(1);
  });
});

describe("createProductionMetricsSnapshotSource — onSnapshot databaseTruthAvailable (REVIEW B)", () => {
  it("reports databaseTruthAvailable=true when the DB-truth query actually succeeded", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    let truthAvailable: boolean | undefined;
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: EMPTY_ROWS_DB,
      poolCapTotal: 10,
      onSnapshot: (_snapshot, databaseTruthAvailable) => {
        truthAvailable = databaseTruthAvailable;
      },
    });
    await source();
    expect(truthAvailable).toBe(true);
  });

  it("reports databaseTruthAvailable=false when the DB probe itself fails", async () => {
    const dbProbe = new CachedDbProbe(async () => {
      throw new Error("connection refused");
    });
    let truthAvailable: boolean | undefined;
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: {
        async query() {
          throw new Error("must not be queried when the DB probe already failed");
        },
      },
      poolCapTotal: 10,
      onSnapshot: (_snapshot, databaseTruthAvailable) => {
        truthAvailable = databaseTruthAvailable;
      },
    });
    await source();
    expect(truthAvailable).toBe(false);
  });

  it("reports databaseTruthAvailable=false when the DB-truth query throws mid-scrape (blip after a healthy probe)", async () => {
    const dbProbe = new CachedDbProbe(async () => {});
    let truthAvailable: boolean | undefined;
    const source = createProductionMetricsSnapshotSource({
      getState: () => readyState(),
      dbProbe,
      db: {
        async query() {
          throw new Error("connection reset mid-query");
        },
      },
      poolCapTotal: 10,
      onSnapshot: (_snapshot, databaseTruthAvailable) => {
        truthAvailable = databaseTruthAvailable;
      },
    });
    await source();
    expect(truthAvailable).toBe(false);
  });
});
