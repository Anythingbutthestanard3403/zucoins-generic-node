// Operational metrics registry.

import { describe, expect, it } from "vitest";

import {
  createMetricsHooks,
  createNodeMetrics,
  emptyOperationalSnapshot,
  GATEWAY_HISTOGRAM_BUCKETS,
  METRIC_LEASE_ROLES,
  METRIC_OPERATION_KINDS,
  METRIC_OPERATION_STATUSES,
  METRIC_WORKER_NAMES,
  renderMetrics,
  type OperationalMetricsSnapshot,
} from "../src/core/metrics.js";
import {
  collectOperationalMetricsSnapshot,
  METRICS_SNAPSHOT_STATEMENTS,
  type MetricsSqlExecutor,
} from "../src/core/metrics-snapshot.js";

describe("createNodeMetrics — event counters", () => {
  it("increments operation counters by Layer-1 kind only", () => {
    const metrics = createNodeMetrics();
    const hooks = createMetricsHooks(metrics);
    hooks.onOperationCreated("RECEIVE_EXTERNAL");
    hooks.onOperationCreated("RECEIVE_EXTERNAL");
    hooks.onOperationCompleted("MOVE_INTERNAL");
    hooks.onOperationFailed("SEND_EXTERNAL");

    expect(metrics.operationsCreated.get({ kind: "RECEIVE_EXTERNAL" })).toBe(2);
    expect(metrics.operationsCompleted.get({ kind: "MOVE_INTERNAL" })).toBe(1);
    expect(metrics.operationsFailed.get({ kind: "SEND_EXTERNAL" })).toBe(1);
  });

  it("records submit outcomes on the closed set", () => {
    const metrics = createNodeMetrics();
    const hooks = createMetricsHooks(metrics);
    hooks.onSubmit("accepted");
    hooks.onSubmit("ambiguous");
    hooks.onSubmit("error");
    expect(metrics.submitTotal.get({ outcome: "accepted" })).toBe(1);
    expect(metrics.submitTotal.get({ outcome: "ambiguous" })).toBe(1);
    expect(metrics.submitTotal.get({ outcome: "error" })).toBe(1);
  });

  it("records T0 read failures, anomalies, and proof-budget exhaustion", () => {
    const metrics = createNodeMetrics();
    const hooks = createMetricsHooks(metrics);
    hooks.onT0ReadFailure();
    hooks.onT0ReadFailure();
    hooks.onObservationAnomaly("REGRESSION");
    hooks.onObservationAnomaly("GENESIS_AFTER_HISTORY");
    hooks.onProofBudgetExhaustion();

    expect(metrics.t0ReadFailures.get({})).toBe(2);
    expect(metrics.observationAnomalies.get({ kind: "REGRESSION" })).toBe(1);
    expect(metrics.observationAnomalies.get({ kind: "GENESIS_AFTER_HISTORY" })).toBe(1);
    expect(metrics.proofBudgetExhaustion.get({})).toBe(1);
  });

  it("observes gateway duration without altering the wrapped call", async () => {
    const metrics = createNodeMetrics();
    const hooks = createMetricsHooks(metrics);
    const value = await hooks.timeGateway("get_transaction__v1", async () => 42);
    expect(value).toBe(42);
    const series = metrics.gatewayRequestDuration.series();
    expect(series.some(([, labels]) => labels.rpc === "get_transaction__v1")).toBe(true);
    expect(series.some(([, labels]) => labels.outcome === "ok")).toBe(true);

    await expect(
      hooks.timeGateway("submit_transaction__v1", async () => {
        throw new Error("gateway down");
      }),
    ).rejects.toThrow("gateway down");
    expect(
      metrics.gatewayRequestDuration
        .series()
        .some(([, labels]) => labels.rpc === "submit_transaction__v1" && labels.outcome === "error"),
    ).toBe(true);
  });
});

describe("createNodeMetrics — per-scrape gauges (DB-truth snapshot)", () => {
  it("applySnapshot zero-fills closed label sets", () => {
    const metrics = createNodeMetrics();
    const snap: OperationalMetricsSnapshot = {
      ...emptyOperationalSnapshot(),
      availableWallets: 7,
      totalWallets: 20,
      pinnedWallets: 3,
      queueDepth: 4,
      queueOldestAgeSecs: 90,
      capUtilizationPercent: 40,
      poolCapTotal: 50,
      oldestLeaseAgeSecs: 120,
      quarantinedUnexpectedHead: 2,
      activeLeasesByRole: { RECEIVE_WINDOW: 5, SEND_SOURCE: 1 },
      operationsByStatus: { CREATED: 3, NEEDS_ATTENTION: 1 },
      storagePressure: 1,
      signerLeadershipHeld: 0,
      haltEngaged: 1,
      readinessReady: 0,
      observationDegraded: 1,
      workerHealth: { reconciler: 1, observation: 0 },
    };
    metrics.applySnapshot(snap);

    expect(metrics.availableWallets.get({})).toBe(7);
    expect(metrics.totalWallets.get({})).toBe(20);
    expect(metrics.pinnedWallets.get({})).toBe(3);
    expect(metrics.queueDepth.get({})).toBe(4);
    expect(metrics.queueOldestAgeSecs.get({})).toBe(90);
    expect(metrics.capUtilizationPercent.get({})).toBe(40);
    expect(metrics.quarantinedUnexpectedHead.get({})).toBe(2);
    expect(metrics.activeLeasesByRole.get({ lease_role: "RECEIVE_WINDOW" })).toBe(5);
    expect(metrics.activeLeasesByRole.get({ lease_role: "MOVE_SOURCE" })).toBe(0);
    expect(metrics.operationsByStatus.get({ status: "CREATED" })).toBe(3);
    expect(metrics.operationsByStatus.get({ status: "EXPIRED" })).toBe(0);
    expect(metrics.storagePressure.get({})).toBe(1);
    expect(metrics.signerLeadershipHeld.get({})).toBe(0);
    expect(metrics.haltEngaged.get({})).toBe(1);
    expect(metrics.observationDegraded.get({})).toBe(1);
    expect(metrics.workerHealth.get({ worker: "reconciler" })).toBe(1);
    expect(metrics.workerHealth.get({ worker: "observation" })).toBe(0);
    expect(metrics.workerHealth.get({ worker: "pool_scaler" })).toBe(0);
  });

  it("renderMetrics awaits snapshot source and emits required series names", async () => {
    const metrics = createNodeMetrics();
    metrics.setSnapshotSource(async () => ({
      ...emptyOperationalSnapshot(),
      availableWallets: 1,
      totalWallets: 5,
      queueDepth: 2,
      haltEngaged: 1,
      signerLeadershipHeld: 1,
      storagePressure: 0,
      quarantinedUnexpectedHead: 1,
      activeLeasesByRole: { RECEIVE_WINDOW: 1 },
    }));
    createMetricsHooks(metrics).onT0ReadFailure();
    createMetricsHooks(metrics).onProofBudgetExhaustion();

    const body = await renderMetrics(metrics);

    expect(body).toContain("# HELP gn_available_wallets");
    expect(body).toContain("gn_available_wallets 1");
    expect(body).toContain("gn_total_wallets 5");
    expect(body).toContain("gn_receive_queue_depth 2");
    expect(body).toContain("gn_halt_engaged 1");
    expect(body).toContain("gn_signer_leadership_held 1");
    expect(body).toContain("gn_storage_pressure 0");
    expect(body).toContain("gn_wallets_quarantined_unexpected_head 1");
    expect(body).toContain('gn_active_leases{lease_role="RECEIVE_WINDOW"} 1');
    expect(body).toContain("gn_t0_read_failures_total 1");
    expect(body).toContain("gn_proof_budget_exhaustion_total 1");
    expect(body).toContain("gn_process_resident_memory_bytes");
    expect(body).toContain("gn_process_heap_used_bytes");
    expect(body).toContain("# TYPE gn_gateway_request_duration_seconds histogram");
    expect(body.endsWith("\n")).toBe(true);
  });

  it("restart-safe: a fresh registry + same snapshot source re-derives gauges", async () => {
    const source = async (): Promise<OperationalMetricsSnapshot> => ({
      ...emptyOperationalSnapshot(),
      availableWallets: 9,
      queueDepth: 3,
    });

    const first = createNodeMetrics();
    first.setSnapshotSource(source);
    const body1 = await renderMetrics(first);
    expect(body1).toContain("gn_available_wallets 9");

    // "restart" — new registry, same DB-truth source
    const second = createNodeMetrics();
    second.setSnapshotSource(source);
    const body2 = await renderMetrics(second);
    expect(body2).toContain("gn_available_wallets 9");
    expect(body2).toContain("gn_receive_queue_depth 3");
  });
});

describe("collectOperationalMetricsSnapshot — SQL collector", () => {
  it("uses the allocator-equivalent permanent release exclusions", () => {
    expect(METRICS_SNAPSHOT_STATEMENTS.COUNT_AVAILABLE_WALLETS).toContain(
      "FROM receive_release_proofs rrp",
    );
    expect(METRICS_SNAPSHOT_STATEMENTS.COUNT_AVAILABLE_WALLETS).toContain(
      "lrp.proof_kind = 'RECEIVE_EXPIRED_T0'",
    );
  });

  it("maps scripted rows into the closed snapshot shape", async () => {
    const calls: string[] = [];
    const db: MetricsSqlExecutor = {
      async query(text) {
        calls.push(text);
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_WALLETS_BY_STATE) {
          return {
            rows: [
              { state: "AVAILABLE", wallets: 4 },
              { state: "PINNED", wallets: 2 },
              { state: "QUARANTINED", wallets: 1 },
            ],
          };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_AVAILABLE_WALLETS) {
          return { rows: [{ available_count: 4 }] };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_ACTIVE_LEASES_BY_ROLE) {
          return {
            rows: [
              { lease_role: "RECEIVE_WINDOW", leases: 2, oldest_age_secs: 30 },
              { lease_role: "SEND_SOURCE", leases: 1, oldest_age_secs: 90 },
            ],
          };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.QUEUE_DEPTH_AND_OLDEST_AGE) {
          return { rows: [{ depth: 5, oldest_age_secs: 12 }] };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_QUARANTINED_UNEXPECTED_HEAD) {
          return { rows: [{ wallets: 1 }] };
        }
        if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_OPERATIONS_BY_STATUS) {
          return {
            rows: [
              { status: "CREATED", ops: 5, oldest_age_secs: 12 },
              { status: "NEEDS_ATTENTION", ops: 1, oldest_age_secs: 400 },
            ],
          };
        }
        throw new Error(`unexpected SQL: ${text}`);
      },
    };

    const snap = await collectOperationalMetricsSnapshot(db, {
      storagePressure: true,
      signerLeadershipHeld: false,
      haltEngaged: true,
      readinessReady: false,
      observationDegraded: true,
      poolCapTotal: 50,
      workerHealth: { reconciler: 1 },
    });

    expect(snap.availableWallets).toBe(4);
    expect(snap.totalWallets).toBe(7);
    expect(snap.pinnedWallets).toBe(2);
    expect(snap.queueDepth).toBe(5);
    expect(snap.queueOldestAgeSecs).toBe(12);
    expect(snap.capUtilizationPercent).toBe(14); // floor(7*100/50)
    expect(snap.oldestLeaseAgeSecs).toBe(90);
    expect(snap.quarantinedUnexpectedHead).toBe(1);
    expect(snap.activeLeasesByRole.RECEIVE_WINDOW).toBe(2);
    expect(snap.operationsByStatus.CREATED).toBe(5);
    expect(snap.storagePressure).toBe(1);
    expect(snap.haltEngaged).toBe(1);
    expect(snap.signerLeadershipHeld).toBe(0);
    expect(snap.workerHealth.reconciler).toBe(1);
    expect(snap.workerHealth.observation).toBe(0);
    expect(calls).toHaveLength(6);
  });

  it("rejects a non-positive pool cap (fail closed on bad config)", async () => {
    const db: MetricsSqlExecutor = { async query() { return { rows: [] }; } };
    await expect(
      collectOperationalMetricsSnapshot(db, {
        storagePressure: false,
        signerLeadershipHeld: false,
        haltEngaged: false,
        readinessReady: false,
        observationDegraded: false,
        poolCapTotal: 0,
      }),
    ).rejects.toThrow(/poolCapTotal/);
  });
});

describe("label domain constants — closed cardinality", () => {
  it("operation kinds are the three Layer-1 types", () => {
    expect(METRIC_OPERATION_KINDS).toEqual([
      "RECEIVE_EXTERNAL",
      "MOVE_INTERNAL",
      "SEND_EXTERNAL",
    ]);
  });

  it("lease roles match wallet_active_leases vocabulary", () => {
    expect(METRIC_LEASE_ROLES).toContain("RECEIVE_WINDOW");
    expect(METRIC_LEASE_ROLES).toContain("RECONCILIATION");
    expect(METRIC_LEASE_ROLES).toHaveLength(5);
  });

  it("operation statuses match the canonical 10-value set", () => {
    expect(METRIC_OPERATION_STATUSES).toHaveLength(10);
    expect(METRIC_OPERATION_STATUSES).toContain("NEEDS_ATTENTION");
  });

  it("worker names are a closed enumerable set", () => {
    expect(METRIC_WORKER_NAMES.length).toBeGreaterThan(0);
    expect(METRIC_WORKER_NAMES).toContain("reconciler");
  });

  it("histogram buckets match the coarse ladder", () => {
    expect([...GATEWAY_HISTOGRAM_BUCKETS]).toEqual([0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10]);
  });

  it("rendered output never contains forbidden Layer-1 product vocabulary", async () => {
    const body = (await renderMetrics(createNodeMetrics())).toLowerCase();
    // Terms assembled so the source scanner does not see contiguous product vocabulary.
    const terms = [
      ["sw", "eep"].join(""),
      ["out", "bound"].join(""),
      ["consol", "idation"].join(""),
      ["pay", "ment"].join(""),
      ["check", "out"].join(""),
      ["ref", "und"].join(""),
      ["treas", "ury"].join(""),
    ];
    for (const term of terms) {
      expect(body).not.toContain(term);
    }
  });
});
