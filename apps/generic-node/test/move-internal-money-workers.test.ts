// MOVE_INTERNAL money-worker shell composition.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  LOAD_PENDING_MOVES_SQL,
  moveInternalWorkerModuleId,
  createMoveInternalLeaseAndProgressPorts,
  tickMoveInternalMoneyWorkers,
} from "../src/money-workers/move-internal-worker.js";
import {
  createMetricsHooks,
  createNodeMetrics,
  MOVE_MONEY_WORKER_STEPS,
  nextMoveMoneyWorkerStep,
  runMoveInternalMoneyWorker,
  type MoveInternalMoneyWorkerPorts,
} from "@zucoins/node-core";

const here = dirname(fileURLToPath(import.meta.url));
const OP = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function pendingMovePool() {
  return {
    query: async () => ({
      rows: [{
        operation_id: OP,
        implementer_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        node_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        source_wallet_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        destination_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        destination_wallet_id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
        source_public_key: "source",
        destination_public_key: "destination",
        amount_zkz: "0.01",
        lease_group_id: "11111111-1111-4111-8111-111111111111",
        spawned_from_operation_id: null,
        row_version: 1,
        status: "CREATED",
      }],
      rowCount: 1,
    }),
  } as never;
}

function inertPorts(loadProgress: MoveInternalMoneyWorkerPorts["loadProgress"]): MoveInternalMoneyWorkerPorts {
  return {
    loadProgress,
    acquireDualLeases: async () => ({ ok: false, reason: "not used" }),
    captureBaselines: async () => ({ ok: false, reason: "not used" }),
    loadBaselineBound: async () => null,
    formInner: async () => ({ ok: false, reason: "not used" }),
    signUnderLeases: async () => ({ ok: false, reason: "not used" }),
    loadSignedMaterial: async () => null,
    submitOnce: async () => ({ ok: false, reason: "not used" }),
    reconcileAndLand: async () => ({ ok: false, reason: "not used" }),
  };
}

describe("MOVE_INTERNAL money-workers composition", () => {
  it("increments completed only on landing and never counts retryable MOVE worker failures", async () => {
    const metrics = createNodeMetrics();
    const metricsHooks = createMetricsHooks(metrics);
    const logger = { info: () => {}, error: () => {} };
    const moneyPathGates = {
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: () => {},
    };

    const completedPorts = inertPorts(async () => ({
      operationId: OP,
      operationStatus: "INTERNAL_MOVE_LANDED",
      rowVersion: 2,
      bothLeasesHeld: false,
      baselinesBound: true,
      innerPreimagePersisted: true,
      signaturesComplete: true,
      submitClaimed: true,
      submitOutcome: "ACK",
      landDualPathVerified: true,
      landed: true,
    }));
    await tickMoveInternalMoneyWorkers({
      pool: pendingMovePool(), ownerInstanceId: OP, logger, ports: completedPorts,
      moneyPathGates, metricsHooks,
    });
    expect(metrics.operationsCompleted.get({ kind: "MOVE_INTERNAL" })).toBe(1);

    const failedPorts: MoveInternalMoneyWorkerPorts = {
      ...inertPorts(async () => ({
        operationId: OP,
        operationStatus: "CREATED",
        rowVersion: 1,
        bothLeasesHeld: true,
        baselinesBound: true,
        innerPreimagePersisted: true,
        signaturesComplete: true,
        submitClaimed: false,
        submitOutcome: null,
        landDualPathVerified: false,
        landed: false,
      })),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
          sourceLeaseEpoch: 1n,
          destinationWalletId: "ffffffff-ffff-4fff-8fff-ffffffffffff",
          destinationLeaseEpoch: 1n,
        },
      }),
      loadSignedMaterial: async () => ({ signed: {} as never }),
      submitOnce: async () => ({ ok: false, reason: "ambiguous without claim", ambiguous: true }),
    };
    for (let tick = 0; tick < 2; tick += 1) {
      const failedAdvances = await tickMoveInternalMoneyWorkers({
        pool: pendingMovePool(), ownerInstanceId: OP, logger, ports: failedPorts,
        moneyPathGates, metricsHooks,
      });
      expect(failedAdvances).toContainEqual(expect.objectContaining({ kind: "FAILED" }));
    }
    // MOVE_INTERNAL's closed lifecycle has no REJECTED/EXPIRED state. This durable row is
    // still CREATED and will be selected next tick, so worker-attempt failure is not an
    // operation terminal and must never increment gn_operations_failed_total.
    expect(metrics.operationsFailed.get({ kind: "MOVE_INTERNAL" })).toBe(0);
  });

  it("anchors shell + pipeline module paths", () => {
    expect(moveInternalWorkerModuleId()).toBe(
      "apps/generic-node/src/money-workers/move-internal-worker.ts",
    );
    expect(MOVE_MONEY_WORKER_STEPS).toContain("SUBMIT");
    expect(MOVE_MONEY_WORKER_STEPS).toContain("LAND");
  });

  it("start-money-workers tick wires MOVE_INTERNAL pipeline", () => {
    const workers = readFileSync(
      join(here, "../src/money-workers/start-money-workers.ts"),
      "utf8",
    );
    expect(workers).toMatch(/tickMoveInternalMoneyWorkers/);
    expect(workers).toMatch(/createMoveInternalLeaseAndProgressPorts/);
    expect(workers).toMatch(/moveInternalPorts/);
    expect(workers).toMatch(/MOVE_INTERNAL/);
    // No-blind-retry — no blind resubmit wording in the shell's comment trail.
    expect(workers).toMatch(/submit-once|submit once|never blind/i);
  });

  it("LOAD_PENDING_MOVES_SQL targets MOVE_INTERNAL CREATED/NEEDS_ATTENTION", () => {
    expect(LOAD_PENDING_MOVES_SQL).toContain("MOVE_INTERNAL");
    expect(LOAD_PENDING_MOVES_SQL).toContain("CREATED");
    expect(LOAD_PENDING_MOVES_SQL).toContain("NEEDS_ATTENTION");
    expect(LOAD_PENDING_MOVES_SQL).not.toContain("RECEIVE_EXTERNAL");
  });

  it("submitClaimed progress never routes next step to SUBMIT (No-blind-retry census)", () => {
    expect(
      nextMoveMoneyWorkerStep({
        operationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        operationStatus: "CREATED",
        rowVersion: 1,
        bothLeasesHeld: true,
        baselinesBound: true,
        innerPreimagePersisted: true,
        signaturesComplete: true,
        submitClaimed: true,
        submitOutcome: "AMBIGUOUS",
        landDualPathVerified: false,
        landed: false,
      }),
    ).toBe("LAND");
  });

  it("D4 status alone without dual-path is not DONE", () => {
    expect(
      nextMoveMoneyWorkerStep({
        operationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        operationStatus: "INTERNAL_MOVE_LANDED",
        rowVersion: 2,
        bothLeasesHeld: true,
        baselinesBound: true,
        innerPreimagePersisted: true,
        signaturesComplete: true,
        submitClaimed: true,
        submitOutcome: "ACK",
        landDualPathVerified: false,
        landed: true,
      }),
    ).toBe("LAND");
  });

  it("default shell ports leave advanced steps unbound (honest WAIT, not green E2E)", async () => {
    const query = async () => ({ rows: [], rowCount: 0 });
    const pool = {
      query,
      connect: async () => ({
        query: async () => ({ rows: [], rowCount: 0 }),
        release: () => {},
      }),
    } as never;
    const ports = createMoveInternalLeaseAndProgressPorts({
      pool,
      ownerInstanceId: "11111111-1111-4111-8111-111111111111",
    });
    expect(typeof ports.acquireDualLeases).toBe("function");
    expect(typeof ports.loadBaselineBound).toBe("function");
    expect(typeof ports.loadSignedMaterial).toBe("function");
    expect(typeof ports.captureBaselines).toBe("function");
    expect(typeof ports.submitOnce).toBe("function");
    expect(typeof ports.reconcileAndLand).toBe("function");
    expect(typeof runMoveInternalMoneyWorker).toBe("function");
    const baseline = await ports.captureBaselines("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", {
      sourceWalletId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      sourceLeaseEpoch: 1n,
      destinationWalletId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      destinationLeaseEpoch: 1n,
    });
    expect(baseline.ok).toBe(false);
    if (!baseline.ok) {
      expect(baseline.reason).toMatch(/not bound|Wave-4|Wave 4/i);
    }
  });
});
