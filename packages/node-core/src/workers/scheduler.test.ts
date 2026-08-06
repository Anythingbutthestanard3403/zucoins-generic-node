import { describe, expect, it, beforeEach } from "vitest";

import { InMemoryClaimStore, acquireClaim } from "./claim.js";
import {
  InMemoryCursorStore,
  InMemoryOperationStore,
  schedulerTick,
  type OperationRow,
} from "./scheduler.js";
import { DEFAULT_POOL_CONFIG, type ReconcileVerdict, type WorkerPoolConfig } from "./types.js";

const CONFIG: WorkerPoolConfig = {
  ...DEFAULT_POOL_CONFIG,
  claimTtlMs: 5000,
  heartbeatIntervalMs: 1000,
  stealGraceMs: 500,
};

function makeRow(id: string, wallet: string, stream: OperationRow["stream"], version = 1): OperationRow {
  return { operationId: id, walletId: wallet, status: "SUBMITTED", rowVersion: version, stream };
}

function classifyAlwaysWaiting(row: OperationRow): ReconcileVerdict {
  return {
    operationId: row.operationId,
    walletId: row.walletId,
    classification: "WAITING",
    expectedRowVersion: row.rowVersion,
    appliedAt: null,
  };
}

describe("reconciliation scheduler", () => {
  let claimStore: InMemoryClaimStore;
  let cursorStore: InMemoryCursorStore;
  let opStore: InMemoryOperationStore;

  beforeEach(() => {
    claimStore = new InMemoryClaimStore();
    cursorStore = new InMemoryCursorStore();
    opStore = new InMemoryOperationStore();
  });

  it("processes operations and advances cursor", () => {
    opStore.addRow(makeRow("op-1", "wallet-A", "SUBMITTED"));
    opStore.addRow(makeRow("op-2", "wallet-A", "SUBMITTED"));

    const results = schedulerTick(claimStore, cursorStore, opStore, classifyAlwaysWaiting, "w1", "wallet-A", 1000, CONFIG);

    expect(results.length).toBeGreaterThan(0);
    const submitted = results.find((r) => r.stream === "SUBMITTED");
    expect(submitted).toBeDefined();
    expect(submitted!.applied).toBe(2);
    expect(submitted!.cursorAdvanced).toBe(true);

    const cursor = cursorStore.getCursor("wallet-A", "SUBMITTED");
    expect(cursor).not.toBeNull();
    expect(cursor!.position).toBe(2);
  });

  it("duplicate tick is idempotent — no double mutation", () => {
    opStore.addRow(makeRow("op-1", "wallet-A", "SUBMITTED"));

    schedulerTick(claimStore, cursorStore, opStore, classifyAlwaysWaiting, "w1", "wallet-A", 1000, CONFIG);

    // Reset cursor to force re-processing same rows
    cursorStore.putCursor({ walletId: "wallet-A", streamKind: "SUBMITTED", position: 0, updatedAt: 2000 });

    const results2 = schedulerTick(claimStore, cursorStore, opStore, classifyAlwaysWaiting, "w1", "wallet-A", 2000, CONFIG);
    const submitted = results2.find((r) => r.stream === "SUBMITTED");
    expect(submitted).toBeDefined();
    expect(submitted!.skipped).toBe(1);
    expect(submitted!.applied).toBe(0);

    const row = opStore.getRow("op-1");
    expect(row!.rowVersion).toBe(2);
  });

  it("cursor persists across restart — resumes from saved position", () => {
    opStore.addRow(makeRow("op-1", "wallet-A", "SUBMITTED"));
    opStore.addRow(makeRow("op-2", "wallet-A", "SUBMITTED"));
    opStore.addRow(makeRow("op-3", "wallet-A", "SUBMITTED"));

    schedulerTick(claimStore, cursorStore, opStore, classifyAlwaysWaiting, "w1", "wallet-A", 1000, CONFIG);

    // Simulate restart: new claim store (claims lost), same cursor store
    const freshClaimStore = new InMemoryClaimStore();
    const results = schedulerTick(freshClaimStore, cursorStore, opStore, classifyAlwaysWaiting, "w2", "wallet-A", 5000, CONFIG);

    const submitted = results.find((r) => r.stream === "SUBMITTED");
    // Cursor was at 3 (all processed), so no new rows
    expect(submitted).toBeUndefined();
  });

  it("serializes reads — second worker blocked while first holds claim", () => {
    opStore.addRow(makeRow("op-1", "wallet-A", "SUBMITTED"));

    // Worker 1 acquires but does not release (simulating in-flight)
    acquireClaim(claimStore, "w1", "wallet-A", 1000, CONFIG);

    // Worker 2 tries to tick the same wallet
    const results = schedulerTick(claimStore, cursorStore, opStore, classifyAlwaysWaiting, "w2", "wallet-A", 1000, CONFIG);
    expect(results).toHaveLength(0);
  });

  it("CAS-conflicted row is requeued, not skipped — a later tick still applies it", () => {
    opStore.addRow(makeRow("op-1", "wallet-A", "SUBMITTED"));
    opStore.addRow(makeRow("op-2", "wallet-A", "SUBMITTED"));

    // op-1 is classified against a stale row_version on the first tick only — exactly
    // what a concurrent writer does to the guarded transition.
    let stale = true;
    const classifyStaleOnce = (row: OperationRow): ReconcileVerdict => {
      const verdict = classifyAlwaysWaiting(row);
      if (row.operationId === "op-1" && stale) {
        stale = false;
        return { ...verdict, expectedRowVersion: row.rowVersion + 99 };
      }
      return verdict;
    };

    const first = schedulerTick(claimStore, cursorStore, opStore, classifyStaleOnce, "w1", "wallet-A", 1000, CONFIG);
    const s1 = first.find((r) => r.stream === "SUBMITTED")!;
    expect(s1.conflicted).toBe(1);
    expect(s1.cursorAdvanced).toBe(false);
    // The conflict is at the head of the batch, so nothing may cross it.
    expect(cursorStore.getCursor("wallet-A", "SUBMITTED")).toBeNull();
    expect(opStore.getRow("op-1")!.status).toBe("SUBMITTED");

    const second = schedulerTick(claimStore, cursorStore, opStore, classifyStaleOnce, "w1", "wallet-A", 2000, CONFIG);
    const s2 = second.find((r) => r.stream === "SUBMITTED")!;
    expect(s2.conflicted).toBe(0);
    expect(s2.applied).toBe(1);
    expect(opStore.getRow("op-1")!.status).toBe("WAITING");
    expect(cursorStore.getCursor("wallet-A", "SUBMITTED")!.position).toBe(2);
  });

  it("cursor advances only through the applied prefix when a later row conflicts", () => {
    opStore.addRow(makeRow("op-1", "wallet-A", "SUBMITTED"));
    opStore.addRow(makeRow("op-2", "wallet-A", "SUBMITTED"));
    opStore.addRow(makeRow("op-3", "wallet-A", "SUBMITTED"));

    const classifyOp2Stale = (row: OperationRow): ReconcileVerdict => {
      const verdict = classifyAlwaysWaiting(row);
      return row.operationId === "op-2"
        ? { ...verdict, expectedRowVersion: row.rowVersion + 99 }
        : verdict;
    };

    const results = schedulerTick(claimStore, cursorStore, opStore, classifyOp2Stale, "w1", "wallet-A", 1000, CONFIG);
    const submitted = results.find((r) => r.stream === "SUBMITTED")!;

    expect(submitted.applied).toBe(2);
    expect(submitted.conflicted).toBe(1);

    // op-3 applied, but it sits behind the conflict — the cursor stops at op-2 so the
    // conflicted row is re-read next tick. Crossing it would lose it permanently.
    expect(cursorStore.getCursor("wallet-A", "SUBMITTED")!.position).toBe(1);
    expect(opStore.getRow("op-2")!.status).toBe("SUBMITTED");
  });

  it("a throw mid-tick still releases the worker claim", () => {
    opStore.addRow(makeRow("op-1", "wallet-A", "SUBMITTED"));

    const classifyThrows = (): ReconcileVerdict => {
      throw new Error("classify exploded");
    };

    expect(() =>
      schedulerTick(claimStore, cursorStore, opStore, classifyThrows, "w1", "wallet-A", 1000, CONFIG),
    ).toThrow("classify exploded");

    // Another worker takes the wallet immediately — no waiting out the claim TTL.
    expect(acquireClaim(claimStore, "w2", "wallet-A", 1001, CONFIG).outcome).toBe("ACQUIRED");
  });

  it("no scheduler path calls a signer or submitter — classification only", () => {
    opStore.addRow(makeRow("op-1", "wallet-A", "RECOVERY"));

    const results = schedulerTick(claimStore, cursorStore, opStore, classifyAlwaysWaiting, "w1", "wallet-A", 1000, CONFIG);
    const recovery = results.find((r) => r.stream === "RECOVERY");
    expect(recovery).toBeDefined();
    expect(recovery!.verdicts[0].classification).toBe("WAITING");
  });
});
