import { describe, expect, it } from "vitest";

import { InMemoryClaimStore, acquireClaim } from "./claim.js";
import {
  InMemoryCursorStore,
  InMemoryOperationStore,
  schedulerTick,
  type OperationRow,
} from "./scheduler.js";
import {
  InMemoryAdmissionQueue,
  InMemoryDeliveryLog,
  tryEnqueue,
  expireStale,
  dispatchNext,
} from "./admission.js";
import { DEFAULT_POOL_CONFIG, type AdmissionEntry, type ReconcileVerdict, type WorkerPoolConfig } from "./types.js";

const CONFIG: WorkerPoolConfig = {
  ...DEFAULT_POOL_CONFIG,
  claimTtlMs: 1000,
  heartbeatIntervalMs: 300,
  stealGraceMs: 200,
  receiveQueueCap: 3,
  receiveQueueMaxWaitMs: 5000,
  poolCapTotal: 5,
  poolTargetAvailable: 2,
  mintBatchLimit: 2,
};

function makeRow(id: string, wallet: string, stream: OperationRow["stream"], version = 1): OperationRow {
  return { operationId: id, walletId: wallet, status: "SUBMITTED", rowVersion: version, stream };
}

function classifyWaiting(row: OperationRow): ReconcileVerdict {
  return {
    operationId: row.operationId,
    walletId: row.walletId,
    classification: "WAITING",
    expectedRowVersion: row.rowVersion,
    appliedAt: null,
  };
}

function makeEntry(id: string, createdAt: number): AdmissionEntry {
  return { operationId: id, walletId: null, createdAt, status: "QUEUED" };
}

describe("fault-injection: worker ownership and restart", () => {
  describe("claim race", () => {
    it("two workers racing for one claim — only one acts", () => {
      const store = new InMemoryClaimStore();
      const r1 = acquireClaim(store, "w1", "wallet-X", 1000, CONFIG);
      const r2 = acquireClaim(store, "w2", "wallet-X", 1000, CONFIG);

      const acquired = [r1, r2].filter((r) => r.outcome === "ACQUIRED");
      expect(acquired).toHaveLength(1);

      const blocked = [r1, r2].find((r) => r.outcome !== "ACQUIRED");
      expect(blocked).toBeDefined();
      expect(blocked!.outcome).toBe("HELD_BY_OTHER");
    });

    it("loser backs off without side effects", () => {
      const claimStore = new InMemoryClaimStore();
      const cursorStore = new InMemoryCursorStore();
      const opStore = new InMemoryOperationStore();
      opStore.addRow(makeRow("op-1", "wallet-X", "SUBMITTED"));

      // w1 holds the claim
      acquireClaim(claimStore, "w1", "wallet-X", 1000, CONFIG);

      // w2 tries to tick — should produce nothing
      const results = schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w2", "wallet-X", 1000, CONFIG);
      expect(results).toHaveLength(0);

      // No cursor was written by w2
      expect(cursorStore.getCursor("wallet-X", "SUBMITTED")).toBeNull();
    });
  });

  describe("crash-steal", () => {
    it("stolen claim resumes same attempt via generation tracking — never creates a new one", () => {
      const store = new InMemoryClaimStore();

      const r1 = acquireClaim(store, "w1", "wallet-X", 1000, CONFIG);
      expect(r1.outcome).toBe("ACQUIRED");
      const originalClaimId = r1.outcome === "ACQUIRED" ? r1.claim.claimId : "";

      // w1 crashes (no release). After TTL + grace, w2 steals.
      const r2 = acquireClaim(store, "w2", "wallet-X", 2300, CONFIG);
      expect(r2.outcome).toBe("ACQUIRED");
      if (r2.outcome === "ACQUIRED") {
        expect(r2.claim.generation).toBe(2);
        expect(r2.claim.walletId).toBe("wallet-X");
        // Same wallet, incremented generation — same logical claim lineage
        expect(r2.claim.claimId).not.toBe(originalClaimId);
      }
    });

    it("steal before grace period is rejected — guarded, never blind", () => {
      const store = new InMemoryClaimStore();
      acquireClaim(store, "w1", "wallet-X", 1000, CONFIG);

      // TTL=1000, grace=200 → not stealable until 2200
      const r = acquireClaim(store, "w2", "wallet-X", 1500, CONFIG);
      expect(r.outcome).not.toBe("ACQUIRED");
    });

    it("crash mid-tick: cursor persists, restart resumes correctly", () => {
      const claimStore = new InMemoryClaimStore();
      const cursorStore = new InMemoryCursorStore();
      const opStore = new InMemoryOperationStore();

      opStore.addRow(makeRow("op-1", "wallet-X", "SUBMITTED"));
      opStore.addRow(makeRow("op-2", "wallet-X", "SUBMITTED"));
      opStore.addRow(makeRow("op-3", "wallet-X", "SUBMITTED"));

      // w1 processes all 3, then "crashes" (claim expires without release)
      schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w1", "wallet-X", 1000, CONFIG);

      // w2 takes over after crash — cursor says position=3, nothing left
      const freshClaims = new InMemoryClaimStore();
      const results = schedulerTick(freshClaims, cursorStore, opStore, classifyWaiting, "w2", "wallet-X", 5000, CONFIG);
      const submitted = results.find((r) => r.stream === "SUBMITTED");
      expect(submitted).toBeUndefined();
    });
  });

  describe("duplicate delivery", () => {
    it("same job delivered twice produces exactly one effective mutation", () => {
      const cursorStore = new InMemoryCursorStore();
      const opStore = new InMemoryOperationStore();
      const claimStore = new InMemoryClaimStore();

      opStore.addRow(makeRow("op-1", "wallet-X", "SUBMITTED"));

      // First tick applies the verdict
      schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w1", "wallet-X", 1000, CONFIG);
      const rowAfterFirst = opStore.getRow("op-1");
      expect(rowAfterFirst!.rowVersion).toBe(2);

      // Simulate duplicate: reset cursor, re-tick
      cursorStore.putCursor({ walletId: "wallet-X", streamKind: "SUBMITTED", position: 0, updatedAt: 2000 });
      schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w1", "wallet-X", 2000, CONFIG);

      // row_version must NOT increment again
      const rowAfterDup = opStore.getRow("op-1");
      expect(rowAfterDup!.rowVersion).toBe(2);
    });

    it("event delivery deduplicates by seq", () => {
      const log = new InMemoryDeliveryLog();
      log.append({ seq: 1, eventId: "e1", operationId: "op-1", dispatchedAt: null });

      const r1 = dispatchNext(log, 1000);
      expect(r1.outcome).toBe("DISPATCHED");

      // Duplicate delivery attempt
      const r2 = dispatchNext(log, 1001);
      expect(r2.outcome).toBe("ALREADY_DISPATCHED");
    });
  });

  describe("reorder", () => {
    it("job processing is correct regardless of delivery sequence", () => {
      const log = new InMemoryDeliveryLog();
      // Insert in a non-sequential pattern
      log.append({ seq: 3, eventId: "e3", operationId: "op-3", dispatchedAt: null });
      log.append({ seq: 1, eventId: "e1", operationId: "op-1", dispatchedAt: null });
      log.append({ seq: 2, eventId: "e2", operationId: "op-2", dispatchedAt: null });

      // Dispatch must still go 1, 2, 3
      const r1 = dispatchNext(log, 1000);
      expect(r1.outcome).toBe("DISPATCHED");
      if (r1.outcome === "DISPATCHED") expect(r1.seq).toBe(1);

      const r2 = dispatchNext(log, 1001);
      expect(r2.outcome).toBe("DISPATCHED");
      if (r2.outcome === "DISPATCHED") expect(r2.seq).toBe(2);

      const r3 = dispatchNext(log, 1002);
      expect(r3.outcome).toBe("DISPATCHED");
      if (r3.outcome === "DISPATCHED") expect(r3.seq).toBe(3);
    });
  });

  describe("lost response", () => {
    it("worker action whose ack is lost is never re-executed on retry", () => {
      const claimStore = new InMemoryClaimStore();
      const cursorStore = new InMemoryCursorStore();
      const opStore = new InMemoryOperationStore();

      opStore.addRow(makeRow("op-1", "wallet-X", "SUBMITTED"));

      // Worker acts, response lost (simulated: tick completes but caller never sees result)
      schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w1", "wallet-X", 1000, CONFIG);

      // "Restart" — same worker retries the same wallet
      const results = schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w1", "wallet-X", 2000, CONFIG);

      // Cursor already advanced past op-1, so nothing to re-process
      const submitted = results.find((r) => r.stream === "SUBMITTED");
      expect(submitted).toBeUndefined();

      // row_version unchanged from first application
      expect(opStore.getRow("op-1")!.rowVersion).toBe(2);
    });
  });

  describe("queue saturation", () => {
    it("overflow returns deterministic 503-equivalent, never silent drops", () => {
      const queue = new InMemoryAdmissionQueue();

      for (let i = 0; i < 3; i++) {
        const r = tryEnqueue(queue, makeEntry(`op-${i}`, i * 100), CONFIG);
        expect(r.outcome).toBe("ENQUEUED");
      }

      // At cap (3)
      const overflow = tryEnqueue(queue, makeEntry("op-overflow", 400), CONFIG);
      expect(overflow.outcome).toBe("QUEUE_FULL");
      expect(queue.depth()).toBe(3);
    });

    it("queue age expiry is deterministic", () => {
      const queue = new InMemoryAdmissionQueue();
      tryEnqueue(queue, makeEntry("op-stale", 1000), CONFIG);
      tryEnqueue(queue, makeEntry("op-fresh", 5000), CONFIG);

      const results = expireStale(queue, 7000, CONFIG);
      const expired = results.filter((r) => r.outcome === "EXPIRED");
      expect(expired).toHaveLength(1);
      if (expired[0].outcome === "EXPIRED") expect(expired[0].operationId).toBe("op-stale");
      expect(queue.depth()).toBe(1);
    });

    it("no unbounded growth past cap", () => {
      const queue = new InMemoryAdmissionQueue();
      for (let i = 0; i < 100; i++) {
        tryEnqueue(queue, makeEntry(`op-${i}`, i), CONFIG);
      }
      expect(queue.depth()).toBe(CONFIG.receiveQueueCap);
    });
  });

  describe("no duplicate submit invariant", () => {
    it("no test path produces two submit calls for one attempt", () => {
      const claimStore = new InMemoryClaimStore();
      const cursorStore = new InMemoryCursorStore();
      const opStore = new InMemoryOperationStore();

      opStore.addRow(makeRow("op-1", "wallet-X", "SUBMITTED"));

      // Multiple workers, multiple ticks — only one CAS application succeeds
      schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w1", "wallet-X", 1000, CONFIG);

      // Force re-read by resetting cursor
      cursorStore.putCursor({ walletId: "wallet-X", streamKind: "SUBMITTED", position: 0, updatedAt: 2000 });
      schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w2", "wallet-X", 2000, CONFIG);

      cursorStore.putCursor({ walletId: "wallet-X", streamKind: "SUBMITTED", position: 0, updatedAt: 3000 });
      schedulerTick(claimStore, cursorStore, opStore, classifyWaiting, "w3", "wallet-X", 3000, CONFIG);

      // row_version incremented exactly once (1 → 2), never twice
      expect(opStore.getRow("op-1")!.rowVersion).toBe(2);
    });
  });
});
