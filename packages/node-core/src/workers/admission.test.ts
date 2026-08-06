import { describe, expect, it, beforeEach } from "vitest";

import {
  InMemoryAdmissionQueue,
  InMemoryDeliveryLog,
  computeMintCount,
  tryEnqueue,
  promoteFifo,
  expireStale,
  dispatchNext,
  type PoolState,
} from "./admission.js";
import { DEFAULT_POOL_CONFIG, type AdmissionEntry, type WorkerPoolConfig } from "./types.js";

const CONFIG: WorkerPoolConfig = {
  ...DEFAULT_POOL_CONFIG,
  receiveQueueCap: 5,
  receiveQueueMaxWaitMs: 10_000,
  poolCapTotal: 10,
  poolTargetAvailable: 3,
  mintBatchLimit: 2,
};

function makeEntry(id: string, createdAt: number): AdmissionEntry {
  return { operationId: id, walletId: null, createdAt, status: "QUEUED" };
}

describe("admission queue — FIFO promotion", () => {
  let queue: InMemoryAdmissionQueue;

  beforeEach(() => {
    queue = new InMemoryAdmissionQueue();
  });

  it("promotes strictly by (createdAt, operationId) sequence", () => {
    tryEnqueue(queue, makeEntry("op-C", 300), CONFIG);
    tryEnqueue(queue, makeEntry("op-A", 100), CONFIG);
    tryEnqueue(queue, makeEntry("op-B", 200), CONFIG);

    const pool: PoolState = { availableWalletCount: 1, nonRetiredPoolWalletCount: 5, activeLeases: 1, pinnedLeases: 0 };
    let walletCounter = 0;

    const r1 = promoteFifo(queue, pool, () => `wallet-${++walletCounter}`, CONFIG);
    expect(r1.outcome).toBe("PROMOTED");
    if (r1.outcome === "PROMOTED") expect(r1.operationId).toBe("op-A");

    const r2 = promoteFifo(queue, pool, () => `wallet-${++walletCounter}`, CONFIG);
    expect(r2.outcome).toBe("PROMOTED");
    if (r2.outcome === "PROMOTED") expect(r2.operationId).toBe("op-B");

    const r3 = promoteFifo(queue, pool, () => `wallet-${++walletCounter}`, CONFIG);
    expect(r3.outcome).toBe("PROMOTED");
    if (r3.outcome === "PROMOTED") expect(r3.operationId).toBe("op-C");
  });

  it("returns QUEUE_FULL at capacity with Retry-After", () => {
    for (let i = 0; i < 5; i++) {
      tryEnqueue(queue, makeEntry(`op-${i}`, i * 100), CONFIG);
    }

    const result = tryEnqueue(queue, makeEntry("op-overflow", 600), CONFIG);
    expect(result.outcome).toBe("QUEUE_FULL");
    if (result.outcome === "QUEUE_FULL") {
      expect(result.retryAfterMs).toBe(CONFIG.heartbeatIntervalMs);
    }
    expect(queue.depth()).toBe(5);
  });

  it("expires entries exceeding max wait time", () => {
    tryEnqueue(queue, makeEntry("op-old", 1000), CONFIG);
    tryEnqueue(queue, makeEntry("op-new", 9000), CONFIG);

    const results = expireStale(queue, 12_000, CONFIG);
    const expired = results.filter((r) => r.outcome === "EXPIRED");
    const notExpired = results.filter((r) => r.outcome === "NOT_EXPIRED");

    expect(expired).toHaveLength(1);
    if (expired[0].outcome === "EXPIRED") expect(expired[0].operationId).toBe("op-old");
    expect(notExpired).toHaveLength(1);
    expect(queue.depth()).toBe(1);
  });

  it("scaler never exceeds min(availableDeficit, remainingCapacity, mintBatchLimit)", () => {
    const pool: PoolState = { availableWalletCount: 0, nonRetiredPoolWalletCount: 9, activeLeases: 5, pinnedLeases: 4 };
    const mint = computeMintCount(pool, CONFIG);
    // availableDeficit = 3, remainingCapacity = 1, mintBatchLimit = 2 → min = 1
    expect(mint).toBe(1);
  });

  it("scaler returns 0 at hard cap even with pinned pressure", () => {
    const pool: PoolState = { availableWalletCount: 0, nonRetiredPoolWalletCount: 10, activeLeases: 6, pinnedLeases: 4 };
    const mint = computeMintCount(pool, CONFIG);
    expect(mint).toBe(0);
  });
});

describe("delivery — strict seq progression", () => {
  let log: InMemoryDeliveryLog;

  beforeEach(() => {
    log = new InMemoryDeliveryLog();
  });

  it("dispatches by strict seq progression", () => {
    log.append({ seq: 1, eventId: "e1", operationId: "op-1", dispatchedAt: null });
    log.append({ seq: 2, eventId: "e2", operationId: "op-2", dispatchedAt: null });
    log.append({ seq: 3, eventId: "e3", operationId: "op-3", dispatchedAt: null });

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

  it("detects gap when seq is missing", () => {
    log.append({ seq: 1, eventId: "e1", operationId: "op-1", dispatchedAt: null });
    log.append({ seq: 3, eventId: "e3", operationId: "op-3", dispatchedAt: null });

    dispatchNext(log, 1000); // dispatches seq 1

    const r = dispatchNext(log, 1001);
    expect(r.outcome).toBe("GAP_DETECTED");
    if (r.outcome === "GAP_DETECTED") {
      expect(r.expectedSeq).toBe(2);
      expect(r.actualSeq).toBe(3);
    }
  });

  it("duplicate dispatch is a no-op", () => {
    log.append({ seq: 1, eventId: "e1", operationId: "op-1", dispatchedAt: null });

    dispatchNext(log, 1000);
    const r = dispatchNext(log, 1001);
    expect(r.outcome).toBe("ALREADY_DISPATCHED");
  });
});
