import {
  type AdmissionEntry,
  type AdmissionPromoteResult,
  type AdmissionExpireResult,
  type DeliveryRecord,
  type DeliveryDispatchResult,
  type WorkerPoolConfig,
  DEFAULT_POOL_CONFIG,
} from "./types.js";

export interface AdmissionQueue {
  enqueue(entry: AdmissionEntry): { outcome: "ENQUEUED" } | { outcome: "QUEUE_FULL"; readonly retryAfterMs: number };
  peekFifo(): AdmissionEntry | null;
  dequeue(operationId: string): void;
  depth(): number;
  entries(): readonly AdmissionEntry[];
}

export class InMemoryAdmissionQueue implements AdmissionQueue {
  private readonly queue: AdmissionEntry[] = [];

  enqueue(entry: AdmissionEntry): { outcome: "ENQUEUED" } | { outcome: "QUEUE_FULL"; readonly retryAfterMs: number } {
    this.queue.push(entry);
    this.queue.sort((a, b) => a.createdAt - b.createdAt || a.operationId.localeCompare(b.operationId));
    return { outcome: "ENQUEUED" };
  }

  peekFifo(): AdmissionEntry | null {
    return this.queue.length > 0 ? this.queue[0] : null;
  }

  dequeue(operationId: string): void {
    const idx = this.queue.findIndex((e) => e.operationId === operationId);
    if (idx >= 0) this.queue.splice(idx, 1);
  }

  depth(): number {
    return this.queue.length;
  }

  entries(): readonly AdmissionEntry[] {
    return [...this.queue];
  }

  clear(): void {
    this.queue.length = 0;
  }
}

export interface PoolState {
  availableWalletCount: number;
  nonRetiredPoolWalletCount: number;
  activeLeases: number;
  pinnedLeases: number;
}

export function computeMintCount(pool: PoolState, config: WorkerPoolConfig = DEFAULT_POOL_CONFIG): number {
  const availableDeficit = Math.max(0, config.poolTargetAvailable - pool.availableWalletCount);
  const remainingCapacity = Math.max(0, config.poolCapTotal - pool.nonRetiredPoolWalletCount);
  return Math.min(availableDeficit, remainingCapacity, config.mintBatchLimit);
}

export function tryEnqueue(
  queue: AdmissionQueue,
  entry: AdmissionEntry,
  config: WorkerPoolConfig = DEFAULT_POOL_CONFIG,
): { outcome: "ENQUEUED" } | { outcome: "QUEUE_FULL"; readonly retryAfterMs: number } {
  if (queue.depth() >= config.receiveQueueCap) {
    return { outcome: "QUEUE_FULL", retryAfterMs: config.heartbeatIntervalMs };
  }
  return queue.enqueue(entry);
}

export function promoteFifo(
  queue: AdmissionQueue,
  pool: PoolState,
  assignWallet: (entry: AdmissionEntry) => string | null,
  config: WorkerPoolConfig = DEFAULT_POOL_CONFIG,
): AdmissionPromoteResult {
  const mintCount = computeMintCount(pool, config);
  if (mintCount <= 0 && pool.availableWalletCount <= 0) {
    return { outcome: "NO_CAPACITY" };
  }

  const next = queue.peekFifo();
  if (!next) return { outcome: "QUEUE_EMPTY" };

  const walletId = assignWallet(next);
  if (!walletId) return { outcome: "NO_CAPACITY" };

  queue.dequeue(next.operationId);
  return { outcome: "PROMOTED", operationId: next.operationId, walletId };
}

export function expireStale(
  queue: AdmissionQueue,
  now: number,
  config: WorkerPoolConfig = DEFAULT_POOL_CONFIG,
): AdmissionExpireResult[] {
  const results: AdmissionExpireResult[] = [];
  const entries = queue.entries();

  for (const entry of entries) {
    if (entry.status !== "QUEUED") {
      results.push({ outcome: "ALREADY_TERMINAL" });
      continue;
    }

    const age = now - entry.createdAt;
    if (age >= config.receiveQueueMaxWaitMs) {
      queue.dequeue(entry.operationId);
      results.push({ outcome: "EXPIRED", operationId: entry.operationId });
    } else {
      results.push({ outcome: "NOT_EXPIRED", remainingMs: config.receiveQueueMaxWaitMs - age });
    }
  }

  return results;
}

export interface DeliveryLog {
  append(record: DeliveryRecord): void;
  getBySeq(seq: number): DeliveryRecord | null;
  lastDispatchedSeq(): number;
  markDispatched(seq: number, at: number): void;
}

export class InMemoryDeliveryLog implements DeliveryLog {
  private readonly records = new Map<number, DeliveryRecord>();
  private lastSeq = 0;

  append(record: DeliveryRecord): void {
    this.records.set(record.seq, record);
    if (record.seq > this.lastSeq) this.lastSeq = record.seq;
  }

  getBySeq(seq: number): DeliveryRecord | null {
    return this.records.get(seq) ?? null;
  }

  lastDispatchedSeq(): number {
    let max = 0;
    for (const r of this.records.values()) {
      if (r.dispatchedAt !== null && r.seq > max) max = r.seq;
    }
    return max;
  }

  markDispatched(seq: number, at: number): void {
    const existing = this.records.get(seq);
    if (existing) {
      this.records.set(seq, { ...existing, dispatchedAt: at });
    }
  }

  clear(): void {
    this.records.clear();
    this.lastSeq = 0;
  }
}

export function dispatchNext(
  log: DeliveryLog,
  now: number,
): DeliveryDispatchResult {
  const lastDispatched = log.lastDispatchedSeq();
  const nextSeq = lastDispatched + 1;

  const record = log.getBySeq(nextSeq);
  if (!record) {
    const anyHigher = log.getBySeq(nextSeq + 1);
    if (anyHigher) {
      return { outcome: "GAP_DETECTED", expectedSeq: nextSeq, actualSeq: nextSeq + 1 };
    }
    return { outcome: "ALREADY_DISPATCHED", seq: lastDispatched };
  }

  if (record.dispatchedAt !== null) {
    return { outcome: "ALREADY_DISPATCHED", seq: record.seq };
  }

  log.markDispatched(nextSeq, now);
  return { outcome: "DISPATCHED", seq: nextSeq };
}
