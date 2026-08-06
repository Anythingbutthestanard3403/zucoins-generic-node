// Serialized live-chain runner lock.
//
// One process-local mutual exclusion so two acceptance runs cannot arm simultaneously.
// Mirrors packages/splitchain/test/live-chain/queue.ts FIFO discipline for the generic-node
// acceptance surface. Pure in-memory; no network, no filesystem, no keys.

export interface RunnerLockHandle {
  readonly holderId: string;
  readonly acquiredAt: string;
  release(): void;
}

export interface RunnerLock {
  /** Try to acquire. Returns null when another holder already owns the lock. */
  tryAcquire(holderId: string, now?: () => Date): RunnerLockHandle | null;
  /** True when some holder currently owns the lock. */
  readonly held: boolean;
  /** Current holder id, or null when free. */
  readonly holderId: string | null;
}

export function createRunnerLock(): RunnerLock {
  let current: { holderId: string; acquiredAt: string } | null = null;

  return {
    tryAcquire(holderId, now = () => new Date()) {
      if (current !== null) return null;
      if (holderId.trim() === "") {
        throw new Error("runner lock holderId must be non-empty");
      }
      current = { holderId, acquiredAt: now().toISOString() };
      const snapshot = current;
      return {
        holderId: snapshot.holderId,
        acquiredAt: snapshot.acquiredAt,
        release() {
          if (current === snapshot) current = null;
        },
      };
    },
    get held() {
      return current !== null;
    },
    get holderId() {
      return current?.holderId ?? null;
    },
  };
}
