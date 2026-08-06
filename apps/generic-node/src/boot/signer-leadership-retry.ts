// bounded-retry wrapper around acquireSignerLeadership for the boot
// lane's signer-leadership step. During a rolling Railway deploy the outgoing
// container can still hold the advisory lock for a brief overlap; retrying
// with backoff instead of failing on the first try lets the new container
// pick up the lock as soon as it's released, without ever removing the
// fail-closed guarantee (a lock that's genuinely never released still causes
// the lane to throw once the wait is exhausted).
// Governing: the readiness-split decision (analogous apps/node fix).

import {
  acquireSignerLeadership,
  type HeldSignerLeadership,
  type LeadershipLockPool,
  type SignerLeadership,
} from "@zucoins/node-core";

import type { BootLogger } from "./boot-lane.js";

export interface SignerLeadershipRetryDeps {
  readonly pool: LeadershipLockPool;
  readonly latch: SignerLeadership;
  readonly lockId?: number;
  readonly maxWaitMs: number;
  readonly logger: BootLogger;
  /** Test seam — defaults to the real node-core retry primitive. */
  readonly acquire?: typeof acquireSignerLeadership;
}

export async function acquireSignerLeadershipWithBoundedRetry(
  deps: SignerLeadershipRetryDeps,
): Promise<HeldSignerLeadership | null> {
  const acquire = deps.acquire ?? acquireSignerLeadership;
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), deps.maxWaitMs);
  try {
    return await acquire({
      pool: deps.pool,
      latch: deps.latch,
      lockId: deps.lockId,
      signal: abort.signal,
      onWaiting: ({ attempt, delayMs }) => {
        deps.logger.info(
          `boot: signer leadership lock held by another instance, retrying ` +
            `(attempt ${attempt}, next wait ${delayMs}ms)`,
        );
      },
      onError: (err, attempt) => {
        deps.logger.error(`boot: signer leadership lock attempt ${attempt} errored`, err);
      },
    });
  } finally {
    clearTimeout(timer);
  }
}
