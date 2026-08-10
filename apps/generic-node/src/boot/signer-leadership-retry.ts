// Retry wrapper around acquireSignerLeadership for the boot lane's
// signer-leadership step (ZPAY-252 / D8.102 class).
//
// During a Railway rolling deploy the outgoing container keeps the advisory
// lock until it is SIGTERM'd — and Railway only SIGTERM's once the NEW
// instance answers /health/ready. Leadership is therefore NON-gating for
// ready; this wrapper waits (abortable on SIGTERM) until the prior holder
// releases, with two distinct log lines:
//   - waiting-for-handover: routine overlap, prior holder still alive
//   - prolonged-wait: wait has exceeded the configured warn threshold
//     (operator signal that the prior holder may be wedged — not a
//     hard failure; acquisition continues until abort)
//
// A short hard timeout would leave a deploy-ready replica that never signs.
// Fail-closed remains: SIGTERM / graceful stop aborts the wait; a lock that
// is never released keeps this process as a ready non-signer until operators
// intervene (or the prior holder dies and the session lock self-releases).

import {
  acquireSignerLeadership,
  type HeldSignerLeadership,
  type LeadershipLockPool,
  type SignerLeadership,
} from "@zucoins/node-core";

import type { BootLogger } from "./boot-lane.js";

/** Default wall-clock before the prolonged-wait (possible deadlock) log. */
export const DEFAULT_SIGNER_LEADERSHIP_PROLONGED_WAIT_MS = 30_000;

export interface SignerLeadershipRetryDeps {
  readonly pool: LeadershipLockPool;
  readonly latch: SignerLeadership;
  readonly lockId?: number;
  /**
   * Optional cooperative abort (SIGTERM / graceful stop). When omitted the
   * wait continues until the lock is acquired — correct for the post-ready
   * background-style boot step.
   */
  readonly signal?: AbortSignal;
  /**
   * Wall-clock after which waiting logs switch from handover to
   * prolonged-wait. Does NOT abort acquisition. Default 30s.
   */
  readonly prolongedWaitMs?: number;
  readonly logger: BootLogger;
  /** Test seam — defaults to the real node-core retry primitive. */
  readonly acquire?: typeof acquireSignerLeadership;
}

export async function acquireSignerLeadershipWithBoundedRetry(
  deps: SignerLeadershipRetryDeps,
): Promise<HeldSignerLeadership | null> {
  const acquire = deps.acquire ?? acquireSignerLeadership;
  const prolongedWaitMs =
    deps.prolongedWaitMs ?? DEFAULT_SIGNER_LEADERSHIP_PROLONGED_WAIT_MS;
  const startedAt = Date.now();
  let prolongedLogged = false;

  return await acquire({
    pool: deps.pool,
    latch: deps.latch,
    lockId: deps.lockId,
    signal: deps.signal,
    onWaiting: ({ attempt, delayMs }) => {
      const waitedMs = Date.now() - startedAt;
      if (!prolongedLogged && waitedMs >= prolongedWaitMs) {
        prolongedLogged = true;
        deps.logger.error(
          `boot: signer leadership prolonged wait (${waitedMs}ms) — prior holder may be wedged; ` +
            `continuing to wait (attempt ${attempt}, next wait ${delayMs}ms). ` +
            `Deploy readiness is independent of this lock; money engines stay unarmed until acquired.`,
        );
        return;
      }
      deps.logger.info(
        `boot: signer leadership waiting-for-handover ` +
          `(attempt ${attempt}, waited ${waitedMs}ms, next wait ${delayMs}ms)`,
      );
    },
    onError: (err, attempt) => {
      deps.logger.error(`boot: signer leadership lock attempt ${attempt} errored`, err);
    },
  });
}
