// non-blocking signer-leadership acquire-with-backoff.
//
// Boot step 1 requires the process-wide signer leadership lock; reconcile posture requires
// that acquisition NEVER gate HTTP bind. The pattern is `try`-acquire + exponential
// backoff with full jitter, abortable on shutdown signal — so a new overlap-deploy
// instance binds /health (liveness 200, readiness reflecting missing leadership as
// a non-gating report) while it waits, and the platform can SIGTERM the old
// instance.
//
// The concrete session-advisory-lock primitive (pg_try_advisory_lock on a dedicated
// connection) is. This module freezes only the
// transport-free acquire loop so boot / health can share one policy without
// depending on a Postgres driver inside node-core.

export interface LeadershipAcquireSignal {
  readonly aborted: boolean;
}

export interface AcquireLeadershipWithBackoffOptions<T> {
  /** One non-blocking attempt. Resolve the handle when held; resolve null when held elsewhere. */
  readonly tryAcquire: () => Promise<T | null>;
  /** Cooperative abort (SIGTERM / graceful stop). */
  readonly signal?: LeadershipAcquireSignal;
  /** Observability before each backoff wait. */
  readonly onWaiting?: (info: { attempt: number; delayMs: number }) => void;
  /** Transient try-acquire error (reported, then retried — never fatal alone). */
  readonly onError?: (err: unknown, attempt: number) => void;
  /** Sleep seam (tests inject a deterministic sleep). */
  readonly sleep?: (ms: number) => Promise<void>;
  /** Base backoff (ms). Default 250. */
  readonly baseDelayMs?: number;
  /** Backoff ceiling (ms). Default 2000. */
  readonly maxDelayMs?: number;
  /**
   * Optional PRNG in [0, 1). Default Math.random. Injected so tests can pin
   * jitter without monkey-patching Math.
   */
  readonly random?: () => number;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Poll `tryAcquire` with exponential backoff + full jitter until the lock is
 * acquired or the caller aborts. Returns the held handle, or `null` if aborted
 * before acquisition (shutdown during wait). A single try-attempt error is
 * reported and retried; it never silently assumes leadership.
 */
export async function acquireLeadershipWithBackoff<T>(
  opts: AcquireLeadershipWithBackoffOptions<T>,
): Promise<T | null> {
  const sleep = opts.sleep ?? defaultSleep;
  const random = opts.random ?? Math.random;
  const base = opts.baseDelayMs ?? 250;
  const max = opts.maxDelayMs ?? 2_000;

  let attempt = 0;
  while (!opts.signal?.aborted) {
    try {
      const held = await opts.tryAcquire();
      if (held !== null) return held;
    } catch (err) {
      opts.onError?.(err, attempt);
    }
    if (opts.signal?.aborted) break;
    attempt += 1;
    const ceil = Math.min(max, base * 2 ** Math.min(attempt, 8));
    const delayMs = Math.floor(random() * ceil);
    opts.onWaiting?.({ attempt, delayMs });
    await sleep(delayMs);
  }
  return null;
}
