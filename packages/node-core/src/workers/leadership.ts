// Process-wide signer leadership (step 1).
//
// Exclusion is arbitrated by the database, never by this module: one dedicated, never-pooled
// connection holds a session-scoped advisory lock for the process lifetime. A session lock is
// CONNECTION-scoped, which buys two properties a heartbeat row cannot:
// - it self-releases when the holder's connection dies, so a crash needs no release logic;
// - for the same reason, losing the connection silently frees the lock server-side while
// this process still believes it holds it. Loss MUST therefore be derived from the
// connection's `error`/`end` event and MUST flip the latch before any other instance
// could acquire. Wall-clock staleness never grants or releases leadership.
//
// The connection is a seam, not a driver import: acquisition is non-blocking (`pg_try_...`)
// and retried with jittered backoff by the caller's boot lane, so HTTP bind and the liveness
// probe are never gated on the outgoing instance releasing its lock — the overlap-deploy
// deadlock class.

// Session advisory lock id for signer leadership, ASCII "SLL". Never change it: two
// instances using different ids would not interlock, defeating the exclusion entirely.
export const SIGNER_LEADERSHIP_LOCK_ID = 0x534c4c; // 5_459_020

export const TRY_ACQUIRE_LEADERSHIP_SQL = "SELECT pg_try_advisory_lock($1) AS locked";
export const RELEASE_LEADERSHIP_SQL = "SELECT pg_advisory_unlock($1) AS released";

/**
 * One dedicated database connection. Shaped after a pooled client so a real driver's client
 * satisfies it structurally; `release` returns it to its pool (or closes it outright).
 *
 * `end` hard-closes the underlying session (pg `Client.end` / pool-client destroy). It is
 * **required**, not optional: on unlock failure the holder MUST destroy the session so a
 * session-scoped advisory lock cannot survive on an idle pooled connection and SPOF the
 * cluster. Adapters that only implement `release` are unsafe and rejected at
 * the type boundary.
 */
export interface LeadershipLockClient {
  query(sql: string, values?: readonly unknown[]): Promise<{ rows: unknown[] }>;
  on(event: "error" | "end", listener: (err?: Error) => void): void;
  removeListener(event: "error" | "end", listener: (err?: Error) => void): void;
  release(): void;
  /**
   * Hard-close the session so a session-scoped advisory lock dies with it.
   * Must not return the connection to an idle pool still holding the lock.
   */
  end(): void | Promise<void>;
}

export interface LeadershipLockPool {
  connect(): Promise<LeadershipLockClient>;
}

/**
 * In-process ownership latch. Non-secret boolean state — no key material ever touches it
 * It satisfies the `core` SignerLeadershipLatch port structurally, and
 * `signUnderLease` — the single signing chokepoint — refuses while `held` is false.
 *
 * Invariant: `held === true` IFF this process holds the leadership lock. The database allows
 * at most one holder, so at most one process has `held === true` and signs at any instant.
 */
export class SignerLeadership {
  static readonly UNACQUIRED_REASON = "boot: signer leadership lock not yet acquired";

  #held = false;
  #reason: string | undefined = SignerLeadership.UNACQUIRED_REASON;
  /**
   * Process flush bridge installed by the shutdown registry.
   * {@link trackSigningInflight} forwards every signUnderLease body into the
   * registry inflight set — non-opt-in for the real chokepoint.
   * Freeze-on-first-install: a later setSigningInflightTracker throws so a
   * noop cannot wipe the flush bridge mid-flight.
   */
  #signingInflightTracker: ((work: Promise<unknown>) => void) | undefined;
  #signingInflightTrackerFrozen = false;

  /** Called the instant the lock is confirmed acquired, never on an attempt. */
  markAcquired(): void {
    this.#held = true;
    this.#reason = undefined;
  }

  /** Called the instant the lock is lost or released. `reason` is a non-secret operator string. */
  markLost(reason: string): void {
    this.#held = false;
    this.#reason = reason;
  }

  get held(): boolean {
    return this.#held;
  }

  get reason(): string | undefined {
    return this.#reason;
  }

  /**
   * Install the custody claim boundary flush bridge. Freeze-on-first-install — second call
   * throws. Shutdown registry calls this once at construction so every
   * subsequent signUnderLease body is observed without caller memory.
   */
  setSigningInflightTracker(tracker: (work: Promise<unknown>) => void): void {
    if (this.#signingInflightTrackerFrozen) {
      throw new Error(
        "setSigningInflightTracker: already installed — refuse replace (flush bridge)",
      );
    }
    this.#signingInflightTracker = tracker;
    this.#signingInflightTrackerFrozen = true;
  }

  /** chokepoint hook — see SignerLeadershipLatch.trackSigningInflight. */
  trackSigningInflight(work: Promise<unknown>): void {
    this.#signingInflightTracker?.(work);
  }
}

/** A held lock. `release` is the graceful handoff; loss is reported through the latch. */
export interface HeldSignerLeadership {
  /** Fired at most once when the dedicated connection dies. The latch is already false. */
  onLost(listener: (reason: string) => void): void;
  release(): Promise<void>;
}

/**
 * ONE non-blocking attempt. Returns the held lock (latch flipped to held, loss detection
 * armed) or `null` when another instance holds it — never blocks waiting for the holder.
 * A query error releases the probe connection and rethrows so the caller's backoff retries;
 * an unreachable database therefore never silently reads as leadership.
 */
export async function tryAcquireSignerLeadership(
  pool: LeadershipLockPool,
  latch: SignerLeadership,
  lockId: number = SIGNER_LEADERSHIP_LOCK_ID,
): Promise<HeldSignerLeadership | null> {
  const client = await pool.connect();
  let locked = false;
  try {
    const result = await client.query(TRY_ACQUIRE_LEADERSHIP_SQL, [lockId]);
    locked = (result.rows[0] as { locked?: unknown } | undefined)?.locked === true;
  } catch (err) {
    client.release();
    throw err;
  }
  if (!locked) {
    // Held elsewhere — hand the probe connection straight back rather than pinning it.
    client.release();
    return null;
  }

  // From here the connection is dedicated: it is never returned until release or loss, so
  // the session-scoped lock persists for as long as this process holds leadership.
  let lost = false;
  // release disposition for this handle. Separates connection-loss (`lost`) from the
  // terminal outcome of release so unlock-fail never looks like a clean unlock on
  // re-entry (boot-lane retains the handle after unlock-fail — re-entrancy SPOF).
  // open — no terminal release yet
  // pooled — confirmed unlock (or prior connection loss); connection returned to pool
  // failed — unlock failed; session destroyed or deliberately NOT pooled; sticky error
  let releaseOutcome: "open" | "pooled" | "failed" = "open";
  let stickyReleaseErr: Error | undefined;
  // Single-flight: installed synchronously on first entry, before any await. Concurrent
  // release during unlock-query / end must join this promise — never fall through to
  // client.release while outcome is still "open" and lost already true (d72fd92).
  let releaseFlight: Promise<void> | undefined;
  const listeners: Array<(reason: string) => void> = [];
  const onLoss = (event: "error" | "end") => (err?: Error): void => {
    if (lost) return;
    lost = true;
    const reason = `signer leadership lock connection ${event}${
      err === undefined ? "" : `: ${err.message}`
    }`;
    // Latch first, synchronously, before any observer runs: the lock is already free
    // server-side, so another instance may acquire at any moment from now.
    latch.markLost(reason);
    for (const listener of listeners) listener(reason);
  };
  const onError = onLoss("error");
  const onEnd = onLoss("end");
  client.on("error", onError);
  client.on("end", onEnd);

  latch.markAcquired();

  const runRelease = async (): Promise<void> => {
    client.removeListener("error", onError);
    client.removeListener("end", onEnd);
    latch.markLost("signer leadership released");
    // A dead connection has already freed the lock server-side; unlocking would only
    // reject. Live unlock must succeed OR the session must be destroyed — never return a
    // still-locked connection to the pool (idle pooled holder = permanent SPOF).
    let unlockErr: unknown;
    if (!lost) {
      try {
        const result = await client.query(RELEASE_LEADERSHIP_SQL, [lockId]);
        const unlocked =
          (result.rows[0] as { released?: unknown } | undefined)?.released === true;
        if (!unlocked) {
          unlockErr = new Error("pg_advisory_unlock did not confirm release");
        }
      } catch (err) {
        unlockErr = err;
      }
    }
    lost = true;
    if (unlockErr !== undefined) {
      // Mandatory destroy — never bare-release a still-locked session into the idle
      // pool (that pins pg_advisory_lock forever and SPOFs standbys). end is required
      // on the client contract; no release fallback exists on this path.
      // Mark failed BEFORE any throw so a concurrent/second release cannot reach the
      // clean client.release path with unlockErr cleared.
      const unlockMsg =
        unlockErr instanceof Error ? unlockErr.message : String(unlockErr);
      if (typeof client.end !== "function") {
        // Structural cast / JS adapter slipped past the type boundary — refuse the
        // SPOF path rather than pool-return. Lock may still be held server-side;
        // boot-lane quarantines on this throw (step 8 failed unlock).
        stickyReleaseErr = new Error(
          `signer leadership unlock failed and session has no end() destroy path: unlock=${unlockMsg}`,
          { cause: unlockErr },
        );
        releaseOutcome = "failed";
        throw stickyReleaseErr;
      }
      let destroyErr: unknown;
      try {
        await Promise.resolve(client.end());
      } catch (err) {
        destroyErr = err;
      }
      if (destroyErr !== undefined) {
        const destroyMsg =
          destroyErr instanceof Error ? destroyErr.message : String(destroyErr);
        stickyReleaseErr = new Error(
          `signer leadership unlock failed and session destroy also failed: unlock=${unlockMsg}; destroy=${destroyMsg}`,
          { cause: unlockErr },
        );
        releaseOutcome = "failed";
        throw stickyReleaseErr;
      }
      // Destroy succeeded — lock free server-side — but still surface unlock failure
      // so boot-lane quarantines (OPS: failed unlock → quarantine, not clean exit).
      stickyReleaseErr =
        unlockErr instanceof Error ? unlockErr : new Error(String(unlockErr));
      releaseOutcome = "failed";
      throw stickyReleaseErr;
    }
    releaseOutcome = "pooled";
    client.release();
  };

  return {
    onLost(listener: (reason: string) => void): void {
      if (lost) return; // already lost — never resurrect a dead lock
      listeners.push(listener);
    },
    async release(): Promise<void> {
      // Idempotent / fail-closed on re-entry. Boot-lane retains the handle after unlock
      // failure (quarantine); a second release must never bare-pool a still
      // locked session just because `lost` already flipped on the first attempt.
      if (releaseOutcome === "pooled") return;
      if (releaseOutcome === "failed") {
        throw (
          stickyReleaseErr ??
          new Error(
            "signer leadership unlock previously failed; session was not returned to pool",
          )
        );
      }
      // Single-flight BEFORE any await: concurrent callers during unlock/end join the
      // in-flight promise instead of observing open+lost and bare-pooling.
      if (releaseFlight === undefined) {
        releaseFlight = runRelease();
      }
      return releaseFlight;
    },
  };
}

export interface AcquireSignerLeadershipOptions {
  readonly pool: LeadershipLockPool;
  readonly latch: SignerLeadership;
  /** Cooperative abort — resolves `null` promptly once set (shutdown during the wait). */
  readonly signal?: { readonly aborted: boolean };
  readonly lockId?: number;
  /** Observability hook before each backoff wait (lock still held elsewhere). */
  readonly onWaiting?: (info: { attempt: number; delayMs: number }) => void;
  /** A single attempt errored (transient database fault) — non-fatal, backs off and retries. */
  readonly onError?: (err: unknown, attempt: number) => void;
  readonly baseDelayMs?: number;
  readonly maxDelayMs?: number;
  /** Seams so the retry policy is testable without real time or real randomness. */
  readonly sleep?: (ms: number) => Promise<void>;
  readonly random?: () => number;
  readonly tryAcquire?: typeof tryAcquireSignerLeadership;
}

/**
 * Retry {@link tryAcquireSignerLeadership} with exponential backoff and FULL jitter until the
 * lock is acquired or the caller aborts. Full jitter (delay ∈ [0, ceiling)) stops several fresh
 * instances from retrying in lockstep on the same released lock.
 */
export async function acquireSignerLeadership(
  options: AcquireSignerLeadershipOptions,
): Promise<HeldSignerLeadership | null> {
  const tryAcquire = options.tryAcquire ?? tryAcquireSignerLeadership;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const random = options.random ?? Math.random;
  const base = options.baseDelayMs ?? 250;
  const max = options.maxDelayMs ?? 2_000;

  const aborted = (): boolean => options.signal?.aborted === true;

  let attempt = 0;
  while (!aborted()) {
    try {
      const held = await tryAcquire(options.pool, options.latch, options.lockId);
      if (held !== null) return held;
    } catch (err) {
      options.onError?.(err, attempt);
    }
    if (aborted()) break;
    attempt += 1;
    const ceiling = Math.min(max, base * 2 ** Math.min(attempt, 8));
    const delayMs = Math.floor(random() * ceiling);
    options.onWaiting?.({ attempt, delayMs });
    await sleep(delayMs);
  }
  return null;
}
