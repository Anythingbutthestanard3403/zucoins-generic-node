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
 * Positive ownership probe on the dedicated leadership connection (ZTR-1156).
 * Confirms THIS backend pid still holds the session advisory lock — independent
 * of transport `error`/`end`. Uses the single-bigint form of the lock id
 * (`objsubid = 1`) that `pg_try_advisory_lock(bigint)` takes.
 *
 * Parameter $1 is the lock id (bigint). Returns one row with `owned = true`
 * when the current backend still holds it.
 */
export const ASSERT_LEADERSHIP_OWNED_SQL = `
SELECT EXISTS (
  SELECT 1
    FROM pg_locks
   WHERE locktype = 'advisory'
     AND granted = true
     AND pid = pg_backend_pid()
     AND objsubid = 1
     AND classid = (($1::bigint >> 32) & 4294967295)::int
     AND objid = ($1::bigint & 4294967295)::int
) AS owned`.replace(/\s+/g, " ").trim();

/** Default interval for the positive ownership watch (ms). Overridable via options. */
export const DEFAULT_LEADERSHIP_OWNERSHIP_ASSERT_INTERVAL_MS = 2_000;

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
  /**
   * Stop the positive ownership watch (if any). Safe to call after loss/release;
   * does not release the lock — use {@link release} for that.
   */
  stopOwnershipWatch(): void;
  release(): Promise<void>;
}

export interface TryAcquireSignerLeadershipOptions {
  /**
   * How often to re-assert ownership server-side on the dedicated connection.
   * `0` disables the watch (tests that only drive loss via error/end).
   * Default {@link DEFAULT_LEADERSHIP_OWNERSHIP_ASSERT_INTERVAL_MS}.
   */
  readonly ownershipAssertIntervalMs?: number;
  /**
   * Timer seams so the ownership watch is unit-testable without real wall time.
   * Production leaves these undefined and uses the global timers.
   */
  readonly setIntervalFn?: (handler: () => void, ms: number) => unknown;
  readonly clearIntervalFn?: (handle: unknown) => void;
}

/**
 * ONE non-blocking attempt. Returns the held lock (latch flipped to held, loss detection
 * armed) or `null` when another instance holds it — never blocks waiting for the holder.
 * A query error releases the probe connection and rethrows so the caller's backoff retries;
 * an unreachable database therefore never silently reads as leadership.
 *
 * `lockIdOrOptions` accepts the legacy positional `lockId` number OR an options bag so
 * existing callers (`tryAcquire(pool, latch)`, `tryAcquire(pool, latch, lockId)`) keep
 * working while ownership-watch knobs travel in the options bag.
 */
export async function tryAcquireSignerLeadership(
  pool: LeadershipLockPool,
  latch: SignerLeadership,
  lockIdOrOptions: number | TryAcquireSignerLeadershipOptions = SIGNER_LEADERSHIP_LOCK_ID,
  maybeOptions?: TryAcquireSignerLeadershipOptions,
): Promise<HeldSignerLeadership | null> {
  const lockId =
    typeof lockIdOrOptions === "number" ? lockIdOrOptions : SIGNER_LEADERSHIP_LOCK_ID;
  const options: TryAcquireSignerLeadershipOptions =
    typeof lockIdOrOptions === "number" ? (maybeOptions ?? {}) : lockIdOrOptions;
  const ownershipAssertIntervalMs =
    options.ownershipAssertIntervalMs ?? DEFAULT_LEADERSHIP_OWNERSHIP_ASSERT_INTERVAL_MS;
  const setIntervalFn = options.setIntervalFn ?? ((handler, ms) => setInterval(handler, ms));
  const clearIntervalFn =
    options.clearIntervalFn ?? ((handle) => clearInterval(handle as ReturnType<typeof setInterval>));

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
  /**
   * True only when the dedicated connection's transport died (`error`/`end`).
   * Transport death frees the session advisory lock server-side, so unlock is skipped.
   * Ownership-assert loss is the opposite: the backend is often still alive and still
   * holds the lock — never treat it as transport-dead (ZTR-1156 bare-pool SPOF).
   */
  let transportDead = false;
  // release disposition for this handle. Separates connection-loss (`lost`) from the
  // terminal outcome of release so unlock-fail never looks like a clean unlock on
  // re-entry (boot-lane retains the handle after unlock-fail — re-entrancy SPOF).
  // open — no terminal release yet
  // pooled — confirmed unlock / transport death / ownership destroy; session not locked-in-pool
  // failed — unlock/destroy failed; session deliberately NOT pooled; sticky error
  let releaseOutcome: "open" | "pooled" | "failed" = "open";
  let stickyReleaseErr: Error | undefined;
  // Single-flight: installed synchronously on first entry, before any await. Concurrent
  // release during unlock-query / end must join this promise — never fall through to
  // client.release while outcome is still "open" and lost already true (d72fd92).
  let releaseFlight: Promise<void> | undefined;
  let ownershipTimer: unknown;
  const listeners: Array<(reason: string) => void> = [];
  const stopOwnershipWatch = (): void => {
    if (ownershipTimer !== undefined) {
      clearIntervalFn(ownershipTimer);
      ownershipTimer = undefined;
    }
  };

  const destroySessionMandatory = async (context: string, cause?: unknown): Promise<void> => {
    const causeMsg =
      cause === undefined ? undefined : cause instanceof Error ? cause.message : String(cause);
    if (typeof client.end !== "function") {
      stickyReleaseErr = new Error(
        `${context} and session has no end() destroy path${
          causeMsg === undefined ? "" : `: cause=${causeMsg}`
        }`,
        cause === undefined ? undefined : { cause },
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
        `${context} and session destroy also failed${
          causeMsg === undefined ? "" : `: cause=${causeMsg}`
        }; destroy=${destroyMsg}`,
        { cause: cause ?? destroyErr },
      );
      releaseOutcome = "failed";
      throw stickyReleaseErr;
    }
  };

  /**
   * Ownership loss while the session may still be alive: destroy the dedicated
   * connection so the advisory lock cannot outlive local authority. Standbys must
   * not wait for process shutdown. Prefer destroy over unlock+pool-return so a
   * flaky unlock cannot bare-pool a still-locked client (ZTR-1156 SPOF).
   */
  const disposeAfterOwnershipLoss = async (): Promise<void> => {
    stopOwnershipWatch();
    client.removeListener("error", onError);
    client.removeListener("end", onEnd);
    // Already latched lost by onLoss. Destroy is the terminal disposition — do not
    // client.release() afterward (end/release(true) already retired the session).
    try {
      await destroySessionMandatory(
        "signer leadership ownership lost",
      );
    } catch (err) {
      // stickyReleaseErr + failed already set inside destroySessionMandatory.
      throw err;
    }
    // Destroy succeeded — lock free server-side with the session. Terminal OK for
    // later release() joins; never pool-return after end.
    releaseOutcome = "pooled";
  };

  const onLoss = (event: "error" | "end" | "ownership") => (err?: Error): void => {
    if (lost) return;
    lost = true;
    if (event === "error" || event === "end") {
      transportDead = true;
    }
    stopOwnershipWatch();
    const reason =
      event === "ownership"
        ? err?.message ?? "signer leadership ownership assertion failed"
        : `signer leadership lock connection ${event}${
            err === undefined ? "" : `: ${err.message}`
          }`;
    // Latch first, synchronously, before any observer runs.
    // Transport death: lock is already free server-side — another instance may acquire now.
    // Ownership loss: lock may still be held — disposeAfterOwnershipLoss frees it next.
    latch.markLost(reason);
    for (const listener of listeners) listener(reason);

    if (event === "ownership" && releaseFlight === undefined) {
      // Arm single-flight immediately (sync) so concurrent release() joins destroy
      // instead of observing open+lost and bare-pooling (d72fd92 class).
      releaseFlight = disposeAfterOwnershipLoss();
      void releaseFlight.catch(() => {
        // Rejection retained on releaseFlight for release() / boot quarantine.
      });
    }
  };
  const onError = onLoss("error");
  const onEnd = onLoss("end");
  const onOwnershipLoss = onLoss("ownership");
  client.on("error", onError);
  client.on("end", onEnd);

  latch.markAcquired();

  // Positive ownership watch — converts silence into a definite answer. A failed
  // assertion latches lost and destroys the live session (not the transport-death
  // skip-unlock path). Transport error/end on the probe still uses onError/onEnd.
  if (ownershipAssertIntervalMs > 0) {
    let assertInFlight = false;
    ownershipTimer = setIntervalFn(() => {
      if (lost || assertInFlight) return;
      assertInFlight = true;
      void client
        .query(ASSERT_LEADERSHIP_OWNED_SQL, [lockId])
        .then((result) => {
          if (lost) return;
          const owned =
            (result.rows[0] as { owned?: unknown } | undefined)?.owned === true;
          if (!owned) {
            onOwnershipLoss(
              new Error(
                "signer leadership ownership assertion failed: lock not held by this backend",
              ),
            );
          }
        })
        .catch((err: unknown) => {
          if (lost) return;
          const msg = err instanceof Error ? err.message : String(err);
          onOwnershipLoss(
            new Error(`signer leadership ownership assertion failed: ${msg}`, {
              cause: err,
            }),
          );
        })
        .finally(() => {
          assertInFlight = false;
        });
    }, ownershipAssertIntervalMs);
  }

  const runRelease = async (): Promise<void> => {
    stopOwnershipWatch();
    client.removeListener("error", onError);
    client.removeListener("end", onEnd);
    latch.markLost("signer leadership released");
    // Skip unlock ONLY on true transport death — the server already dropped the
    // session lock. Ownership-assert loss must NOT take this branch (transportDead
    // stays false); that path destroys via disposeAfterOwnershipLoss instead.
    // Live unlock must succeed OR the session must be destroyed — never return a
    // still-locked connection to the pool (idle pooled holder = permanent SPOF).
    let unlockErr: unknown;
    if (!transportDead) {
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
    // Transport-dead or confirmed unlock: return the (unlocked / dead) client to the pool.
    client.release();
  };

  return {
    onLost(listener: (reason: string) => void): void {
      if (lost) return; // already lost — never resurrect a dead lock
      listeners.push(listener);
    },
    stopOwnershipWatch,
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
      // Ownership-loss already arms releaseFlight with disposeAfterOwnershipLoss.
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
  /** Forwarded to each {@link tryAcquireSignerLeadership} attempt (ownership watch). */
  readonly ownershipAssertIntervalMs?: number;
  readonly setIntervalFn?: TryAcquireSignerLeadershipOptions["setIntervalFn"];
  readonly clearIntervalFn?: TryAcquireSignerLeadershipOptions["clearIntervalFn"];
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

  const tryOptions: TryAcquireSignerLeadershipOptions = {
    ownershipAssertIntervalMs: options.ownershipAssertIntervalMs,
    setIntervalFn: options.setIntervalFn,
    clearIntervalFn: options.clearIntervalFn,
  };

  let attempt = 0;
  while (!aborted()) {
    try {
      const held = await tryAcquire(
        options.pool,
        options.latch,
        options.lockId ?? SIGNER_LEADERSHIP_LOCK_ID,
        tryOptions,
      );
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
