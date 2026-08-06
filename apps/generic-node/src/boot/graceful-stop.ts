// Graceful stop (SIGTERM/SIGINT) for the v2 node.
//
// Governing: the frozen SHUTDOWN_SEQUENCE / SHUTDOWN_SEQUENCE_INVARIANTS + the
// axiom "persist before crossing an irreversible boundary" applied to shutdown.
//
// Frozen sequence — exit mirror of BOOT_SEQUENCE:
//   1. SIGNER_AUTHORITY_WITHDRAW — synchronous latch flip so request-driven
//      signers refuse immediately (before any await).
//   2. ENGINE_QUIESCE — money workers stop ACCEPTING new work (synchronous,
//      no await: a signal handler that stays synchronous cannot interleave
//      with a new request's handler — same invariant v1's shutdown.ts
//      documents). readiness flips false with the authority withdraw.
//   3. server.close() — stop accepting connections (the call itself is
//      synchronous); in-flight requests flush asynchronously.
//   4. INFLIGHT_SIGNING_COMPLETE — awaited, bounded by timeoutMs: in-flight
//      persist/sign steps complete; we never wait indefinitely.
//   5. LEADERSHIP_RELEASE — the process-wide signer leadership lock is
//      released cleanly ONLY after a successful flush. Releasing earlier
//      (or after a hung/failed flush) would let a successor acquire the
//      lock while residual async work on this instance could still execute.
//      On flush timeout or rejection the process exits holding the lock;
//      connection death frees it only after this process can no longer run
//      (LEADERSHIP_LOCK_EXIT.freed_by_connection_loss_or_failover).
//   6. exit(0) on clean stop; exit(1) on close/flush/release failure — never
//      a swallowed failure.
//
// Everything is injected (server, timers, exit, emitter) so tests never
// signal a real process — same discipline as v1's shutdown.ts.

import type { NodeReadiness } from "./readiness.js";
import type { BootLogger } from "./boot-lane.js";

export interface GracefulStopServer {
  close(callback: (err?: Error) => void): void;
}

export interface GracefulStopEmitter {
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface GracefulStopTimers {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export const DEFAULT_GRACEFUL_STOP_TIMEOUT_MS = 10_000;

export interface InstallGracefulStopOptions {
  readonly server: GracefulStopServer;
  readonly readiness: NodeReadiness;
  /**
   * Shutdown step SIGNER_AUTHORITY_WITHDRAW — synchronous. Flip the in-process signer
   * authority latch so new sign attempts refuse immediately. MUST NOT release
   * the DB leadership lock (that is `releaseLeadership`, last and only after
   * a successful flush).
   */
  readonly withdrawSignerAuthority?: () => void;
  /** Shutdown step ENGINE_QUIESCE — stop accepting new money-worker work (sync). */
  readonly stopWorkers?: () => void;
  /** Shutdown step INFLIGHT_SIGNING_COMPLETE — await in-flight persist/sign steps. */
  readonly flushInFlight?: () => Promise<void>;
  /**
   * Shutdown step LEADERSHIP_RELEASE — graceful unlock. Invoked only after a
   * successful flush. On flush timeout/rejection the stop exits without
   * calling this so the lock stays held until process/connection death.
   */
  readonly releaseLeadership?: () => Promise<void> | void;
  readonly timeoutMs?: number;
  readonly logger?: BootLogger;
  readonly exit?: (code: number) => void;
  readonly signals?: readonly NodeJS.Signals[];
  readonly emitter?: GracefulStopEmitter;
  readonly timers?: GracefulStopTimers;
}

export interface GracefulStop {
  readonly stopping: () => boolean;
  handleSignal(signal: string): void;
}

const noopLogger: BootLogger = {
  info: () => {},
  error: () => {},
};

const systemTimers: GracefulStopTimers = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => clearTimeout(handle as NodeJS.Timeout),
};

export function installGracefulStop(options: InstallGracefulStopOptions): GracefulStop {
  const {
    server,
    readiness,
    withdrawSignerAuthority,
    stopWorkers,
    flushInFlight,
    releaseLeadership,
    timeoutMs = DEFAULT_GRACEFUL_STOP_TIMEOUT_MS,
    logger = noopLogger,
    exit = (code) => process.exit(code),
    signals = ["SIGTERM", "SIGINT"],
    emitter = process,
    timers = systemTimers,
  } = options;

  let stopping = false;

  function handleSignal(signal: string): void {
    if (stopping) {
      logger.info(`shutdown: ${signal} received again — already stopping, ignoring`);
      return;
    }
    stopping = true;
    logger.info(`shutdown: ${signal} received, starting graceful stop`);

    // Steps 1-2: synchronous, no await (signer_authority_withdrawn_first +
    // engines_quiesce; sequencing invariant above).
    readiness.beginShutdown();
    withdrawSignerAuthority?.();
    stopWorkers?.();

    // Step 3: close() is synchronous to call; the flush completes via callback.
    server.close((closeErr) => {
      if (closeErr) {
        logger.error(
          "shutdown: generic-node HTTP server reported an error while draining; worker and database cleanup will continue. Inspect in-flight requests and the server error.",
          closeErr,
        );
      } else {
        logger.info("shutdown: server closed to new connections");
      }
      void flushThenMaybeRelease(closeErr);
    });
  }

  async function flushThenMaybeRelease(closeErr: Error | undefined): Promise<void> {
    const flushed = await flushBounded();
    if (!flushed) {
      // Shutdown invariant inflight_signing_completes_before_leadership_release: a hung or
      // failed flush must NOT hand the lock to a successor while residual async
      // work on this instance may still execute. Exit holding the lock; the
      // session-scoped advisory lock frees on connection/process death only
      // after this process can no longer run code.
      logger.error(
        `shutdown: in-flight work did not complete cleanly within ${timeoutMs}ms ` +
          "(or reported an error) — exiting without explicit leadership release; " +
          "lock frees on process/connection death",
      );
      exit(1);
      return;
    }

    // Step 5: release the signer leadership lock only after a successful flush.
    let releaseFailed = false;
    if (releaseLeadership !== undefined) {
      try {
        await releaseLeadership();
        readiness.setSignerLeadershipHeld(false);
        logger.info("shutdown: signer leadership released");
      } catch (err) {
        releaseFailed = true;
        logger.error(
          "shutdown: generic-node could not explicitly release signer leadership; shutdown will continue and connection close should release the lock. Verify that no replacement signer starts until this process exits.",
          err,
        );
      }
    }

    const failed = closeErr !== undefined || releaseFailed;
    logger.info(`shutdown: complete, exiting (${failed ? 1 : 0})`);
    exit(failed ? 1 : 0);
  }

  // Step 4: the in-flight persist steps race a bounded timer — bounded
  // graceful stop, never an indefinite wait. Timeout resolves false without
  // cancelling the underlying promise (we cannot abort arbitrary work); the
  // caller then takes the hard-fail no-release path above.
  function flushBounded(): Promise<boolean> {
    if (flushInFlight === undefined) return Promise.resolve(true);
    return new Promise<boolean>((resolve) => {
      let settled = false;
      const finish = (ok: boolean): void => {
        if (settled) return;
        settled = true;
        resolve(ok);
      };
      const handle = timers.setTimeout(() => finish(false), timeoutMs);
      flushInFlight()
        .then(() => {
          timers.clearTimeout(handle);
          finish(true);
        })
        .catch((err: unknown) => {
          timers.clearTimeout(handle);
          logger.error(
            "shutdown: generic-node could not flush all in-flight work before exit; no new work is accepted, but unfinished operations require reconciliation after restart. Inspect the operation queue and transaction status before retrying any submit.",
            err,
          );
          finish(false);
        });
    });
  }

  for (const signal of signals) {
    emitter.on(signal, () => handleSignal(signal));
  }

  return { stopping: () => stopping, handleSignal };
}
