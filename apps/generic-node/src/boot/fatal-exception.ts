// Last-resort process net for uncaught exceptions (ZTR-1185).
//
// A synchronous throw that escapes a request handler propagates out of Node's
// request emit; with no `uncaughtException` handler the process dies on one
// unauthenticated request. Node routes unhandled rejections here too (origin
// "unhandledRejection") while no separate rejection listener is registered —
// one net, both classes.
//
// An uncaught exception means unknown state, so the posture is fail-closed,
// never swallow-and-continue: log through the central redactor
// (scrubErrorDetails — never a second hand-rolled one), run the entry point's
// graceful stop, and exit non-zero. Readiness is not flipped here because both
// graceful stops do it synchronously as their first step.
//
// Registered in both entry points before any listener is created, so the stop
// is wired late — it exists only once boot has built the server. A fatal before
// wiring exits 1 immediately. `tripped()` lets the composition root floor the
// graceful stop's exit code: a clean stop still exits 1 after a fatal.
//
// Everything is injected (emitter, exit, timers, logger) so tests never signal
// a real process — same discipline as graceful-stop.ts.

// Subpath, not the root barrel: stage1-main.ts imports this module, and the barrel
// would pull node-core's vault / signing-key / gateway-submit surfaces into the
// zero-custody entry point's module graph. observability is a leaf.
import { scrubErrorDetails } from "@zucoins/node-core/observability";

export interface FatalExceptionLogger {
  error(message: string, details?: unknown): void;
}

export interface FatalExceptionEmitter {
  on(event: "uncaughtException", listener: (err: unknown, origin: string) => void): unknown;
}

export interface FatalExceptionTimers {
  setTimeout(callback: () => void, ms: number): unknown;
}

/** Absolute deadline on the graceful stop attempt before a forced exit 1. */
export const DEFAULT_FATAL_EXCEPTION_TIMEOUT_MS = 15_000;

export interface InstallFatalExceptionHandlerOptions {
  readonly logger?: FatalExceptionLogger;
  readonly exit?: (code: number) => void;
  readonly timeoutMs?: number;
  readonly emitter?: FatalExceptionEmitter;
  readonly timers?: FatalExceptionTimers;
}

export interface FatalExceptionHandler {
  /** True once a fatal fired — any later exit code must be floored to non-zero. */
  readonly tripped: () => boolean;
  /** Late-wire the entry point's graceful stop, once boot has constructed it. */
  wire(beginGracefulStop: () => void): void;
}

const systemTimers: FatalExceptionTimers = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
};

export function installFatalExceptionHandler(
  options: InstallFatalExceptionHandlerOptions = {},
): FatalExceptionHandler {
  const {
    logger = { error: (message, details) => console.error(message, details) },
    exit = (code) => process.exit(code),
    timeoutMs = DEFAULT_FATAL_EXCEPTION_TIMEOUT_MS,
    emitter = process,
    timers = systemTimers,
  } = options;

  let tripped = false;
  let beginGracefulStop: (() => void) | undefined;

  emitter.on("uncaughtException", (err, origin) => {
    logger.error(
      `fatal: ${origin} — unknown state, stopping (exit will be non-zero)`,
      scrubErrorDetails({ err }),
    );
    if (tripped) return; // a second fatal while already on the exit path
    tripped = true;

    if (beginGracefulStop === undefined) {
      // Fatal before boot wired a stop: no in-flight work we know how to finish.
      exit(1);
      return;
    }
    // A stop that hangs before reaching its own bounded timers must not keep a
    // known-bad process alive.
    timers.setTimeout(() => exit(1), timeoutMs);
    try {
      beginGracefulStop();
    } catch (stopErr) {
      logger.error("fatal: graceful stop failed to start", scrubErrorDetails({ err: stopErr }));
      exit(1);
    }
  });

  return {
    tripped: () => tripped,
    wire: (stop) => {
      beginGracefulStop = stop;
    },
  };
}
