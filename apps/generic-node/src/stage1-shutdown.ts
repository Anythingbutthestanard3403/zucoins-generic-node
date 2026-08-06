// Stage-1 graceful stop — bounded, rejection-safe SIGTERM/SIGINT for the
// zero-custody composition root.
//
// Stage 1 has no signer authority, leadership lock, or money engines, so it
// deliberately does NOT call installGracefulStop (SHUTDOWN_SEQUENCE).
// Sequence here is HTTP drain → DB pool close → exit, with one absolute // contract-allow:drain:frozen structural vocabulary
// deadline covering both phases so a hung server.close() or pool.end() cannot
// wait for platform SIGKILL.
//
// Everything is injected (stop, timers, exit, emitter) so tests never signal
// a real process.

export interface Stage1ShutdownLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface Stage1ShutdownEmitter {
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface Stage1ShutdownTimers {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/** Default total budget for drain + database close (under typical SIGTERM→SIGKILL grace). */ // contract-allow:drain:frozen structural vocabulary
export const DEFAULT_STAGE1_SHUTDOWN_TIMEOUT_MS = 15_000;

export interface InstallStage1GracefulStopOptions {
  /**
   * Full Stage-1 teardown: stop accepting connections, drain, close DB. // contract-allow:drain:frozen structural vocabulary
   * Implementations MUST reject on server-close or database-close failure so
   * this installer can exit non-zero rather than leave an unhandled rejection.
   */
  readonly stop: () => Promise<void>;
  readonly timeoutMs?: number;
  readonly logger?: Stage1ShutdownLogger;
  readonly exit?: (code: number) => void;
  readonly signals?: readonly NodeJS.Signals[];
  readonly emitter?: Stage1ShutdownEmitter;
  readonly timers?: Stage1ShutdownTimers;
}

export interface Stage1GracefulStop {
  readonly stopping: () => boolean;
  handleSignal(signal: string): void;
}

const DEFAULT_SIGNALS: readonly NodeJS.Signals[] = ["SIGTERM", "SIGINT"];

const noopLogger: Stage1ShutdownLogger = {
  info: () => {},
  error: () => {},
};

const systemTimers: Stage1ShutdownTimers = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => clearTimeout(handle as NodeJS.Timeout),
};

export function installStage1GracefulStop(
  options: InstallStage1GracefulStopOptions,
): Stage1GracefulStop {
  const {
    stop,
    timeoutMs = DEFAULT_STAGE1_SHUTDOWN_TIMEOUT_MS,
    logger = noopLogger,
    exit = (code) => process.exit(code),
    signals = DEFAULT_SIGNALS,
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
    logger.info(`shutdown: ${signal} received, starting Stage-1 graceful stop`);

    let exited = false;
    const exitOnce = (code: number): void => {
      if (exited) return;
      exited = true;
      timers.clearTimeout(deadline);
      exit(code);
    };

    const deadline = timers.setTimeout(() => {
      logger.error(
        `shutdown: Stage-1 stop did not finish within ${timeoutMs}ms — exiting 1. Inspect hung HTTP connections and PostgreSQL pool.end(); the next process start is unaffected.`,
      );
      exitOnce(1);
    }, timeoutMs);

    void stop()
      .then(() => {
        logger.info("shutdown: Stage-1 stop complete, exiting 0");
        exitOnce(0);
      })
      .catch((err: unknown) => {
        logger.error(
          "shutdown: Stage-1 stop failed (HTTP drain or database close); exiting 1. No secrets are logged. Inspect the server and PostgreSQL pool before the next deploy.", // contract-allow:drain:frozen structural vocabulary
          err,
        );
        exitOnce(1);
      });
  }

  for (const signal of signals) {
    emitter.on(signal, () => handleSignal(signal));
  }

  return { stopping: () => stopping, handleSignal };
}
