// shared SSE connection lifecycle for the two node-core accelerators:
// reporting/event-stream-sse and api/operation-subscribe-sse
// Both arm an optional poll timer and an optional heartbeat timer, then release
// them in the same sequence behind an idempotent close. Only the per-tick data callback
// differs, so that is the parameter; the connection lifecycle itself is shared.
//
// Poll errors are delivery-only (OUTBOX_DECOUPLING): a rejected tick is swallowed here and
// never reaches durable state. The caller's poll body must re-check isClosed after its
// own await before writing to the sink — a tick already in flight when close lands must
// not emit.
//
// Boundary: reporting/ is a leaf in boundaries.test.ts (ALLOWED_INTERNAL_IMPORTS.reporting
// is empty), so this module imports nothing internal. api/ may import reporting.

/**
 * Closed-state cell. The caller creates it because its own subscribe listener is wired
 * up before the lifecycle is armed and must already be able to read closed-ness;
 * startSseLifecycle is the only writer.
 */
export interface SseClosedGate {
  closed: boolean;
}

export interface SseLifecycleOptions {
  readonly gate: SseClosedGate;
  /** Poll interval in ms. Values <= 0 disable the poll timer entirely. */
  readonly pollMs: number;
  /** Keep-alive comment interval in ms. undefined or <= 0 disables heartbeats. */
  readonly heartbeatMs?: number;
  /** One poll tick. Rejections are swallowed — delivery-only, never durable state. */
  readonly poll: () => Promise<void>;
  /** One heartbeat tick — writes a comment frame; never advances a cursor. */
  readonly heartbeat: () => void;
  /** Store/log unsubscribe. Invoked exactly once, on the first close. */
  readonly unsubscribe: () => void;
  /** Sink close. Invoked exactly once, after both timers are cleared. */
  readonly closeSink: () => void;
  readonly setInterval?: (handler: () => void, ms: number) => unknown;
  readonly clearInterval?: (handle: unknown) => void;
}

export interface SseLifecycle {
  close(): void;
}

/**
 * Arm the poll and heartbeat timers for one open SSE connection and return its idempotent
 * close. Call this *after* the caller has subscribed and replayed its backlog, so a
 * failed backlog read can unsubscribe without ever arming a timer.
 */
export function startSseLifecycle(options: SseLifecycleOptions): SseLifecycle {
  const gate = options.gate;
  const setIntervalFn = options.setInterval ?? globalThis.setInterval;
  const clearIntervalFn: (handle: unknown) => void =
    options.clearInterval ??
    ((handle) =>
      globalThis.clearInterval(handle as Parameters<typeof globalThis.clearInterval>[0]));

  let pollHandle: unknown;
  if (options.pollMs > 0) {
    pollHandle = setIntervalFn(() => {
      if (gate.closed) return;
      void options.poll().catch(() => {
        // Poll errors are delivery-only; durable state is unchanged.
      });
    }, options.pollMs);
  }

  let heartbeatHandle: unknown;
  if (options.heartbeatMs !== undefined && options.heartbeatMs > 0) {
    heartbeatHandle = setIntervalFn(() => {
      if (!gate.closed) options.heartbeat();
    }, options.heartbeatMs);
  }

  return {
    close() {
      if (gate.closed) return;
      gate.closed = true;
      options.unsubscribe();
      if (pollHandle !== undefined) clearIntervalFn(pollHandle);
      if (heartbeatHandle !== undefined) clearIntervalFn(heartbeatHandle);
      options.closeSink();
    },
  };
}
