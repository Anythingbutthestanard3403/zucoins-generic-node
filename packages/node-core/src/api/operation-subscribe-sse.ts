// SSE accelerator for GET /v1/operations/:operation_id/subscribe
// Emits only the six-field lifecycle projection.
//
// Cursor: this route binds to the operation's own row_version (not the tenant-wide
// implementer_seq). A reconnecting client receives the *current* state at minimum;
// intermediate transitions are best-effort via subscribe + poll. No durable
// per-operation event cursor is required (ticket AC: converge on current state).
//
// Framing reuses the shared SSE helpers from reporting/event-stream-sse (api may
// import reporting; reporting must not import api).

import {
  formatSseFrame,
  formatSseHeartbeat,
  sseComment,
  SSE_HEADERS,
  SSE_MEDIA_TYPE,
  type SseSink,
} from "../reporting/event-stream-sse.js";
import { startSseLifecycle } from "../reporting/sse-connection-lifecycle.js";
import {
  renderOperationLifecycleBody,
  type OperationLifecycleRow,
  type OperationLifecycleStore,
} from "./subscription-handle.js";

export { SSE_HEADERS, SSE_MEDIA_TYPE };

export const OPERATION_SUBSCRIBE_SSE_EVENT = "operation.lifecycle" as const;

export interface OperationSubscribeSseConfig {
  readonly lifecycleStore: OperationLifecycleStore;
  readonly heartbeatMs?: number;
  readonly pollMs?: number;
  readonly setInterval?: (handler: () => void, ms: number) => unknown;
  readonly clearInterval?: (handle: unknown) => void;
}

export interface OperationSubscribeSseConnection {
  close(): void;
}

export interface OperationSubscribeAccelerator {
  open(
    input: {
      readonly operationId: string;
      readonly initial: OperationLifecycleRow;
    },
    sink: SseSink,
  ): OperationSubscribeSseConnection;
}

const DEFAULT_POLL_MS = 250;

function frameLifecycle(row: OperationLifecycleRow): string {
  return formatSseFrame({
    id: String(row.rowVersion),
    event: OPERATION_SUBSCRIBE_SSE_EVENT,
    data: renderOperationLifecycleBody(row),
  });
}

/**
 * Open a lifecycle SSE stream for one operation. Concurrent connections on the
 * same handle are permitted and each receives independent consistent state.
 */
export function createOperationSubscribeAccelerator(
  config: OperationSubscribeSseConfig,
): OperationSubscribeAccelerator {
  const pollMs = config.pollMs ?? DEFAULT_POLL_MS;

  return {
    open(input, sink): OperationSubscribeSseConnection {
      // Written only by the lifecycle's close; read by emit below.
      const gate = { closed: false };
      let lastRowVersion = 0;
      // Track last rendered body so a same-version no-op poll does not re-emit.
      let lastBody: string | null = null;

      const emit = (row: OperationLifecycleRow): void => {
        if (gate.closed) return;
        if (row.operationId !== input.operationId) return;
        // Monotonic by row_version: skip stale / duplicate versions.
        if (row.rowVersion < lastRowVersion) return;
        const body = renderOperationLifecycleBody(row);
        if (row.rowVersion === lastRowVersion && body === lastBody) return;
        sink.write(frameLifecycle(row));
        lastRowVersion = row.rowVersion;
        lastBody = body;
      };

      sink.write(sseComment("connected"));

      // Subscribe BEFORE the initial emit so a concurrent advance cannot be missed.
      const unsubscribe = config.lifecycleStore.subscribe(input.operationId, (row) => {
        emit(row);
      });

      // Snapshot replay: always emit current state so reconnect converges.
      emit(input.initial);

      const lifecycle = startSseLifecycle({
        gate,
        pollMs,
        heartbeatMs: config.heartbeatMs,
        setInterval: config.setInterval,
        clearInterval: config.clearInterval,
        poll: async () => {
          const row = await config.lifecycleStore.getLifecycle(input.operationId);
          // emit re-checks isClosed; the null guard is this route's own.
          if (row !== null) emit(row);
        },
        heartbeat: () => sink.write(formatSseHeartbeat()),
        unsubscribe,
        closeSink: () => sink.close(),
      });

      return {
        close: () => lifecycle.close(),
      };
    },
  };
}
