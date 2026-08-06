// SSE accelerator for GET /v1/events/stream.
// Media type text/event-stream. Resume: query after_implementer_seq; Last-Event-ID, when
// supplied, must equal it or the node returns 400 cursor_mismatch.
//
// Framing reuses frameImplementerEventStream from events-read-service so the
// SSE data line is byte-identical to the pull-route proof representation for single-line
// proofs; multi-line proofs use formatSseFrame (SSE multi-data-line form).
//
// Heartbeats are SSE comment frames only — they never advance the resume cursor and never
// appear in a client's event-id dedup set.
//
// Delivery failure is irrelevant to operation truth: the event row is already committed by
// the implementer event log before any frame is attempted (OUTBOX_DECOUPLING).
//
// Boundary: this module lives in reporting/ and must not import api/ (boundaries.test.ts).

import {
  frameImplementerEventStream,
  resolveStreamCursor,
  type ServedImplementerEvent,
} from "./events-read-service.js";
import type { ImplementerEventLog, StoredImplementerEvent } from "./implementer-event-log.js";
import { startSseLifecycle } from "./sse-connection-lifecycle.js";

export const SSE_MEDIA_TYPE = "text/event-stream" as const;
export const SSE_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": SSE_MEDIA_TYPE,
  "cache-control": "no-cache",
  connection: "keep-alive",
});

export function sseComment(text: string): string {
  return `: ${text}\n\n`;
}

export function formatSseHeartbeat(): string {
  return sseComment("heartbeat");
}

/** Multi-line-safe SSE frame (used when proof text may contain newlines). */
export function formatSseFrame(input: {
  readonly id: string;
  readonly event: string;
  readonly data: string;
}): string {
  const dataLines = input.data.split("\n").map((line) => `data: ${line}`);
  return [`id: ${input.id}`, `event: ${input.event}`, ...dataLines, "", ""].join("\n");
}

export interface SseSink {
  write(chunk: string): void;
  close(): void;
}

export interface SseStreamOpenRequest {
  readonly requestId: string;
  readonly implementerId: string;
  readonly afterImplementerSeq: bigint | null;
  readonly lastEventId: string | null;
}

export interface SseConnection {
  readonly resumeSeq: bigint | null;
  close(): void;
}

export type SseRejectCode = "cursor_mismatch" | "service_unavailable";

export type SseOpenOutcome =
  | { readonly kind: "OPEN"; readonly connection: SseConnection }
  | { readonly kind: "REJECTED"; readonly code: SseRejectCode; readonly requestId: string };

export interface EventStreamAcceleratorConfig {
  readonly log: ImplementerEventLog;
  /** Keep-alive comment interval. Heartbeats never advance after_seq. */
  readonly heartbeatMs?: number;
  /** Poll interval for durable logs when process-local subscribe is insufficient. */
  readonly pollMs?: number;
  readonly backlogLimit?: number;
  readonly setInterval?: (handler: () => void, ms: number) => unknown;
  readonly clearInterval?: (handle: unknown) => void;
}

export interface EventStreamAccelerator {
  open(request: SseStreamOpenRequest, sink: SseSink): Promise<SseOpenOutcome>;
}

const DEFAULT_POLL_MS = 200;
const DEFAULT_BACKLOG_LIMIT = 500;

function frameEvent(event: ServedImplementerEvent): string {
  if (!event.proofRepresentation.includes("\n")) {
    return frameImplementerEventStream([event]);
  }
  return formatSseFrame({
    id: event.implementerSeq.toString(),
    event: event.eventType,
    data: event.proofRepresentation,
  });
}

export function createEventStreamAccelerator(
  config: EventStreamAcceleratorConfig,
): EventStreamAccelerator {
  const pollMs = config.pollMs ?? DEFAULT_POLL_MS;
  const backlogLimit = config.backlogLimit ?? DEFAULT_BACKLOG_LIMIT;

  return {
    async open(request: SseStreamOpenRequest, sink: SseSink): Promise<SseOpenOutcome> {
      const cursor = resolveStreamCursor(request.afterImplementerSeq, request.lastEventId);
      if (!cursor.ok) {
        return {
          kind: "REJECTED",
          code: "cursor_mismatch",
          requestId: request.requestId,
        };
      }

      // Written only by the lifecycle's close; read by the subscribe listener and poll.
      const gate = { closed: false };
      // Exclusive resume: lastSent starts at the cursor (0n when resuming from beginning).
      let lastSent = cursor.afterImplementerSeq ?? 0n;
      const buffer: ServedImplementerEvent[] = [];
      // No sink writes until backlog succeeds so cursor/backlog reject never commits SSE head.
      let committed = false;

      const flushBuffer = (): void => {
        if (!committed) return;
        buffer.sort((a, b) =>
          a.implementerSeq < b.implementerSeq ? -1 : a.implementerSeq > b.implementerSeq ? 1 : 0,
        );
        while (buffer.length > 0) {
          const next = buffer[0];
          if (next === undefined) break;
          if (next.implementerSeq <= lastSent) {
            buffer.shift();
            continue;
          }
          buffer.shift();
          sink.write(frameEvent(next));
          lastSent = next.implementerSeq;
        }
      };

      // Subscribe BEFORE the backlog read so a concurrent append cannot be missed.
      const unsubscribe = config.log.subscribe(
        request.implementerId,
        (event: StoredImplementerEvent) => {
          if (gate.closed) return;
          buffer.push(event);
          flushBuffer();
        },
      );

      try {
        const backlog = await config.log.readEvents(
          request.implementerId,
          cursor.afterImplementerSeq,
          backlogLimit,
        );
        for (const event of backlog.events) buffer.push(event);
      } catch {
        unsubscribe();
        return {
          kind: "REJECTED",
          code: "service_unavailable",
          requestId: request.requestId,
        };
      }

      committed = true;
      sink.write(sseComment("connected"));
      flushBuffer();

      const lifecycle = startSseLifecycle({
        gate,
        pollMs,
        heartbeatMs: config.heartbeatMs,
        setInterval: config.setInterval,
        clearInterval: config.clearInterval,
        poll: async () => {
          const page = await config.log.readEvents(request.implementerId, lastSent, backlogLimit);
          if (gate.closed) return;
          for (const event of page.events) buffer.push(event);
          flushBuffer();
        },
        heartbeat: () => sink.write(formatSseHeartbeat()),
        unsubscribe,
        closeSink: () => sink.close(),
      });

      return {
        kind: "OPEN",
        connection: {
          resumeSeq: cursor.afterImplementerSeq,
          close: () => lifecycle.close(),
        },
      };
    },
  };
}
