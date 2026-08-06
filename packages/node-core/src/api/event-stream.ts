// runtime binder for GET /v1/events/stream.
// Auth is the signed reporting credential; the reporting pipeline verifies it
// before this handler runs. This module is the transport edge: parse after_implementer_seq,
// read Last-Event-ID, open the SSE accelerator over the durable implementer event log.
//
// r2: openSink only after cursor validation; liveStream returned so the HTTP adapter
// holds the socket and closes poll timers on client disconnect.

import {
  createEventStreamAccelerator,
  SSE_HEADERS,
  type EventStreamAccelerator,
  type SseSink,
} from "../reporting/event-stream-sse.js";
import type { ImplementerEventLog } from "../reporting/implementer-event-log.js";
import {
  reportingErrorResponse,
  type ReportingHttpResponse,
} from "../reporting/errors.js";
import type {
  ReportingHandlerResult,
  ReportingRouteHandler,
  ReportingTransportSideChannel,
} from "../reporting/request-handler.js";
import type { VerifiedReportRequest } from "../reporting/request-verifier.js";
import { REPORTING_ROUTE_IDS } from "../reporting/route-table.js";
import { resolveStreamCursor } from "../reporting/events-read-service.js";
import { apiErrorResponse, type ApiErrorCode, type ApiErrorResponse } from "./error-envelope.js";
import { DecimalSeqStringSchema } from "./scalars.js";

export const EVENTS_STREAM_ROUTE_ID = REPORTING_ROUTE_IDS.eventsStream;
export const EVENTS_STREAM_PATH = "/v1/events/stream" as const;

const DISCARD_SINK: SseSink = {
  write() {
    /* discard */
  },
  close() {
    /* no-op */
  },
};

export interface EventsStreamRouteQuery {
  readonly afterImplementerSeq: bigint | null;
}

export type EventsStreamQueryParse =
  | { readonly ok: true; readonly query: EventsStreamRouteQuery }
  | { readonly ok: false; readonly message: string };

export function parseEventsStreamQueryFromTarget(rawTarget: string): EventsStreamQueryParse {
  const qIndex = rawTarget.indexOf("?");
  const search = qIndex < 0 ? "" : rawTarget.slice(qIndex + 1);
  const params = new URLSearchParams(search);

  if (params.has("after_seq")) {
    return {
      ok: false,
      message:
        "after_seq is not accepted; use after_implementer_seq",
    };
  }

  let afterImplementerSeq: bigint | null = null;
  const afterRaw = params.get("after_implementer_seq");
  if (afterRaw !== null) {
    const parsed = DecimalSeqStringSchema.safeParse(afterRaw);
    if (!parsed.success) {
      return {
        ok: false,
        message: "after_implementer_seq must be a non-negative decimal string",
      };
    }
    afterImplementerSeq = BigInt(parsed.data);
  }

  for (const key of params.keys()) {
    if (key !== "after_implementer_seq") {
      return { ok: false, message: `unknown query parameter: ${key}` };
    }
  }

  return { ok: true, query: { afterImplementerSeq } };
}

export function lastEventIdFromHeaders(
  headers: Readonly<Record<string, string | string[] | undefined>>,
): string | null {
  const raw =
    headers["last-event-id"] ??
    headers["Last-Event-ID"] ??
    headers["LAST-EVENT-ID"];
  if (raw === undefined) return null;
  if (Array.isArray(raw)) return raw[0] ?? null;
  return raw;
}

export interface EventsStreamRouteDeps {
  readonly log: ImplementerEventLog;
  readonly nowMs: () => number;
  readonly newRequestId: () => string;
  readonly heartbeatMs?: number;
  readonly pollMs?: number;
  /**
   * Opens the live SSE body after cursor validation. Preferred path: reporting transport
   * side-channel openSink (per-request). Factory openSink is a test-only fallback.
   */
  readonly openSink?: (headers: Readonly<Record<string, string>>) => SseSink;
  readonly accelerator?: EventStreamAccelerator;
}

function toReportingResponse(
  status: number,
  headers: Readonly<Record<string, string>>,
  body: string,
): ReportingHttpResponse {
  return {
    status,
    headers: { ...headers },
    bodyBytes: new TextEncoder().encode(body),
  };
}

/**
 * Pure open helper used by tests and the route binder. Returns either a cursor rejection
 * or an opened SSE connection. Does not write to sink on REJECTED (accelerator defers
 * first frame until backlog is readable).
 */
export async function openEventsStream(
  deps: EventsStreamRouteDeps,
  input: {
    readonly requestId: string;
    readonly implementerId: string;
    readonly rawTarget: string;
    readonly headers: Readonly<Record<string, string | string[] | undefined>>;
    readonly sink: SseSink;
  },
): Promise<
  | { readonly kind: "OPEN"; readonly connection: { close(): void } }
  | { readonly kind: "REJECTED"; readonly response: ApiErrorResponse }
> {
  const parsed = parseEventsStreamQueryFromTarget(input.rawTarget);
  if (!parsed.ok) {
    return {
      kind: "REJECTED",
      response: apiErrorResponse("invalid_scalar", input.requestId, parsed.message),
    };
  }

  // Resolve cursor before any sink write so mismatch never opens SSE.
  const cursor = resolveStreamCursor(
    parsed.query.afterImplementerSeq,
    lastEventIdFromHeaders(input.headers),
  );
  if (!cursor.ok) {
    return {
      kind: "REJECTED",
      response: apiErrorResponse("cursor_mismatch", input.requestId),
    };
  }

  const accelerator =
    deps.accelerator ??
    createEventStreamAccelerator({
      log: deps.log,
      heartbeatMs: deps.heartbeatMs,
      pollMs: deps.pollMs,
    });

  const outcome = await accelerator.open(
    {
      requestId: input.requestId,
      implementerId: input.implementerId,
      afterImplementerSeq: parsed.query.afterImplementerSeq,
      lastEventId: lastEventIdFromHeaders(input.headers),
    },
    input.sink,
  );

  if (outcome.kind === "REJECTED") {
    const code: ApiErrorCode =
      outcome.code === "cursor_mismatch" ? "cursor_mismatch" : "service_unavailable";
    return {
      kind: "REJECTED",
      response: apiErrorResponse(code, outcome.requestId),
    };
  }
  return { kind: "OPEN", connection: outcome.connection };
}

export function createEventsStreamRouteHandler(
  deps: EventsStreamRouteDeps,
): ReportingRouteHandler {
  return async (
    request: VerifiedReportRequest,
    transport?: ReportingTransportSideChannel,
  ): Promise<ReportingHandlerResult> => {
    try {
      const requestId = deps.newRequestId();

      // lastEventId was extracted from raw transport headers at verify time
      // (VerifiedReportRequest.lastEventId). Rebuild the header map the open helper
      // already understands so Last-Event-ID reaches resolveStreamCursor.
      const headers: Record<string, string | undefined> =
        request.lastEventId === null ? {} : { "Last-Event-ID": request.lastEventId };

      // Pre-validate without openSink so cursor / query reject stays JSON 4xx.
      const parsed = parseEventsStreamQueryFromTarget(request.fingerprint.rawTarget);
      if (!parsed.ok) {
        const err = apiErrorResponse("invalid_scalar", requestId, parsed.message);
        return {
          response: toReportingResponse(err.status, err.headers, err.body),
          persistChild: null,
        };
      }
      const cursor = resolveStreamCursor(parsed.query.afterImplementerSeq, request.lastEventId);
      if (!cursor.ok) {
        const err = apiErrorResponse("cursor_mismatch", requestId);
        return {
          response: toReportingResponse(err.status, err.headers, err.body),
          persistChild: null,
        };
      }

      const openSink = transport?.openSink ?? deps.openSink;
      let sinkOpened = false;
      const sink: SseSink =
        openSink !== undefined
          ? (() => {
              sinkOpened = true;
              return openSink(SSE_HEADERS);
            })()
          : DISCARD_SINK;

      const outcome = await openEventsStream(deps, {
        requestId,
        implementerId: request.binding.implementerId,
        rawTarget: request.fingerprint.rawTarget,
        headers,
        sink,
      });

      if (outcome.kind === "REJECTED") {
        if (sinkOpened) {
          try {
            sink.close();
          } catch {
            /* already closed */
          }
        }
        return {
          response: toReportingResponse(
            outcome.response.status,
            outcome.response.headers,
            outcome.response.body,
          ),
          persistChild: null,
        };
      }

      if (openSink === undefined) {
        outcome.connection.close();
        return {
          response: {
            status: 200,
            headers: { ...SSE_HEADERS },
            bodyBytes: new Uint8Array(),
          },
          persistChild: null,
        };
      }

      return {
        response: {
          status: 200,
          headers: { ...SSE_HEADERS },
          bodyBytes: new Uint8Array(),
          liveStream: outcome.connection,
        },
        persistChild: null,
      };
    } catch {
      return {
        response: reportingErrorResponse("internal_error", deps.newRequestId()),
        persistChild: null,
      };
    }
  };
}

export function eventsStreamHandlerEntry(
  deps: EventsStreamRouteDeps,
): Readonly<Record<string, ReportingRouteHandler>> {
  return {
    [EVENTS_STREAM_ROUTE_ID]: createEventsStreamRouteHandler(deps),
  };
}
