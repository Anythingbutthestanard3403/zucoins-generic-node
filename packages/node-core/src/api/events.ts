// runtime request→response handler for `GET /v1/events`
//
// Auth is the signed reporting credential; the reporting request pipeline
// verifies the credential before this handler runs. This module is the transport edge:
// parse the exclusive after_implementer_seq / limit / wait_seconds query, read a page from
// the implementer-scoped store, and emit the frozen envelope. It never writes, never
// re-serializes a proof representation, and never projects product fields.
//
// Cursor field names on the wire match the dual-continuity API surface
// (after_implementer_seq / implementer_watermark_seq / next_after_implementer_seq). The
// underlying pagination semantics are the exclusive-after + watermark + next-after contract
// frozen as CURSOR_CONTRACT (packages/generic-node-contracts event-sequencing). /
// UP-07: body also always carries `checkpoints[]` (opaque zp-implementer-checkpoint-v1
// proofs) for the implementer — the anti-rollback companion channel.
//
// Long-poll (wait_seconds): when the page is empty and wait_seconds > 0, the handler polls
// the store until an event appears after the cursor or the wait budget expires. It never
// busy-spins the database — each poll is spaced by LONG_POLL_INTERVAL_MS.

import {
  clampEventsLimit,
  listEvents,
  renderEventsListBody,
  type ImplementerEventReadStore,
  type ServedImplementerEvent,
} from "../reporting/events-read-service.js";
import {
  reportingErrorResponse,
  type ReportingHttpResponse,
} from "../reporting/errors.js";
import type {
  ReportingHandlerResult,
  ReportingRouteHandler,
} from "../reporting/request-handler.js";
import type { VerifiedReportRequest } from "../reporting/request-verifier.js";
import { REPORTING_ROUTE_IDS } from "../reporting/route-table.js";
import { apiErrorResponse, type ApiErrorResponse } from "./error-envelope.js";
import { DecimalSeqStringSchema } from "./scalars.js";

export const EVENTS_WAIT_SECONDS_MIN = 0 as const;
export const EVENTS_WAIT_SECONDS_MAX = 30 as const;
export const EVENTS_WAIT_SECONDS_DEFAULT = 0;
export const LONG_POLL_INTERVAL_MS = 200 as const;

export const EVENTS_LIST_CURSOR_FIELDS = Object.freeze({
  requestCursorField: "after_implementer_seq",
  requestCursorExclusive: true,
  responseWatermarkField: "implementer_watermark_seq",
  responseNextCursorField: "next_after_implementer_seq",
  applyRule: "strictly_after_watermark",
  tracks: "dedicated_gapless_sequence",
  monotonic: true,
} as const);

export interface EventsListRouteQuery {
  readonly afterImplementerSeq: bigint | null;
  readonly limit: number;
  readonly waitSeconds: number;
}

export type EventsListQueryParse =
  | { readonly ok: true; readonly query: EventsListRouteQuery }
  | { readonly ok: false; readonly message: string };

export function parseEventsListQueryFromTarget(rawTarget: string): EventsListQueryParse {
  const qIndex = rawTarget.indexOf("?");
  const search = qIndex < 0 ? "" : rawTarget.slice(qIndex + 1);
  const params = new URLSearchParams(search);

  const afterRaw = params.get("after_implementer_seq");
  if (afterRaw === null && params.has("after_seq")) {
    return {
      ok: false,
      message: "after_seq is not accepted; use after_implementer_seq",
    };
  }

  let afterImplementerSeq: bigint | null = null;
  if (afterRaw !== null) {
    const parsed = DecimalSeqStringSchema.safeParse(afterRaw);
    if (!parsed.success) {
      return { ok: false, message: "after_implementer_seq must be a non-negative decimal string" };
    }
    afterImplementerSeq = BigInt(parsed.data);
  }

  let limit: number | undefined;
  const limitRaw = params.get("limit");
  if (limitRaw !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(limitRaw)) {
      return { ok: false, message: "limit must be an integer decimal string" };
    }
    limit = Number(limitRaw);
  }

  let waitSeconds = EVENTS_WAIT_SECONDS_DEFAULT;
  const waitRaw = params.get("wait_seconds");
  if (waitRaw !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(waitRaw)) {
      return { ok: false, message: "wait_seconds must be an integer decimal string" };
    }
    const wait = Number(waitRaw);
    if (wait < EVENTS_WAIT_SECONDS_MIN || wait > EVENTS_WAIT_SECONDS_MAX) {
      return {
        ok: false,
        message: `wait_seconds must be in [${EVENTS_WAIT_SECONDS_MIN}, ${EVENTS_WAIT_SECONDS_MAX}]`,
      };
    }
    waitSeconds = wait;
  }

  for (const key of params.keys()) {
    if (key !== "after_implementer_seq" && key !== "limit" && key !== "wait_seconds") {
      return { ok: false, message: `unknown query parameter: ${key}` };
    }
  }

  return {
    ok: true,
    query: {
      afterImplementerSeq,
      limit: clampEventsLimit(limit),
      waitSeconds,
    },
  };
}

export interface EventsListRequest {
  readonly requestId: string;
  readonly implementerId: string;
  readonly rawTarget: string;
  readonly nowMs: () => number;
  readonly sleepMs?: (ms: number) => Promise<void>;
}

export interface EventsListOk {
  readonly status: 200;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export type EventsListResponse = EventsListOk | ApiErrorResponse;

const JSON_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "application/json",
});

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

const FORBIDDEN_PROOF_SUBSTRINGS = [
  "private_key",
  "transfer_code",
  "gateway_raw",
  "raw_gateway",
  "totp_secret",
] as const;

function assertNoDataLeak(events: readonly ServedImplementerEvent[]): void {
  for (const event of events) {
    const proof = event.proofRepresentation;
    for (const needle of FORBIDDEN_PROOF_SUBSTRINGS) {
      if (proof.includes(needle)) {
        throw new Error(`event proof contains forbidden field marker: ${needle}`);
      }
    }
  }
}

export async function handleGetEvents(
  request: EventsListRequest,
  store: ImplementerEventReadStore,
): Promise<EventsListResponse> {
  const parsed = parseEventsListQueryFromTarget(request.rawTarget);
  if (!parsed.ok) {
    return apiErrorResponse("invalid_scalar", request.requestId, parsed.message);
  }

  const sleep = request.sleepMs ?? defaultSleep;
  const deadlineMs =
    parsed.query.waitSeconds === 0
      ? request.nowMs()
      : request.nowMs() + parsed.query.waitSeconds * 1000;

  let result = await listEvents(store, {
    implementerId: request.implementerId,
    afterImplementerSeq: parsed.query.afterImplementerSeq,
    limit: parsed.query.limit,
  });

  while (result.events.length === 0 && request.nowMs() < deadlineMs) {
    const remaining = deadlineMs - request.nowMs();
    if (remaining <= 0) break;
    await sleep(Math.min(LONG_POLL_INTERVAL_MS, remaining));
    result = await listEvents(store, {
      implementerId: request.implementerId,
      afterImplementerSeq: parsed.query.afterImplementerSeq,
      limit: parsed.query.limit,
    });
  }

  try {
    assertNoDataLeak(result.events);
  } catch {
    return apiErrorResponse("service_unavailable", request.requestId);
  }

  const body = renderEventsListBody(result);
  return {
    status: 200,
    headers: JSON_HEADERS,
    body,
  };
}

export const EVENTS_LIST_ROUTE_ID = REPORTING_ROUTE_IDS.eventsList;
export const EVENTS_LIST_PATH = "/v1/events" as const;

export interface EventsListRouteDeps {
  readonly store: ImplementerEventReadStore;
  readonly nowMs: () => number;
  readonly newRequestId: () => string;
  readonly sleepMs?: (ms: number) => Promise<void>;
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

export function createEventsListRouteHandler(
  deps: EventsListRouteDeps,
): ReportingRouteHandler {
  return async (request: VerifiedReportRequest): Promise<ReportingHandlerResult> => {
    try {
      const result = await handleGetEvents(
        {
          requestId: deps.newRequestId(),
          implementerId: request.binding.implementerId,
          rawTarget: request.fingerprint.rawTarget,
          nowMs: deps.nowMs,
          sleepMs: deps.sleepMs,
        },
        deps.store,
      );
      return {
        response: toReportingResponse(result.status, result.headers, result.body),
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

export function eventsListHandlerEntry(
  deps: EventsListRouteDeps,
): Readonly<Record<string, ReportingRouteHandler>> {
  return {
    [EVENTS_LIST_ROUTE_ID]: createEventsListRouteHandler(deps),
  };
}
