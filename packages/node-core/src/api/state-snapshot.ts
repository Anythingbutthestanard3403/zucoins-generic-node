// runtime binder for GET /v1/state/snapshot.
// Auth is the signed reporting credential. Returns a transactionally consistent
// tenant snapshot + implementer_watermark_seq. Snapshot is bootstrap convenience, not chain
// evidence.

import {
  createSnapshotService,
  renderSnapshotBody,
  type SnapshotService,
  type SnapshotStateReader,
  type SnapshotStore,
} from "../reporting/snapshot-service.js";
import type { ImplementerEventLog } from "../reporting/implementer-event-log.js";
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

export const STATE_SNAPSHOT_ROUTE_ID = REPORTING_ROUTE_IDS.stateSnapshot;
export const STATE_SNAPSHOT_PATH = "/v1/state/snapshot" as const;

/** Default bounded read budget for GET /v1/state/snapshot capture. */
export const DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS = 5_000;

const JSON_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "application/json",
});

export interface StateSnapshotOk {
  readonly status: 200;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export type StateSnapshotResponse = StateSnapshotOk | ApiErrorResponse;

export interface StateSnapshotRouteDeps {
  readonly log: ImplementerEventLog;
  readonly reader: SnapshotStateReader;
  readonly store: SnapshotStore;
  readonly nowMs: () => number;
  readonly newRequestId: () => string;
  /** When true, capture a fresh snapshot on every GET; otherwise serve latest or capture if absent. */
  readonly captureOnRead?: boolean;
  readonly service?: SnapshotService;
  /**
   * Bounded capture budget forwarded to {@link createSnapshotService}.
   * Defaults to {@link DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS}. Pass `0` to
   * force the unbounded legacy path (tests only).
   */
  readonly captureTimeoutMs?: number;
}

export async function handleGetStateSnapshot(
  deps: StateSnapshotRouteDeps,
  implementerId: string,
  requestId: string,
): Promise<StateSnapshotResponse> {
  const service =
    deps.service ??
    createSnapshotService({
      log: deps.log,
      reader: deps.reader,
      store: deps.store,
      nowMs: deps.nowMs,
      captureTimeoutMs:
        deps.captureTimeoutMs === undefined
          ? DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS
          : deps.captureTimeoutMs,
    });

  try {
    let snapshot =
      deps.captureOnRead === false ? await service.latest(implementerId) : null;
    if (snapshot === null) {
      snapshot = await service.capture(implementerId);
    }
    return {
      status: 200,
      headers: JSON_HEADERS,
      body: renderSnapshotBody(snapshot),
    };
  } catch {
    return apiErrorResponse("service_unavailable", requestId);
  }
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

export function createStateSnapshotRouteHandler(
  deps: StateSnapshotRouteDeps,
): ReportingRouteHandler {
  return async (request: VerifiedReportRequest): Promise<ReportingHandlerResult> => {
    try {
      const result = await handleGetStateSnapshot(
        deps,
        request.binding.implementerId,
        deps.newRequestId(),
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

export function stateSnapshotHandlerEntry(
  deps: StateSnapshotRouteDeps,
): Readonly<Record<string, ReportingRouteHandler>> {
  return {
    [STATE_SNAPSHOT_ROUTE_ID]: createStateSnapshotRouteHandler(deps),
  };
}
