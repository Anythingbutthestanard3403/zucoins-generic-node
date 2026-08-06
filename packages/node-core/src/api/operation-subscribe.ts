// runtime binder for GET /v1/operations/:operation_id/subscribe
// Auth class: SUBSCRIPTION_HANDLE (Bearer sh_…).
// Distinct from the reporting-credential-gated event/snapshot routes (.2).
//
// Composition note (review): the HTTP adapter must hold the socket open via
// openSink and must not wrap this handler in a JSON body encoder. bodyBytes is empty
// on the success path; live frames go only through the SseSink side-channel.
//
// r2: openSink runs only after AUTHORIZED so deny stays 401 JSON (never 200 SSE).
// When openSink is set, liveConnection is returned so the adapter can close on client drop.

import type { SseSink } from "../reporting/event-stream-sse.js";
import { UuidSchema } from "./scalars.js";
import {
  createOperationSubscribeAccelerator,
  SSE_HEADERS,
  type OperationSubscribeAccelerator,
  type OperationSubscribeSseConnection,
} from "./operation-subscribe-sse.js";
import {
  authorizeOperationSubscribe,
  type OperationLifecycleStore,
  type SubscriptionHandleStore,
} from "./subscription-handle.js";
import { apiErrorResponse, type ApiErrorResponse } from "./error-envelope.js";

export const OPERATION_SUBSCRIBE_PATH_TEMPLATE =
  "/v1/operations/:operation_id/subscribe" as const;

export const OPERATION_SUBSCRIBE_METHOD = "GET" as const;

const DISCARD_SINK: SseSink = {
  write() {
    /* discard */
  },
  close() {
    /* no-op */
  },
};

export interface OperationSubscribeRouteDeps {
  readonly handleStore: SubscriptionHandleStore;
  readonly lifecycleStore: OperationLifecycleStore;
  readonly nowMs: () => number;
  readonly newRequestId: () => string;
  readonly heartbeatMs?: number;
  readonly pollMs?: number;
  /**
   * Opens the live SSE body. Invoked only after AUTHORIZED. When omitted, the handler
   * validates auth then returns an empty 200 with SSE headers (unit-test path) and closes
   * the connection.
   */
  readonly openSink?: (headers: Readonly<Record<string, string>>) => SseSink;
  readonly accelerator?: OperationSubscribeAccelerator;
}

export interface OperationSubscribeHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly bodyBytes: Uint8Array;
  /**
   * Present only when openSink held the stream. Adapter must call close on client
   * disconnect (request/response close/aborted) so poll timers do not leak.
   */
  readonly liveConnection?: OperationSubscribeSseConnection;
}

export interface OperationSubscribeRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

export type OperationSubscribeMatch =
  | { readonly kind: "MATCH"; readonly operationId: string }
  | { readonly kind: "NO_MATCH" };

/**
 * Match GET /v1/operations/:operation_id/subscribe. Operation id must be a lowercase
 * canonical UUID; anything else is NO_MATCH (caller maps to generic 404).
 */
export function matchOperationSubscribeRoute(
  method: string,
  pathname: string,
): OperationSubscribeMatch {
  if (method.toUpperCase() !== OPERATION_SUBSCRIBE_METHOD) return { kind: "NO_MATCH" };
  const segments = pathname.split("/");
  // ["", "v1", "operations", "<uuid>", "subscribe"]
  if (
    segments.length !== 5 ||
    segments[0] !== "" ||
    segments[1] !== "v1" ||
    segments[2] !== "operations" ||
    segments[4] !== "subscribe"
  ) {
    return { kind: "NO_MATCH" };
  }
  const operationId = segments[3] ?? "";
  if (!UuidSchema.safeParse(operationId).success) return { kind: "NO_MATCH" };
  return { kind: "MATCH", operationId };
}

function emptySseResponse(
  liveConnection?: OperationSubscribeSseConnection,
): OperationSubscribeHttpResponse {
  return {
    status: 200,
    headers: { ...SSE_HEADERS },
    body: "",
    bodyBytes: new Uint8Array(),
    ...(liveConnection !== undefined ? { liveConnection } : {}),
  };
}

function errorToHttp(response: ApiErrorResponse): OperationSubscribeHttpResponse {
  return {
    status: response.status,
    headers: { ...response.headers },
    body: response.body,
    bodyBytes: new TextEncoder().encode(response.body),
  };
}

/**
 * Pure open helper: authorize then start the SSE accelerator. Used by tests and the
 * route handler. The HTTP adapter holds the socket open when openSink is provided.
 * Callers that supply a production sink must only do so after AUTHORIZED (or use
 * handleOperationSubscribe, which sequences that).
 */
export async function openOperationSubscribe(
  deps: OperationSubscribeRouteDeps,
  input: {
    readonly requestId: string;
    readonly operationId: string;
    readonly headers: Readonly<Record<string, string | string[] | undefined>>;
    readonly sink: SseSink;
  },
): Promise<
  | { readonly kind: "OPEN"; readonly connection: OperationSubscribeSseConnection }
  | { readonly kind: "REJECTED"; readonly response: ApiErrorResponse }
> {
  const auth = await authorizeOperationSubscribe({
    requestId: input.requestId,
    pathOperationId: input.operationId,
    headers: input.headers,
    handleStore: deps.handleStore,
    lifecycleStore: deps.lifecycleStore,
    nowMs: deps.nowMs,
  });

  if (auth.kind === "DENIED") {
    return { kind: "REJECTED", response: auth.response };
  }

  const accelerator =
    deps.accelerator ??
    createOperationSubscribeAccelerator({
      lifecycleStore: deps.lifecycleStore,
      heartbeatMs: deps.heartbeatMs,
      pollMs: deps.pollMs,
    });

  const connection = accelerator.open(
    { operationId: input.operationId, initial: auth.lifecycle },
    input.sink,
  );
  return { kind: "OPEN", connection };
}

/**
 * Full request handler. Returns 200 + SSE headers on success (body empty — frames
 * via sink). All auth/binding/expiry failures → 401 invalid_api_key before any openSink.
 */
export async function handleOperationSubscribe(
  deps: OperationSubscribeRouteDeps,
  request: OperationSubscribeRequest,
): Promise<OperationSubscribeHttpResponse> {
  const requestId = deps.newRequestId();
  const match = matchOperationSubscribeRoute(request.method, request.path);
  if (match.kind === "NO_MATCH") {
    return errorToHttp(apiErrorResponse("not_found", requestId));
  }

  // Authorize before any openSink / writeHead so deny cannot commit 200 SSE.
  const auth = await authorizeOperationSubscribe({
    requestId,
    pathOperationId: match.operationId,
    headers: request.headers,
    handleStore: deps.handleStore,
    lifecycleStore: deps.lifecycleStore,
    nowMs: deps.nowMs,
  });

  if (auth.kind === "DENIED") {
    return errorToHttp(auth.response);
  }

  let sink: SseSink = DISCARD_SINK;
  let sinkOpened = false;
  try {
    if (deps.openSink !== undefined) {
      sink = deps.openSink(SSE_HEADERS);
      sinkOpened = true;
    }

    const accelerator =
      deps.accelerator ??
      createOperationSubscribeAccelerator({
        lifecycleStore: deps.lifecycleStore,
        heartbeatMs: deps.heartbeatMs,
        pollMs: deps.pollMs,
      });

    const connection = accelerator.open(
      { operationId: match.operationId, initial: auth.lifecycle },
      sink,
    );

    if (deps.openSink === undefined) {
      connection.close();
      return emptySseResponse();
    }

    return emptySseResponse(connection);
  } catch {
    if (sinkOpened) {
      try {
        sink.close();
      } catch {
        /* already closed */
      }
    }
    return errorToHttp(apiErrorResponse("service_unavailable", requestId));
  }
}

export function createOperationSubscribeHandler(
  deps: OperationSubscribeRouteDeps,
): (request: OperationSubscribeRequest) => Promise<OperationSubscribeHttpResponse> {
  return (request) => handleOperationSubscribe(deps, request);
}
