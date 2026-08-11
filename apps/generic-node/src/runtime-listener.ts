// The node's runtime HTTP listener: one node:http entry point that
// dispatches `/v1` operation traffic through the frozen validation pipeline +
// operation handlers (via @zucoins/node-core's createOperationRouter) and leaves
// everything else on the UNCHANGED health surface.
//
// The body is read with a hard byte cap BEFORE anything looks at it — the socket
// is never buffered unbounded; an over-cap body is passed to the pipeline, which
// emits the canonical `request_too_large` 400. Named `createNodeRuntimeListener`
// (not `createNodeHttpListener`) to avoid shadowing the reporting adapter's
// existing export of that name.
//
// Unexpected exceptions on the /v1 path still return the byte-exact
// service_unavailable 503 envelope with no stack leak, and emit one
// sanitized server-side log (request_id + method/path class + cause) via an
// injected logger port. Credentials, bodies, signed payloads, transfer codes,
// and keys never enter the log.

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  apiErrorResponse,
  buildTransportHardeningConfig,
  CachedDbProbe,
  createDestinationsRouter,
  createOperationRouter,
  DEFAULT_MAX_BODY_BYTES,
  enforceTransportGuards,
  handleOperationSubscribe,
  InMemoryReportingRateLimiter,
  handleWellKnown,
  matchOperationSubscribeRoute,
  MIN_HTTP_VERSION,
  PUSH_RECEIVER_PATH_PREFIX,
  REPORTING_HEADER_NAMES,
  type ApiErrorCode,
  type ApiErrorResponse,
  type DestinationService,
  type MetricsSnapshotSource,
  type MetricsHooks,
  type NodeMetrics,
  type OperationAuthBinding,
  type OperationRouteStore,
  type OperationRouter,
  type OperationSubscribeRouteDeps,
  type StorageBackpressure,
  type TransportRejectionCode,
  type WellKnownDeps,
} from "@zucoins/node-core";

import {
  createAdminRouter,
  type AdminRouteDeps,
  type AdminRouter,
} from "./admin-router.js";
import { createHealthHttpListener, createHealthRouter } from "./health/routes.js";
import type { NodeReadiness } from "./boot/readiness.js";
import { createMetricsMount, type MetricsMount } from "./metrics/routes.js";
import { resolveAdminSpaDist, tryServeAdminSpa } from "./admin-spa.js";
import { resolveEmbedDist, tryServeEmbed } from "./embed-spa.js";

/** Structured event for one unexpected /v1 listener failure. */
export interface RuntimeListenerFailureEvent {
  readonly event: "operation_listener_unexpected_failure";
  readonly request_id: string;
  readonly method: string;
  readonly path_class: string;
  readonly cause_name: string;
  readonly cause_message: string;
}

/**
 * Logger/telemetry port injected at listener composition.
 * Implementations must only receive the sanitized event fields — never raw
 * headers, bodies, or Error stacks.
 */
export interface RuntimeListenerLogger {
  error(event: RuntimeListenerFailureEvent): void;
}

const NOOP_RUNTIME_LISTENER_LOGGER: RuntimeListenerLogger = {
  error() {},
};

// Volume ceiling for the three POST create routes, per authenticated implementer.
// Deliberately the SAME window and ceiling main.ts gives the signed reporting surface
// (600/60s) so the node has one number for "too many requests" rather than two.
// 600/minute is ~10 creates/second sustained from a single implementer; no legitimate
// caller of a custody node's create surface runs anywhere near that, and a caller that
// does is already past every downstream money control's own admission checks. Hardcoded,
// matching the reporting limiter's precedent — no new env knob, so config/env-schema.ts
// gains nothing to validate.
export const OPERATION_CREATE_RATE_WINDOW_MS = 60_000;
export const OPERATION_CREATE_RATE_MAX_REQUESTS = 600;

// Transport hardening, applied at both layers node gives us: the server options main.ts
// spreads into createServer, and the intake guards handleJsonRoute runs below. The module
// (node-core api/transport-hardening.ts) is deliberately framework-agnostic, so the mapping
// onto node's option names and the API error taxonomy is the composition root's job.
//
// buildHardenedTlsConfig stays deliberately uncalled: nothing in this repository terminates
// TLS. See the note above it in api/transport-hardening.ts.
const TRANSPORT_HARDENING = buildTransportHardeningConfig();
// Same limits with the JSON Content-Type requirement lifted — the config used for a request
// that declares no body, where there is no Content-Type to check.
const TRANSPORT_HARDENING_BODYLESS = buildTransportHardeningConfig({
  requireJsonContentType: false,
});

/**
 * The options object main.ts passes as createServer's FIRST argument. Without them node's own
 * defaults hold — requestTimeout 300 s, headersTimeout 60 s — so a client that dribbles its
 * headers, or declares a Content-Length and then sends the body one byte at a time, keeps a
 * socket and a request slot for five minutes on a surface with no other admission control.
 *
 * maxHeaderSize is enforced by node's own parser, which answers 431 and closes the connection
 * before any listener runs, so the header cap needs no in-listener guard.
 */
export const HARDENED_HTTP_SERVER_OPTIONS = Object.freeze({
  requestTimeout: TRANSPORT_HARDENING.requestTimeoutMs,
  headersTimeout: TRANSPORT_HARDENING.headersTimeoutMs,
  maxHeaderSize: TRANSPORT_HARDENING.maxHeaderBytes,
});

export interface NodeRuntimeListenerDeps {
  readonly readiness: NodeReadiness;
  /** Fail-closed DB probe for the health half. Required. */
  readonly pingDb: () => Promise<void>;
  readonly operationStore: OperationRouteStore;
  /**
   * Branded auth from createRejectAllOperationAuth / createImplementerBearerAuth
   * / createImplementerBearerAuthFromService. Production
   * main mounts the service-backed binder. createOperationRouter refuses
   * unbranded/permissive hooks and refuses reject-all auth paired with a live store.
   */
  readonly operationAuth: OperationAuthBinding;
  readonly newRequestId: () => string;
  /**
   * Pre-/health/ready hook. Production main mounts
   * createProductionStoragePressureWiring(...).onBeforeEvaluate so every ready
   * probe re-stamps storage_pressure from the write-latency collector.
   */
  readonly onBeforeEvaluate?: () => void | Promise<void>;
  /**
   * Live storage gate composed with write-latency util. Held on the
   * listener deps so money-worker tickets consult the same instance main built;
   * not read by the HTTP half today.
   */
  readonly storageBackpressure?: StorageBackpressure;
  /**
   * Shared DB-reachability cache handed to the health router so
   * /health/ready and the /metrics snapshot source (built from the same
   * instance in main.ts) agree within one TTL window. Omitted → the health
   * router builds its own (prior behavior).
   */
  readonly dbProbe?: CachedDbProbe;
  /**
   * Metrics scrape token. Falsy/absent => /metrics is not mounted.
   * When set, createMetricsMount builds the bearer-gated handler.
   */
  readonly metricsScrapeToken?: string;
  /** Optional shared NodeMetrics registry (call-seam hooks + scrape). */
  readonly metrics?: NodeMetrics;
  /** Live auth/idempotency/operation lifecycle instrumentation for operation routes. */
  readonly metricsHooks?: MetricsHooks;
  /** Per-scrape snapshot source (DB + process stamps). */
  readonly metricsSnapshotSource?: MetricsSnapshotSource;
  /**
   * Server-side log port for unexpected /v1 failures. Absent → no-op
   * (tests remain silent). Production main injects a BootLogger adapter.
   */
  readonly logger?: RuntimeListenerLogger;
  /**
   * Extended production surface. When absent, only the six core
   * operation routes + health/(metrics) remain reachable (backward-compat tests).
   */
  readonly destinationService?: DestinationService;
  /** Required with destinationService — custody node uuid for destination rows. */
  readonly nodeId?: string;
  readonly adminRouter?: AdminRouter;
  /** Optional factory when adminRouter not prebuilt — ignored if adminRouter set. */
  readonly adminRouteDeps?: AdminRouteDeps;
  readonly discoveryDocument?: WellKnownDeps["buildDocument"];
  /**
   * Embedding-site origins allowed to frame GET /embed/:token (embed CSP
   * frame-ancestors). Empty/omit → 'self' only. Co-located with discovery
   * keys so the embed can pin-verify on this origin.
   */
  readonly embedMerchantFrameAncestors?: readonly string[];
  /**
   * Optional token → session id resolver for #zp-bootstrap. Null → 404.
   * When omitted, the URL token is used as session_id/order_id.
   */
  readonly resolveEmbedToken?: (
    token: string,
  ) =>
    | { sessionId: string; orderId: string }
    | null
    | Promise<{ sessionId: string; orderId: string } | null>;
  /** Override embed dist root (tests). Default: packages/widget/dist-embed. */
  readonly embedDistRoot?: string | null;
  /** Override admin SPA dist root (tests). Default: resolveAdminSpaDist(). */
  readonly adminSpaDist?: string | null;
  /**
   * Signed reporting pipeline listener (raw capture). Required for the seven
   * REPORTING_CREDENTIAL ROUTE_POLICIES entries when production_full is mounted.
   */
  readonly reportingListener?: (
    request: IncomingMessage,
    response: ServerResponse,
  ) => void | Promise<void>;
  /** SSE subscription route deps (subscription_handle auth). */
  readonly subscribeDeps?: OperationSubscribeRouteDeps;
  /**
   * fire-and-forget receiver-channel deposit (origin-relay; the endpoint id is the credential).
   * Internal adapter into money-workers candidate intake; not a ROUTE_POLICIES
   * public money-op. When omitted the path is absent (same as disabled flag).
   */
  readonly onReceiverChannelDeposit?: (rawBody: unknown) => void;
  /**
   * inbound Web Push delivery (delivery channel 1). The push service POSTs a
   * binary RFC 8291 `aes128gcm` body to `/v1/receivers/push/:endpoint_id`; the handler
   * decrypts it and feeds the SAME candidate-intake inbox the origin relay uses. Like
   * the relay this is fire-and-forget: every outcome is 204, so a probe cannot
   * distinguish a known endpoint from an unknown one. Absent when push is not composed.
   * `authorizationHeader` is the raw `Authorization` value (RFC 8292 VAPID) when present.
   */
  readonly onPushDelivery?: (
    endpointId: string,
    body: Buffer,
    authorizationHeader?: string | null,
  ) => Promise<void>;
}

const ITEM_COLLECTIONS = new Set(["receives", "internal-moves", "external-sends"]);

const MAX_CAUSE_MESSAGE_CHARS = 200;

// Collapse /v1 money-path URLs to a stable method+template class so logs never
// embed operation ids, query strings, or rate-limit fingerprints.
export function operationPathClass(method: string, rawUrl: string): string {
  const verb = (method.trim() || "UNKNOWN").toUpperCase();
  const pathname = (rawUrl.split(/[?#]/, 1)[0] ?? "").replace(/\/+$/u, "") || "/";
  if (!pathname.startsWith("/v1")) {
    return `${verb} /*`;
  }
  const segments = pathname.slice(1).split("/").filter((s) => s.length > 0);
  // ["v1"] only
  if (segments.length === 1) {
    return `${verb} /v1`;
  }
  const collection = segments[1] ?? "";
  if (ITEM_COLLECTIONS.has(collection)) {
    if (segments.length === 2) {
      return `${verb} /v1/${collection}`;
    }
    if (segments.length === 3) {
      return `${verb} /v1/${collection}/:operation_id`;
    }
  }
  return `${verb} /v1/*`;
}

// Strip credential / key / transfer-code / high-entropy material that may ride an
// Error.message before anything reaches the logger port.
export function sanitizeFailureCause(err: unknown): {
  readonly cause_name: string;
  readonly cause_message: string;
} {
  const cause_name =
    err instanceof Error
      ? err.name.slice(0, 80) || "Error"
      : typeof err === "string"
        ? "string"
        : err === null
          ? "null"
          : typeof err;
  let message = err instanceof Error ? err.message : String(err);
  message = message
    .replace(/Bearer\s+\S+/giu, "Bearer [redacted]")
    .replace(/\bik_[A-Za-z0-9_-]+/gu, "ik_[redacted]")
    .replace(/\bsh_[A-Za-z0-9_-]+/gu, "sh_[redacted]")
    .replace(
      /\b(authorization|api[_-]?key|private[_-]?key|master[_-]?key|secret|password|totp|transfer[_-]?code|preimage|signature|credential)\b\s*[:=]\s*\S+/giu,
      "$1=[redacted]",
    )
    .replace(/(?:[A-Za-z0-9+/_-]{48,}={0,2})/gu, "[redacted-blob]");
  if (message.length > MAX_CAUSE_MESSAGE_CHARS) {
    message = `${message.slice(0, MAX_CAUSE_MESSAGE_CHARS)}…`;
  }
  return { cause_name, cause_message: message };
}

function emitUnexpectedFailure(
  logger: RuntimeListenerLogger,
  event: RuntimeListenerFailureEvent,
): void {
  try {
    logger.error(event);
  } catch {
    // Logger failures must never replace the fail-closed 503 write.
  }
}

// Build the router's flat header map from node's rawHeaders (a [name, value, …]
// array that preserves each occurrence), NOT from request.headers — the latter has
// ALREADY comma-joined a repeated Idempotency-Key into "k1, k2" (which slips past
// IdempotencyKeySchema as a forged key) and silently kept only the first of a
// repeated Authorization. Duplicates of those two are rejected upstream
// (duplicateSensitiveHeaderError); every remaining header is single-valued, so a
// lowercased last-wins map reproduces the router contract exactly.
function normalizeHeaders(rawHeaders: readonly string[]): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    out[rawHeaders[index]!.toLowerCase()] = rawHeaders[index + 1];
  }
  return out;
}

// Count occurrences of a header name (lowercased) across node's rawHeaders array —
// mirrors the reporting adapter's raw-header counting (http-adapter.ts).
function countHeader(rawHeaders: readonly string[], name: string): number {
  let count = 0;
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (rawHeaders[index]!.toLowerCase() === name) count += 1;
  }
  return count;
}

// Reject a smuggled duplicate of a security-bearing header at the transport, BEFORE
// the router/store runs. A repeated Idempotency-Key is a "repeated" key
// → 400 invalid_idempotency_key. A repeated Authorization is an ambiguous credential
// → the generic 401 invalid_api_key (no 403/forbidden code exists). Kept at
// the listener, not the pure router, which receives already-flattened headers by
// contract — exactly as http-adapter.ts rejects duplicates for the reporting surface.
function duplicateSensitiveHeaderError(
  rawHeaders: readonly string[],
  newRequestId: () => string,
): ApiErrorResponse | null {
  if (countHeader(rawHeaders, "idempotency-key") > 1) {
    return apiErrorResponse("invalid_idempotency_key", newRequestId());
  }
  if (countHeader(rawHeaders, "authorization") > 1) {
    return apiErrorResponse("invalid_api_key", newRequestId());
  }
  return null;
}

// TransportRejectionCode → wire code.
//
// request_too_large and headers_too_large are unreachable from the call below and are mapped
// only to keep the table total: body size stays with readBoundedBody, which is the single
// enforcement point for the cap, and the header cap is enforced by node's own parser from
// maxHeaderSize (HARDENED_HTTP_SERVER_OPTIONS) before any listener runs.
const TRANSPORT_REJECTION_WIRE_CODE: Readonly<Record<TransportRejectionCode, ApiErrorCode>> = {
  http_version_too_old: "http_version_too_old",
  unsupported_content_type: "unsupported_content_type",
  request_too_large: "request_too_large",
  headers_too_large: "request_too_large",
};

// A request only has to declare JSON when it actually carries a body. Every GET, and the
// bodiless POSTs on the admin surface (bless / retire), legitimately send no Content-Type and
// must not be rejected for the absence of one.
function declaresBody(request: IncomingMessage): boolean {
  if (request.headers["transfer-encoding"] !== undefined) return true;
  const declared = Number.parseInt(request.headers["content-length"] ?? "", 10);
  return Number.isFinite(declared) && declared > 0;
}

// Pre-pipeline transport rejection for the JSON route surface: HTTP version floor and, for a
// request that carries a body, the application/json Content-Type requirement. Applied here in
// handleJsonRoute because every JSON router (admin, destinations, operations) routes through
// it, and only through it — the binary Web Push delivery route, the origin-relay deposit, the
// SPA/asset paths, health and /metrics all dispatch earlier and are untouched.
//
// The verdict depends on nothing but the request's own headers, so it cannot distinguish an
// existing route from an absent one.
function transportRejection(
  request: IncomingMessage,
  newRequestId: () => string,
): ApiErrorResponse | null {
  const outcome = enforceTransportGuards(
    {
      // node always populates httpVersion on a real socket; the fallback keeps the
      // in-process listener seam the unit tests drive from failing the floor.
      httpVersion: request.httpVersion ?? MIN_HTTP_VERSION,
      contentType: request.headers["content-type"],
      // Deliberately 0: body size is NOT re-checked here. readBoundedBody is the single
      // enforcement point for the cap, and a second check keyed on the DECLARED
      // Content-Length could disagree with the bytes actually read.
      contentLength: 0,
    },
    declaresBody(request) ? TRANSPORT_HARDENING : TRANSPORT_HARDENING_BODYLESS,
  );
  return outcome.ok
    ? null
    : apiErrorResponse(TRANSPORT_REJECTION_WIRE_CODE[outcome.code], newRequestId());
}

// Read the request body with a hard cap. The chunk that crosses the cap is kept so
// the accumulated length exceeds it, then reading stops — the buffer is bounded to
// cap + one socket chunk, and the pipeline's strict-JSON gate turns the over-cap
// length into a 400 request_too_large. A body exactly at the cap is accepted.
async function readBoundedBody(request: IncomingMessage, cap: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = chunk as Uint8Array;
    chunks.push(bytes);
    total += bytes.length;
    if (total > cap) break;
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

function writeJson(
  response: ServerResponse,
  status: number,
  body: string,
  headers: Record<string, string>,
): void {
  response.writeHead(status, { ...headers, "content-length": Buffer.byteLength(body).toString() });
  response.end(body);
}

type JsonRouter = (
  method: string,
  rawPath: string,
  rawBody: Uint8Array,
  headers: Record<string, string | undefined>,
  /** Socket peer address — the only client identity a client cannot forge. */
  remoteAddress?: string | null,
) => Promise<{ status: number; body: string; headers: Record<string, string> }>;

async function handleJsonRoute(
  router: JsonRouter,
  newRequestId: () => string,
  logger: RuntimeListenerLogger,
  request: IncomingMessage,
  response: ServerResponse,
  metricsHooks?: MetricsHooks,
): Promise<void> {
  const method = request.method ?? "";
  const url = request.url ?? "";
  try {
    // Outermost layer: decided from request headers alone, before any credential is read,
    // so a rejection here reveals nothing about the key, the route, or the store.
    const transportError = transportRejection(request, newRequestId);
    if (transportError) {
      writeJson(response, transportError.status, transportError.body, { ...transportError.headers });
      return;
    }
    const rawHeaders = request.rawHeaders;
    const duplicateError = duplicateSensitiveHeaderError(rawHeaders, newRequestId);
    if (duplicateError) {
      if (duplicateError.status === 401) metricsHooks?.onAuth("rejected");
      else metricsHooks?.onIdempotency("invalid");
      writeJson(response, duplicateError.status, duplicateError.body, { ...duplicateError.headers });
      return;
    }
    const body = await readBoundedBody(request, DEFAULT_MAX_BODY_BYTES);
    const result = await router(
      method,
      url,
      body,
      normalizeHeaders(rawHeaders),
      // Optional chain: socket is null on an already-destroyed connection, and
      // this seam turns any throw into an opaque 503.
      request.socket?.remoteAddress ?? null,
    );
    if (metricsHooks !== undefined) {
      if (result.status === 401) metricsHooks.onAuth("rejected");
      else if (result.status >= 500) metricsHooks.onAuth("error");
      else metricsHooks.onAuth("authorized");
      const collection = (url.split(/[?#]/, 1)[0] ?? "").split("/")[2] ?? "";
      if (method.toUpperCase() === "POST" && ITEM_COLLECTIONS.has(collection)) {
        const replay = Object.entries(result.headers).some(
          ([name, value]) => name.toLowerCase() === "idempotency-replayed" && value === "true",
        );
        if (replay) metricsHooks.onIdempotency("replay");
        else if (result.status === 409) metricsHooks.onIdempotency("conflict");
        else if (result.status === 400 && result.body.includes("invalid_idempotency_key")) metricsHooks.onIdempotency("invalid");
        else if (result.status >= 200 && result.status < 300) {
          metricsHooks.onIdempotency("first");
          const kind = collection === "receives" ? "RECEIVE_EXTERNAL" : collection === "internal-moves" ? "MOVE_INTERNAL" : "SEND_EXTERNAL";
          metricsHooks.onOperationCreated(kind);
        }
      }
      const pathname = url.split(/[?#]/, 1)[0] ?? "";
      if (
        method.toUpperCase() === "POST" &&
        /^\/admin\/v1\/external-sends\/[^/]+\/reject$/.test(pathname) &&
        result.status >= 200 &&
        result.status < 300
      ) {
        // The admin router returns 2xx only after rejectSendOperation's CREATED→REJECTED
        // CAS succeeds. Conflicts/auth failures/transport uncertainty never reach this seam.
        metricsHooks.onOperationFailed("SEND_EXTERNAL");
      }
    }
    writeJson(response, result.status, result.body, result.headers);
  } catch (cause) {
    const requestId = newRequestId();
    const { cause_name, cause_message } = sanitizeFailureCause(cause);
    emitUnexpectedFailure(logger, {
      event: "operation_listener_unexpected_failure",
      request_id: requestId,
      method: (method.trim() || "UNKNOWN").toUpperCase(),
      path_class: operationPathClass(method, url),
      cause_name,
      cause_message,
    });
    const error = apiErrorResponse("service_unavailable", requestId);
    try {
      writeJson(response, error.status, error.body, { ...error.headers });
    } catch {
      // Response already committed or socket closed — client already failed closed.
    }
  }
}

function hasReportingSignedHeaders(rawHeaders: readonly string[]): boolean {
  let found = 0;
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    if (rawHeaders[i]!.toLowerCase() === REPORTING_HEADER_NAMES.keyId) found += 1;
  }
  return found > 0;
}

const REPORTING_PATH_EXACT = new Set([
  "/v1/events",
  "/v1/events/stream",
  "/v1/state/snapshot",
  "/v1/destinations",
]);

const REPORTING_OPERATION_RE =
  /^\/v1\/operations\/[^/]+\/(armed|verification-complete|verification-material)$/;

function isReportingPath(pathname: string): boolean {
  if (REPORTING_PATH_EXACT.has(pathname)) return true;
  return REPORTING_OPERATION_RE.test(pathname);
}

/**
 * Production HTTP census keys currently dispatched by createNodeRuntimeListener.
 * Used by route-surface census tests. Optional surfaces appear only when deps mounted.
 */
export function runtimeMountedRouteKeys(opts: {
  readonly metricsMounted: boolean;
  readonly fullRoutePolicies: boolean;
}): readonly string[] {
  const keys = [
    "GET /health",
    "GET /health/ready",
    "POST /v1/receives",
    "GET /v1/receives/:operation_id",
    "POST /v1/internal-moves",
    "GET /v1/internal-moves/:operation_id",
    "POST /v1/external-sends",
    "GET /v1/external-sends/:operation_id",
  ];
  if (opts.metricsMounted) keys.push("GET /metrics");
  if (opts.fullRoutePolicies) {
    keys.push(
      "POST /v1/destinations",
      "GET /v1/destinations",
      "GET /v1/events",
      "GET /v1/events/stream",
      "GET /v1/state/snapshot",
      "GET /v1/operations/:operation_id/subscribe",
      "POST /v1/operations/:operation_id/armed",
      "POST /v1/operations/:operation_id/verification-complete",
      "GET /v1/operations/:operation_id/verification-material",
      "GET /admin/v1/external-sends/:operation_id/approval-challenge",
      "POST /admin/v1/external-sends/:operation_id/approve",
      "POST /admin/v1/external-sends/:operation_id/reject",
      "POST /admin/v1/destinations/:destination_id/bless",
      "POST /admin/v1/destinations/:destination_id/retire",
      "GET /admin/v1/operations/needs-attention",
      "GET /admin/v1/operations/:operation_id/recovery",
      "POST /admin/v1/operations/:operation_id/recovery-actions",
      "GET /.well-known/zupay-node",
    );
  }
  return keys;
}

export function createNodeRuntimeListener(
  deps: NodeRuntimeListenerDeps,
): (request: IncomingMessage, response: ServerResponse) => void {
  // Snapshot once so a getter/Proxy on listener deps cannot dual-read past the
  // composition gate inside createOperationRouter (TOCTOU class) or drop
  // the write-latency refresh between construction and first probe.
  const operationStore = deps.operationStore;
  const operationAuth = deps.operationAuth;
  const newRequestId = deps.newRequestId;
  const onBeforeEvaluate = deps.onBeforeEvaluate;
  const logger = deps.logger ?? NOOP_RUNTIME_LISTENER_LOGGER;
  const discoveryDocument = deps.discoveryDocument;
  const reportingListener = deps.reportingListener;
  const subscribeDeps = deps.subscribeDeps;
  const onReceiverChannelDeposit = deps.onReceiverChannelDeposit;
  const onPushDelivery = deps.onPushDelivery;
  const healthListener = createHealthHttpListener(
    createHealthRouter({
      readiness: deps.readiness,
      pingDb: deps.pingDb,
      onBeforeEvaluate,
      dbProbe: deps.dbProbe,
    }),
  );
  // Bearer-gated /metrics — genuinely unmounted when no scrape token.
  const metricsMount: MetricsMount | undefined = createMetricsMount({
    scrapeToken: deps.metricsScrapeToken,
    metrics: deps.metrics,
    snapshotSource: deps.metricsSnapshotSource,
  });
  const operationRouter: OperationRouter = createOperationRouter({
    store: operationStore,
    auth: operationAuth,
    newRequestId,
    createThrottle: {
      limiter: new InMemoryReportingRateLimiter(
        OPERATION_CREATE_RATE_WINDOW_MS,
        OPERATION_CREATE_RATE_MAX_REQUESTS,
      ),
      nodeId: deps.nodeId ?? "",
      retryAfterSeconds: OPERATION_CREATE_RATE_WINDOW_MS / 1000,
    },
  });

  const destinationsRouter =
    deps.destinationService !== undefined && deps.nodeId !== undefined
      ? createDestinationsRouter({
          store: operationStore,
          auth: operationAuth,
          destinationService: deps.destinationService,
          nodeId: deps.nodeId as never,
          newRequestId,
        })
      : null;

  const adminRouter: AdminRouter | null =
    deps.adminRouter ??
    (deps.adminRouteDeps !== undefined ? createAdminRouter(deps.adminRouteDeps) : null);
  const adminSpaDist = deps.adminSpaDist !== undefined ? deps.adminSpaDist : resolveAdminSpaDist();
  const embedDistRoot =
    deps.embedDistRoot !== undefined ? deps.embedDistRoot : resolveEmbedDist();

  return (request, response) => {
    const rawUrl = request.url ?? "";
    const pathname = rawUrl.split(/[?#]/, 1)[0] ?? rawUrl;

    // /metrics is top-level — only dispatched when configured
    if (pathname === "/metrics" && metricsMount !== undefined) {
      metricsMount.listener(request, response);
      return;
    }

    // GET /embed/:token — node-origin embed. Same origin as
    // discovery so default verifyArtifactForEmbed can resolve the pin.
    if (pathname.startsWith("/embed/") && embedDistRoot !== null) {
      if (
        tryServeEmbed(request, response, {
          distRoot: embedDistRoot,
          resolveToken: deps.resolveEmbedToken,
          merchantFrameAncestors: deps.embedMerchantFrameAncestors,
        })
      ) {
        return;
      }
    }

    // GET /.well-known/zupay-node — public discovery (AC5)
    if (pathname === "/.well-known/zupay-node" && discoveryDocument !== undefined) {
      void (async () => {
        try {
          const result = await handleWellKnown({ buildDocument: discoveryDocument });
          writeJson(response, result.status, result.body, { ...result.headers });
        } catch {
          const error = apiErrorResponse("service_unavailable", newRequestId());
          try {
            writeJson(response, error.status, error.body, { ...error.headers });
          } catch {
            // already committed
          }
        }
      })();
      return;
    }

    // /admin/v1/* — operator session / CSRF / TOTP
    if (pathname.startsWith("/admin/v1")) {
      if (adminRouter === null) {
        const error = apiErrorResponse("not_found", newRequestId());
        writeJson(response, error.status, error.body, { ...error.headers });
        return;
      }
      void handleJsonRoute(adminRouter, newRequestId, logger, request, response, deps.metricsHooks);
      return;
    }

    // Non /v1 → admin SPA (if built), else health (and 404 for unknown)
    if (!pathname.startsWith("/v1")) {
      if (adminSpaDist !== null && tryServeAdminSpa(request, response, adminSpaDist)) {
        return;
      }
      healthListener(request, response);
      return;
    }

    // internal receiver-channel deposit (origin-relay). Not in ROUTE_POLICIES, and unlike the
    // Web Push delivery route below it carries no endpoint id, so there is no credential to
    // check here — every deposit is instead re-verified against the chain before it can credit
    // anything. Resource exhaustion is bounded upstream by the per-lane inbox cap, not here.
    // 204 whether the deposit was enqueued or refused; malformed/disabled/refused all look
    // like absent, so the response leaks nothing about whether the channel is configured.
    if (
      pathname === "/v1/receivers/origin-relay" &&
      (request.method ?? "").toUpperCase() === "POST" &&
      onReceiverChannelDeposit !== undefined
    ) {
      void (async () => {
        try {
          const bodyBytes = await readBoundedBody(request, DEFAULT_MAX_BODY_BYTES);
          let parsed: unknown;
          try {
            parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as unknown;
          } catch {
            parsed = undefined;
          }
          onReceiverChannelDeposit(parsed);
          response.writeHead(204);
          response.end();
        } catch (cause) {
          const requestId = newRequestId();
          const { cause_name, cause_message } = sanitizeFailureCause(cause);
          emitUnexpectedFailure(logger, {
            event: "operation_listener_unexpected_failure",
            request_id: requestId,
            method: "POST",
            path_class: "POST /v1/receivers/origin-relay",
            cause_name,
            cause_message,
          });
          // Still 204 — channel is fire-and-forget; never storm a relay client.
          try {
            response.writeHead(204);
            response.end();
          } catch {
            /* committed */
          }
        }
      })();
      return;
    }

    // inbound Web Push delivery (delivery channel 1). Body is BINARY aes128gcm,
    // never JSON, so it is passed through as bytes. Not in ROUTE_POLICIES: like the
    // origin relay this is an inbound channel adapter, not a public money operation.
    if (
      pathname.startsWith(`${PUSH_RECEIVER_PATH_PREFIX}/`) &&
      (request.method ?? "").toUpperCase() === "POST" &&
      onPushDelivery !== undefined
    ) {
      const endpointId = pathname.slice(PUSH_RECEIVER_PATH_PREFIX.length + 1);
      // Single Authorization value only — duplicate headers are treated as absent so
      // a smuggled second header cannot bypass VAPID parse (fail closed at verify).
      const authorizationHeader =
        countHeader(request.rawHeaders, "authorization") === 1
          ? (normalizeHeaders(request.rawHeaders).authorization ?? null)
          : null;
      void (async () => {
        try {
          const bodyBytes = await readBoundedBody(request, DEFAULT_MAX_BODY_BYTES);
          await onPushDelivery(endpointId, Buffer.from(bodyBytes), authorizationHeader);
        } catch (cause) {
          const requestId = newRequestId();
          const { cause_name, cause_message } = sanitizeFailureCause(cause);
          emitUnexpectedFailure(logger, {
            event: "operation_listener_unexpected_failure",
            request_id: requestId,
            method: "POST",
            // Endpoint id is an unguessable credential — never in a log line.
            path_class: "POST /v1/receivers/push/:endpoint_id",
            cause_name,
            cause_message,
          });
        }
        // Uniform 204 on every path: accepted, unknown endpoint, and decrypt failure are
        // indistinguishable to the caller (discard semantics).
        try {
          response.writeHead(204);
          response.end();
        } catch {
          /* committed */
        }
      })();
      return;
    }

    // Reporting signed routes — raw-capture listener (AC3)
    if (
      reportingListener !== undefined &&
      isReportingPath(pathname) &&
      (pathname !== "/v1/destinations" || hasReportingSignedHeaders(request.rawHeaders))
    ) {
      // Dual-auth GET /v1/destinations: reporting headers → signed pipeline;
      // implementer bearer falls through to destinationsRouter below.
      if (pathname === "/v1/destinations" && !hasReportingSignedHeaders(request.rawHeaders)) {
        // fall through
      } else {
        void Promise.resolve(reportingListener(request, response)).catch((cause) => {
          const requestId = newRequestId();
          const { cause_name, cause_message } = sanitizeFailureCause(cause);
          emitUnexpectedFailure(logger, {
            event: "operation_listener_unexpected_failure",
            request_id: requestId,
            method: (request.method ?? "UNKNOWN").toUpperCase(),
            path_class: operationPathClass(request.method ?? "GET", rawUrl),
            cause_name,
            cause_message,
          });
          const error = apiErrorResponse("service_unavailable", requestId);
          try {
            writeJson(response, error.status, error.body, { ...error.headers });
          } catch {
            // committed
          }
        });
        return;
      }
    }

    // SSE subscribe — openSink only after AUTHORIZED; wire liveConnection cleanup.
    if (subscribeDeps !== undefined) {
      const match = matchOperationSubscribeRoute(request.method ?? "GET", pathname);
      if (match.kind === "MATCH") {
        void (async () => {
          try {
            const headers = normalizeHeaders(request.rawHeaders);
            let sseOpened = false;
            const perRequestSubscribe = {
              ...subscribeDeps,
              openSink: (sseHeaders: Readonly<Record<string, string>>) => {
                sseOpened = true;
                response.writeHead(200, { ...sseHeaders });
                return {
                  write(chunk: string) {
                    response.write(chunk);
                  },
                  close() {
                    response.end();
                  },
                };
              },
            };
            const result = await handleOperationSubscribe(perRequestSubscribe, {
              method: request.method ?? "GET",
              path: pathname,
              headers,
            });
            if (result.status >= 200 && result.status < 300 && result.body.length === 0) {
              if (result.liveConnection !== undefined) {
                // openSink committed head; stop poll/heartbeat on client drop.
                let cleaned = false;
                const cleanup = (): void => {
                  if (cleaned) return;
                  cleaned = true;
                  try {
                    result.liveConnection!.close();
                  } catch {
                    /* already closed */
                  }
                };
                request.once("close", cleanup);
                response.once("close", cleanup);
                return;
              }
              // Unit-test / no-openSink path: emit empty SSE and end.
              if (!sseOpened) {
                response.writeHead(result.status, { ...result.headers });
                response.end();
              }
              return;
            }
            // Auth deny and other errors: SSE head was never written — safe 401 JSON.
            writeJson(response, result.status, result.body, { ...result.headers });
          } catch (cause) {
            const requestId = newRequestId();
            const { cause_name, cause_message } = sanitizeFailureCause(cause);
            emitUnexpectedFailure(logger, {
              event: "operation_listener_unexpected_failure",
              request_id: requestId,
              method: (request.method ?? "UNKNOWN").toUpperCase(),
              path_class: operationPathClass(request.method ?? "GET", rawUrl),
              cause_name,
              cause_message,
            });
            const error = apiErrorResponse("service_unavailable", requestId);
            try {
              writeJson(response, error.status, error.body, { ...error.headers });
            } catch {
              // committed
            }
          }
        })();
        return;
      }
    }

    // Destinations (implementer bearer)
    if (pathname === "/v1/destinations" && destinationsRouter !== null) {
      void handleJsonRoute(destinationsRouter, newRequestId, logger, request, response);
      return;
    }

    // Six operation create/query routes
    void handleJsonRoute(operationRouter, newRequestId, logger, request, response, deps.metricsHooks);
  };
}
