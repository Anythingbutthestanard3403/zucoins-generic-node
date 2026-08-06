// Mounts the six v1 create/query operation routes onto the
// validation pipeline and the operation handlers. This is the ONLY place
// that maps a raw (method, path) to a handler; it holds no per-wallet state (the
// injected store owns concurrency), calls the store exactly once per request
// (no retry loop anywhere), and serves the handler's success body VERBATIM
// (never JSON.parse/re-stringify, so the signed expected_artifact bytes survive
// unchanged).
//
// Scope for stage 3 comes from ROUTE_POLICIES via runValidationPipeline — this
// router never invents a scope of its own.

import { apiErrorResponse, type ApiErrorResponse } from "./error-envelope.js";
import {
  assertOperationAuthComposition,
  type OperationAuthBinding,
} from "./operation-auth.js";
import {
  runValidationPipeline,
  type PipelineConfig,
  type PipelineContext,
  type PipelineRequest,
} from "./pipeline.js";
import { findRouteSchema } from "./route-schemas.js";
import {
  handleCreateReceive,
  handleGetReceive,
  handleCreateInternalMove,
  handleGetInternalMove,
  handleCreateExternalSend,
  handleGetExternalSend,
  type OperationRouteStore,
  type RouteHandlerResult,
} from "./routes/index.js";

// the media type is application/json; charset=utf-8 for every JSON route.
const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

export interface OperationRouterDeps {
  readonly store: OperationRouteStore;
  /**
   * Branded auth binding from createRejectAllOperationAuth /
   * createImplementerBearerAuth. Unbranded always-true hooks are
   * refused at construction — production cannot mount a live store open.
   */
  readonly auth: OperationAuthBinding;
  readonly newRequestId: PipelineConfig["newRequestId"];
  readonly strictJson?: PipelineConfig["strictJson"];
}

export interface RouterResponse {
  readonly status: number;
  readonly body: string;
  readonly headers: Record<string, string>;
}

export type OperationRouter = (
  method: string,
  rawPath: string,
  rawBody: Uint8Array,
  headers: Record<string, string | undefined>,
) => Promise<RouterResponse>;

// The three collection roots whose item form is `GET /v1/<name>/:operation_id`.
const ITEM_COLLECTIONS = ["receives", "internal-moves", "external-sends"] as const;

type RouteMatch =
  | { readonly kind: "route"; readonly template: string; readonly operationId?: string }
  | { readonly kind: "not_found" };

// Match a pathname against exactly the six mounted templates. Any other /v1/*
// (action, admin, destinations, events, state, list, or a forbidden alias) is a
// genuine 404, never a shim. Route identity is (method, path): a known path with the
// wrong method addresses no resource AT that method, so it collapses to the SAME
// disposition as an unknown path — `not_found` (404). The frozen taxonomy (
// API_ERROR_CODES) enumerates no 405 and no `method_not_allowed` code; a 404 is
// contract-legal and, unlike a 405, enumerates no allowed-method set.
//
// GET /v1/operations is intentionally NOT mounted: / #1135 dropped the
// out-of-scope list route; six create/query routes are the frozen surface.
function matchRoute(method: string, pathname: string): RouteMatch {
  for (const name of ITEM_COLLECTIONS) {
    if (pathname === `/v1/${name}`) {
      return method === "POST" ? { kind: "route", template: `/v1/${name}` } : { kind: "not_found" };
    }
  }
  // Item form: exactly ["", "v1", <name>, <id>]. A trailing slash yields an empty
  // final segment (`/v1/receives/` → id ""), which is NOT a valid:operation_id.
  const segments = pathname.split("/");
  if (segments.length === 4 && segments[0] === "" && segments[1] === "v1") {
    const name = segments[2] ?? "";
    const id = segments[3] ?? "";
    if ((ITEM_COLLECTIONS as readonly string[]).includes(name) && id !== "") {
      return method === "GET"
        ? { kind: "route", template: `/v1/${name}/:operation_id`, operationId: id }
        : { kind: "not_found" };
    }
  }
  return { kind: "not_found" };
}

function errorResponse(error: ApiErrorResponse): RouterResponse {
  return { status: error.status, body: error.body, headers: { ...error.headers } };
}

function parseQuery(querystring: string): Record<string, string | undefined> {
  return Object.fromEntries(new URLSearchParams(querystring));
}

async function dispatch(
  template: string,
  ctx: PipelineContext,
  store: OperationRouteStore,
  operationId: string,
): Promise<RouteHandlerResult> {
  switch (template) {
    case "/v1/receives":
      return handleCreateReceive(ctx, store);
    case "/v1/receives/:operation_id":
      return handleGetReceive(ctx, store, operationId);
    case "/v1/internal-moves":
      return handleCreateInternalMove(ctx, store);
    case "/v1/internal-moves/:operation_id":
      return handleGetInternalMove(ctx, store, operationId);
    case "/v1/external-sends":
      return handleCreateExternalSend(ctx, store);
    case "/v1/external-sends/:operation_id":
      return handleGetExternalSend(ctx, store, operationId);
    default:
      // Unreachable: matchRoute only ever yields the six templates above. A future
      // template added to matchRoute without a case here must NOT silently fall through
      // to a wrong store method (money-path hazard); fail loud instead.
      throw new Error(`operation-router: unreachable dispatch template "${template}"`);
  }
}

export function createOperationRouter(deps: OperationRouterDeps): OperationRouter {
  // snapshot store+auth ONCE before assert and hook capture. Dual-read of
  // deps.auth / deps.store would let a getter or Proxy pass the WeakSet gate with
  // identity A then install always-true hooks (or a live store) from identity B.
  const store = deps.store;
  const auth = deps.auth;
  const newRequestId = deps.newRequestId;
  assertOperationAuthComposition(store, auth);

  // Production wire: install resolveCredential from implementer-bearer
  // auth so principal / idempotencyTenantId bind into PipelineContext. reject_all
  // has no resolver — authenticate still denies before any handler runs.
  const config: PipelineConfig = {
    newRequestId,
    strictJson: deps.strictJson,
    authenticate: auth.authenticate,
    authorizeScope: auth.authorizeScope,
    ...(auth.kind === "implementer_bearer"
      ? { resolveCredential: auth.resolveCredential }
      : {}),
  };

  return async (method, rawPath, rawBody, headers) => {
    const queryIndex = rawPath.indexOf("?");
    const pathname = queryIndex >= 0 ? rawPath.slice(0, queryIndex) : rawPath;
    const querystring = queryIndex >= 0 ? rawPath.slice(queryIndex + 1) : "";

    const match = matchRoute(method, pathname);
    if (match.kind === "not_found") {
      return errorResponse(apiErrorResponse("not_found", newRequestId()));
    }

    const routeSchema = findRouteSchema(method, match.template);
    if (routeSchema === undefined) {
      // Unreachable: every mounted template is registered in ROUTE_SCHEMAS. Treated
      // as a 404 rather than a crash if the two tables ever drift.
      return errorResponse(apiErrorResponse("not_found", newRequestId()));
    }

    const request: PipelineRequest = {
      method,
      path: pathname,
      rawBody,
      headers,
      query: parseQuery(querystring),
    };

    const outcome = await runValidationPipeline(config, request, routeSchema);
    if (!outcome.ok) {
      return errorResponse(outcome.error);
    }

    // The store handler runs exactly once — no retry, no catch-and-resubmit.
    // Dispatch closes over the snapshotted `store`, never re-reads deps.store.
    const result = await dispatch(match.template, outcome.context, store, match.operationId ?? "");
    if (!result.ok) {
      return errorResponse(result.error);
    }
    // Serve the handler's body string byte-for-byte (carries signed artifact bytes).
    // Preserve any handler success headers (e.g. Idempotency-Replayed) under the
    // frozen JSON content-type.
    return {
      status: result.status,
      body: result.body,
      headers: { "content-type": JSON_CONTENT_TYPE, ...result.headers },
    };
  };
}
