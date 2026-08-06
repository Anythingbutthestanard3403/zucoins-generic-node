// destinations sub-router (POST/GET /v1/destinations).
// Implementer-bearer path for the dual-auth read (reporting takes the
// signed pipeline in the shell). Governing:.

import { apiErrorResponse, type ApiErrorResponse } from "./error-envelope.js";
import {
  assertOperationAuthComposition,
  type OperationAuthBinding,
} from "./operation-auth.js";
import {
  runValidationPipeline,
  type PipelineConfig,
  type PipelineRequest,
} from "./pipeline.js";
import { findRouteSchema } from "./route-schemas.js";
import type { DestinationService } from "./destination.js";
import type { OperationRouteStore } from "./routes/operation-routes.js";
import { handleCreateDestination, handleListDestinations } from "./destination-http.js";
import type { Uuid } from "../protocol/scalars.js";

const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

export interface DestinationsRouterDeps {
  readonly store: OperationRouteStore;
  readonly auth: OperationAuthBinding;
  readonly destinationService: DestinationService;
  readonly nodeId: Uuid;
  readonly newRequestId: PipelineConfig["newRequestId"];
}

export type DestinationsRouter = (
  method: string,
  rawPath: string,
  rawBody: Uint8Array,
  headers: Record<string, string | undefined>,
) => Promise<{ status: number; body: string; headers: Record<string, string> }>;

function err(error: ApiErrorResponse) {
  return { status: error.status, body: error.body, headers: { ...error.headers } };
}

function ok(status: number, body: string) {
  return { status, body, headers: { "content-type": JSON_CONTENT_TYPE } };
}

export function createDestinationsRouter(deps: DestinationsRouterDeps): DestinationsRouter {
  const store = deps.store;
  const auth = deps.auth;
  const service = deps.destinationService;
  const nodeId = deps.nodeId;
  const newRequestId = deps.newRequestId;
  assertOperationAuthComposition(store, auth);

  const config: PipelineConfig = {
    newRequestId,
    authenticate: auth.authenticate,
    authorizeScope: auth.authorizeScope,
    ...(auth.kind === "implementer_bearer" ? { resolveCredential: auth.resolveCredential } : {}),
  };

  const httpDeps = { service, nodeId };

  return async (method, rawPath, rawBody, headers) => {
    const queryIndex = rawPath.indexOf("?");
    const pathname = queryIndex >= 0 ? rawPath.slice(0, queryIndex) : rawPath;
    const querystring = queryIndex >= 0 ? rawPath.slice(queryIndex + 1) : "";
    const verb = method.trim().toUpperCase();

    if (pathname !== "/v1/destinations") {
      return err(apiErrorResponse("not_found", newRequestId()));
    }

    if (verb === "POST" || verb === "GET") {
      const routeSchema = findRouteSchema(verb, "/v1/destinations");
      if (routeSchema === undefined) {
        return err(apiErrorResponse("not_found", newRequestId()));
      }
      const request: PipelineRequest = {
        method: verb,
        path: pathname,
        rawBody,
        headers,
        query: Object.fromEntries(new URLSearchParams(querystring)),
      };
      const outcome = await runValidationPipeline(config, request, routeSchema);
      if (!outcome.ok) return err(outcome.error);
      const result =
        verb === "POST"
          ? await handleCreateDestination(outcome.context, httpDeps)
          : await handleListDestinations(outcome.context, httpDeps);
      if (!result.ok) return err(result.error);
      return ok(result.status, result.body);
    }

    return err(apiErrorResponse("not_found", newRequestId()));
  };
}

export function createFailClosedDestinationService(): DestinationService {
  const reject = async (): Promise<never> => {
    throw new Error("destination engine store is not yet wired — fail-closed");
  };
  return Object.freeze({
    register: reject,
    bless: reject,
    retire: reject,
    list: reject,
    get: reject,
  });
}
