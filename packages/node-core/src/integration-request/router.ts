// Public integration-request sub-router (POST create + GET claim poll).
// Auth class PUBLIC — claim token is application-layer, not pipeline bearer.

import { apiErrorResponse, type ApiErrorResponse } from "../api/error-envelope.js";
import {
  runValidationPipeline,
  type PipelineConfig,
  type PipelineRequest,
} from "../api/pipeline.js";
import { findRouteSchema } from "../api/route-schemas.js";
import {
  handleCreateIntegrationRequest,
  handleGetIntegrationRequest,
  type IntegrationRequestHandlerDeps,
} from "./handlers.js";
import type { IntegrationRequestStore } from "./types.js";

const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

export interface IntegrationRequestRouterDeps {
  readonly store: IntegrationRequestStore;
  readonly nodeId: string;
  readonly newRequestId: PipelineConfig["newRequestId"];
  readonly strictJson?: PipelineConfig["strictJson"];
  /** Resolve peer IP per request (socket remoteAddress). */
  readonly resolveSourceIp?: () => string | null;
  readonly now?: () => Date;
  readonly pendingCap?: number;
  readonly ttlMs?: number;
  readonly readGraceMs?: number;
}

export type IntegrationRequestRouter = (
  method: string,
  rawPath: string,
  rawBody: Uint8Array,
  headers: Record<string, string | undefined>,
  sourceIp?: string | null,
) => Promise<{ status: number; body: string; headers: Record<string, string> }>;

function err(error: ApiErrorResponse) {
  return { status: error.status, body: error.body, headers: { ...error.headers } };
}

function ok(status: number, body: string, extraHeaders?: Record<string, string>) {
  return {
    status,
    body,
    headers: { "content-type": JSON_CONTENT_TYPE, ...extraHeaders },
  };
}

const ITEM_RE = /^\/v1\/integration-requests\/([^/]+)$/;

export function createIntegrationRequestRouter(
  deps: IntegrationRequestRouterDeps,
): IntegrationRequestRouter {
  return async (method, rawPath, rawBody, headers, sourceIp) => {
    const pathOnly = rawPath.split(/[?#]/, 1)[0] ?? rawPath;
    const m = method.toUpperCase();

    let template: string | null = null;
    let requestId: string | undefined;
    if (m === "POST" && pathOnly === "/v1/integration-requests") {
      template = "/v1/integration-requests";
    } else if (m === "GET") {
      const match = ITEM_RE.exec(pathOnly);
      if (match) {
        template = "/v1/integration-requests/:id";
        requestId = match[1];
      }
    }

    if (template === null) {
      const requestIdGen = deps.newRequestId();
      return err(apiErrorResponse("not_found", requestIdGen));
    }

    const routeSchema = findRouteSchema(m, template);
    if (routeSchema === undefined) {
      return err(apiErrorResponse("not_found", deps.newRequestId()));
    }

    const pipelineRequest: PipelineRequest = {
      method: m,
      path: template,
      rawBody,
      headers,
      query: {},
    };

    const outcome = await runValidationPipeline(
      {
        newRequestId: deps.newRequestId,
        strictJson: deps.strictJson,
        // PUBLIC auth — no credential resolver.
      },
      pipelineRequest,
      routeSchema,
    );

    if (!outcome.ok) {
      return err(outcome.error);
    }

    const handlerDeps: IntegrationRequestHandlerDeps = {
      store: deps.store,
      nodeId: deps.nodeId,
      sourceIp:
        sourceIp !== undefined
          ? sourceIp
          : deps.resolveSourceIp !== undefined
            ? deps.resolveSourceIp()
            : null,
      now: deps.now,
      pendingCap: deps.pendingCap,
      ttlMs: deps.ttlMs,
      readGraceMs: deps.readGraceMs,
    };

    const result =
      template === "/v1/integration-requests"
        ? await handleCreateIntegrationRequest(outcome.context, handlerDeps)
        : await handleGetIntegrationRequest(
            outcome.context,
            handlerDeps,
            requestId!,
          );

    if (!result.ok) {
      return err(result.error);
    }
    return ok(result.status, result.body, result.headers as Record<string, string> | undefined);
  };
}
