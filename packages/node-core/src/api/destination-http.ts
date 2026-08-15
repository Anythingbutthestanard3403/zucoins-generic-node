// HTTP handlers for POST/GET /v1/destinations.
//
// is dual-auth — `destination:read` on the implementer-bearer pipeline
// (handleListDestinations) OR a signed reporting credential on the reporting pipeline
// (createDestinationsListRouteHandler). Both call the same DestinationService.list and
// render through the same listDestinationsBody, so the two pages cannot drift.

import { z } from "zod";

import { apiErrorResponse, type ApiErrorResponse } from "./error-envelope.js";
import type { PipelineContext } from "./pipeline.js";
import { CreateDestinationBody, ListDestinationsQuery } from "./route-schemas.js";
import type { RouteHandlerResult } from "./routes/operation-routes.js";
import type {
  DestinationListItem,
  DestinationPage,
  DestinationRecord,
  DestinationService,
} from "./destination.js";
import { reportingErrorResponse, reportingJsonResponse } from "../reporting/errors.js";
import type {
  ReportingHandlerResult,
  ReportingRouteHandler,
} from "../reporting/request-handler.js";
import type { VerifiedReportRequest } from "../reporting/request-verifier.js";
import type { Uuid } from "../protocol/scalars.js";

export interface DestinationHttpDeps {
  readonly service: DestinationService;
  /** Frozen node uuid — destinations are custody-node-scoped. */
  readonly nodeId: Uuid;
}

function assertPrincipal(ctx: PipelineContext): string | null {
  return (
    (ctx.principal as { implementerId?: string } | undefined)?.implementerId ??
    ctx.idempotencyTenantId ??
    null
  );
}

function success(status: number, body: unknown): RouteHandlerResult {
  return { ok: true, status, body: JSON.stringify(body) };
}

function fail(error: ApiErrorResponse): RouteHandlerResult {
  return { ok: false, error };
}

/**
 * Public v1 dest JSON is snake_case (`destination_id`, `wallet_id`, …).
 * Domain records stay camelCase; this is the only HTTP projection.
 */
export function destinationToWire(
  item: DestinationRecord | DestinationListItem,
): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    destination_id: item.destinationId,
    node_id: item.nodeId,
    wallet_id: item.walletId,
    wallet_public_key: item.walletPublicKey,
    state: item.state,
    label: item.label,
    blessed_at: item.blessedAt,
    blessed_by_device_key_id: item.blessedByDeviceKeyId,
    blessing_artifact_id: item.blessingArtifactId,
    retired_at: item.retiredAt,
    created_at: item.createdAt,
  };
  if ("move_eligible" in item) {
    wire.move_eligible = item.move_eligible;
    wire.ineligibility_reason = item.ineligibility_reason;
  }
  return wire;
}

export async function handleCreateDestination(
  ctx: PipelineContext,
  deps: DestinationHttpDeps,
): Promise<RouteHandlerResult> {
  try {
    if (assertPrincipal(ctx) === null) {
      return fail(apiErrorResponse("invalid_api_key", ctx.requestId));
    }
    const body = CreateDestinationBody.parse(ctx.parsedBody) as z.infer<typeof CreateDestinationBody>;
    const idempotencyKey =
      typeof ctx.request.headers["idempotency-key"] === "string"
        ? ctx.request.headers["idempotency-key"]!
        : "";
    if (idempotencyKey.length === 0) {
      return fail(apiErrorResponse("invalid_idempotency_key", ctx.requestId));
    }
    const result = await deps.service.register({
      nodeId: deps.nodeId,
      label: body.label,
      idempotencyKey,
    });
    return success(result.status === "created" ? 201 : 200, destinationToWire(result.destination));
  } catch (err) {
    if (err instanceof z.ZodError) {
      // Canonical invalid_scalar only — never pass Zod's serialized issue array
      // (field paths / expected / received) into the implementer-facing body.
      return fail(apiErrorResponse("invalid_scalar", ctx.requestId));
    }
    return fail(apiErrorResponse("service_unavailable", ctx.requestId));
  }
}

/**
 * The single response body. Both auth classes render through this, so an
 * implementer-bearer page and a reporting-credential page over the same tenant/node
 * are byte-identical by construction.
 */
export function listDestinationsBody(page: DestinationPage): string {
  return JSON.stringify({
    items: page.items.map(destinationToWire),
    next_after: page.nextAfter,
  });
}

type ListDestinationsFilter = z.infer<typeof ListDestinationsQuery>;

export type ListDestinationsQueryParse =
  | { readonly ok: true; readonly query: ListDestinationsFilter }
  | { readonly ok: false };

/**
 * query off the opaque exact raw signed target. Delegates to the same strict
 * ListDestinationsQuery the bearer pipeline validates with (state enum, `after` uuid,
 * `limit` 1–100), so an unknown parameter is rejected on both auth classes alike.
 */
export function parseListDestinationsQueryFromTarget(
  rawTarget: string,
): ListDestinationsQueryParse {
  const question = rawTarget.indexOf("?");
  const search = question < 0 ? "" : rawTarget.slice(question + 1);
  const parsed = ListDestinationsQuery.safeParse(
    Object.fromEntries(new URLSearchParams(search)),
  );
  if (!parsed.success) return { ok: false };
  return { ok: true, query: parsed.data };
}

async function listPage(
  service: DestinationService,
  nodeId: Uuid,
  query: ListDestinationsFilter,
): Promise<DestinationPage> {
  return service.list(nodeId, {
    state: query.state ?? undefined,
    after: (query.after ?? undefined) as never,
    limit: query.limit,
  });
}

export async function handleListDestinations(
  ctx: PipelineContext,
  deps: DestinationHttpDeps,
): Promise<RouteHandlerResult> {
  try {
    if (assertPrincipal(ctx) === null) {
      return fail(apiErrorResponse("invalid_api_key", ctx.requestId));
    }
    const query = ListDestinationsQuery.parse(ctx.request.query ?? {});
    const page = await listPage(deps.service, deps.nodeId, query);
    return { ok: true, status: 200, body: listDestinationsBody(page) };
  } catch {
    return fail(apiErrorResponse("service_unavailable", ctx.requestId));
  }
}

export interface DestinationsListRouteDeps {
  readonly service: DestinationService;
  readonly newRequestId: () => string;
}

/**
 * on the signed reporting credential. The reporting pipeline has
 * already verified the credential and burned the nonce; this is the transport edge only.
 *
 * Tenant scope is `request.binding.nodeId` — the node the presented reporting key is
 * registered to — never ambient config, so a credential bound to another node's
 * registration collapses to `{"items":[],"next_after":null}`. A foreign or unknown
 * `after` uuid stays an opaque ordering bound and is never answered with a
 * differentiated 404: that would be the existence oracle the reporting-persistence
 * CONTRACT forbids.
 *
 * Read-only: persistChild is always null, so no completion row is written.
 */
export function createDestinationsListRouteHandler(
  deps: DestinationsListRouteDeps,
): ReportingRouteHandler {
  return async (request: VerifiedReportRequest): Promise<ReportingHandlerResult> => {
    const parsed = parseListDestinationsQueryFromTarget(request.fingerprint.rawTarget);
    if (!parsed.ok) {
      // Same envelope the bearer pipeline emits for a bad query (api error vocabulary);
      // the frozen reporting-rejection codes stay reserved for the pre-handler auth stages.
      // No message override: Zod issue dumps stay off the wire (non-oracular surface).
      const error = apiErrorResponse("invalid_scalar", deps.newRequestId());
      return {
        response: reportingJsonResponse(error.status, error.body),
        persistChild: null,
      };
    }
    try {
      const page = await listPage(
        deps.service,
        request.binding.nodeId as Uuid,
        parsed.query,
      );
      return {
        response: reportingJsonResponse(200, listDestinationsBody(page)),
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
