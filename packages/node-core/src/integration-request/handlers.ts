// HTTP handlers for public Route 2 handshake:
//   POST /v1/integration-requests
//   GET  /v1/integration-requests/:id
// ZTR-1239.

import { apiErrorResponse, type ApiErrorResponse } from "../api/error-envelope.js";
import type { PipelineContext } from "../api/pipeline.js";
import type { RouteHandlerResult } from "../api/routes/operation-routes.js";
import {
  parseProposedIntegrationRule,
  serializeProposedRule,
} from "./proposed-rule.js";
import { consumeIntegrationRequestAttempt } from "./rate-limit.js";
import { claimTokenHashesEqual, generateClaimToken, hashClaimToken } from "./token.js";
import {
  INTEGRATION_REQUEST_INTAKE_SCOPES,
  INTEGRATION_REQUEST_PENDING_CAP,
  INTEGRATION_REQUEST_READ_GRACE_MS,
  INTEGRATION_REQUEST_TTL_MS,
  type IntegrationRequestIntakeScope,
  type IntegrationRequestStore,
} from "./types.js";

const JSON_OK = (status: number, body: unknown): RouteHandlerResult => ({
  ok: true,
  status,
  body: JSON.stringify(body),
});

const fail = (error: ApiErrorResponse): RouteHandlerResult => ({
  ok: false,
  error,
});

export interface IntegrationRequestHandlerDeps {
  readonly store: IntegrationRequestStore;
  readonly nodeId: string;
  /** Source IP for intake rate limit (socket peer). */
  readonly sourceIp: string | null;
  readonly now?: () => Date;
  readonly pendingCap?: number;
  readonly ttlMs?: number;
  readonly readGraceMs?: number;
}

function isIntakeScope(s: string): s is IntegrationRequestIntakeScope {
  return (INTEGRATION_REQUEST_INTAKE_SCOPES as readonly string[]).includes(s);
}

/**
 * Extract claim token from Authorization: Bearer <token> or X-ZP-Claim-Token.
 * Empty / missing → null (caller maps to uniform 404 after id lookup path).
 */
export function extractClaimToken(
  headers: Readonly<Record<string, string | undefined>>,
): string | null {
  const dedicated = headers["x-zp-claim-token"];
  if (typeof dedicated === "string" && dedicated.length > 0) {
    return dedicated.trim();
  }
  const auth = headers["authorization"];
  if (typeof auth !== "string") return null;
  const m = /^Bearer\s+(\S+)$/i.exec(auth.trim());
  return m?.[1] ?? null;
}

export async function handleCreateIntegrationRequest(
  ctx: PipelineContext,
  deps: IntegrationRequestHandlerDeps,
): Promise<RouteHandlerResult> {
  const now = deps.now?.() ?? new Date();

  if (!consumeIntegrationRequestAttempt(deps.sourceIp, now.getTime())) {
    return fail(apiErrorResponse("rate_limited", ctx.requestId));
  }

  const body = ctx.parsedBody;
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return fail(apiErrorResponse("invalid_scalar", ctx.requestId));
  }
  const rec = body as Record<string, unknown>;

  // display_name
  if (typeof rec.display_name !== "string") {
    return fail(apiErrorResponse("invalid_scalar", ctx.requestId));
  }
  const displayName = rec.display_name.trim();
  if (displayName.length < 1 || displayName.length > 120) {
    return fail(apiErrorResponse("invalid_scalar", ctx.requestId));
  }

  // requested_scopes ⊆ {send:create, send:read}, non-empty
  if (!Array.isArray(rec.requested_scopes) || rec.requested_scopes.length === 0) {
    return fail(apiErrorResponse("invalid_scalar", ctx.requestId));
  }
  const scopes: IntegrationRequestIntakeScope[] = [];
  const seen = new Set<string>();
  for (const s of rec.requested_scopes) {
    if (typeof s !== "string" || !isIntakeScope(s)) {
      return fail(apiErrorResponse("invalid_scalar", ctx.requestId));
    }
    if (!seen.has(s)) {
      seen.add(s);
      scopes.push(s);
    }
  }

  // proposed_rule
  const rule = parseProposedIntegrationRule(rec.proposed_rule);
  if (rule === null) {
    return fail(apiErrorResponse("invalid_scalar", ctx.requestId));
  }
  // Reject unknown top-level fields beyond the three intake fields.
  for (const key of Object.keys(rec)) {
    if (key !== "display_name" && key !== "requested_scopes" && key !== "proposed_rule") {
      return fail(apiErrorResponse("unknown_field", ctx.requestId));
    }
  }

  const pendingCap = deps.pendingCap ?? INTEGRATION_REQUEST_PENDING_CAP;
  const pending = await deps.store.countPending();
  if (pending >= pendingCap) {
    return fail(apiErrorResponse("rate_limited", ctx.requestId));
  }

  const claimToken = generateClaimToken();
  const claimTokenHash = hashClaimToken(claimToken);
  const proposedRuleJson = serializeProposedRule(rule);

  try {
    const row = await deps.store.insertPending({
      nodeId: deps.nodeId,
      displayName,
      requestedScopes: scopes,
      proposedRuleJson,
      claimTokenHash,
      now,
      ttlMs: deps.ttlMs ?? INTEGRATION_REQUEST_TTL_MS,
    });
    return JSON_OK(201, {
      request_id: row.id,
      claim_token: claimToken,
      expires_at: row.expires_at,
    });
  } catch {
    return fail(apiErrorResponse("service_unavailable", ctx.requestId));
  }
}

export async function handleGetIntegrationRequest(
  ctx: PipelineContext,
  deps: IntegrationRequestHandlerDeps,
  requestId: string,
): Promise<RouteHandlerResult> {
  const now = deps.now?.() ?? new Date();
  const readGraceMs = deps.readGraceMs ?? INTEGRATION_REQUEST_READ_GRACE_MS;
  const notFound = () => fail(apiErrorResponse("not_found", ctx.requestId));

  // UUID shape — invalid id is the same 404 as unknown (non-oracular).
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      requestId,
    )
  ) {
    return notFound();
  }

  const rawToken = extractClaimToken(ctx.request.headers);
  if (rawToken === null) {
    return notFound();
  }
  const tokenHash = hashClaimToken(rawToken);

  let row = await deps.store.findById(requestId);
  if (row === null) return notFound();

  // Token auth before any status disclosure.
  if (!claimTokenHashesEqual(row.claim_token_hash, tokenHash)) {
    return notFound();
  }

  // Lazy expire PENDING/APPROVED past TTL.
  if (
    (row.status === "PENDING" || row.status === "APPROVED") &&
    Date.parse(row.expires_at) <= now.getTime()
  ) {
    row = (await deps.store.lazyExpire(requestId, now)) ?? row;
  }

  // Past read-grace: plain 404 for terminal / expired rows.
  const expiresMs = Date.parse(row.expires_at);
  if (
    Number.isFinite(expiresMs) &&
    now.getTime() > expiresMs + readGraceMs &&
    row.status !== "CLAIMED" &&
    row.status !== "APPROVED"
  ) {
    // CLAIMED stays readable (status only) indefinitely so platforms can confirm.
    // APPROVED past TTL should already be EXPIRED via lazy path; if still APPROVED
    // and past grace, collapse.
    return notFound();
  }
  if (
    row.status === "EXPIRED" ||
    row.status === "DECLINED" ||
    row.status === "PENDING"
  ) {
    if (Number.isFinite(expiresMs) && now.getTime() > expiresMs + readGraceMs) {
      return notFound();
    }
    return JSON_OK(200, { status: row.status });
  }

  if (row.status === "CLAIMED") {
    return JSON_OK(200, { status: "CLAIMED" });
  }

  if (row.status === "APPROVED") {
    // Past TTL without lazy success still blocks claim.
    if (Date.parse(row.expires_at) <= now.getTime()) {
      row = (await deps.store.lazyExpire(requestId, now)) ?? row;
      if (row.status !== "APPROVED") {
        return JSON_OK(200, { status: row.status });
      }
    }

    const outcome = await deps.store.claimApproved({
      id: requestId,
      claimTokenHash: tokenHash,
      nodeId: deps.nodeId,
      now,
    });

    if (outcome.kind === "not_found") return notFound();
    if (outcome.kind === "status") {
      return JSON_OK(200, { status: outcome.status });
    }
    return JSON_OK(200, {
      status: "CLAIMED",
      api_key: outcome.api_key,
      public_prefix: outcome.public_prefix,
      scopes: outcome.scopes,
      approved_rule: outcome.approved_rule,
      implementer_id: outcome.implementer_id,
      credential_id: outcome.credential_id,
    });
  }

  return JSON_OK(200, { status: row.status });
}
