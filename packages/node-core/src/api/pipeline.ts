// The eight-stage request pipeline middleware. Implements the frozen
// REQUEST_PIPELINE stage sequence from generic-node-contracts as a composable
// validation layer. Each stage either passes the request forward or emits the
// canonical error envelope for its failure mode.
//
// Stage sequence (frozen, REQUEST_PIPELINE):
// 1. assign_request_id
// 2. authenticate_credential → failsWith invalid_api_key (401)
// 3. authorize_scope → failsWith invalid_api_key (401) [never 403]
// 4. enforce_idempotency → deferred to
// 5. resolve_object_with_tenant_predicate → failsWith not_found (404)
// 6. handler
// 7. audit_record → deferred to
// 8. emit_error_envelope
//
// Route-policy/pipeline.ts.

import {
  ROUTE_POLICIES,
  routeAuthClasses,
  type RoutePolicy,
} from "@zucoins/generic-node-contracts/route-policy";

import type { ApiErrorCode, ApiErrorResponse } from "./error-envelope.js";
import { apiErrorResponse, scopeDenialResponse } from "./error-envelope.js";
import { parseStrictJson, type StrictJsonConfig } from "./strict-json.js";
import { IdempotencyKeySchema } from "./scalars.js";
import type { RouteSchema } from "./route-schemas.js";
import type { AuthPrincipal, CredentialResolver } from "./tenant-middleware.js";
import { runTenantScopeGate } from "./tenant-middleware.js";

export interface PipelineRequest {
  readonly method: string;
  readonly path: string;
  readonly rawBody: Uint8Array;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly query: Readonly<Record<string, string | undefined>>;
}

export interface PipelineContext {
  readonly requestId: string;
  readonly request: PipelineRequest;
  readonly routeSchema: RouteSchema;
  parsedBody?: unknown;
  parsedQuery?: unknown;
  principal?: AuthPrincipal;
  idempotencyTenantId?: string;
  resolvedObject?: unknown;
}

export type PipelineOutcome =
  | { readonly ok: true; readonly context: PipelineContext }
  | { readonly ok: false; readonly error: ApiErrorResponse };

export interface PipelineConfig {
  readonly newRequestId: () => string;
  readonly strictJson?: Partial<StrictJsonConfig>;
  readonly authenticate?: (request: PipelineRequest) => boolean | Promise<boolean>;
  readonly authorizeScope?: (request: PipelineRequest, scope: string | null) => boolean | Promise<boolean>;
  readonly resolveCredential?: CredentialResolver;
  readonly resolveObjectWithTenantPredicate?: (
    context: Readonly<PipelineContext>,
    implementerId: string,
  ) => unknown | null | Promise<unknown | null>;
}

// Stage 1: assign_request_id — always succeeds, attaches a UUID.
function assignRequestId(config: PipelineConfig): string {
  return config.newRequestId();
}

const routeKey = (route: { readonly method: string; readonly path: string }): string =>
  `${route.method} ${route.path}`;

const POLICY_BY_ROUTE: ReadonlyMap<string, RoutePolicy> = new Map(
  ROUTE_POLICIES.map((policy) => [routeKey(policy), policy]),
);

// Routes this node serves that intentionally carry no 05-api-contract policy row. Empty after
// UP-13: `GET /health` is a PUBLIC ROUTE_POLICIES row (same posture as
// `GET /.well-known/zupay-node`), so it resolves through the policy table. Keeping this list
// (and the resolveRoutePolicy branch) means a future infrastructure-only probe can opt in under
// the api-validation exemption-laundering rules without inventing a second fail-open path.
// test/api-validation.test.ts consumes this same constant, so the drift gate and the
// enforcement below cannot diverge.
export const POLICY_EXEMPT_ROUTES: readonly string[] = [];

type PolicyResolution =
  | { readonly policed: true; readonly policy: RoutePolicy | null }
  | { readonly policed: false };

// Stage 3's input. ROUTE_POLICIES is the only source of a route's required scope. A null
// scope means the route's auth class carries no bearer scope (OPERATOR_SESSION, REPORTING_
// CREDENTIAL, SUBSCRIPTION_HANDLE, PUBLIC) and is authorized at stage 2 — that is NOT the same
// as a route having no policy at all, which is unpoliced and must not be served.
function resolveRoutePolicy(routeSchema: RouteSchema): PolicyResolution {
  const key = routeKey(routeSchema);
  const policy = POLICY_BY_ROUTE.get(key);
  if (policy !== undefined) return { policed: true, policy };
  if (POLICY_EXEMPT_ROUTES.includes(key)) return { policed: true, policy: null };
  return { policed: false };
}

// Stage 2+3 combined gate: authenticate then authorize. phantom 403 collapsed to 401 mandates that
// scope denial returns the SAME 401 as unknown key — no 403, no distinct code.
type AuthGateResult =
  | { readonly error: ApiErrorResponse; readonly principal?: never }
  | { readonly error: null; readonly principal?: AuthPrincipal };

async function authenticateAndAuthorize(
  config: PipelineConfig,
  request: PipelineRequest,
  policy: RoutePolicy | null,
  requestId: string,
): Promise<AuthGateResult> {
  if (policy === null || policy.authClass === "PUBLIC") {
    return { error: null };
  }
  const accepted = routeAuthClasses(policy);
  if (config.resolveCredential) {
    // IMPLEMENTER_BEARER admission (including multi-class rows like GET /v1/destinations).
    // Non-implementer classes on multi-class routes are NOT handled by the ik_ gate
    // they need their own presentation path. A bare ik_ on a route that does not accept
    // IMPLEMENTER_BEARER collapses to the generic 401 (phantom 403 collapsed to 401).
    if (!accepted.includes("IMPLEMENTER_BEARER")) {
      return { error: apiErrorResponse("invalid_api_key", requestId) };
    }
    // Scope gates only the IMPLEMENTER_BEARER path (RoutePolicy.scope doc).
    const outcome = await runTenantScopeGate(
      config.resolveCredential,
      request.headers,
      policy.scope,
      requestId,
    );
    return outcome.ok
      ? { error: null, principal: outcome.principal }
      : { error: outcome.error };
  }
  if (!config.authenticate) {
    return { error: apiErrorResponse("invalid_api_key", requestId) };
  }
  const authenticated = await config.authenticate(request);
  if (!authenticated) {
    return { error: apiErrorResponse("invalid_api_key", requestId) };
  }
  if (policy.scope !== null) {
    if (!config.authorizeScope) {
      return { error: scopeDenialResponse(requestId) };
    }
    const authorized = await config.authorizeScope(request, policy.scope);
    if (!authorized) {
      // scope denial is the generic 401, never 403.
      return { error: scopeDenialResponse(requestId) };
    }
  }
  // Legacy boolean hooks never bind principal — callers that need tenant isolation
  // must install resolveCredential (production createOperationRouter does).
  return { error: null };
}

// Stage 4: enforce_idempotency — validates Idempotency-Key header form on POST
// mutations. Full replay/conflict logic is deferred to.
function enforceIdempotency(
  request: PipelineRequest,
  routeSchema: RouteSchema,
  requestId: string,
): ApiErrorResponse | null {
  if (!routeSchema.requiresIdempotencyKey) return null;
  const raw = request.headers["idempotency-key"];
  if (raw === undefined || raw === "") {
    return apiErrorResponse("invalid_idempotency_key", requestId);
  }
  const result = IdempotencyKeySchema.safeParse(raw);
  if (!result.success) {
    return apiErrorResponse("invalid_idempotency_key", requestId);
  }
  return null;
}

// Validate the request body through strict JSON intake then the route's Zod schema.
function validateBody(
  rawBody: Uint8Array,
  routeSchema: RouteSchema,
  requestId: string,
  strictJsonConfig?: Partial<StrictJsonConfig>,
): { ok: true; value: unknown } | { ok: false; error: ApiErrorResponse } {
  if (routeSchema.method !== "POST" || !routeSchema.bodySchema) {
    return { ok: true, value: undefined };
  }

  const jsonOutcome = parseStrictJson(rawBody, strictJsonConfig);
  if (!jsonOutcome.ok) {
    return { ok: false, error: apiErrorResponse(jsonOutcome.code as ApiErrorCode, requestId) };
  }

  const schemaResult = routeSchema.bodySchema.safeParse(jsonOutcome.value);
  if (!schemaResult.success) {
    const issue = schemaResult.error.issues[0];
    const code: ApiErrorCode = issue?.code === "unrecognized_keys"
      ? "unknown_field"
      : "invalid_scalar";
    return { ok: false, error: apiErrorResponse(code, requestId) };
  }

  return { ok: true, value: schemaResult.data };
}

// Validate GET query parameters through the route's query schema.
function validateQuery(
  query: Readonly<Record<string, string | undefined>>,
  routeSchema: RouteSchema,
  requestId: string,
): { ok: true; value: unknown } | { ok: false; error: ApiErrorResponse } {
  if (!routeSchema.querySchema) {
    return { ok: true, value: undefined };
  }

  // Filter out undefined values for schema validation.
  const defined: Record<string, string> = {};
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) defined[key] = value;
  }

  const schemaResult = routeSchema.querySchema.safeParse(defined);
  if (!schemaResult.success) {
    const issue = schemaResult.error.issues[0];
    const code: ApiErrorCode = issue?.code === "unrecognized_keys"
      ? "unknown_field"
      : "invalid_scalar";
    return { ok: false, error: apiErrorResponse(code, requestId) };
  }

  return { ok: true, value: schemaResult.data };
}

// The full pipeline: runs stages 1–5 (validation portion) and returns either a
// validated context ready for the handler (stage 6) or an error envelope (stage 8).
export async function runValidationPipeline(
  config: PipelineConfig,
  request: PipelineRequest,
  routeSchema: RouteSchema,
): Promise<PipelineOutcome> {
  // Stage 1: assign request id.
  const requestId = assignRequestId(config);

  // Stage 2+3: authenticate and authorize scope. Fail closed — a route with neither a policy
  // row nor a structural exemption is unpoliced, and is rejected with stage 3's frozen failure
  // code rather than served as though it required no scope.
  const resolved = resolveRoutePolicy(routeSchema);
  if (!resolved.policed) return { ok: false, error: scopeDenialResponse(requestId) };

  const auth = await authenticateAndAuthorize(
    config,
    request,
    resolved.policy,
    requestId,
  );
  if (auth.error) return { ok: false, error: auth.error };

  // Stage 4: enforce idempotency key form.
  const idempotencyError = enforceIdempotency(request, routeSchema, requestId);
  if (idempotencyError) return { ok: false, error: idempotencyError };

  // Body validation (strict JSON + Zod schema) — runs before object resolution.
  const bodyOutcome = validateBody(request.rawBody, routeSchema, requestId, config.strictJson);
  if (!bodyOutcome.ok) return { ok: false, error: bodyOutcome.error };

  // Query validation for GET routes.
  const queryOutcome = validateQuery(request.query, routeSchema, requestId);
  if (!queryOutcome.ok) return { ok: false, error: queryOutcome.error };

  // Stage 5 (resolve_object_with_tenant_predicate) is handler-level; the pipeline
  // provides the validated context. The handler must use tenant-scoped lookups that
  // collapse cross-tenant to not_found (CANONICAL_NOT_FOUND_CODE).

  const context: PipelineContext = {
    requestId,
    request,
    routeSchema,
    parsedBody: bodyOutcome.value,
    parsedQuery: queryOutcome.value,
    principal: auth.principal,
    idempotencyTenantId: auth.principal?.implementerId,
  };

  // Stage 5: tenant-scoped routes require a tenant-predicated object resolver OR a
  // credential-bound principal that handlers will use for every store lookup.
  // Fail closed when tenantScoped is set but neither path can enforce the predicate
  // — silent skip was the production money-path hole.
  if (resolved.policy?.tenantScoped) {
    if (!auth.principal) {
      // No principal means the legacy boolean path was used without tenant binding.
      return { ok: false, error: apiErrorResponse("invalid_api_key", requestId) };
    }
    if (config.resolveObjectWithTenantPredicate) {
      const object = await config.resolveObjectWithTenantPredicate(
        context,
        auth.principal.implementerId,
      );
      if (object === null) {
        return { ok: false, error: apiErrorResponse("not_found", requestId) };
      }
      context.resolvedObject = object;
    }
    // else: principal is bound; handlers MUST tenant-predicate every get/create
    // (OperationRouteStore signatures require implementerId — see operation-routes.ts).
  }

  return { ok: true, context };
}
