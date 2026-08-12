// The frozen route→policy catalog for the v2 launch API. Every launch route appears exactly
// once with its auth class, scope, tenant-scoping, and idempotency requirement. This is the
// single mapping the centralized pipeline consults; a route that is not here has no policy and
// must not be served.
//
// Governed by the API contract's wire/idempotency conventions, authentication classes, route
// inventory, and retired/forbidden paths, under the frozen non-oracular error vocabulary.

import type { AuthClass } from "./auth-classes.js";

// REQUIRED = Idempotency-Key mandatory (every POST mutation unless a read-like SSE stream).
// NA = not applicable (reads, SSE streams, discovery). The key mechanism/length/replay contract
// is the idempotency concern's; this catalog freezes only which routes require it.
export type IdempotencyRequirement = "REQUIRED" | "NA";

export interface RoutePolicy {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly authClass: AuthClass;
  // The full set of accepted auth classes, for the rare route that accepts more than one
  // (`GET /v1/destinations` — "`destination:read` or signed reporting credential" — is
  // the only such route in the frozen catalog). Omitted for every single-class route, where
  // `authClass` alone is authoritative. Always read the resolved set via routeAuthClasses(),
  // never `authClass` alone, when checking what a route accepts.
  readonly authClasses?: readonly AuthClass[];
  // Implementer bearer scope, or null for non-bearer classes / public. Gates only the
  // IMPLEMENTER_BEARER path on a multi-class route; a REPORTING_CREDENTIAL presentation carries
  // no scope, as on every other REPORTING_CREDENTIAL route.
  readonly scope: string | null;
  // True when the route resolves objects inside the authenticated implementer tenant, so a
  // cross-tenant reference must collapse to the same not_found as an absent object.
  readonly tenantScoped: boolean;
  readonly idempotency: IdempotencyRequirement;
}

// The full accepted auth-class set for a route: its declared `authClasses` when the route is
// multi-auth, otherwise the single `authClass`. Use this (never `route.authClass` alone) to ask
// "what can authenticate this route" — see the RoutePolicy.authClasses doc comment.
export function routeAuthClasses(route: RoutePolicy): readonly AuthClass[] {
  return route.authClasses ?? [route.authClass];
}

export const ROUTE_POLICIES = [
  // RECEIVE_EXTERNAL
  { method: "POST", path: "/v1/receives", authClass: "IMPLEMENTER_BEARER", scope: "receive:create", tenantScoped: true, idempotency: "REQUIRED" },
  { method: "GET", path: "/v1/receives/:operation_id", authClass: "IMPLEMENTER_BEARER", scope: "receive:read", tenantScoped: true, idempotency: "NA" },
  // MOVE_INTERNAL
  { method: "POST", path: "/v1/internal-moves", authClass: "IMPLEMENTER_BEARER", scope: "move:create", tenantScoped: true, idempotency: "REQUIRED" },
  { method: "GET", path: "/v1/internal-moves/:operation_id", authClass: "IMPLEMENTER_BEARER", scope: "move:read", tenantScoped: true, idempotency: "NA" },
  // SEND_EXTERNAL
  { method: "POST", path: "/v1/external-sends", authClass: "IMPLEMENTER_BEARER", scope: "send:create", tenantScoped: true, idempotency: "REQUIRED" },
  { method: "GET", path: "/v1/external-sends/:operation_id", authClass: "IMPLEMENTER_BEARER", scope: "send:read", tenantScoped: true, idempotency: "NA" },
  // Destinations
  { method: "POST", path: "/v1/destinations", authClass: "IMPLEMENTER_BEARER", scope: "destination:create", tenantScoped: true, idempotency: "REQUIRED" },
  // Dual-auth: destination:read bearer scope OR a signed reporting credential.
  { method: "GET", path: "/v1/destinations", authClass: "IMPLEMENTER_BEARER", authClasses: ["IMPLEMENTER_BEARER", "REPORTING_CREDENTIAL"], scope: "destination:read", tenantScoped: true, idempotency: "NA" },
  // Events, snapshot, browser status
  { method: "GET", path: "/v1/events", authClass: "REPORTING_CREDENTIAL", scope: null, tenantScoped: true, idempotency: "NA" },
  { method: "GET", path: "/v1/events/stream", authClass: "REPORTING_CREDENTIAL", scope: null, tenantScoped: true, idempotency: "NA" },
  { method: "GET", path: "/v1/state/snapshot", authClass: "REPORTING_CREDENTIAL", scope: null, tenantScoped: true, idempotency: "NA" },
  { method: "GET", path: "/v1/operations/:operation_id/subscribe", authClass: "SUBSCRIPTION_HANDLE", scope: null, tenantScoped: true, idempotency: "NA" },
  // Arm and verification barriers
  { method: "POST", path: "/v1/operations/:operation_id/armed", authClass: "REPORTING_CREDENTIAL", scope: null, tenantScoped: true, idempotency: "REQUIRED" },
  { method: "POST", path: "/v1/operations/:operation_id/verification-complete", authClass: "REPORTING_CREDENTIAL", scope: null, tenantScoped: true, idempotency: "REQUIRED" },
  // Verification material
  { method: "GET", path: "/v1/operations/:operation_id/verification-material", authClass: "REPORTING_CREDENTIAL", scope: null, tenantScoped: true, idempotency: "NA" },
  // Operator endpoints
  { method: "GET", path: "/admin/v1/external-sends/:operation_id/approval-challenge", authClass: "OPERATOR_SESSION", scope: null, tenantScoped: false, idempotency: "NA" },
  { method: "POST", path: "/admin/v1/external-sends/:operation_id/approve", authClass: "OPERATOR_SESSION", scope: null, tenantScoped: false, idempotency: "REQUIRED" },
  { method: "POST", path: "/admin/v1/external-sends/:operation_id/reject", authClass: "OPERATOR_SESSION", scope: null, tenantScoped: false, idempotency: "REQUIRED" },
  { method: "POST", path: "/admin/v1/destinations/:destination_id/bless", authClass: "OPERATOR_SESSION", scope: null, tenantScoped: false, idempotency: "REQUIRED" },
  { method: "POST", path: "/admin/v1/destinations/:destination_id/retire", authClass: "OPERATOR_SESSION", scope: null, tenantScoped: false, idempotency: "REQUIRED" },
  { method: "GET", path: "/admin/v1/operations/needs-attention", authClass: "OPERATOR_SESSION", scope: null, tenantScoped: false, idempotency: "NA" },
  { method: "GET", path: "/admin/v1/operations/:operation_id/recovery", authClass: "OPERATOR_SESSION", scope: null, tenantScoped: false, idempotency: "NA" },
  { method: "POST", path: "/admin/v1/operations/:operation_id/recovery-actions", authClass: "OPERATOR_SESSION", scope: null, tenantScoped: false, idempotency: "REQUIRED" },
  // Route 2 public handshake (platform intake + one-time claim poll)
  { method: "POST", path: "/v1/integration-requests", authClass: "PUBLIC", scope: null, tenantScoped: false, idempotency: "NA" },
  { method: "GET", path: "/v1/integration-requests/:id", authClass: "PUBLIC", scope: null, tenantScoped: false, idempotency: "NA" },
  // Discovery
  { method: "GET", path: "/.well-known/zupay-node", authClass: "PUBLIC", scope: null, tenantScoped: false, idempotency: "NA" },
  // Liveness (public, unauthenticated, no Idempotency-Key) — closes the ROUTE_SCHEMAS census.
  { method: "GET", path: "/health", authClass: "PUBLIC", scope: null, tenantScoped: false, idempotency: "NA" },
] as const satisfies readonly RoutePolicy[];

export type RoutePath = (typeof ROUTE_POLICIES)[number]["path"];

// Retired/forbidden path prefixes. Kept as data so the census test can assert no frozen
// route ever matches one — they must not exist as an alias, redirect, or compatibility shim.
export const FORBIDDEN_ROUTE_PREFIXES = [
  "/v1/reservations", // contract-allow:frozen-forbidden-route-denylist-entry-per-05-api-contract-s13
  "/v1/outbound-requests", // contract-allow:frozen-forbidden-route-denylist-entry-per-05-api-contract-s13
  "/v1/payments", // contract-allow:frozen-forbidden-route-denylist-entry-per-05-api-contract-s13
  "/v1/refunds", // contract-allow:frozen-forbidden-route-denylist-entry-per-05-api-contract-s13
  "/admin/v1/drains", // contract-allow:frozen-forbidden-route-denylist-entry-per-05-api-contract-s13
] as const;

// The exact proof-body intake route remains unauthorized until its owning concern freezes its
// method, path, authentication, body, and idempotency contract. Recorded here so nothing
// silently mints an endpoint for it; it carries no policy row above.
export const DEFERRED_UNFROZEN_ROUTES = [
  { concern: "exact proof-body intake", blocker: "intake contract not yet frozen", owner: "proof-body-intake" },
] as const;
