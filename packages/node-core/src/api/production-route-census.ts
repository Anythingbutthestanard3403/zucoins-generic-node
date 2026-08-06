// production HTTP census against frozen ROUTE_POLICIES.
//
// Reachable set contract:
// ROUTE_POLICIES ∪ {GET /health/ready} ∪ optional {GET /metrics}
//
// `GET /health` is inside ROUTE_POLICIES (PUBLIC). Only readiness
// remains an operational probe outside the frozen table.
//
// `/admin/v1/halt` is mounted live on the admin router (session /
// session+TOTP) as a SPA money-control extension alongside login/me/inventory
// same posture as HALT_ADMIN_ROUTES. It stays out of the frozen ROUTE_POLICIES
// table (operator_session surface, not implementer_bearer).
//
// `/admin/v1/operations/:operation_id/attention-retraction` is mounted
// live on the admin router (session+CSRF+fresh TOTP) alongside halt/recovery-actions
// — same posture as LIVE_HALT_ROUTES. It stays out of the frozen ROUTE_POLICIES
// table for the same reason (operator_session surface, not implementer_bearer).

import { ROUTE_POLICIES } from "@zucoins/generic-node-contracts/route-policy";
import { ADMIN_ROUTES, PUBLIC_ROUTES } from "@zucoins/generic-node-contracts/operations";

export const OPERATIONAL_PROBE_PATHS = [
  { method: "GET", path: "/health/ready" },
] as const;

/** Optional scrape surface — mounted only when METRICS_SCRAPE_TOKEN is set. */
export const OPTIONAL_METRICS_ROUTE = { method: "GET", path: "/metrics" } as const;

/**
 * Live operator halt surface (HALT_ADMIN_ROUTES).
 * Not in ROUTE_POLICIES; mounted on the admin dispatcher.
 */
export const LIVE_HALT_ROUTES = Object.freeze([
  { method: "GET" as const, path: "/admin/v1/halt", authMode: "operator_session" as const },
  {
    method: "POST" as const,
    path: "/admin/v1/halt",
    authMode: "operator_session_totp" as const,
  },
] as const);

/**
 * @deprecated mounted halt live — alias kept so prior imports compile.
 * Prefer LIVE_HALT_ROUTES.
 */
export const DEFERRED_HALT_ROUTE = Object.freeze({
  method: "POST" as const,
  path: "/admin/v1/halt",
  reason: "live on admin router — not in frozen ROUTE_POLICIES table",
  live: true as const,
});

/**
 * Live operator attention-retraction surface. Not in ROUTE_POLICIES;
 * mounted on the admin dispatcher (session+CSRF+fresh TOTP, same auth class as
 * the halt POST route).
 */
export const LIVE_ATTENTION_RETRACTION_ROUTES = Object.freeze([
  {
    method: "POST" as const,
    path: "/admin/v1/operations/:operation_id/attention-retraction",
    authMode: "operator_session_totp" as const,
  },
] as const);

export type RouteKey = `${string} ${string}`;

export function routeKeyOf(method: string, path: string): RouteKey {
  return `${method.trim().toUpperCase()} ${path}` as RouteKey;
}

/** Frozen catalog keys the production process must dispatch. */
export function routePolicyKeys(): readonly RouteKey[] {
  return ROUTE_POLICIES.map((r) => routeKeyOf(r.method, r.path));
}

/** Readiness probe always mounted outside ROUTE_POLICIES (`GET /health` is in the table). */
export function operationalProbeKeys(): readonly RouteKey[] {
  return OPERATIONAL_PROBE_PATHS.map((r) => routeKeyOf(r.method, r.path));
}

/**
 * Minimum reachable set excluding optional /metrics. Equality of the
 * production dispatch census against this set (plus optional metrics) is AC2.
 */
export function requiredProductionRouteKeys(): readonly RouteKey[] {
  return [...routePolicyKeys(), ...operationalProbeKeys()];
}

/** ADMIN_ROUTES path templates must match recovery registration (AC8). */
export function adminRouteKeys(): readonly RouteKey[] {
  return ADMIN_ROUTES.map((r) => routeKeyOf(r.method, r.path));
}

export function publicRouteKeys(): readonly RouteKey[] {
  return PUBLIC_ROUTES.map((r) => routeKeyOf(r.method, r.path));
}

/** Assert PUBLIC∪ADMIN equals ROUTE_POLICIES (manifest parity / OpenAPI honesty). */
export function routeManifestParityFindings(): readonly string[] {
  const policy = new Set(routePolicyKeys());
  const declared = new Set([...publicRouteKeys(), ...adminRouteKeys()]);
  const findings: string[] = [];
  for (const key of policy) {
    if (!declared.has(key)) findings.push(`policy_only: ${key}`);
  }
  for (const key of declared) {
    if (!policy.has(key)) findings.push(`declared_only: ${key}`);
  }
  return findings;
}
