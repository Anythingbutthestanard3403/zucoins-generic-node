// Pure verifiers over the route-policy contract. The credential/error matrix consumes these to
// prove that no route and no auth class re-introduces the scope/existence oracle the
// auth-errors freeze closed. All checks are structural over the frozen data; none performs I/O.
//
// Governed by the API contract's wire conventions, authentication classes, and retired paths,
// under the frozen non-oracular error vocabulary.

import {
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_NOT_FOUND_CODE,
} from "../auth-errors/index.js";
import { AUTH_CLASS_POLICY, type AuthClass, type AuthClassPolicy } from "./auth-classes.js";
import { FORBIDDEN_ROUTE_PREFIXES, routeAuthClasses, type RoutePolicy } from "./routes.js";

// The single forbidden HTTP status for an auth/scope denial. Any auth-class or route that would
// emit this is an oracle and is rejected by the verifiers below.
export const FORBIDDEN_AUTH_STATUS = 403 as const;

// True iff an auth class satisfies the non-oracularity invariants that apply to it. The 403 ban
// applies to EVERY class, frozen or not. A `nonOracularFrozen:false` class (OPERATOR_SESSION,
// PUBLIC) proves only that hard invariant here: its full credential/tenant code taxonomy is
// legitimately deferred to a later owner (the admin-auth concern — a different threat model), so
// this class-level check cannot assert its full collapse. It is NOT a free pass to non-oracularity —
// a tenant-scoped route on such a class is caught by isRoutePolicyNonOracular below, which is where
// the probing surface is known. A `nonOracularFrozen:true` class must additionally use exactly
// the canonical auth-error codes.
export function isAuthClassNonOracular(policy: AuthClassPolicy): boolean {
  if (policy.authFailureStatus === FORBIDDEN_AUTH_STATUS) return false;
  if (!policy.nonOracularFrozen) return true;
  if (policy.authFailureStatus !== 401) return false;
  if (policy.authFailureCode !== CANONICAL_AUTH_FAILURE_CODE) return false;
  return policy.tenantResolutionCode === CANONICAL_NOT_FOUND_CODE;
}

// True iff a route's policy is non-oracular. EVERY accepted auth class must pass — a route can
// accept more than one (the dual-auth `GET /v1/destinations`), so the check reads the full
// resolved set via routeAuthClasses(), never `route.authClass` alone (else a multi-auth route's
// secondary class goes unverified). A tenant-scoped route is the multi-implementer probing surface
// where credential / scope / cross-tenant existence oracles live, so EACH of its classes MUST have
// a FROZEN, proven non-oracular collapse — an unfrozen class defers its credential/tenant codes and
// cannot be asserted non-oracular here, so it fails closed rather than free-passing.
// Non-tenant-scoped admin/public routes legitimately ride the partial ("never 403") freeze:
// their code taxonomy is a different threat model deferred to the admin-auth concern.
export function isRoutePolicyNonOracular(route: RoutePolicy): boolean {
  for (const authClass of routeAuthClasses(route)) {
    const policy = AUTH_CLASS_POLICY[authClass];
    if (!isAuthClassNonOracular(policy)) return false;
    if (route.tenantScoped) {
      if (!policy.nonOracularFrozen) return false;
      if (policy.tenantResolutionCode !== CANONICAL_NOT_FOUND_CODE) return false;
    }
  }
  return true;
}

// True iff the path is one of the retired/forbidden prefixes (must never be served).
export function isForbiddenRoute(path: string): boolean {
  return FORBIDDEN_ROUTE_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

// Scan every route policy and return the path of the first oracular or forbidden route, or null
// when the whole catalog is clean. A caller feeds ROUTE_POLICIES and requires null.
export function firstOracularRoute(routes: readonly RoutePolicy[]): string | null {
  for (const route of routes) {
    if (isForbiddenRoute(route.path)) return route.path;
    if (!isRoutePolicyNonOracular(route)) return route.path;
  }
  return null;
}

// The auth classes whose full non-oracular collapse the route-policy freezes (used by the census test).
export function fullyFrozenAuthClasses(): AuthClass[] {
  return (Object.keys(AUTH_CLASS_POLICY) as AuthClass[]).filter(
    (name) => AUTH_CLASS_POLICY[name].nonOracularFrozen,
  );
}
