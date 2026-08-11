// Route-policy concern manifest: the single serialized surface the freeze gate snapshots.
// buildRoutePolicyManifest() aggregates every frozen route-policy fact into one plain
// JSON-serializable object; manifest.freeze.test.ts diffs it against gen/route-policy.json.
// Evolving a frozen fact is a deliberate paired change: edit the fact and regenerate the golden.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { AUTH_CLASSES, AUTH_CLASS_POLICY } from "./auth-classes.js";
import {
  ROUTE_POLICIES,
  FORBIDDEN_ROUTE_PREFIXES,
  DEFERRED_UNFROZEN_ROUTES,
  type RoutePolicy,
} from "./routes.js";
import { REQUEST_PIPELINE, AUTH_STAGE_SEQUENCE, PIPELINE_INVARIANTS } from "./pipeline.js";

// Provisional ConcernManifest, mirroring the auth-errors provisional shape; superseded by the
// canonical shared ConcernManifest registration below.
export const routePolicyConcernManifest = {
  concern: "route-policy",
  ticket: "route-policy-freeze",
  frozen: [
    "AUTH_CLASS_POLICY",
    "ROUTE_POLICIES",
    "FORBIDDEN_ROUTE_PREFIXES",
    "REQUEST_PIPELINE",
    "AUTH_STAGE_SEQUENCE",
    "PIPELINE_INVARIANTS",
  ],
} as const;

// Build the serializable manifest the freeze gate diffs against gen/route-policy.json.
export function buildRoutePolicyManifest() {
  return {
    concern: routePolicyConcernManifest.concern,
    ticket: routePolicyConcernManifest.ticket,
    governing: {
      spec: "API contract: wire conventions, authentication classes, retired paths",
      decision: "non-oracular-auth-errors",
      dependsOn: "auth-errors-freeze",
    },
    authClasses: AUTH_CLASSES.map((name) => ({
      name,
      authFailureStatus: AUTH_CLASS_POLICY[name].authFailureStatus,
      authFailureCode: AUTH_CLASS_POLICY[name].authFailureCode,
      tenantResolutionCode: AUTH_CLASS_POLICY[name].tenantResolutionCode,
      nonOracularFrozen: AUTH_CLASS_POLICY[name].nonOracularFrozen,
      nonAuthorizationStatuses: [...AUTH_CLASS_POLICY[name].nonAuthorizationStatuses],
    })),
    routes: ROUTE_POLICIES.map((r: RoutePolicy) => ({
      method: r.method,
      path: r.path,
      authClass: r.authClass,
      // Present only for the dual-auth destinations read; omitted (not serialized) everywhere else.
      ...(r.authClasses ? { authClasses: [...r.authClasses] } : {}),
      scope: r.scope,
      tenantScoped: r.tenantScoped,
      idempotency: r.idempotency,
    })),
    forbiddenRoutePrefixes: [...FORBIDDEN_ROUTE_PREFIXES],
    deferredUnfrozenRoutes: DEFERRED_UNFROZEN_ROUTES.map((d) => ({
      concern: d.concern,
      blocker: d.blocker,
      owner: d.owner,
    })),
    pipeline: REQUEST_PIPELINE.map((s) => ({
      order: s.order, // contract-allow:frozen-manifest-field-name
      name: s.name,
      failsWith: s.failsWith,
      deferredTo: s.deferredTo,
    })),
    authStageSequence: [...AUTH_STAGE_SEQUENCE],
    pipelineInvariants: [...PIPELINE_INVARIANTS],
  } as const;
}

export type RoutePolicyManifest = ReturnType<typeof buildRoutePolicyManifest>;

/**
 * The route-policy concern's self-registered ConcernManifest. Wraps the exact
 * `buildRoutePolicyManifest()` output — the same call the freeze gate diffs against
 * `gen/route-policy.json` — byte-identically under the canonical shape;
 * `routePolicyConcernManifest` above is the provisional form it supersedes.
 * Registration export only — the concern-manifest registry assembles `src/registry.ts`.
 */
export const ROUTE_POLICY_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "route-policy",
  decisionRefs: ["non-oracular-auth-errors"],
  frozenValues: { routePolicy: buildRoutePolicyManifest() },
  goldenRefs: [
    {
      path: "src/route-policy/gen/route-policy.json",
      sha256: "3ffb407268b2f8c4c3cefacd3bd46b4090df6f39bab0384c73c7bebdd9a6bc22",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "API contract: wire conventions, authentication classes, retired paths",
    "non-oracular-auth-errors: credential/scope/tenant failures collapse to canonical 401/404 bodies; never 403",
  ],
});
