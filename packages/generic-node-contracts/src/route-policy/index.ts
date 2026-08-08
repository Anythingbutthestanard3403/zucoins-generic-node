// the auth-errors/route-policy concern.2 — Public surface of the route-policy concern. Concern-local barrel owned by the
// the auth-errors/route-policy concern.2 slice; NOT the package index (src/index.ts, owned by the concern-manifest registry). the auth-errors/route-policy concern.3 consumes this.

export {
  type AuthClass,
  type AuthClassPolicy,
  AUTH_CLASSES,
  AUTH_CLASS_POLICY,
} from "./auth-classes.js";

export {
  type IdempotencyRequirement,
  type RoutePolicy,
  type RoutePath,
  ROUTE_POLICIES,
  FORBIDDEN_ROUTE_PREFIXES,
  DEFERRED_UNFROZEN_ROUTES,
  routeAuthClasses,
} from "./routes.js";

export {
  type PipelineStage,
  type PipelineStageName,
  REQUEST_PIPELINE,
  AUTH_STAGE_SEQUENCE,
  PIPELINE_INVARIANTS,
} from "./pipeline.js";

export {
  FORBIDDEN_AUTH_STATUS,
  isAuthClassNonOracular,
  isRoutePolicyNonOracular,
  isForbiddenRoute,
  firstOracularRoute,
  firstReportingTaxonomyLeak,
  fullyFrozenAuthClasses,
} from "./verifier.js";

export {
  type RoutePolicyManifest,
  routePolicyConcernManifest,
  buildRoutePolicyManifest,
} from "./manifest.js";
