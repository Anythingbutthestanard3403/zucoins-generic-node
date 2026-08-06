// shape-only route classification for the seven signed reporting routes.
// The frozen `validateReportingRequestTarget` (reporting-tuples/request-target.ts) remains the
// ONLY authority on acceptable signed target bytes; this module's shape list is used twice:
// (1) BEFORE validation, to split "this server has no such route" (404) from "route exists but
// the target bytes fail the canonical policy" (400), and (2) AFTER the validator passes, to
// classify the route for evidence retention and idempotency. Because classification runs
// strictly post-validator, it can never admit a target the validator rejected.
//
// Governing spec: (route_id and
// retention_class CHECK constraints — the retention literals below are the frozen DDL values).

import type { ReportingRouteClass } from "@zucoins/generic-node-contracts";

// The two MUTATION route ids are frozen (FINGERPRINT_GUARDED_ROUTE_IDS and the DDL
// CHECK constraints). The five READ route ids are evidence projections ("never replay scope"
// per the reporting-persistence CONTRACT) — runtime literals chosen here, stable from this
// slice forward.
export const REPORTING_ROUTE_IDS = {
  destinationsList: "destinations_list",
  eventsList: "events_list",
  eventsStream: "events_stream",
  stateSnapshot: "state_snapshot",
  verificationMaterial: "verification_material",
  operationArmed: "operation_armed",
  verificationComplete: "verification_complete",
} as const;

export type ReportingRouteId = (typeof REPORTING_ROUTE_IDS)[keyof typeof REPORTING_ROUTE_IDS];

// The frozen DDL retention_class CHECK values (reporting_request_nonces).
export const REPORTING_RETENTION_CLASSES = {
  read: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE",
  mutation: "PERMANENT_MUTATION",
} as const;

export type ReportingRetentionClass =
  (typeof REPORTING_RETENTION_CLASSES)[keyof typeof REPORTING_RETENTION_CLASSES];

export interface ReportingRouteClassification {
  readonly routeId: ReportingRouteId;
  readonly requestClass: ReportingRouteClass;
  readonly retentionClass: ReportingRetentionClass;
}

interface RouteShape {
  readonly path: string;
  readonly classification: ReportingRouteClassification;
}

const READ = (routeId: ReportingRouteId): ReportingRouteClassification => ({
  routeId,
  requestClass: "READ",
  retentionClass: REPORTING_RETENTION_CLASSES.read,
});

const MUTATION = (routeId: ReportingRouteId): ReportingRouteClassification => ({
  routeId,
  requestClass: "MUTATION",
  retentionClass: REPORTING_RETENTION_CLASSES.mutation,
});

const FIXED_PATH_SHAPES: readonly RouteShape[] = [
  { path: "/v1/destinations", classification: READ(REPORTING_ROUTE_IDS.destinationsList) },
  { path: "/v1/events", classification: READ(REPORTING_ROUTE_IDS.eventsList) },
  { path: "/v1/events/stream", classification: READ(REPORTING_ROUTE_IDS.eventsStream) },
  { path: "/v1/state/snapshot", classification: READ(REPORTING_ROUTE_IDS.stateSnapshot) },
];

// Mirrors the frozen validator's operation-path pattern (same two capture groups: the
// operation id, then the action) so the two can never drift apart.
const OPERATION_PATH_SHAPE = /^\/v1\/operations\/([^/]+)\/(armed|verification-complete|verification-material)$/;

function pathOf(rawTarget: string): string {
  const question = rawTarget.indexOf("?");
  return question < 0 ? rawTarget : rawTarget.slice(0, question);
}

// Path-only shape probe: does this server carry a signed reporting route under this path?
// Deliberately method-agnostic — a wrong method on a known path must reach the frozen
// validator (which rejects it with a 400-class target failure), not vanish as an unknown
// route. Never decodes, never normalizes: the raw target is only split at its first `?`.
export function reportingRouteShapeMatches(rawTarget: string): boolean {
  const path = pathOf(rawTarget);
  if (FIXED_PATH_SHAPES.some((shape) => shape.path === path)) return true;
  return OPERATION_PATH_SHAPE.test(path);
}

// Method-exact classification. MUST run only after `validateReportingRequestTarget` accepted
// the (method, target) pair, so a null here is defensive dead code rather than an admission
// failure mode.
export function classifyReportingRoute(
  method: string,
  rawTarget: string,
): ReportingRouteClassification | null {
  const path = pathOf(rawTarget);
  if (method === "GET") {
    const fixed = FIXED_PATH_SHAPES.find((shape) => shape.path === path);
    if (fixed !== undefined) return fixed.classification;
  }
  const operation = path.match(OPERATION_PATH_SHAPE);
  if (operation === null) return null;
  const action = operation[2];
  if (action === "verification-material" && method === "GET") {
    return READ(REPORTING_ROUTE_IDS.verificationMaterial);
  }
  if (action === "armed" && method === "POST") {
    return MUTATION(REPORTING_ROUTE_IDS.operationArmed);
  }
  if (action === "verification-complete" && method === "POST") {
    return MUTATION(REPORTING_ROUTE_IDS.verificationComplete);
  }
  return null;
}
