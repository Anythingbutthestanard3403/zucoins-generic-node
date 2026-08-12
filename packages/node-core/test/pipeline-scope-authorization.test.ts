// Stage 3 (authorize_scope) enforcement: the scope the pipeline hands to config.authorizeScope
// comes from ROUTE_POLICIES, and a route with no policy row is rejected rather than served.
//
// Governing spec: the API contract (auth classes, implementer bearer scopes),
// route-policy/pipeline.ts REQUEST_PIPELINE stage 3. Canonical: (scope denial is the
// generic 401, never 403), GET /health is the liveness probe, outside.

import { describe, expect, it } from "vitest";

import { runValidationPipeline, POLICY_EXEMPT_ROUTES } from "../src/api/pipeline.js";
import type { PipelineConfig, PipelineRequest } from "../src/api/pipeline.js";
import { ROUTE_SCHEMAS, type RouteSchema } from "../src/api/route-schemas.js";
import { apiErrorResponse, scopeDenialResponse } from "../src/api/error-envelope.js";
import { ROUTE_POLICIES } from "@zucoins/generic-node-contracts/route-policy";

const REQUEST_ID = "11111111-1111-4111-8111-111111111111";

const routeKey = (route: { readonly method: string; readonly path: string }): string =>
  `${route.method} ${route.path}`;

function requestFor(route: RouteSchema): PipelineRequest {
  // PUBLIC POST routes skip authenticate; body validation still runs. Supply a
  // schema-valid body so the unpoliced check only sees auth/policy failures.
  const needsBody = route.method === "POST" && route.bodySchema !== undefined;
  let payload: unknown = {};
  if (route.path === "/v1/integration-requests") {
    payload = {
      display_name: "probe",
      requested_scopes: ["send:create"],
      proposed_rule: {
        per_send_max_zkz: "1",
        window_hours: 1,
        window_cap_zkz: "1",
      },
    };
  }
  const rawBody = needsBody
    ? new TextEncoder().encode(JSON.stringify(payload))
    : new Uint8Array();
  return {
    method: route.method,
    path: route.path,
    rawBody,
    headers: needsBody
      ? { "content-type": "application/json" }
      : {},
    query: {},
  };
}

interface Spy {
  readonly config: PipelineConfig;
  readonly authenticateCalls: string[];
  // The scope argument of every authorizeScope call, in order. Empty ⇒ stage 3 never fired.
  readonly scopeCalls: (string | null)[];
}

function spyConfig(overrides: Partial<PipelineConfig> = {}): Spy {
  const authenticateCalls: string[] = [];
  const scopeCalls: (string | null)[] = [];
  const config: PipelineConfig = {
    newRequestId: () => REQUEST_ID,
    authenticate: (request) => {
      authenticateCalls.push(routeKey(request));
      return true;
    },
    authorizeScope: (_request, scope) => {
      scopeCalls.push(scope);
      return true;
    },
    ...overrides,
  };
  return { config, authenticateCalls, scopeCalls };
}

describe("stage 3 authorize_scope reads the scope from ROUTE_POLICIES", () => {
  it("passes the route's real policy scope, not null (POST /v1/receives → receive:create)", async () => {
    const route = ROUTE_SCHEMAS.find((r) => r.method === "POST" && r.path === "/v1/receives");
    expect(route).toBeDefined();

    const spy = spyConfig();
    await runValidationPipeline(spy.config, requestFor(route as RouteSchema), route as RouteSchema);

    expect(spy.scopeCalls).toEqual(["receive:create"]);
  });

  // Derived from the two frozen tables, so it cannot drift alongside a hand-written list: for
  // EVERY route the node validates, the scope reaching authorizeScope must be exactly the scope
  // its policy row declares. A null-scope policy (OPERATOR_SESSION, REPORTING_CREDENTIAL,
  // SUBSCRIPTION_HANDLE, PUBLIC) carries no bearer scope and is authorized at stage 2, so stage 3
  // correctly does not fire for it; the assertion records that as "no call" rather than skipping.
  it("every route in ROUTE_SCHEMAS receives its declared policy scope", async () => {
    const observed: Record<string, string | null | "NOT_CALLED"> = {};
    for (const route of ROUTE_SCHEMAS) {
      const spy = spyConfig();
      await runValidationPipeline(spy.config, requestFor(route), route);
      observed[routeKey(route)] = spy.scopeCalls.length === 0 ? "NOT_CALLED" : spy.scopeCalls[0]!;
    }

    const expected: Record<string, string | null | "NOT_CALLED"> = {};
    for (const route of ROUTE_SCHEMAS) {
      const policy = ROUTE_POLICIES.find((p) => routeKey(p) === routeKey(route));
      expected[routeKey(route)] = policy?.scope ?? "NOT_CALLED";
    }

    expect(observed).toEqual(expected);
  });

  // The eight implementer bearer routes are the ones that must actually be scope-gated;
  // pinning the count catches a policy row silently losing its scope.
  it("stage 3 fires for exactly the policy rows carrying a non-null scope", async () => {
    const scoped: string[] = [];
    for (const route of ROUTE_SCHEMAS) {
      const spy = spyConfig();
      await runValidationPipeline(spy.config, requestFor(route), route);
      if (spy.scopeCalls.length > 0) scoped.push(routeKey(route));
    }

    const expected = ROUTE_POLICIES.filter((p) => p.scope !== null).map(routeKey);
    expect(scoped.sort()).toEqual([...expected].sort());
    expect(scoped.length).toBe(8);
  });

  it("no route in ROUTE_SCHEMAS is currently unpoliced beyond POLICY_EXEMPT_ROUTES", async () => {
    const rejected: string[] = [];
    for (const route of ROUTE_SCHEMAS) {
      const spy = spyConfig();
      const outcome = await runValidationPipeline(spy.config, requestFor(route), route);
      // A policy-resolution rejection happens before stage 2, so authenticate never runs.
      if (!outcome.ok && spy.authenticateCalls.length === 0) rejected.push(routeKey(route));
    }
    expect(rejected).toEqual([]);
    expect(POLICY_EXEMPT_ROUTES).toEqual([]);
  });
});

describe("stage 3 denial is the generic 401", () => {
  it("a wrong-scope caller gets the generic 401, never a 403", async () => {
    const route = ROUTE_SCHEMAS.find((r) => r.method === "GET" && r.path === "/v1/destinations");
    const spy = spyConfig({ authorizeScope: () => false });

    const outcome = await runValidationPipeline(
      spy.config,
      requestFor(route as RouteSchema),
      route as RouteSchema,
    );

    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toEqual(scopeDenialResponse(REQUEST_ID));
    expect(outcome.error.status).toBe(401);
    expect(outcome.error.status).not.toBe(403);
    // byte-identical to an unknown-key rejection, so the response is no scope oracle.
    expect(outcome.error).toEqual(apiErrorResponse("invalid_api_key", REQUEST_ID));
  });
});

describe("an unpoliced route is rejected, not served", () => {
  // A route added to ROUTE_SCHEMAS with no ROUTE_POLICIES counterpart — the drift shape that
  // previously shipped served-with-no-auth-class.
  const unpoliced: RouteSchema = {
    method: "GET",
    path: "/v1/operations",
    requiresIdempotencyKey: false,
  };

  it("rejects a schema route with no policy row", async () => {
    const spy = spyConfig();
    const outcome = await runValidationPipeline(spy.config, requestFor(unpoliced), unpoliced);

    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toEqual(scopeDenialResponse(REQUEST_ID));
    expect(outcome.error.status).toBe(401);
  });

  // Fail closed means closed even for a caller holding a valid credential: the route has no
  // policy, so there is nothing to authorize against and it must not reach the handler.
  it("rejects it before authentication, so a valid credential cannot open it", async () => {
    const spy = spyConfig();
    await runValidationPipeline(spy.config, requestFor(unpoliced), unpoliced);

    expect(spy.authenticateCalls).toEqual([]);
    expect(spy.scopeCalls).toEqual([]);
  });

  it("a POST mutation with no policy is rejected rather than falling through as scope-free", async () => {
    const unpolicedPost: RouteSchema = {
      method: "POST",
      path: "/v1/quarantines",
      requiresIdempotencyKey: true,
    };
    const spy = spyConfig();
    const outcome = await runValidationPipeline(spy.config, requestFor(unpolicedPost), unpolicedPost);

    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.status).toBe(401);
    expect(spy.authenticateCalls).toEqual([]);
  });
});

describe("structural carve-outs stay open without a scope check", () => {
  // GET /health resolves through its PUBLIC policy row, not POLICY_EXEMPT_ROUTES.
  it("GET /health resolves through its PUBLIC policy row, not an exemption", async () => {
    const route = ROUTE_SCHEMAS.find((r) => r.method === "GET" && r.path === "/health");
    const spy = spyConfig();
    const outcome = await runValidationPipeline(
      spy.config,
      requestFor(route as RouteSchema),
      route as RouteSchema,
    );

    expect(outcome.ok).toBe(true);
    expect(spy.scopeCalls).toEqual([]);
    expect(POLICY_EXEMPT_ROUTES).not.toContain("GET /health");
    const policy = ROUTE_POLICIES.find((p) => routeKey(p) === "GET /health");
    expect(policy?.authClass).toBe("PUBLIC");
    expect(policy?.scope).toBeNull();
    expect(policy?.idempotency).toBe("NA");
  });

  // The discovery route is NOT an exemption — it resolves through its PUBLIC policy row, whose
  // scope is null. Pinning that here is what makes removing the row a failure rather than a
  // silent fall-through to unpoliced service.
  it("GET /.well-known/zupay-node resolves through its PUBLIC policy row, not an exemption", async () => {
    const route = ROUTE_SCHEMAS.find(
      (r) => r.method === "GET" && r.path === "/.well-known/zupay-node",
    );
    const spy = spyConfig();
    const outcome = await runValidationPipeline(
      spy.config,
      requestFor(route as RouteSchema),
      route as RouteSchema,
    );

    expect(outcome.ok).toBe(true);
    expect(spy.scopeCalls).toEqual([]);
    expect(POLICY_EXEMPT_ROUTES).not.toContain("GET /.well-known/zupay-node");
    const policy = ROUTE_POLICIES.find((p) => routeKey(p) === "GET /.well-known/zupay-node");
    expect(policy?.authClass).toBe("PUBLIC");
    expect(policy?.scope).toBeNull();
  });
});
