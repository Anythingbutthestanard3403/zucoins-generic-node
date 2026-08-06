// Tenant-isolation and scope-enforcement middleware tests.
// Governing spec: the API contract (auth classes, implementer bearer scopes).
// A scope denial is indistinguishable from an unknown key — both
// emit the generic 401 invalid_api_key; there is no 403 in this surface.

import { describe, expect, it } from "vitest";
import {
  bindTenant,
  enforceScope,
  extractImplementerBearer,
  hasScope,
  parseScope,
  runTenantScopeGate,
  runValidationPipeline,
  scopeDenialResponse,
  scopeMatches,
  apiErrorResponse,
  findRouteSchema,
  type AuthPrincipal,
  type CredentialResolver,
  type PipelineConfig,
  type PipelineRequest,
} from "../src/api/index.js";

const REQUEST_ID = "7b8bb326-0f2b-4dad-a8e7-40115b375ec4";

function headers(authorization: string | undefined): Record<string, string | undefined> {
  return { authorization };
}

function principal(implementerId: string, scopes: readonly string[]): AuthPrincipal {
  return { implementerId, scopes };
}

// A resolver keyed by raw bearer token; unknown tokens resolve to null.
function resolverFor(table: Record<string, AuthPrincipal>): CredentialResolver {
  return {
    resolve: async (bearerKey: string) => table[bearerKey] ?? null,
  };
}

function request(overrides: Partial<PipelineRequest> = {}): PipelineRequest {
  return {
    method: "GET",
    path: "/v1/destinations",
    rawBody: new Uint8Array(),
    headers: {},
    query: {},
    ...overrides,
  };
}

describe("scope grammar (parseScope)", () => {
  it("parses operation:action", () => {
    expect(parseScope("receive:create")).toEqual({ operation: "receive", action: "create" });
  });

  it("parses a wildcard action", () => {
    expect(parseScope("admin:*")).toEqual({ operation: "admin", action: "*" });
  });

  it("rejects a scope with no separator", () => {
    expect(parseScope("receivecreate")).toBeNull();
  });

  it("rejects an empty operation", () => {
    expect(parseScope(":create")).toBeNull();
  });

  it("rejects an empty action", () => {
    expect(parseScope("receive:")).toBeNull();
  });

  it("splits on the first separator only", () => {
    expect(parseScope("a:b:c")).toEqual({ operation: "a", action: "b:c" });
  });
});

describe("scope matching (scopeMatches / hasScope)", () => {
  it("matches an exact scope", () => {
    expect(scopeMatches("receive:create", "receive:create")).toBe(true);
  });

  it("does not match a different action on the same operation", () => {
    expect(scopeMatches("receive:read", "receive:create")).toBe(false);
  });

  it("does not match the same action on a different operation", () => {
    expect(scopeMatches("send:create", "receive:create")).toBe(false);
  });

  it("grants any action via an operation wildcard", () => {
    expect(scopeMatches("admin:*", "admin:approve")).toBe(true);
    expect(scopeMatches("admin:*", "admin:reject")).toBe(true);
  });

  it("does not let an operation wildcard cross operations", () => {
    expect(scopeMatches("admin:*", "receive:create")).toBe(false);
  });

  it("grants everything via the full wildcard", () => {
    expect(scopeMatches("*", "send:create")).toBe(true);
  });

  it("never grants from a malformed granted scope", () => {
    expect(scopeMatches("nonsense", "receive:create")).toBe(false);
    expect(scopeMatches(":", "receive:create")).toBe(false);
  });

  it("hasScope scans the granted set", () => {
    const granted = ["receive:read", "send:create"];
    expect(hasScope(granted, "send:create")).toBe(true);
    expect(hasScope(granted, "send:read")).toBe(false);
    expect(hasScope(granted, "move:create")).toBe(false);
  });

  it("hasScope is false for an empty grant set", () => {
    expect(hasScope([], "receive:create")).toBe(false);
  });
});

describe("bearer extraction (extractImplementerBearer)", () => {
  it("extracts an ik_ bearer token", () => {
    expect(extractImplementerBearer(headers("Bearer ik_abc123"))).toBe("ik_abc123");
  });

  it("is case-insensitive on the Bearer scheme", () => {
    expect(extractImplementerBearer(headers("bearer ik_abc123"))).toBe("ik_abc123");
    expect(extractImplementerBearer(headers("BEARER ik_abc123"))).toBe("ik_abc123");
  });

  it("trims surrounding whitespace on the token", () => {
    expect(extractImplementerBearer(headers("Bearer   ik_abc123  "))).toBe("ik_abc123");
  });

  it("returns null when the header is absent", () => {
    expect(extractImplementerBearer(headers(undefined))).toBeNull();
  });

  it("returns null for a non-Bearer scheme", () => {
    expect(extractImplementerBearer(headers("Basic ik_abc123"))).toBeNull();
  });

  it("returns null for a scheme-only header with no token", () => {
    expect(extractImplementerBearer(headers("Bearer"))).toBeNull();
  });

  it("rejects a subscription handle (sh_) on the implementer path", () => {
    expect(extractImplementerBearer(headers("Bearer sh_abc123"))).toBeNull();
  });

  it("rejects an empty token", () => {
    expect(extractImplementerBearer(headers("Bearer "))).toBeNull();
  });
});

describe("tenant isolation (bindTenant)", () => {
  const table = {
    ik_known: principal("impl-aaa", ["receive:create", "receive:read"]),
  };

  it("binds the implementer_id from a valid credential", async () => {
    const outcome = await bindTenant(resolverFor(table), headers("Bearer ik_known"), REQUEST_ID);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.principal.implementerId).toBe("impl-aaa");
  });

  it("never derives the tenant from the request body — only the credential", async () => {
    // A caller attempting to assert a foreign tenant via body/query gets only the
    // identity its own credential resolves to.
    const outcome = await bindTenant(resolverFor(table), headers("Bearer ik_known"), REQUEST_ID);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.principal.implementerId).toBe("impl-aaa");
      expect(outcome.principal.implementerId).not.toBe("impl-attacker");
    }
  });

  it("rejects an unknown key with the generic 401", async () => {
    const outcome = await bindTenant(resolverFor(table), headers("Bearer ik_unknown"), REQUEST_ID);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(outcome.error.body).toBe(apiErrorResponse("invalid_api_key", REQUEST_ID).body);
    }
  });

  it("rejects a missing header with the generic 401", async () => {
    const outcome = await bindTenant(resolverFor(table), headers(undefined), REQUEST_ID);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error.status).toBe(401);
  });
});

describe("scope enforcement (enforceScope)", () => {
  const cred = principal("impl-aaa", ["receive:create", "receive:read"]);

  it("passes when the credential holds the required scope", () => {
    expect(enforceScope(cred, "receive:create", REQUEST_ID)).toBeNull();
  });

  it("passes when no scope is required (null)", () => {
    expect(enforceScope(cred, null, REQUEST_ID)).toBeNull();
  });

  it("denies an out-of-scope operation", () => {
    const denial = enforceScope(cred, "send:create", REQUEST_ID);
    expect(denial).not.toBeNull();
    expect(denial!.status).toBe(401);
  });

  it("a scope denial is byte-identical to the unknown-key 401 (no 403)", () => {
    const denial = enforceScope(cred, "send:create", REQUEST_ID);
    const unknownKey = apiErrorResponse("invalid_api_key", REQUEST_ID);
    expect(denial!.status).toBe(401);
    expect(denial!.status).not.toBe(403);
    expect(denial!.body).toBe(unknownKey.body);
    expect(denial!.body).toBe(scopeDenialResponse(REQUEST_ID).body);
  });

  it("honours an operation wildcard grant", () => {
    const admin = principal("impl-admin", ["admin:*"]);
    expect(enforceScope(admin, "admin:approve", REQUEST_ID)).toBeNull();
    expect(enforceScope(admin, "receive:create", REQUEST_ID)).not.toBeNull();
  });
});

describe("combined gate (runTenantScopeGate)", () => {
  const table = {
    ik_recv: principal("impl-aaa", ["receive:create"]),
  };

  it("passes a valid, in-scope request and returns the principal", async () => {
    const outcome = await runTenantScopeGate(
      resolverFor(table),
      headers("Bearer ik_recv"),
      "receive:create",
      REQUEST_ID,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.principal.implementerId).toBe("impl-aaa");
  });

  it("fails authentication before scope is even considered", async () => {
    const outcome = await runTenantScopeGate(
      resolverFor(table),
      headers("Bearer ik_unknown"),
      "receive:create",
      REQUEST_ID,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error.status).toBe(401);
  });

  it("fails scope after successful authentication, with the generic 401", async () => {
    const outcome = await runTenantScopeGate(
      resolverFor(table),
      headers("Bearer ik_recv"),
      "send:create",
      REQUEST_ID,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(outcome.error.body).toBe(scopeDenialResponse(REQUEST_ID).body);
    }
  });
});

describe("pipeline integration", () => {
  const table = {
    ik_dest: principal("impl-bbb", ["destination:read"]),
    ik_send: principal("impl-ccc", ["send:create"]),
  };

  function config(): PipelineConfig {
    return {
      newRequestId: () => REQUEST_ID,
      resolveCredential: resolverFor(table),
    };
  }

  it("binds the resolved principal into the pipeline context on success", async () => {
    const route = findRouteSchema("GET", "/v1/destinations")!;
    const outcome = await runValidationPipeline(
      config(),
      request({ headers: headers("Bearer ik_dest") }),
      route,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.context.principal?.implementerId).toBe("impl-bbb");
      expect(outcome.context.principal?.scopes).toEqual(["destination:read"]);
    }
  });

  it("rejects a credential that lacks the route's required scope (generic 401)", async () => {
    const route = findRouteSchema("GET", "/v1/destinations")!;
    // ik_send holds send:create, not destination:read.
    const outcome = await runValidationPipeline(
      config(),
      request({ headers: headers("Bearer ik_send") }),
      route,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(outcome.error.body).toBe(scopeDenialResponse(REQUEST_ID).body);
    }
  });

  it("rejects a missing credential with the generic 401", async () => {
    const route = findRouteSchema("GET", "/v1/destinations")!;
    const outcome = await runValidationPipeline(config(), request({ headers: {} }), route);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error.status).toBe(401);
  });

  it("REJECTS a signed-reporting route presented with a bare implementer bearer", async () => {
    // /v1/events is a REPORTING_CREDENTIAL route: it is NOT authenticated by the implementer
    // bearer class. A valid ik_ bearer that lacks the signed reporting credential is the wrong
    // credential class and must collapse to the generic 401  — never admitted here.
    const route = findRouteSchema("GET", "/v1/events")!;
    const outcome = await runValidationPipeline(
      config(),
      request({ method: "GET", path: "/v1/events", headers: headers("Bearer ik_dest") }),
      route,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(outcome.error.body).toBe(apiErrorResponse("invalid_api_key", REQUEST_ID).body);
    }
  });

  it("PUBLIC discovery route passes with NO Authorization header even with a resolver configured", async () => {
    // The D1 regression: with a credential resolver set, a PUBLIC route (discovery) must still
    // be reachable with no Authorization header. PUBLIC means "no credential required", not
    // "credential required but scope skipped".
    const route = findRouteSchema("GET", "/.well-known/zupay-node")!;
    const outcome = await runValidationPipeline(
      config(),
      request({ method: "GET", path: "/.well-known/zupay-node", headers: {} }),
      route,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.context.principal).toBeUndefined();
  });

  it("PUBLIC liveness route (/health) passes with NO Authorization header and a resolver configured", async () => {
    const route = findRouteSchema("GET", "/health")!;
    const outcome = await runValidationPipeline(
      config(),
      request({ method: "GET", path: "/health", headers: {} }),
      route,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.context.principal).toBeUndefined();
  });

  it("fails closed on tenantScoped routes when legacy boolean hooks leave principal unbound (D3)", async () => {
    // D3: tenantScoped without a bound principal is not servable. Legacy
    // always-true hooks used to pass with principal undefined — that was the hole.
    const legacy: PipelineConfig = {
      newRequestId: () => REQUEST_ID,
      authenticate: () => true,
      authorizeScope: () => true,
    };
    const route = findRouteSchema("GET", "/v1/destinations")!;
    const outcome = await runValidationPipeline(
      legacy,
      request({ headers: headers("Bearer ik_dest") }),
      route,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(outcome.error.body).toBe(apiErrorResponse("invalid_api_key", REQUEST_ID).body);
    }
  });

  it("runs scope authorization before tenant-predicated object resolution", async () => {
    let lookups = 0;
    const route = findRouteSchema("GET", "/v1/destinations")!;
    const outcome = await runValidationPipeline(
      {
        ...config(),
        resolveObjectWithTenantPredicate: () => {
          lookups += 1;
          return null;
        },
      },
      request({ headers: headers("Bearer ik_send") }),
      route,
    );
    expect(outcome.ok).toBe(false);
    expect(lookups).toBe(0);
  });

  it("collapses cross-tenant and absent objects to byte-identical 404", async () => {
    const route = findRouteSchema("GET", "/v1/destinations")!;
    const run = (objectId: string) =>
      runValidationPipeline(
        {
          ...config(),
          resolveObjectWithTenantPredicate: (_context, implementerId) => {
            const rows = [{ id: "dest-foreign", implementerId: "impl-other" }];
            return rows.find(
              (row) =>
                row.id === objectId && row.implementerId === implementerId,
            ) ?? null;
          },
        },
        request({ headers: headers("Bearer ik_dest") }),
        route,
      );
    const crossTenant = await run("dest-foreign");
    const absent = await run("dest-absent");
    expect(crossTenant.ok).toBe(false);
    expect(absent.ok).toBe(false);
    if (!crossTenant.ok && !absent.ok) {
      expect(crossTenant.error.status).toBe(404);
      expect(crossTenant.error).toEqual(absent.error);
      expect(crossTenant.error.body).toBe(
        apiErrorResponse("not_found", REQUEST_ID).body,
      );
    }
  });

  it("binds idempotency namespace from credential tenant", async () => {
    const route = findRouteSchema("GET", "/v1/destinations")!;
    const outcome = await runValidationPipeline(
      config(),
      request({ headers: headers("Bearer ik_dest") }),
      route,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.context.idempotencyTenantId).toBe("impl-bbb");
    }
  });

  it("admits IMPLEMENTER_BEARER on multi-class GET /v1/destinations via authClasses (D4)", async () => {
    // Frozen policy: authClass IMPLEMENTER_BEARER + authClasses [IMPLEMENTER_BEARER, REPORTING_CREDENTIAL].
    // Gate must use routeAuthClasses, not primary authClass alone.
    const route = findRouteSchema("GET", "/v1/destinations")!;
    const outcome = await runValidationPipeline(
      config(),
      request({ headers: headers("Bearer ik_dest") }),
      route,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.context.principal?.implementerId).toBe("impl-bbb");
  });

  it("tenantScoped with resolveCredential and no stage-5 hook still binds principal for handlers", async () => {
    // Handlers enforce the tenant predicate via OperationRouteStore implementerId.
    // Stage-5 hook is optional when principal is bound; missing principal fails closed (above).
    const route = findRouteSchema("GET", "/v1/receives/:operation_id")!;
    const outcome = await runValidationPipeline(
      {
        newRequestId: () => REQUEST_ID,
        resolveCredential: resolverFor({
          ik_recv: principal("impl-aaa", ["receive:read"]),
        }),
      },
      request({
        method: "GET",
        path: "/v1/receives/00000000-0000-0000-0000-000000000001",
        headers: headers("Bearer ik_recv"),
      }),
      route,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.context.principal?.implementerId).toBe("impl-aaa");
      expect(outcome.context.resolvedObject).toBeUndefined();
    }
  });

  it("legacy path still collapses a scope denial to the generic 401", async () => {
    const legacy: PipelineConfig = {
      newRequestId: () => REQUEST_ID,
      authenticate: () => true,
      authorizeScope: () => false,
    };
    const route = findRouteSchema("GET", "/v1/destinations")!;
    const outcome = await runValidationPipeline(
      legacy,
      request({ headers: headers("Bearer ik_dest") }),
      route,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(outcome.error.body).toBe(scopeDenialResponse(REQUEST_ID).body);
    }
  });
});
