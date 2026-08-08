// Freeze + census gate for the route-policy / centralized-pipeline contract.
//
// Governed by the API contract under the frozen non-oracular error vocabulary. Proves: (a) the
// serialized manifest matches the committed golden; (b) every frozen route is non-oracular and
// none is a retired/forbidden path; (c) the centralized pipeline's auth stages match the
// auth-errors frozen AUTH_CHECK_ORDER (so the auth-errors freeze wins on conflict); and (d) —
// mandatory negative path — an oracular 403 auth class and a retired/forbidden route are both
// rejected by the verifiers.
import { describe, expect, it } from "vitest";

import golden from "./gen/route-policy.json" with { type: "json" };
import {
  AUTH_CHECK_ORDER,
  CANONICAL_AUTH_FAILURE_CODE,
  REJECTION_STATUS,
  REPORTING_CREDENTIAL_REJECTION_CODES,
  REPORTING_REJECTION_CODES,
  REPORTING_REQUEST_SHAPE_401_CODES,
  reportingWireCode,
  type ReportingRejectionCode,
} from "../auth-errors/index.js";
import { AUTH_CLASS_POLICY, AUTH_CLASSES, type AuthClassPolicy } from "./auth-classes.js";
import { ROUTE_POLICIES, routeAuthClasses, type RoutePolicy } from "./routes.js";
import { AUTH_STAGE_SEQUENCE, REQUEST_PIPELINE } from "./pipeline.js";
import { buildRoutePolicyManifest } from "./manifest.js";
import {
  firstOracularRoute,
  firstReportingTaxonomyLeak,
  fullyFrozenAuthClasses,
  isAuthClassNonOracular,
  isForbiddenRoute,
  isRoutePolicyNonOracular,
} from "./verifier.js";

describe("route-policy manifest freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildRoutePolicyManifest()).toEqual(golden);
  });

  it("every route uses a known auth class and each method+path appears exactly once", () => {
    const keys = ROUTE_POLICIES.map((r) => `${r.method} ${r.path}`);
    expect(new Set(keys).size).toBe(keys.length);
    for (const route of ROUTE_POLICIES) {
      expect(AUTH_CLASSES).toContain(route.authClass);
    }
  });

  it("GET /v1/destinations accepts exactly the frozen dual-auth set — bearer AND reporting credential, not just one", () => {
    const route = ROUTE_POLICIES.find((r) => r.method === "GET" && r.path === "/v1/destinations");
    if (!route) throw new Error("route not found: GET /v1/destinations");
    // Set equality, not count or single-membership: this fails if either class is missing,
    // if a third class sneaks in, or if the route regresses to single-auth.
    expect(new Set(routeAuthClasses(route))).toEqual(
      new Set(["IMPLEMENTER_BEARER", "REPORTING_CREDENTIAL"]),
    );
  });

  it("every other route accepts exactly its single declared auth class (no accidental widening)", () => {
    for (const route of ROUTE_POLICIES) {
      if (route.method === "GET" && route.path === "/v1/destinations") continue;
      expect(routeAuthClasses(route)).toEqual([route.authClass]);
    }
  });
});

describe("route-policy census: no route is an oracle or a forbidden path", () => {
  it("the whole route catalog is non-oracular and forbidden-path-free", () => {
    expect(firstOracularRoute(ROUTE_POLICIES)).toBeNull();
  });

  // "Any import endpoint" is retired/forbidden; unlike the other five retired entries (each a
  // specific ex-v1 literal path), no single literal names this one — greenfield launch exposes
  // NO wallet-key import endpoint anywhere, at any path shape, so FORBIDDEN_ROUTE_PREFIXES'
  // exact/prefix matcher (verifier.ts's isForbiddenRoute) cannot encode it as one entry without
  // both fabricating an unsourced literal and under-covering every other shape a future import
  // route could take. This substring census is the faithful equivalent: it fails on any frozen
  // route whose path contains "import", wherever it would appear.
  it("no frozen route path is an import endpoint", () => {
    const importRoutes = ROUTE_POLICIES.filter((r) => r.path.toLowerCase().includes("import"));
    expect(importRoutes).toEqual([]);
  });

  it("every fully frozen auth class collapses onto the canonical auth-error codes", () => {
    for (const name of fullyFrozenAuthClasses()) {
      expect(isAuthClassNonOracular(AUTH_CLASS_POLICY[name])).toBe(true);
    }
    // No auth class denies with 403, frozen or not.
    for (const name of AUTH_CLASSES) {
      expect(AUTH_CLASS_POLICY[name].authFailureStatus).not.toBe(403);
    }
  });

  it("every tenant-scoped route resolves through a not_found collapse", () => {
    for (const route of ROUTE_POLICIES) {
      if (route.tenantScoped) {
        expect(isRoutePolicyNonOracular(route)).toBe(true);
      }
    }
  });
});

describe("route-policy pipeline aligns with the auth-errors freeze (auth-errors wins on conflict)", () => {
  it("the pipeline's auth stages match the auth-errors AUTH_CHECK_ORDER, in sequence", () => {
    expect([...AUTH_STAGE_SEQUENCE]).toEqual(AUTH_CHECK_ORDER.map((s) => s.name));
    const pipelineNames = REQUEST_PIPELINE.map((s) => s.name);
    const authStagesInPipeline = pipelineNames.filter((n) =>
      (AUTH_STAGE_SEQUENCE as readonly string[]).includes(n),
    );
    expect(authStagesInPipeline).toEqual([...AUTH_STAGE_SEQUENCE]);
  });

  it("no pipeline stage emits a 403 for a scope denial", () => {
    for (const stage of REQUEST_PIPELINE) {
      expect(stage.failsWith).not.toBe("forbidden");
    }
  });
});

describe("route-policy non-oracularity verifier (mandatory negative path)", () => {
  it("REJECTS an auth class that denies scope with a 403", () => {
    const oracle403: AuthClassPolicy = {
      authFailureStatus: 403,
      authFailureCode: "forbidden",
      tenantResolutionCode: "not_found",
      nonOracularFrozen: true,
    };
    expect(isAuthClassNonOracular(oracle403)).toBe(false);
  });

  it("REJECTS a frozen class that swaps in a bespoke credential code", () => {
    const bespoke: AuthClassPolicy = {
      authFailureStatus: 401,
      authFailureCode: "invalid_reporting_key",
      tenantResolutionCode: "not_found",
      nonOracularFrozen: true,
    };
    expect(isAuthClassNonOracular(bespoke)).toBe(false);
  });

  it("REJECTS a retired/forbidden route injected into a catalog", () => {
    const forbidden: RoutePolicy = {
      method: "POST",
      path: "/v1/payments", // contract-allow:product-route-negative-fixture
      authClass: "IMPLEMENTER_BEARER",
      scope: "send:create",
      tenantScoped: true,
      idempotency: "REQUIRED",
    };
    expect(isForbiddenRoute(forbidden.path)).toBe(true);
    expect(firstOracularRoute([...ROUTE_POLICIES, forbidden])).toBe("/v1/payments"); // contract-allow:product-route-negative-fixture
  });

  it("REJECTS a tenant-scoped route backed by a nonOracularFrozen:false class (the free-pass breaking input)", () => {
    // the verifier used to free-pass any nonOracularFrozen:false class after only the 403
    // check, so a tenant-scoped route whose class defers its credential/tenant codes passed with
    // those codes unchecked — reopening the oracle on the probing surface. OPERATOR_SESSION is the
    // unfrozen class; on a tenant-scoped route it must now FAIL verification.
    expect(AUTH_CLASS_POLICY.OPERATOR_SESSION.nonOracularFrozen).toBe(false);
    const leakyTenantScoped: RoutePolicy = {
      method: "GET",
      path: "/v1/leaky-admin-read",
      authClass: "OPERATOR_SESSION",
      scope: null,
      tenantScoped: true,
      idempotency: "NA",
    };
    expect(isRoutePolicyNonOracular(leakyTenantScoped)).toBe(false);
    expect(firstOracularRoute([...ROUTE_POLICIES, leakyTenantScoped])).toBe("/v1/leaky-admin-read");
    // Non-regression: the real catalog (unfrozen classes only on non-tenant-scoped routes) stays clean.
    expect(firstOracularRoute(ROUTE_POLICIES)).toBeNull();
  });

  it("REJECTS a tenant-scoped dual-auth route whose SECONDARY class is unfrozen (checks every accepted class)", () => {
    // Under the dual-auth model the check must read routeAuthClasses(), not authClass alone:
    // a frozen primary must not shield an unfrozen secondary on the probing surface.
    const dualAuthLeak: RoutePolicy = {
      method: "GET",
      path: "/v1/dual-auth-leak",
      authClass: "IMPLEMENTER_BEARER",
      authClasses: ["IMPLEMENTER_BEARER", "OPERATOR_SESSION"],
      scope: "destination:read",
      tenantScoped: true,
      idempotency: "NA",
    };
    expect(isRoutePolicyNonOracular(dualAuthLeak)).toBe(false);
    // The real dual-auth route (bearer + reporting, both frozen) still passes.
    const destinationsRead = ROUTE_POLICIES.find(
      (r) => r.method === "GET" && r.path === "/v1/destinations",
    );
    if (!destinationsRead) throw new Error("route not found: GET /v1/destinations");
    expect(isRoutePolicyNonOracular(destinationsRead)).toBe(true);
  });
});

describe("REPORTING_CREDENTIAL's frozen collapse binds the SERVED rejection taxonomy", () => {
  // The gap this closes: AUTH_CLASS_POLICY.REPORTING_CREDENTIAL asserted `nonOracularFrozen`
  // while REJECTION_STATUS served ten distinguishable 401 codes from a module the verifiers
  // never read. Nothing structurally related the two, which is how they drifted apart.
  it("the served taxonomy is no wider than the frozen collapse allows", () => {
    expect(firstReportingTaxonomyLeak()).toBeNull();
  });

  it("catches the pre-fix taxonomy, where each credential code reached the wire verbatim", () => {
    // The mandatory negative path: feed the identity mapping the surface used before the
    // collapse and require the gate to name a credential-state code.
    const leak = firstReportingTaxonomyLeak((code) => code);
    expect(leak).not.toBeNull();
    expect(REPORTING_CREDENTIAL_REJECTION_CODES).toContain(leak as ReportingRejectionCode);
  });

  it("every 401 code is declared exactly once, as credential state or as request shape", () => {
    // Totality + disjointness of the partition. A 401 reject reason added later that declares
    // itself in neither array (or in both) fails here and in firstReportingTaxonomyLeak.
    const credential = new Set<string>(REPORTING_CREDENTIAL_REJECTION_CODES);
    const requestShape = new Set<string>(REPORTING_REQUEST_SHAPE_401_CODES);
    const declared = REPORTING_REJECTION_CODES.filter((code) => REJECTION_STATUS[code] === 401);
    expect(declared.length).toBe(credential.size + requestShape.size);
    for (const code of declared) {
      expect(credential.has(code) !== requestShape.has(code)).toBe(true);
    }
  });

  it("collapses exactly the six credential-state codes and no others", () => {
    // Set equality, so neither a silent removal nor a silent addition passes.
    expect(new Set(REPORTING_CREDENTIAL_REJECTION_CODES)).toEqual(
      new Set([
        "unknown_reporting_key",
        "tenant_binding_mismatch",
        "reporting_key_not_active",
        "reporting_auth_hold",
        "invalid_signature",
        "nonce_replay",
      ]),
    );
    for (const code of REPORTING_REJECTION_CODES) {
      const collapses = (REPORTING_CREDENTIAL_REJECTION_CODES as readonly string[]).includes(code);
      expect(reportingWireCode(code)).toBe(collapses ? CANONICAL_AUTH_FAILURE_CODE : code);
    }
  });
});
