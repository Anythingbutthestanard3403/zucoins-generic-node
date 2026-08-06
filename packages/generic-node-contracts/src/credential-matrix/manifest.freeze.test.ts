// Credential-matrix freeze + full credential/error response matrix. Consumes the auth-errors
// non-oracularity verifier (indistinguishable / isNonOracular) and the route-policy verifiers to
// prove, across every frozen auth class × failure state × representative route, that unknown,
// expired, revoked, wrong-tenant, and wrong-scope credentials create no existence or scope
// oracle, no failing request reaches the handler (no protected mutation/enumeration), and every
// pinned body is byte-identical. Mandatory negatives: one per matrix dimension (credential,
// scope, tenant, mutation/enumeration).
//
// Governed by the API contract's wire conventions and authentication classes, under the frozen
// non-oracular error vocabulary. Depends on the auth-errors and route-policy freezes.
import { describe, expect, it } from "vitest";

import golden from "./gen/credential-matrix.json" with { type: "json" };
import {
  type WireResponse,
  CANONICAL_AUTH_FAILURE_BODY,
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_NOT_FOUND_BODY,
  buildAuthErrorBody,
  indistinguishable,
  isNonOracular,
  normalizeRequestId,
} from "../auth-errors/index.js";
import {
  ROUTE_POLICIES,
  firstOracularRoute,
  isRoutePolicyNonOracular,
} from "../route-policy/index.js";
import {
  type MatrixCell,
  MATRIX_AUTH_CLASSES,
  REPRESENTATIVE_ROUTES,
  buildCredentialMatrix,
  renderCellResponse,
} from "./matrix.js";
import { buildCredentialMatrixManifest } from "./manifest.js";

// A distinct, valid lowercase-canonical UUID per index, so synthesized responses vary only where
// a real per-request response would (the request_id the verifier normalizes away).
const rid = (i: number): string => `${i.toString(16).padStart(8, "0")}-0000-4000-8000-000000000000`;

const MATRIX = buildCredentialMatrix();
const cellsFor = (authClass: string, path: string): MatrixCell[] =>
  MATRIX.filter((c) => c.authClass === authClass && c.path === path);

describe("credential-matrix freeze", () => {
  it("serialized matrix manifest matches the committed golden snapshot", () => {
    expect(buildCredentialMatrixManifest()).toEqual(golden);
  });

  it("every representative route exists in the route-policy catalog with a matching auth class", () => {
    for (const authClass of MATRIX_AUTH_CLASSES) {
      for (const route of REPRESENTATIVE_ROUTES[authClass]) {
        const found = ROUTE_POLICIES.find((r) => r.method === route.method && r.path === route.path);
        expect(found, `${route.method} ${route.path}`).toBeDefined();
        expect(found?.authClass).toBe(authClass);
      }
    }
  });
});

describe("credential-matrix census: the whole matrix is non-oracular", () => {
  it("no cell yields a 403 and every cell uses the canonical auth-error code", () => {
    for (const cell of MATRIX) {
      expect(cell.status).not.toBe(403);
      expect(["invalid_api_key", "not_found"]).toContain(cell.code);
    }
  });

  it("no failing request reaches the handler (no protected mutation or enumeration)", () => {
    expect(MATRIX.every((c) => !c.reachesHandler)).toBe(true);
  });
});

describe("credential-matrix non-oracle across every class × route", () => {
  for (const authClass of MATRIX_AUTH_CLASSES) {
    for (const route of REPRESENTATIVE_ROUTES[authClass]) {
      const cells = cellsFor(authClass, route.path);
      const credential = cells.filter((c) => c.dimension !== "tenant");
      const tenant = cells.filter((c) => c.dimension === "tenant");

      it(`credential+scope states collapse to one 401 body on ${authClass} ${route.path}`, () => {
        const responses = credential.map((c, i) => renderCellResponse(c, rid(i + 1)));
        expect(isNonOracular(responses)).toBe(true);
        for (const r of responses) {
          expect(r.status).toBe(401);
          expect(normalizeRequestId(r.body)).toBe(CANONICAL_AUTH_FAILURE_BODY);
        }
      });

      it(`absent and cross-tenant collapse to one 404 body on ${authClass} ${route.path}`, () => {
        const responses = tenant.map((c, i) => renderCellResponse(c, rid(i + 100)));
        expect(isNonOracular(responses)).toBe(true);
        for (const r of responses) {
          expect(r.status).toBe(404);
          expect(normalizeRequestId(r.body)).toBe(CANONICAL_NOT_FOUND_BODY);
        }
      });
    }
  }
});

describe("credential-matrix timing class: credential/scope failures resolve before object lookup", () => {
  it("every credential/scope cell short-circuits before the tenant cells' stage", () => {
    for (const authClass of MATRIX_AUTH_CLASSES) {
      for (const route of REPRESENTATIVE_ROUTES[authClass]) {
        const cells = cellsFor(authClass, route.path);
        const objectStageOrder = cells.find((c) => c.dimension === "tenant")?.resolvingStageOrder;
        expect(objectStageOrder).toBeDefined();
        for (const cell of cells.filter((c) => c.dimension !== "tenant")) {
          expect(cell.resolvingStageOrder).toBeLessThan(objectStageOrder as number);
        }
      }
    }
  });
});

describe("credential-matrix centralization: identical failure response across a class's routes", () => {
  it("a class+state response is route-independent", () => {
    for (const authClass of MATRIX_AUTH_CLASSES) {
      const routes = REPRESENTATIVE_ROUTES[authClass];
      const first = cellsFor(authClass, routes[0].path);
      for (const route of routes.slice(1)) {
        const other = cellsFor(authClass, route.path);
        for (let i = 0; i < first.length; i += 1) {
          expect(
            indistinguishable(renderCellResponse(first[i], rid(7)), renderCellResponse(other[i], rid(7))),
          ).toBe(true);
        }
      }
    }
  });
});

describe("credential-matrix consumes the route-policy verifiers", () => {
  it("the full route catalog is non-oracular and every representative route passes", () => {
    expect(firstOracularRoute(ROUTE_POLICIES)).toBeNull();
    for (const authClass of MATRIX_AUTH_CLASSES) {
      for (const route of REPRESENTATIVE_ROUTES[authClass]) {
        const policy = ROUTE_POLICIES.find((r) => r.method === route.method && r.path === route.path);
        expect(policy && isRoutePolicyNonOracular(policy)).toBe(true);
      }
    }
  });
});

describe("credential-matrix mandatory negatives (one per matrix dimension)", () => {
  const canonical401: WireResponse = { status: 401, body: CANONICAL_AUTH_FAILURE_BODY };
  const canonical404: WireResponse = { status: 404, body: CANONICAL_NOT_FOUND_BODY };

  it("credential dimension: an unknown-key body that leaks 'unknown' is caught", () => {
    const leaky: WireResponse = {
      status: 401,
      body: buildAuthErrorBody(CANONICAL_AUTH_FAILURE_CODE, "Unknown API key.", rid(1)),
    };
    expect(isNonOracular([canonical401, leaky])).toBe(false);
  });

  it("scope dimension: an out-of-scope 403 is caught", () => {
    const scope403: WireResponse = {
      status: 403,
      body: buildAuthErrorBody("forbidden", "Insufficient scope.", rid(2)),
    };
    expect(indistinguishable(canonical401, scope403)).toBe(false);
  });

  it("tenant dimension: a cross-tenant 403 wrong_tenant is caught", () => {
    const tenant403: WireResponse = {
      status: 403,
      body: buildAuthErrorBody("wrong_tenant", "Object belongs to another tenant.", rid(3)),
    };
    expect(indistinguishable(canonical404, tenant403)).toBe(false);
  });

  it("mutation/enumeration dimension: a failure that reaches the handler is caught", () => {
    const reachedHandler = { ...MATRIX[0], reachesHandler: true };
    expect([reachedHandler].every((c) => !c.reachesHandler)).toBe(false);
  });
});
