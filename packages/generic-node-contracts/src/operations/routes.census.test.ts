import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  PUBLIC_ROUTES,
  ADMIN_ROUTES,
  RETIRED_ROUTES,
  isRetiredImportEndpoint,
  type RouteEntry,
} from "./routes.contract.ts";

/**
 * A retired path pattern carries zero authority; this asserts no active route path matches
 * any retired prefix pattern.
 */
const assertNoRetiredRouteActive = (activeRoutes: readonly RouteEntry[]): void => {
  for (const retiredPattern of RETIRED_ROUTES) {
    const prefix = retiredPattern.replace(/\*$/, "");
    const collision = activeRoutes.find((route) => route.path.startsWith(prefix));
    if (collision !== undefined) {
      throw new Error(
        `active route "${collision.method} ${collision.path}" matches retired pattern "${retiredPattern}"`,
      );
    }
  }
};

/**
 * The retired "any import endpoint" category carries no concrete path pattern; this asserts no
 * active route path classifies as an import endpoint under `isRetiredImportEndpoint`.
 */
const assertNoImportEndpointActive = (activeRoutes: readonly RouteEntry[]): void => {
  const collision = activeRoutes.find((route) => isRetiredImportEndpoint(route.path));
  if (collision !== undefined) {
    throw new Error(
      `active route "${collision.method} ${collision.path}" is a retired import endpoint`,
    );
  }
};

/**
 * Full-object freeze (path+method+authMode) of the public routes, in canonical sequence. A
 * cardinality-only check (`toHaveLength`) does not catch an authMode downgrade or a swapped-in
 * route of the same count; `assertFieldOrder` (exact `toEqual`) does.
 */
const FROZEN_PUBLIC_ROUTES: readonly RouteEntry[] = [
  { method: "POST", path: "/v1/receives", authMode: "implementer_bearer" },
  { method: "GET", path: "/v1/receives/:operation_id", authMode: "implementer_bearer" },
  { method: "POST", path: "/v1/internal-moves", authMode: "implementer_bearer" },
  { method: "GET", path: "/v1/internal-moves/:operation_id", authMode: "implementer_bearer" },
  { method: "POST", path: "/v1/external-sends", authMode: "implementer_bearer" },
  { method: "GET", path: "/v1/external-sends/:operation_id", authMode: "implementer_bearer" },
  { method: "POST", path: "/v1/destinations", authMode: "implementer_bearer" },
  { method: "GET", path: "/v1/destinations", authMode: "implementer_bearer_or_signed_reporting" },
  { method: "GET", path: "/v1/events", authMode: "signed_reporting_credential" },
  { method: "GET", path: "/v1/events/stream", authMode: "signed_reporting_credential" },
  { method: "GET", path: "/v1/state/snapshot", authMode: "signed_reporting_credential" },
  { method: "GET", path: "/v1/operations/:operation_id/subscribe", authMode: "subscription_handle" },
  {
    method: "POST",
    path: "/v1/operations/:operation_id/armed",
    authMode: "signed_reporting_credential",
  },
  {
    method: "POST",
    path: "/v1/operations/:operation_id/verification-complete",
    authMode: "signed_reporting_credential",
  },
  {
    method: "GET",
    path: "/v1/operations/:operation_id/verification-material",
    authMode: "signed_reporting_credential",
  },
  { method: "POST", path: "/v1/integration-requests", authMode: "public" },
  { method: "GET", path: "/v1/integration-requests/:id", authMode: "public" },
  { method: "GET", path: "/.well-known/zupay-node", authMode: "public" },
  { method: "GET", path: "/health", authMode: "public" },
];

/** Full-object freeze of the admin routes, in canonical sequence. */
const FROZEN_ADMIN_ROUTES: readonly RouteEntry[] = [
  {
    method: "GET",
    path: "/admin/v1/external-sends/:operation_id/approval-challenge",
    authMode: "operator_session",
  },
  {
    method: "POST",
    path: "/admin/v1/external-sends/:operation_id/approve",
    authMode: "operator_session_totp",
  },
  {
    method: "POST",
    path: "/admin/v1/external-sends/:operation_id/reject",
    authMode: "operator_session_totp",
  },
  {
    method: "POST",
    path: "/admin/v1/destinations/:destination_id/bless",
    authMode: "operator_session_totp_device",
  },
  {
    method: "POST",
    path: "/admin/v1/destinations/:destination_id/retire",
    authMode: "operator_session",
  },
  { method: "GET", path: "/admin/v1/operations/needs-attention", authMode: "operator_session" },
  {
    method: "GET",
    path: "/admin/v1/operations/:operation_id/recovery",
    authMode: "operator_session",
  },
  {
    method: "POST",
    path: "/admin/v1/operations/:operation_id/recovery-actions",
    authMode: "operator_session_totp",
  },
];

describe("routes census", () => {
  it("freezes the public route inventory exactly (path+method+authMode)", () => {
    assertFieldOrder(PUBLIC_ROUTES, FROZEN_PUBLIC_ROUTES);
  });

  it("freezes the admin route inventory exactly (path+method+authMode)", () => {
    assertFieldOrder(ADMIN_ROUTES, FROZEN_ADMIN_ROUTES);
  });

  it("rejects an authMode downgrade on the external-send approval route (negative path)", () => {
    expectRejects(
      () =>
        ADMIN_ROUTES.map((route) =>
          route.path === "/admin/v1/external-sends/:operation_id/approve"
            ? { ...route, authMode: "operator_session" as const }
            : route,
        ),
      (mutated) => assertFieldOrder(mutated, FROZEN_ADMIN_ROUTES),
    );
  });

  it("rejects an added unauthenticated product-aliased route (negative path)", () => {
    expectRejects(
      () => [
        ...PUBLIC_ROUTES,
        {
          method: "POST" as const,
          path: "/v1/sweeps", // contract-allow:product-route-negative-fixture
          authMode: "public" as const,
        },
      ],
      (mutated) => assertFieldOrder(mutated, FROZEN_PUBLIC_ROUTES),
    );
  });

  it("freezes the retired/forbidden path list", () => {
    expect(RETIRED_ROUTES).toEqual([
      "/v1/reservations*", // contract-allow:retired-route-citation
      "/v1/outbound-requests*", // contract-allow:retired-route-citation
      "/v1/payments*", // contract-allow:retired-route-citation
      "/v1/refunds*", // contract-allow:retired-route-citation
      "/admin/v1/drains*", // contract-allow:retired-route-citation
    ]);
  });

  it("has no active route colliding with a retired pattern", () => {
    assertNoRetiredRouteActive(PUBLIC_ROUTES);
    assertNoRetiredRouteActive(ADMIN_ROUTES);
  });

  it("rejects a retired route present in the active inventory (negative path)", () => {
    // Deliberately re-adds a retired path to prove the census gate rejects it.
    const retiredPathReintroduced = "/v1/reservations"; // contract-allow:retired-route-citation
    expectRejects(
      () => [
        ...PUBLIC_ROUTES,
        { method: "POST" as const, path: retiredPathReintroduced, authMode: "implementer_bearer" as const },
      ],
      (mutated) => assertNoRetiredRouteActive(mutated),
    );
  });

  it.each([
    "/v1/outbound-requests", // contract-allow:retired-route-citation
    "/v1/payments", // contract-allow:retired-route-citation
    "/v1/refunds", // contract-allow:retired-route-citation
    "/admin/v1/drains", // contract-allow:retired-route-citation
  ])("rejects retired path %s present in the active inventory (negative path)", (retiredPath) => {
    // One seeded negative per remaining retired path family (the fifth is covered above).
    expectRejects(
      () => [
        ...PUBLIC_ROUTES,
        { method: "POST" as const, path: retiredPath, authMode: "implementer_bearer" as const },
      ],
      (mutated) => assertNoRetiredRouteActive(mutated),
    );
  });

  it("has no active route matching the retired import-endpoint category", () => {
    assertNoImportEndpointActive(PUBLIC_ROUTES);
    assertNoImportEndpointActive(ADMIN_ROUTES);
  });

  it("rejects an import endpoint present in the active inventory (negative path)", () => {
    // Deliberately seeds an import-category path to prove the retired non-path category is
    // enforced structurally, not just recorded as the RETIRED_ROUTES_NON_PATH_CATEGORY string.
    expectRejects(
      () => [
        ...PUBLIC_ROUTES,
        { method: "POST" as const, path: "/v1/wallets/import", authMode: "implementer_bearer" as const },
      ],
      (mutated) => assertNoImportEndpointActive(mutated),
    );
  });
});
