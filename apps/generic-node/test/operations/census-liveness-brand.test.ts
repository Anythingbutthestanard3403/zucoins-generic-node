// Behavioural liveness census. A fail-closed VARIANT (different object reference,
// same 501 behaviour, no LIVE brand) is NOT reported as a live reporting engine, unlike the
// prior reference-identity check (`mounted !== failClosed`) which would have registered it.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { reportingErrorResponse } from "@zucoins/node-core";
import {
  createProductionRouteSurface,
  LIVE_HANDLER_BRAND,
  brandLiveHandler,
  type LiveReportingRouteHandler,
} from "../../src/full-http-mount.js";


/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);


const stubPool = () =>
  ({
    query: async () => ({ rows: [] }),
    connect: async () => ({
      query: async () => ({ rows: [] }),
      release: () => {},
    }),
  }) as never;

const NODE_FOR_STUB = "11111111-1111-4111-8111-111111111111";

describe("behavioural liveness census (brand, not reference identity)", () => {
  it("the census positively brands live handlers (LIVE_HANDLER_BRAND) instead of negative identity", () => {
    const src = readFileSync(
      fileURLToPath(new URL("../../src/full-http-mount.ts", import.meta.url)),
      "utf8",
    );
    expect(src).toMatch(/LIVE_HANDLER_BRAND/);
    expect(src).toMatch(/brandLiveHandler/);
    // The census checks the brand, not `!== failClosed`.
    expect(src).toMatch(/LIVE_HANDLER_BRAND\]/);
    expect(src).not.toMatch(/mounted !== failClosed/);
  });

  it("a live handler carries the brand and is reported; a fail-closed variant does NOT and is excluded", () => {
    const live: LiveReportingRouteHandler = brandLiveHandler(async () => ({
      response: { status: 200, headers: {}, bodyBytes: new Uint8Array() },
      persistChild: null,
    }));
    const failClosedVariant = async () => ({
      response: reportingErrorResponse("internal_error", "req-1"),
      persistChild: null,
    });
    // The live handler carries the brand; the variant does NOT.
    expect(Boolean((live as unknown as Record<symbol, unknown>)[LIVE_HANDLER_BRAND])).toBe(true);
    expect(Boolean((failClosedVariant as unknown as Record<symbol, unknown>)[LIVE_HANDLER_BRAND])).toBe(false);
  });

  it("the production surface still reports the 5 live routes (brand does not drop existing liveness)", () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_FOR_STUB,
      pool: stubPool(),
      env: {},
    });
    const routeIds = surface.liveReportingEngines.map((e) => e.routeId);
    expect(routeIds).toContain("operation_armed");
    expect(routeIds).toContain("events_list");
    expect(routeIds).toContain("events_stream");
    expect(routeIds).toContain("state_snapshot");
    expect(routeIds).toContain("verification_material");
  });
});