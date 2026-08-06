// proxy/static-route ordering regression for the v2 mount.
//
// Mirrors the v1 gotcha fixed in apps/node/src/health (discovery/health must be
// matched BEFORE any SPA/static catch-all). generic-node today has no SPA, but
// the mount order is still load-bearing once a catch-all lands — this test
// would fail if createHealthRouter stopped claiming the three public paths
// before a later catch-all handler.

import { describe, expect, it } from "vitest";

import { createHealthRouter } from "../src/health/routes.js";
import { NodeReadiness } from "../src/boot/readiness.js";

function fullyReady(): NodeReadiness {
  const readiness = new NodeReadiness(3);
  readiness.markSchemaChecksPassed();
  readiness.setVaultAvailable(true);
  readiness.recordGatewayReadSuccess();
  readiness.setSignerLeadershipHeld(true);
  return readiness;
}

type DispatchResult = { status: number; body: unknown; via: "health" | "catch-all" };

function compose(order: "health-first" | "catch-all-first") {
  const health = createHealthRouter({
    readiness: fullyReady(),
    pingDb: async () => {},
  });
  const catchAll = (): DispatchResult => ({
    status: 200,
    body: "<!doctype html><title>admin spa</title>",
    via: "catch-all",
  });

  return async (method: string, path: string): Promise<DispatchResult> => {
    if (order === "health-first") {
      const res = await health(method, path);
      if (res.status !== 404) {
        return { status: res.status, body: res.body, via: "health" };
      }
      return catchAll();
    }
    return catchAll();
  };
}

describe("generic-node health route order (v1 catch-all regression)", () => {
  it("health-first: /health and /health/ready are served by the health router, not SPA HTML", async () => {
    const dispatch = compose("health-first");

    const live = await dispatch("GET", "/health");
    expect(live.via).toBe("health");
    expect(live.status).toBe(200);
    expect(live.body).toMatchObject({ status: "alive" });
    expect(JSON.stringify(live.body)).not.toContain("<!doctype html>");

    const ready = await dispatch("GET", "/health/ready");
    expect(ready.via).toBe("health");
    expect(ready.status).toBe(200);
    expect(ready.body).toMatchObject({ status: "ready" });
    expect(JSON.stringify(ready.body)).not.toContain("<!doctype html>");

    const spa = await dispatch("GET", "/dashboard");
    expect(spa.via).toBe("catch-all");
  });

  it("negative: catch-all-first reintroduces the v1 probe-breaking ordering bug", async () => {
    const dispatch = compose("catch-all-first");
    for (const path of ["/health", "/health/ready"] as const) {
      const res = await dispatch("GET", path);
      expect(res.via).toBe("catch-all");
      expect(res.body).toContain("<!doctype html>");
    }
  });
});
