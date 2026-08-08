import { describe, expect, it } from "vitest";

import { createHealthHttpListener, createHealthRouter } from "../src/health/routes.js";
import { createEventSignerAuthority } from "../src/boot/event-signer-authority.js";
import { NodeReadiness } from "../src/boot/readiness.js";

/** Success probe — DB reachable. */
const pingDbOk = async (): Promise<void> => {};

/**
 * Fail-closed probe — same rejection shape main.ts wires via
 * surfaceNotYetWired("database adapter") until a real DatabaseAdapter lands.
 */
function pingDbNotWired(): () => Promise<never> {
  return () =>
    Promise.reject(
      new Error(
        "database adapter is not yet wired in this build — readiness stays false (fail-closed)",
      ),
    );
}

function fullyReadyStamps(): NodeReadiness {
  const readiness = new NodeReadiness(3);
  readiness.markSchemaChecksPassed();
  readiness.setVaultAvailable(true);
  readiness.setSignerLeadershipHeld(true);
  readiness.recordGatewayReadSuccess();
  // /health/ready now gates on EVENT_SIGNING availability (ZTR-1179).
  readiness.setEventSignerAvailable(true);
  return readiness;
}

describe("health routes — liveness vs readiness separation (review indicator 3)", () => {
  it("liveness is 200 while every readiness gate is closed", async () => {
    const router = createHealthRouter({
      readiness: new NodeReadiness(3),
      pingDb: pingDbNotWired(),
    });
    const res = await router("GET", "/health");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "alive" });
  });

  it("liveness stays 200 while readiness is 503", async () => {
    const readiness = new NodeReadiness(3);
    const router = createHealthRouter({ readiness, pingDb: pingDbNotWired() });
    const ready = await router("GET", "/health/ready");
    expect(ready.status).toBe(503);
    const live = await router("GET", "/health");
    expect(live.status).toBe(200);
  });
});

describe("health routes — readiness gating", () => {
  it("readiness is 503 with a per-check breakdown until gating checks pass", async () => {
    const readiness = new NodeReadiness(3);
    // Explicit OK probe so database_reachable is not the only closed gate under test.
    const router = createHealthRouter({ readiness, pingDb: pingDbOk });

    const before = await router("GET", "/health/ready");
    expect(before.status).toBe(503);
    expect(before.body).toMatchObject({ status: "not_ready" });
    const checks = (before.body as { checks: Array<{ name: string; ready: boolean }> }).checks;
    expect(checks.find((c) => c.name === "schema_migrated")?.ready).toBe(false);
    expect(checks.find((c) => c.name === "database_reachable")?.ready).toBe(true);
    expect(checks.find((c) => c.name === "vault_available")?.ready).toBe(false);
    expect(checks.find((c) => c.name === "observation_read_capable")?.ready).toBe(false);

    readiness.markSchemaChecksPassed();
    const schemaOnly = await router("GET", "/health/ready");
    expect(schemaOnly.status).toBe(503);
    const schemaChecks = (schemaOnly.body as { checks: Array<{ name: string; ready: boolean }> })
      .checks;
    expect(schemaChecks.find((c) => c.name === "schema_migrated")?.ready).toBe(true);
    expect(schemaChecks.find((c) => c.name === "vault_available")?.ready).toBe(false);
  });

  it("readiness is 200 after schema, vault, observation, and DB — leadership optional", async () => {
    const readiness = fullyReadyStamps();
    readiness.setSignerLeadershipHeld(false);
    const router = createHealthRouter({ readiness, pingDb: pingDbOk });
    const res = await router("GET", "/health/ready");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "ready" });
    const checks = (res.body as { checks: Array<{ name: string; ready: boolean; gating: boolean }> })
      .checks;
    expect(checks.find((c) => c.name === "signer_leadership")).toMatchObject({
      ready: false,
      gating: false,
    });
  });

  it("DB failure flips readiness to 503; leadership loss does not", async () => {
    const readiness = fullyReadyStamps();
    const routerOk = createHealthRouter({ readiness, pingDb: pingDbOk });
    expect((await routerOk("GET", "/health/ready")).status).toBe(200);

    const routerDbDown = createHealthRouter({
      readiness,
      pingDb: async () => {
        throw new Error("db down");
      },
    });
    expect((await routerDbDown("GET", "/health/ready")).status).toBe(503);

    readiness.setSignerLeadershipHeld(false);
    expect((await routerOk("GET", "/health/ready")).status).toBe(200);
  });

  it("gateway failure past the budget flips readiness to degraded/503", async () => {
    const readiness = fullyReadyStamps();
    const router = createHealthRouter({ readiness, pingDb: pingDbOk });

    readiness.recordGatewayReadFailure();
    readiness.recordGatewayReadFailure();
    expect((await router("GET", "/health/ready")).status).toBe(200);

    readiness.recordGatewayReadFailure();
    const exceeded = await router("GET", "/health/ready");
    expect(exceeded.status).toBe(503);
    expect(exceeded.body).toMatchObject({ status: "degraded" });
  });

  it("production-style fail-closed pingDb keeps database_reachable false even with all stamps open", async () => {
    // Mirrors main.ts: createHealthRouter({ readiness, pingDb: surfaceNotYetWired("database adapter") }).
    // Regression: prior defaultPingDb always resolved so this gate failed open.
    const readiness = fullyReadyStamps();
    const router = createHealthRouter({
      readiness,
      pingDb: pingDbNotWired(),
    });
    const res = await router("GET", "/health/ready");
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ status: "not_ready" });
    const checks = (res.body as { checks: Array<{ name: string; ready: boolean; gating: boolean }> })
      .checks;
    expect(checks.find((c) => c.name === "database_reachable")).toMatchObject({
      ready: false,
      gating: true,
    });
    expect(checks.find((c) => c.name === "schema_migrated")?.ready).toBe(true);
    expect(checks.find((c) => c.name === "vault_available")?.ready).toBe(true);
    expect(checks.find((c) => c.name === "observation_read_capable")?.ready).toBe(true);
  });
});

describe("health routes — EVENT_SIGNING availability gates /health/ready (ZTR-1179)", () => {
  it("a runtime EVENT_SIGNING withdrawal flips /health/ready to 503", async () => {
    const readiness = fullyReadyStamps();
    const authority = createEventSignerAuthority({
      readiness,
      withdrawSignerAuthority: () => {},
      stopWorkers: () => {},
      logger: { info: () => {}, error: () => {} },
    });
    const armed = authority.arm({
      signingKeyId: "key-1",
      sign: () => {
        throw new Error("sealed row unreadable");
      },
    });
    const router = createHealthRouter({ readiness, pingDb: pingDbOk });
    expect((await router("GET", "/health/ready")).status).toBe(200);

    // The first runtime sign failure withdraws authority and must close /health/ready.
    expect(() => armed.sign(new Uint8Array())).toThrow(/sealed row unreadable/);

    const res = await router("GET", "/health/ready");
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ status: "not_ready" });
  });

  it("a boot-unarmed signer keeps /health/ready 503 even with every other gate open", async () => {
    const readiness = new NodeReadiness(3);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.recordGatewayReadSuccess();
    const router = createHealthRouter({ readiness, pingDb: pingDbOk });
    const res = await router("GET", "/health/ready");
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ status: "not_ready" });
  });
});

describe("health http listener", () => {
  it("routes through the real node:http listener seam, ignoring query/fragment", async () => {
    const readiness = fullyReadyStamps();
    const router = createHealthRouter({ readiness, pingDb: pingDbOk });
    const listener = createHealthHttpListener(router);

    let capturedStatus = 0;
    let capturedHeaders: Record<string, string> = {};
    let capturedBody = "";
    const fakeResponse = {
      writeHead: (status: number, headers: Record<string, string>) => {
        capturedStatus = status;
        capturedHeaders = headers;
      },
      end: (body: string) => {
        capturedBody = body;
      },
    };

    listener(
      { method: "GET", url: "/health/ready?probe=1#frag" } as never,
      fakeResponse as never,
    );

    // Listener is async via Promise.resolve — wait a tick.
    await new Promise((r) => setImmediate(r));

    expect(capturedStatus).toBe(200);
    expect(capturedHeaders["content-type"]).toBe("application/json");
    expect(JSON.parse(capturedBody)).toMatchObject({ status: "ready" });
  });

  it("returns 404 for an unknown path via the real listener seam", async () => {
    const listener = createHealthHttpListener(
      createHealthRouter({ readiness: new NodeReadiness(3), pingDb: pingDbNotWired() }),
    );
    let capturedStatus = 0;
    const fakeResponse = {
      writeHead: (status: number) => {
        capturedStatus = status;
      },
      end: () => {},
    };
    listener({ method: "GET", url: "/unknown" } as never, fakeResponse as never);
    await new Promise((r) => setImmediate(r));
    expect(capturedStatus).toBe(404);
  });
});
