// Liveness and readiness routes for the v2 node.
//
// Wired for the deployment target's probe conventions (healthcheck path
// /health/ready). Route logic and readiness gating live in
// `@zucoins/node-core`; this module is the node:http mount adapter.
//
// Liveness: zero-dependency, always 200 while the event loop runs.
// Readiness: gates on schema_migrated ∧ database_reachable ∧ vault_available ∧
// observation_read_capable ∧ restore_hold_clear (ZTR-1172). signer_leadership,
// halt, and storage_pressure are reported but non-gating. DB probe is TTL-cached so the
// unauthenticated route cannot be flooded into pool exhaustion.
//
// Transport: raw node:http — packages/node-core/test/boundaries.test.ts
// requires the app shell's sole external import to be @zucoins/node-core.

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  CachedDbProbe,
  createHealthHandlers,
  NODE_CORE_VERSION,
  type HealthRouteHandlers,
  type ReadinessStateInputs,
} from "@zucoins/node-core";

import type { NodeReadiness } from "../boot/readiness.js";

export interface HealthRouteDeps {
  readonly readiness: NodeReadiness;
  /**
   * Live DB reachability. MUST throw (or reject) on failure.
   * Required — no success default. A forgotten probe would fail the
   * `database_reachable` gate open.
   * Production main.ts wires `runtime.database.checkReady` when the
   * adapter exists, or a fail-closed stub until then.
   */
  readonly pingDb: () => Promise<void>;
  readonly version?: string;
  readonly dbPingTtlMs?: number;
  readonly dbPingTimeoutMs?: number;
  readonly now?: () => string;
  readonly clock?: () => number;
  /**
   * Pre-evaluate hook. Production main mounts
   * createProductionStoragePressureWiring(...).onBeforeEvaluate via
   * createNodeRuntimeListener so /health/ready re-stamps storage_pressure
   * from the write-latency collector before the verdict.
   */
  readonly onBeforeEvaluate?: () => void | Promise<void>;
  /**
   * Optional shared DB-reachability cache. Production main builds
   * one CachedDbProbe over pingDb and hands it to both /health/ready and the
   * /metrics snapshot source so the two surfaces agree within one TTL window
   * and a DB blip is probed once, not twice, per cycle. Omitted → this router
   * builds its own (prior behavior; tests keep working unchanged).
   */
  readonly dbProbe?: CachedDbProbe;
}

export interface HealthRouteResponse {
  readonly status: number;
  readonly body: unknown;
}

export type HealthRouter = (
  method: string,
  path: string,
) => HealthRouteResponse | Promise<HealthRouteResponse>;

/**
 * Build the (method, path) → response router. Readiness is async because of
 * the cached DB probe; liveness is sync and never awaits.
 */
export function createHealthRouter(deps: HealthRouteDeps): HealthRouter {
  const handlers: HealthRouteHandlers = createHealthHandlers({
    version: deps.version ?? NODE_CORE_VERSION,
    getState: (): ReadinessStateInputs => deps.readiness.core.snapshot(),
    pingDb: deps.pingDb,
    now: deps.now,
    clock: deps.clock,
    dbPingTtlMs: deps.dbPingTtlMs,
    dbPingTimeoutMs: deps.dbPingTimeoutMs,
    onBeforeEvaluate: deps.onBeforeEvaluate,
    dbProbe: deps.dbProbe,
  });

  return async (method, path) => {
    if (method === "GET" && path === "/health") {
      const result = handlers.liveness();
      return { status: result.statusCode, body: result.body };
    }

    if (method === "GET" && path === "/health/ready") {
      const result = await handlers.readiness();
      return { status: result.statusCode, body: result.body };
    }

    return { status: 404, body: { status: "not_found" } };
  };
}

/** Bind the router to a real node:http request/response pair. */
export function createHealthHttpListener(
  router: HealthRouter,
): (request: IncomingMessage, response: ServerResponse) => void {
  return (request, response) => {
    const rawUrl = request.url ?? "";
    const path = rawUrl.split(/[?#]/, 1)[0] ?? rawUrl;
    void Promise.resolve(router(request.method ?? "", path)).then((result) => {
      const payload = JSON.stringify(result.body);
      response.writeHead(result.status, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload).toString(),
      });
      response.end(payload);
    });
  };
}
