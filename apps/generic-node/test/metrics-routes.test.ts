// generic-node /metrics mount adapter + runtime-listener wiring.

import { describe, expect, it } from "vitest";

import {
  createFailClosedOperationStore,
  createImplementerBearerAuth,
  createNodeMetrics,
  emptyOperationalSnapshot,
  type NodeMetrics,
} from "@zucoins/node-core";

import { createMetricsMount } from "../src/metrics/routes.js";
import { createNodeRuntimeListener } from "../src/runtime-listener.js";
import { NodeReadiness } from "../src/boot/readiness.js";

const TOKEN = "a".repeat(32);

function fakeResponse(): {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  res: {
    writeHead: (status: number, headers?: Record<string, string>) => void;
    end: (body?: string) => void;
  };
} {
  const state = { statusCode: 0, headers: {} as Record<string, string>, body: "" };
  return {
    get statusCode() {
      return state.statusCode;
    },
    get headers() {
      return state.headers;
    },
    get body() {
      return state.body;
    },
    res: {
      writeHead(status: number, headers?: Record<string, string>) {
        state.statusCode = status;
        state.headers = { ...(headers ?? {}) };
      },
      end(body?: string) {
        state.body = body ?? "";
      },
    },
  };
}

function fakeRequest(opts: {
  method?: string;
  url: string;
  authorization?: string;
}): {
  method: string;
  url: string;
  rawHeaders: string[];
  headers: Record<string, string | undefined>;
  [Symbol.asyncIterator]: () => AsyncIterator<never>;
} {
  const rawHeaders: string[] = [];
  if (opts.authorization !== undefined) {
    rawHeaders.push("Authorization", opts.authorization);
  }
  return {
    method: opts.method ?? "GET",
    url: opts.url,
    rawHeaders,
    headers: opts.authorization
      ? { authorization: opts.authorization }
      : {},
    async *[Symbol.asyncIterator]() {
      /* empty body */
    },
  };
}

describe("createMetricsMount — fail-closed", () => {
  it("returns undefined when scrape token is absent", () => {
    expect(createMetricsMount({ scrapeToken: undefined })).toBeUndefined();
  });

  it("returns a mount when a token is configured", () => {
    const mount = createMetricsMount({ scrapeToken: TOKEN });
    expect(mount).toBeDefined();
    expect(typeof mount!.listener).toBe("function");
  });
});

describe("createMetricsMount — bearer gate via node:http seam", () => {
  it("401 without Authorization", async () => {
    const mount = createMetricsMount({ scrapeToken: TOKEN })!;
    const fake = fakeResponse();
    mount.listener(fakeRequest({ url: "/metrics" }) as never, fake.res as never);
    await new Promise((r) => setTimeout(r, 10));
    expect(fake.statusCode).toBe(401);
    expect(fake.body).toBe("");
  });

  it("200 with correct bearer and emits required gauge names", async () => {
    const metrics: NodeMetrics = createNodeMetrics();
    metrics.setSnapshotSource(async () => ({
      ...emptyOperationalSnapshot(),
      availableWallets: 3,
      haltEngaged: 1,
      queueDepth: 2,
    }));
    const mount = createMetricsMount({ scrapeToken: TOKEN, metrics })!;
    const fake = fakeResponse();
    mount.listener(
      fakeRequest({ url: "/metrics", authorization: `Bearer ${TOKEN}` }) as never,
      fake.res as never,
    );
    await new Promise((r) => setTimeout(r, 20));
    expect(fake.statusCode).toBe(200);
    expect(fake.headers["content-type"]).toContain("text/plain");
    expect(fake.body).toContain("gn_available_wallets 3");
    expect(fake.body).toContain("gn_halt_engaged 1");
    expect(fake.body).toContain("gn_receive_queue_depth 2");
  });
});

describe("runtime-listener — /metrics dispatch", () => {
  const auth = createImplementerBearerAuth({
    keys: [
      {
        token: "ik_test_metrics_listener_token_0001",
        implementerId: "impl",
        scopes: ["receive:create", "receive:read"] as never,
      },
    ],
  });

  it("does not mount /metrics when token is absent (health 404, not open metrics)", async () => {
    const listener = createNodeRuntimeListener({
      readiness: new NodeReadiness(3),
      pingDb: async () => {},
      operationStore: createFailClosedOperationStore(),
      operationAuth: auth,
      newRequestId: () => "req-1",
      // no metricsScrapeToken
    });
    const fake = fakeResponse();
    listener(fakeRequest({ url: "/metrics" }) as never, fake.res as never);
    await new Promise((r) => setTimeout(r, 20));
    // Health half returns 404 JSON for unknown paths — never Prometheus body.
    expect(fake.statusCode).toBe(404);
    expect(fake.body).not.toContain("gn_");
  });

  it("serves bearer-gated /metrics when token is configured", async () => {
    const listener = createNodeRuntimeListener({
      readiness: new NodeReadiness(3),
      pingDb: async () => {},
      operationStore: createFailClosedOperationStore(),
      operationAuth: auth,
      newRequestId: () => "req-1",
      metricsScrapeToken: TOKEN,
      metricsSnapshotSource: async () => ({
        ...emptyOperationalSnapshot(),
        signerLeadershipHeld: 1,
        storagePressure: 1,
      }),
    });
    const denied = fakeResponse();
    listener(fakeRequest({ url: "/metrics" }) as never, denied.res as never);
    await new Promise((r) => setTimeout(r, 20));
    expect(denied.statusCode).toBe(401);

    const ok = fakeResponse();
    listener(
      fakeRequest({ url: "/metrics", authorization: `Bearer ${TOKEN}` }) as never,
      ok.res as never,
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(ok.statusCode).toBe(200);
    expect(ok.body).toContain("gn_signer_leadership_held 1");
    expect(ok.body).toContain("gn_storage_pressure 1");
    expect(ok.body).toContain("gn_process_resident_memory_bytes");
  });

  it("synthetic halt/signer stamp moves gauges within one scrape", async () => {
    const readiness = new NodeReadiness(3);
    readiness.setHalted(true);
    readiness.setSignerLeadershipHeld(false);
    const metrics = createNodeMetrics();
    const listener = createNodeRuntimeListener({
      readiness,
      pingDb: async () => {},
      operationStore: createFailClosedOperationStore(),
      operationAuth: auth,
      newRequestId: () => "req-1",
      metricsScrapeToken: TOKEN,
      metrics,
      metricsSnapshotSource: async () => {
        const s = readiness.core.snapshot();
        return {
          ...emptyOperationalSnapshot(),
          haltEngaged: s.halted ? 1 : 0,
          signerLeadershipHeld: s.leadershipLockHeld ? 1 : 0,
        };
      },
    });

    const first = fakeResponse();
    listener(
      fakeRequest({ url: "/metrics", authorization: `Bearer ${TOKEN}` }) as never,
      first.res as never,
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(first.body).toContain("gn_halt_engaged 1");
    expect(first.body).toContain("gn_signer_leadership_held 0");

    readiness.setHalted(false);
    readiness.setSignerLeadershipHeld(true);
    const second = fakeResponse();
    listener(
      fakeRequest({ url: "/metrics", authorization: `Bearer ${TOKEN}` }) as never,
      second.res as never,
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(second.body).toContain("gn_halt_engaged 0");
    expect(second.body).toContain("gn_signer_leadership_held 1");
  });
});
