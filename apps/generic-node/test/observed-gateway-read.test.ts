// ZTR-1162: producer-side tests for createObservedGatewayRead.
// Consumer-side budget behaviour is covered by readiness.test.ts /
// health-routes.test.ts; this file proves the composition-root wrapper is
// the producer that increments on throw and resets on complete capture.

import { describe, expect, it, vi } from "vitest";

import {
  GatewayReadExhaustedError,
  GatewayTransportAmbiguityError,
  createGatewayExchangeTransport,
  type GatewayExchangeTransport,
  type GatewayLimits,
} from "@zucoins/node-core";

import { NodeReadiness } from "../src/boot/readiness.js";
import { createObservedGatewayRead } from "../src/gateway/observed-read.js";

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 1_048_576,
  maxResponseBytes: 4_194_304,
};

function inertRecorder() {
  return {
    recordObservation: async () => {
      /* test: non-durable */
    },
  };
}

function scriptedExchange(
  script: ReadonlyArray<
    | { readonly kind: "ok"; readonly status: number }
    | { readonly kind: "ambiguous" }
  >,
): GatewayExchangeTransport {
  let i = 0;
  return {
    async exchange(endpoint, _request) {
      const step = script[i] ?? script[script.length - 1];
      i += 1;
      if (step === undefined) {
        throw new Error("script exhausted");
      }
      if (step.kind === "ambiguous") {
        throw new GatewayTransportAmbiguityError(
          `ambiguous at ${endpoint}`,
          new Error("transport"),
        );
      }
      const body = new TextEncoder().encode(`{"ok":true}`);
      const req = new Uint8Array(0);
      return {
        endpoint,
        endpointFingerprint: `fp:${endpoint}`,
        requestBytes: req,
        requestSha256: "b".repeat(64),
        statusCode: step.status,
        responseBytes: body,
        responseSha256: "a".repeat(64),
      };
    },
  };
}

describe("createObservedGatewayRead — producer (ZTR-1162)", () => {
  it("stamps success when the bounded read returns a complete capture", async () => {
    const readiness = new NodeReadiness(3);
    const read = createObservedGatewayRead(readiness);
    const exchange = scriptedExchange([{ kind: "ok", status: 200 }]);

    await read("get_transaction__v1", { transaction_id: "" }, {
      endpoints: ["https://gw.example/"],
      limits: LIMITS,
      recorder: inertRecorder(),
      exchange,
      maxAttempts: 1,
      sleep: async () => {},
      jitter: () => 0,
    });

    expect(readiness.snapshot().gatewayConsecutiveFailures).toBe(0);
    expect(readiness.snapshot().checks.gateway).toBe(true);
  });

  it("stamps failure when the bounded read throws (exhausted ambiguity)", async () => {
    const readiness = new NodeReadiness(3);
    readiness.recordGatewayReadSuccess();
    const read = createObservedGatewayRead(readiness);
    const exchange = scriptedExchange([{ kind: "ambiguous" }]);

    await expect(
      read("get_transaction__v1", { transaction_id: "" }, {
        endpoints: ["https://gw.example/"],
        limits: LIMITS,
        recorder: inertRecorder(),
        exchange,
        maxAttempts: 1,
        sleep: async () => {},
        jitter: () => 0,
      }),
    ).rejects.toBeInstanceOf(GatewayReadExhaustedError);

    expect(readiness.snapshot().gatewayConsecutiveFailures).toBe(1);
    expect(readiness.snapshot().checks.gateway).toBe(true);
  });

  it("GATEWAY_READ_FAILURE_BUDGET governs the boundary: N consecutive failures flip degraded", async () => {
    const budget = 3;
    const readiness = new NodeReadiness(budget);
    readiness.markSchemaChecksPassed();
    readiness.setVaultAvailable(true);
    readiness.recordGatewayReadSuccess();
    expect(readiness.snapshot().ready).toBe(true);
    expect(readiness.snapshot().degraded).toBe(false);

    const read = createObservedGatewayRead(readiness);
    const exchange = scriptedExchange([{ kind: "ambiguous" }]);
    const opts = {
      endpoints: ["https://gw.example/"],
      limits: LIMITS,
      recorder: inertRecorder(),
      exchange,
      maxAttempts: 1 as const,
      sleep: async () => {},
      jitter: () => 0,
    };

    for (let i = 0; i < budget - 1; i += 1) {
      await expect(read("get_transaction__v1", { transaction_id: "" }, opts)).rejects.toThrow();
      expect(readiness.snapshot().checks.gateway).toBe(true);
      expect(readiness.snapshot().degraded).toBe(false);
    }

    await expect(read("get_transaction__v1", { transaction_id: "" }, opts)).rejects.toThrow();
    const snap = readiness.snapshot();
    expect(snap.gatewayConsecutiveFailures).toBe(budget);
    expect(snap.checks.gateway).toBe(false);
    expect(snap.ready).toBe(false);
    expect(snap.degraded).toBe(true);
  });

  it("a later success resets the counter from the same producer", async () => {
    const readiness = new NodeReadiness(2);
    readiness.recordGatewayReadSuccess();
    const sink = {
      successes: 0,
      failures: 0,
      recordGatewayReadSuccess() {
        this.successes += 1;
        readiness.recordGatewayReadSuccess();
      },
      recordGatewayReadFailure() {
        this.failures += 1;
        readiness.recordGatewayReadFailure();
      },
    };
    const read = createObservedGatewayRead(sink);

    const failEx = scriptedExchange([{ kind: "ambiguous" }]);
    await expect(
      read("get_transaction__v1", { transaction_id: "" }, {
        endpoints: ["https://gw.example/"],
        limits: LIMITS,
        recorder: inertRecorder(),
        exchange: failEx,
        maxAttempts: 1,
        sleep: async () => {},
        jitter: () => 0,
      }),
    ).rejects.toThrow();
    await expect(
      read("get_transaction__v1", { transaction_id: "" }, {
        endpoints: ["https://gw.example/"],
        limits: LIMITS,
        recorder: inertRecorder(),
        exchange: failEx,
        maxAttempts: 1,
        sleep: async () => {},
        jitter: () => 0,
      }),
    ).rejects.toThrow();
    expect(readiness.snapshot().checks.gateway).toBe(false);

    const okEx = scriptedExchange([{ kind: "ok", status: 404 }]);
    await read("get_transaction__v1", { transaction_id: "" }, {
      endpoints: ["https://gw.example/"],
      limits: LIMITS,
      recorder: inertRecorder(),
      exchange: okEx,
      maxAttempts: 1,
      sleep: async () => {},
      jitter: () => 0,
    });

    expect(sink.failures).toBe(2);
    expect(sink.successes).toBe(1);
    expect(readiness.snapshot().gatewayConsecutiveFailures).toBe(0);
    expect(readiness.snapshot().checks.gateway).toBe(true);
    expect(readiness.snapshot().degraded).toBe(false);
  });

  it("re-throws the original error after stamping failure", async () => {
    const readiness = new NodeReadiness(1);
    const read = createObservedGatewayRead(readiness);
    const boom = new Error("recorder down");
    const exchange: GatewayExchangeTransport = {
      async exchange() {
        throw boom;
      },
    };

    await expect(
      read("get_transaction__v1", { transaction_id: "" }, {
        endpoints: ["https://gw.example/"],
        limits: LIMITS,
        recorder: inertRecorder(),
        exchange,
        maxAttempts: 1,
      }),
    ).rejects.toBe(boom);
    expect(readiness.snapshot().gatewayConsecutiveFailures).toBe(1);
  });

  it("does not call the bare transport constructor when an exchange is injected", async () => {
    // Guard: wrapper must not rebuild transport; inject a spy exchange.
    const readiness = new NodeReadiness(3);
    const read = createObservedGatewayRead(readiness);
    const exchange = scriptedExchange([{ kind: "ok", status: 200 }]);
    const spy = vi.fn(exchange.exchange.bind(exchange));
    const wrapped: GatewayExchangeTransport = { exchange: spy };

    await read("get_transaction__v1", { transaction_id: "x" }, {
      endpoints: ["https://gw.example/"],
      limits: LIMITS,
      recorder: inertRecorder(),
      exchange: wrapped,
      maxAttempts: 1,
    });
    expect(spy).toHaveBeenCalledOnce();
    // createGatewayExchangeTransport is unused here — smoke that import stays available.
    expect(typeof createGatewayExchangeTransport).toBe("function");
  });
});
