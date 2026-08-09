// Production write-latency pressure composition.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  createHostEvidenceRuntimeMetricsCollector,
  DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD,
  WRITE_LATENCY_PRESSURE_UTILIZATION,
  type EvidenceRuntimeMetricsCollector,
  type EvidenceRuntimeStorageSignals,
  type WriteLatencyPercentiles,
} from "@zucoins/node-core";

import { NodeReadiness } from "../src/boot/readiness.js";
import { createHealthRouter } from "../src/health/routes.js";
import {
  createNodeRuntimeListener,
  type NodeRuntimeListenerDeps,
} from "../src/runtime-listener.js";
import { createProductionStoragePressureWiring } from "../src/storage-pressure.js";
import {
  createFailClosedOperationStore,
  createRejectAllOperationAuth,
} from "@zucoins/node-core";
import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

function fullyReady(): NodeReadiness {
  const readiness = new NodeReadiness(3);
  // /health/ready now gates on EVENT_SIGNING availability (ZTR-1179).
  readiness.setEventSignerAvailable(true);
  readiness.markSchemaChecksPassed();
  readiness.setVaultAvailable(true);
  readiness.setSignerLeadershipHeld(true);
  readiness.recordGatewayReadSuccess();
  return readiness;
}

function mutableCollector(initial: WriteLatencyPercentiles): {
  collector: EvidenceRuntimeMetricsCollector;
  setLatency: (latency: WriteLatencyPercentiles) => void;
} {
  let writeLatency = initial;
  return {
    setLatency: (latency) => {
      writeLatency = latency;
    },
    collector: {
      // Explicit non-stub injector (tests) — still requires diskUtilization for
      // a permissive BP path (attack review).
      signalKind: "live",
      collect: async (): Promise<EvidenceRuntimeStorageSignals> => ({
        diskFreeBytes: 1_000_000_000,
        diskFreeBytesAfterWalOverhead: 1_000_000_000,
        indexBytes: 0,
        writeLatency,
        observedAtMillis: Date.now(),
      }),
    },
  };
}

/** Healthy headroom disk probe — opens admission when paired with clear latency. */
const lowDisk = async (): Promise<number> => 0.1;

describe("createProductionStoragePressureWiring — production refresh + BP", () => {
  it("stamps storage_pressure and refuses evidence when collector p99 clears threshold", async () => {
    const readiness = fullyReady();
    const baseline: WriteLatencyPercentiles = { p50Ms: 1, p99Ms: 2, sampleCount: 10 };
    const slow: WriteLatencyPercentiles = {
      p50Ms: 5,
      p99Ms: DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD.absoluteP99Ms + 5,
      sampleCount: 10,
    };
    const { collector, setLatency } = mutableCollector(baseline);
    const wiring = createProductionStoragePressureWiring({
      readiness,
      collector,
      baseline,
      diskUtilization: lowDisk,
    });

    setLatency(baseline);
    await wiring.refresh();
    expect(readiness.core.snapshot().storagePressure).toBe(false);
    await wiring.storageBackpressure.refresh();
    expect(wiring.storageBackpressure.canAcceptEvidence("w1")).toBe(true);

    setLatency(slow);
    const result = await wiring.refresh();
    expect(result.pressure).toBe(true);
    expect(readiness.core.snapshot().storagePressure).toBe(true);
    await wiring.storageBackpressure.refresh();
    expect(wiring.storageBackpressure.globalState()).not.toBe("NORMAL");
    expect(wiring.storageBackpressure.canAcceptEvidence("w1")).toBe(false);
    expect(wiring.storageBackpressure.snapshot().global.utilization).toBe(
      WRITE_LATENCY_PRESSURE_UTILIZATION,
    );
  });

  it("combines disk util with write-latency util via Math.max", async () => {
    const readiness = fullyReady();
    const baseline: WriteLatencyPercentiles = { p50Ms: 1, p99Ms: 2, sampleCount: 5 };
    const { collector } = mutableCollector(baseline);
    const wiring = createProductionStoragePressureWiring({
      readiness,
      collector,
      baseline,
      diskUtilization: async () => 0.96,
    });
    await wiring.onBeforeEvaluate();
    expect(readiness.core.snapshot().storagePressure).toBe(false);
    await wiring.storageBackpressure.refresh();
    // Disk alone at 0.96 → CRITICAL band; evidence refused even without latency pressure.
    expect(wiring.storageBackpressure.canAcceptEvidence("w1")).toBe(false);
  });

  it("fail closed (no evidence) when default wiring has zero live signal", async () => {
    const readiness = fullyReady();
    const alerts: Array<{ reason: string }> = [];
    const wiring = createProductionStoragePressureWiring({
      readiness,
      onEarlyAlert: (e) => {
        alerts.push({ reason: e.reason });
      },
    });
    expect(wiring.hasLiveSignal).toBe(false);
    const result = await wiring.refresh();
    expect(result.pressure).toBe(true);
    expect(readiness.core.snapshot().storagePressure).toBe(true);
    expect(wiring.storageBackpressure.canAcceptEvidence("w1")).toBe(false);
    expect(wiring.storageBackpressure.globalState()).toBe("CRITICAL");
    expect(alerts.some((a) => a.reason === "missing_live_signal")).toBe(true);

    // Explicit BP refresh remains fail-closed (source returns NaN).
    await wiring.storageBackpressure.refresh();
    expect(wiring.storageBackpressure.canAcceptEvidence("w1")).toBe(false);
  });

  it("stub collector alone fails closed; live disk probe can open admitted path", async () => {
    const readiness = fullyReady();
    const closed = createProductionStoragePressureWiring({
      readiness,
      // Explicit stub — not live, no disk.
      collector: {
        signalKind: "stub",
        collect: async () => ({
          diskFreeBytes: 0,
          diskFreeBytesAfterWalOverhead: 0,
          indexBytes: 0,
          writeLatency: { p50Ms: 0, p99Ms: 0, sampleCount: 0 },
          observedAtMillis: 0,
        }),
      },
    });
    await closed.refresh();
    expect(closed.storageBackpressure.canAcceptEvidence("w1")).toBe(false);

    const open = createProductionStoragePressureWiring({
      readiness: fullyReady(),
      diskUtilization: async () => 0.1,
    });
    expect(open.hasLiveSignal).toBe(true);
    await open.refresh();
    await open.storageBackpressure.refresh();
    expect(open.storageBackpressure.canAcceptEvidence("w1")).toBe(true);
  });

  it("host/live collector alone fails closed without diskUtilization", async () => {
    // Attack review: host collect() returns free bytes but BP never read them;
    // empty latency ⇒ util 0 ⇒ NORMAL under fill. Composition must CRITICAL.
    const host = createHostEvidenceRuntimeMetricsCollector({ path: process.cwd() });
    const hostOnly = createProductionStoragePressureWiring({
      readiness: fullyReady(),
      collector: host,
    });
    expect(hostOnly.hasLiveSignal).toBe(false);
    await hostOnly.refresh();
    expect(hostOnly.storageBackpressure.canAcceptEvidence("w1")).toBe(false);
    expect(hostOnly.storageBackpressure.globalState()).toBe("CRITICAL");
    await hostOnly.storageBackpressure.refresh();
    expect(hostOnly.storageBackpressure.canAcceptEvidence("w1")).toBe(false);

    const liveOnly = createProductionStoragePressureWiring({
      readiness: fullyReady(),
      collector: {
        signalKind: "live",
        collect: async () => ({
          diskFreeBytes: 9e15,
          diskFreeBytesAfterWalOverhead: 9e15,
          indexBytes: 0,
          writeLatency: { p50Ms: 0, p99Ms: 0, sampleCount: 0 },
          observedAtMillis: Date.now(),
        }),
      },
    });
    expect(liveOnly.hasLiveSignal).toBe(false);
    await liveOnly.refresh();
    await liveOnly.storageBackpressure.refresh();
    expect(liveOnly.storageBackpressure.canAcceptEvidence("w1")).toBe(false);

    // Untagged injector (was treated as "live" by isLiveEvidenceRuntimeCollector).
    const untagged = createProductionStoragePressureWiring({
      readiness: fullyReady(),
      collector: {
        collect: async () => ({
          diskFreeBytes: 9e15,
          diskFreeBytesAfterWalOverhead: 9e15,
          indexBytes: 0,
          writeLatency: { p50Ms: 0, p99Ms: 0, sampleCount: 0 },
          observedAtMillis: Date.now(),
        }),
      },
    });
    expect(untagged.hasLiveSignal).toBe(false);
    await untagged.refresh();
    await untagged.storageBackpressure.refresh();
    expect(untagged.storageBackpressure.canAcceptEvidence("w1")).toBe(false);
  });

  it("disk probe failure (throw/NaN) fails closed and early-alerts", async () => {
    const readiness = fullyReady();
    const baseline: WriteLatencyPercentiles = { p50Ms: 1, p99Ms: 2, sampleCount: 4 };
    const { collector } = mutableCollector(baseline);
    const alerts: string[] = [];
    const wiring = createProductionStoragePressureWiring({
      readiness,
      collector,
      baseline,
      diskUtilization: async () => Number.NaN,
      onEarlyAlert: (e) => {
        alerts.push(e.reason);
      },
    });
    await wiring.refresh();
    expect(wiring.storageBackpressure.canAcceptEvidence("w1")).toBe(false);
    expect(alerts).toContain("indeterminate_disk");
  });

  it("health router onBeforeEvaluate path stamps pressure before ready verdict", async () => {
    const readiness = fullyReady();
    const slow: WriteLatencyPercentiles = {
      p50Ms: 10,
      p99Ms: DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD.absoluteP99Ms,
      sampleCount: 8,
    };
    const { collector } = mutableCollector(slow);
    const wiring = createProductionStoragePressureWiring({
      readiness,
      collector,
      diskUtilization: lowDisk,
    });
    const router = createHealthRouter({
      readiness,
      pingDb: async () => undefined,
      onBeforeEvaluate: wiring.onBeforeEvaluate,
    });
    const res = await router("GET", "/health/ready");
    expect(res.status).toBe(200); // storage_pressure non-gating
    expect(readiness.core.snapshot().storagePressure).toBe(true);
    const checks = (res.body as { checks: Array<{ name: string; ready: boolean }> }).checks;
    expect(checks.find((c) => c.name === "storage_pressure")?.ready).toBe(false);
  });
});

describe("createNodeRuntimeListener — mounts onBeforeEvaluate into health half", () => {
  it("GET /health/ready runs production refresh and stamps storage_pressure", async () => {
    const readiness = fullyReady();
    const slow: WriteLatencyPercentiles = {
      p50Ms: 12,
      p99Ms: DEFAULT_WRITE_LATENCY_PRESSURE_THRESHOLD.absoluteP99Ms + 1,
      sampleCount: 6,
    };
    const { collector } = mutableCollector(slow);
    const wiring = createProductionStoragePressureWiring({
      readiness,
      collector,
      diskUtilization: lowDisk,
    });
    const deps: NodeRuntimeListenerDeps = {
      readiness,
      pingDb: async () => undefined,
      operationStore: createFailClosedOperationStore(),
      operationAuth: createRejectAllOperationAuth(),
      newRequestId: () => randomUUID(),
      onBeforeEvaluate: wiring.onBeforeEvaluate,
      storageBackpressure: wiring.storageBackpressure,
    };
    const listener = createNodeRuntimeListener(deps);
    const captured = await new Promise<{ status: number; body: string }>((resolve) => {
      let status = 0;
      const response = {
        writeHead(code: number) {
          status = code;
        },
        end(payload?: string | Uint8Array) {
          resolve({
            status,
            body:
              typeof payload === "string"
                ? payload
                : Buffer.from(payload ?? "").toString("utf8"),
          });
        },
      };
      listener(
        {
          method: "GET",
          url: "/health/ready",
          headers: {},
          rawHeaders: [],
          async *[Symbol.asyncIterator]() {},
        } as unknown as IncomingMessage,
        response as unknown as ServerResponse,
      );
    });
    expect(captured.status).toBe(200);
    expect(readiness.core.snapshot().storagePressure).toBe(true);
    await wiring.storageBackpressure.refresh();
    expect(wiring.storageBackpressure.canAcceptEvidence("w1")).toBe(false);
  });
});

describe("production source guards — write-latency pressure mount", () => {
  const mainSrc = readFileSync(
    fileURLToPath(new URL("../src/main.ts", import.meta.url)),
    "utf8",
  );
  const listenerSrc = readFileSync(
    fileURLToPath(new URL("../src/runtime-listener.ts", import.meta.url)),
    "utf8",
  );

  it("main.ts composes live host disk probe + createProductionStoragePressureWiring", () => {
    expect(mainSrc).toMatch(/createProductionStoragePressureWiring\s*\(/);
    expect(mainSrc).toMatch(/createHostEvidenceRuntimeMetricsCollector\s*\(/);
    expect(mainSrc).toMatch(/createStatfsDiskUtilization\s*\(/);
    expect(mainSrc).toMatch(/onBeforeEvaluate:\s*storagePressure\.onBeforeEvaluate/);
    expect(mainSrc).toMatch(/storageBackpressure:\s*storagePressure\.storageBackpressure/);
    expect(mainSrc).toMatch(/createNodeRuntimeListener\s*\(/);
    // Must not leave production on the zero-signal stub mount alone.
    expect(mainSrc).not.toMatch(
      /createProductionStoragePressureWiring\(\s*\{\s*readiness\s*\}\s*\)/,
    );
  });

  it("runtime-listener forwards onBeforeEvaluate into createHealthRouter", () => {
    expect(listenerSrc).toMatch(/onBeforeEvaluate\??:/);
    expect(listenerSrc).toMatch(/createHealthRouter\s*\(\s*\{[\s\S]*onBeforeEvaluate/);
    // Must not drop the dep the way the prior FAIL head did (readiness+pingDb only).
    expect(listenerSrc).not.toMatch(
      /createHealthRouter\(\{\s*readiness:\s*deps\.readiness,\s*pingDb:\s*deps\.pingDb\s*\}\)/,
    );
  });
});
