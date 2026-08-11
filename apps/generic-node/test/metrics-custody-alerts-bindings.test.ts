// ZTR-1144 — bind P0/P1 alert inputs to real readings and deliver P0 to webhook.
import { describe, expect, it, vi } from "vitest";

import {
  createNodeMetrics,
  createSafetyAlertEvaluator,
  emptyOperationalSnapshot,
  type AlertNotification,
} from "@zucoins/node-core";

import {
  createWebhookAlertChannel,
  custodyAlertCountersFromMetrics,
  custodyAlertInputFromSnapshot,
  evaluateAndDispatchCustodyAlerts,
} from "../src/metrics/custody-alerts.js";

describe("ZTR-1144 custody alert bindings", () => {
  it("maps process counters and snapshot gauges onto previously-zero inputs", () => {
    const metrics = createNodeMetrics();
    metrics.invariantBreaches.inc({});
    metrics.invariantBreaches.inc({});
    metrics.duplicateSubmitRejections.inc({});
    metrics.proofBudgetExhaustion.inc({});
    metrics.observationAnomalies.inc({ kind: "REGRESSION" });
    metrics.observationAnomalies.inc({ kind: "ENDPOINT_DISAGREEMENT" });
    metrics.receiveQueueFull503.inc({});
    metrics.t0ReadFailures.inc({});
    metrics.t0ReadFailures.inc({});
    metrics.t0ReadFailures.inc({});

    const snapshot = {
      ...emptyOperationalSnapshot(),
      attentionRequiredOps: 4,
      queueOldestAgeSecs: 90,
      signerInFlightAmbiguous: 1 as const,
      signerLeadershipHeld: 0 as const,
      poolCapTotal: 10,
      totalWallets: 5,
      pinnedWallets: 1,
    };
    const input = custodyAlertInputFromSnapshot(
      snapshot,
      custodyAlertCountersFromMetrics(metrics),
    );
    expect(input.invariantBreachCount).toBe(2);
    expect(input.duplicateSubmitRejectionCount).toBe(1);
    expect(input.pathGapCount).toBe(1);
    expect(input.regressionCount).toBe(1);
    expect(input.endpointDisagreementCount).toBe(1);
    expect(input.receiveQueueFull503Rate).toBe(1);
    expect(input.gatewayReadFailureCount).toBe(3);
    expect(input.attentionRequiredCount).toBe(4);
    expect(input.queueOldestAgeSecs).toBe(90);
    expect(input.signerInFlightAmbiguous).toBe(1);
  });

  it("end-to-end: inject invariant breach → P0 dispatched to webhook channel", async () => {
    const posted: Array<{ url: string; body: string }> = [];
    const fetchImpl = vi.fn(async (url: string | URL, init?: RequestInit) => {
      posted.push({ url: String(url), body: String(init?.body ?? "") });
      return new Response("ok", { status: 200 });
    }) as unknown as typeof fetch;

    const webhook = createWebhookAlertChannel({
      url: "https://alerts.example.test/hooks/custody",
      fetchImpl,
    });
    const delivered: AlertNotification[] = [];
    const evaluator = createSafetyAlertEvaluator({
      channels: {
        log: {
          kind: "log",
          deliver: async (n) => {
            delivered.push(n);
          },
        },
        webhook,
      },
      cooldownMs: 0,
    });

    const metrics = createNodeMetrics();
    metrics.invariantBreaches.inc({});
    const snapshot = {
      ...emptyOperationalSnapshot(),
      signerLeadershipHeld: 1 as const,
      poolCapTotal: 10,
    };

    await evaluateAndDispatchCustodyAlerts(
      evaluator,
      snapshot,
      true,
      custodyAlertCountersFromMetrics(metrics),
    );

    expect(delivered.some((n) => n.signal === "invariant_breach" && n.severity === "P0")).toBe(
      true,
    );
    expect(posted).toHaveLength(1);
    expect(posted[0]!.url).toBe("https://alerts.example.test/hooks/custody");
    const payload = JSON.parse(posted[0]!.body) as { signal: string; severity: string };
    expect(payload.signal).toBe("invariant_breach");
    expect(payload.severity).toBe("P0");
  });

  it("suppresses attention_backlog and queue_oldest_age when DB-truth is unavailable", async () => {
    const delivered: string[] = [];
    const evaluator = createSafetyAlertEvaluator({
      channels: {
        log: {
          kind: "log",
          deliver: async (n) => {
            delivered.push(n.signal);
          },
        },
      },
    });
    const snapshot = {
      ...emptyOperationalSnapshot(),
      attentionRequiredOps: 9,
      queueOldestAgeSecs: 999,
      oldestLeaseAgeSecs: 600,
      signerLeadershipHeld: 1 as const,
      poolCapTotal: 10,
    };
    await evaluateAndDispatchCustodyAlerts(evaluator, snapshot, false, {});
    expect(delivered).not.toContain("attention_backlog");
    expect(delivered).not.toContain("queue_oldest_age");
    expect(delivered).not.toContain("lease_age");
  });

  it("fires gateway_read_failure from t0 counter even when DB-truth is unavailable", async () => {
    const delivered: string[] = [];
    const evaluator = createSafetyAlertEvaluator({
      channels: {
        log: {
          kind: "log",
          deliver: async (n) => {
            delivered.push(n.signal);
          },
        },
      },
    });
    const metrics = createNodeMetrics();
    metrics.t0ReadFailures.inc({});
    await evaluateAndDispatchCustodyAlerts(
      evaluator,
      { ...emptyOperationalSnapshot(), signerLeadershipHeld: 1 as const, poolCapTotal: 10 },
      false,
      custodyAlertCountersFromMetrics(metrics),
    );
    expect(delivered).toContain("gateway_read_failure");
  });

  // ZTR-1144 D3 residual — in-process 503 arm must not ride the DB-truth gate on queue_caps.
  it("pages queue_caps from process 503 counter when DB-truth is unavailable", async () => {
    const delivered: string[] = [];
    const evaluator = createSafetyAlertEvaluator({
      channels: {
        log: {
          kind: "log",
          deliver: async (n) => {
            delivered.push(`${n.signal}:${n.severity}`);
          },
        },
      },
    });
    const metrics = createNodeMetrics();
    metrics.receiveQueueFull503.inc({});
    const snapshot = {
      ...emptyOperationalSnapshot(),
      // Fallback DB gauges look full — must not be the reason we page (or clear).
      queueDepth: 10,
      poolCapTotal: 10,
      capUtilizationPercent: 100,
      totalWallets: 10,
      pinnedWallets: 10,
      signerLeadershipHeld: 1 as const,
    };
    await evaluateAndDispatchCustodyAlerts(
      evaluator,
      snapshot,
      false,
      custodyAlertCountersFromMetrics(metrics),
    );
    expect(delivered).toContain("queue_caps:P1");
    // Pure DB-truth signals still suppressed.
    expect(delivered).not.toContain("lease_age");
    expect(delivered).not.toContain("attention_backlog");
  });

  it("does not page queue_caps from fallback depth/pool/pinned alone when DB-truth is down", async () => {
    const delivered: string[] = [];
    const evaluator = createSafetyAlertEvaluator({
      channels: {
        log: {
          kind: "log",
          deliver: async (n) => {
            delivered.push(n.signal);
          },
        },
      },
    });
    await evaluateAndDispatchCustodyAlerts(
      evaluator,
      {
        ...emptyOperationalSnapshot(),
        queueDepth: 10,
        poolCapTotal: 10,
        capUtilizationPercent: 100,
        totalWallets: 5,
        pinnedWallets: 5,
        oldestLeaseAgeSecs: 600,
        signerLeadershipHeld: 1 as const,
      },
      false,
      {},
    );
    expect(delivered).not.toContain("queue_caps");
    expect(delivered).not.toContain("lease_age");
  });

  it("composition: MOVE park and boot recovery emit onInvariantBreach (source ratchet)", async () => {
    const { readFileSync } = await import("node:fs");
    const { join, dirname } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const here = dirname(fileURLToPath(import.meta.url));
    const move = readFileSync(join(here, "../src/money-workers/move-advanced-ports.ts"), "utf8");
    expect(move).toMatch(/outcome\.kind === "INVARIANT_BREACH"/);
    expect(move).toMatch(/metricsHooks\?\.onInvariantBreach\(\)/);
    const main = readFileSync(join(here, "../src/main.ts"), "utf8");
    expect(main).toMatch(/onInvariantBreach:\s*\(\)\s*=>\s*metricsHooks\.onInvariantBreach\(\)/);
    expect(main).toMatch(/signingInflightCount/);
    const rules = readFileSync(
      join(here, "../../../docs/operations/alerts/generic-node.rules.yml"),
      "utf8",
    );
    expect(rules).toMatch(/GenericNodeReceiveQueueFull503/);
    expect(rules).toMatch(/increase\(gn_receive_queue_full_503_total/);
    // 503 arm must not share the DB-truth conjunct with depth/pool gauges.
    const queueCapsBlock = rules.slice(
      rules.indexOf("alert: GenericNodeQueueCaps"),
      rules.indexOf("alert: GenericNodeReceiveQueueFull503"),
    );
    expect(queueCapsBlock).not.toMatch(/gn_receive_queue_full_503_total/);
  });

});
