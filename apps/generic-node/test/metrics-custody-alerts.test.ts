// Actionable alert rules for stuck/failed custody operations, wired
// from the /metrics DB-truth snapshot into node-core's safety-alert rule set
// (packages/node-core/src/operator/safety-alerts.ts). This exercises the
// composition, not the rule set itself (already covered by
// packages/node-core/test/safety-alerts.test.ts).

import { describe, expect, it } from "vitest";

import { createSafetyAlertEvaluator, emptyOperationalSnapshot } from "@zucoins/node-core";

import {
  custodyAlertInputFromSnapshot,
  evaluateAndDispatchCustodyAlerts,
} from "../src/metrics/custody-alerts.js";

describe("custodyAlertInputFromSnapshot", () => {
  it("maps live snapshot fields onto the signals this scrape has truthful data for", () => {
    const snapshot = {
      ...emptyOperationalSnapshot(),
      oldestLeaseAgeSecs: 400,
      queueDepth: 9,
      poolCapTotal: 10,
      totalWallets: 10,
      pinnedWallets: 3,
      capUtilizationPercent: 90,
      signerLeadershipHeld: 0 as const,
    };
    const input = custodyAlertInputFromSnapshot(snapshot);
    expect(input.oldestLeaseAgeMs).toBe(400_000);
    expect(input.receiveQueueUtilization).toBeCloseTo(0.9);
    expect(input.poolCapUtilization).toBeCloseTo(0.9);
    expect(input.pinnedPoolRatio).toBeCloseTo(0.3);
    expect(input.signerLeadershipHeld).toBe(0);
    // Process counters omitted → empty defaults (never fabricated).
    expect(input.invariantBreachCount).toBe(0);
    expect(input.backupAgeMs).toBe(0);
    expect(input.attentionRequiredCount).toBe(0);
  });

  it("does not divide by zero when poolCapTotal is 0 (fresh/greenfield node)", () => {
    const snapshot = { ...emptyOperationalSnapshot(), poolCapTotal: 0, queueDepth: 3 };
    const input = custodyAlertInputFromSnapshot(snapshot);
    expect(Number.isFinite(input.receiveQueueUtilization)).toBe(true);
    expect(input.receiveQueueUtilization).toBe(0);
    expect(Number.isFinite(input.pinnedPoolRatio)).toBe(true);
    expect(input.pinnedPoolRatio).toBe(0);
  });

  // consumer-less node: every landed receive pins a wallet until
  // verification-complete. queue_caps must see the PINNED drain even when the
  // live pool is still at POOL_FLOOR and cap utilization is low.
  it("feeds pinned ratio so a fully-PINNED floor pool fires queue_caps", async () => {
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
    const snapshot = {
      ...emptyOperationalSnapshot(),
      // E2E-shaped: 5 wallets all PINNED, POOL_CAP_TOTAL=50 → cap util 10%, pinned ratio 100%.
      totalWallets: 5,
      pinnedWallets: 5,
      poolCapTotal: 50,
      capUtilizationPercent: 10,
      signerLeadershipHeld: 1 as const,
    };
    const input = custodyAlertInputFromSnapshot(snapshot);
    expect(input.pinnedPoolRatio).toBe(1);
    expect(input.poolCapUtilization).toBeCloseTo(0.1);
    await evaluateAndDispatchCustodyAlerts(evaluator, snapshot);
    expect(delivered).toContain("queue_caps:P1");
  });

  it("does not fire queue_caps on a healthy full pool with zero PINNED wallets", async () => {
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
    // Cap util alone at 100% still fires today's queue_caps band (pre-existing);
    // isolate the pinned-ratio path by keeping cap util below 0.9 with zero PINNED.
    const snapshot = {
      ...emptyOperationalSnapshot(),
      totalWallets: 40,
      pinnedWallets: 0,
      poolCapTotal: 50,
      capUtilizationPercent: 80,
      signerLeadershipHeld: 1 as const,
    };
    await evaluateAndDispatchCustodyAlerts(evaluator, snapshot);
    expect(delivered).not.toContain("queue_caps:P1");
    expect(delivered).toEqual([]);
  });
});

describe("evaluateAndDispatchCustodyAlerts", () => {
  it("fires the lease_age P1 alert once a stuck lease crosses the default 5-minute band", async () => {
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
    const snapshot = { ...emptyOperationalSnapshot(), oldestLeaseAgeSecs: 600 };
    await evaluateAndDispatchCustodyAlerts(evaluator, snapshot);
    expect(delivered).toContain("lease_age:P1");
  });

  it("stays silent when nothing is stuck", async () => {
    const delivered: string[] = [];
    const evaluator = createSafetyAlertEvaluator({
      channels: {
        log: { kind: "log", deliver: async (n) => { delivered.push(n.signal); } },
      },
    });
    const snapshot = {
      ...emptyOperationalSnapshot(),
      poolCapTotal: 10,
      // Healthy: this process holds leadership, no lease/queue pressure.
      signerLeadershipHeld: 1 as const,
    };
    await evaluateAndDispatchCustodyAlerts(evaluator, snapshot);
    expect(delivered).toEqual([]);
  });

  // REVIEW B — custody alerts must not go dark exactly during a DB blip. A stamps-only
  // fallback snapshot means "unknown", not "no lease/no queue"; lease_age/queue_caps must
  // never be evaluated from it. signer_loss (process stamps, always live) is unaffected.
  describe("databaseTruthAvailable=false — DB blip must not fabricate a healthy reading", () => {
    it("does not fire lease_age even when the snapshot carries a stuck-lease reading", async () => {
      const delivered: string[] = [];
      const evaluator = createSafetyAlertEvaluator({
        channels: {
          log: { kind: "log", deliver: async (n) => { delivered.push(n.signal); } },
        },
      });
      const snapshot = { ...emptyOperationalSnapshot(), oldestLeaseAgeSecs: 600 };
      await evaluateAndDispatchCustodyAlerts(evaluator, snapshot, false);
      expect(delivered).not.toContain("lease_age");
    });

    it("does not fire queue_caps even when the snapshot carries a full-queue reading", async () => {
      const delivered: string[] = [];
      const evaluator = createSafetyAlertEvaluator({
        channels: {
          log: { kind: "log", deliver: async (n) => { delivered.push(n.signal); } },
        },
      });
      const snapshot = {
        ...emptyOperationalSnapshot(),
        queueDepth: 10,
        poolCapTotal: 10,
        capUtilizationPercent: 100,
      };
      await evaluateAndDispatchCustodyAlerts(evaluator, snapshot, false);
      expect(delivered).not.toContain("queue_caps");
    });

    it("still fires signer_loss — it is fed from process stamps, never DB-truth", async () => {
      const delivered: string[] = [];
      const evaluator = createSafetyAlertEvaluator({
        channels: {
          log: { kind: "log", deliver: async (n) => { delivered.push(n.signal); } },
        },
      });
      const snapshot = { ...emptyOperationalSnapshot(), signerLeadershipHeld: 0 as const };
      await evaluateAndDispatchCustodyAlerts(evaluator, snapshot, false);
      expect(delivered).toContain("signer_loss");
    });

    it("end-to-end: a real stuck lease alerts before the blip, and the blip itself never fabricates a clear", async () => {
      const delivered: string[] = [];
      const evaluator = createSafetyAlertEvaluator({
        channels: {
          log: { kind: "log", deliver: async (n) => { delivered.push(`${n.signal}:${n.severity}`); } },
        },
      });
      // Prior scrape: DB-truth read, real 600s-stuck lease — fires. Leadership held so
      // signer_loss stays silent and isolates the lease_age assertion below.
      const dbTruthSnapshot = {
        ...emptyOperationalSnapshot(),
        oldestLeaseAgeSecs: 600,
        signerLeadershipHeld: 1 as const,
      };
      await evaluateAndDispatchCustodyAlerts(evaluator, dbTruthSnapshot, true);
      expect(delivered).toContain("lease_age:P1");

      // Next scrape: DB blip — DB-truth query threw mid-scrape, snapshot-source fell back
      // to stamps-only (oldestLeaseAgeSecs reads 0, the fallback's "unknown", not "0 stuck
      // seconds"). Must not be evaluated as a truthful reading.
      delivered.length = 0;
      const fallbackSnapshot = {
        ...emptyOperationalSnapshot(),
        oldestLeaseAgeSecs: 0,
        signerLeadershipHeld: 1 as const,
      };
      await evaluateAndDispatchCustodyAlerts(evaluator, fallbackSnapshot, false);
      expect(delivered).toEqual([]);
    });

    it("fires storage-pressure and available stale-backup alerts from live snapshot values", async () => {
      const delivered: string[] = [];
      const evaluator = createSafetyAlertEvaluator({
        backupMaxAgeMs: 24 * 60 * 60 * 1000,
        channels: {
          log: { kind: "log", deliver: async (n) => { delivered.push(n.signal); } },
        },
      });
      await evaluateAndDispatchCustodyAlerts(evaluator, {
        ...emptyOperationalSnapshot(),
        signerLeadershipHeld: 1,
        storagePressure: 1,
        backupLastSuccessAvailable: 1,
        backupLastSuccessAgeSecs: 25 * 60 * 60,
      });
      expect(delivered).toContain("storage_pressure");
      expect(delivered).toContain("backup_age");
    });

    it("does not fabricate backup_age when no successful-backup timestamp is available", async () => {
      const delivered: string[] = [];
      const evaluator = createSafetyAlertEvaluator({
        backupMaxAgeMs: 1,
        channels: {
          log: { kind: "log", deliver: async (n) => { delivered.push(n.signal); } },
        },
      });
      await evaluateAndDispatchCustodyAlerts(evaluator, {
        ...emptyOperationalSnapshot(),
        signerLeadershipHeld: 1,
        backupLastSuccessAvailable: 0,
        backupLastSuccessAgeSecs: 999_999,
      });
      expect(delivered).not.toContain("backup_age");
    });
  });
});
