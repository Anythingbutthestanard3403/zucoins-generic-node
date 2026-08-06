// Actionable alert rules for stuck/failed custody operations, wired
// from the /metrics DB-truth snapshot into node-core's already-built (and
// already-tested) safety-alert rule set (packages/node-core/src/operator/
// safety-alerts.ts). That evaluator covers lease_age,
// queue_caps and signer_loss with spec-cited P0/P1 severities and postures —
// it was exported but never composed anywhere in apps/generic-node.
//
// Snapshot-backed signals are fed only when their authoritative source is available:
// lease/queue DB truth, live storage pressure, signer leadership, and scheduler backup age.
//
// databaseTruthAvailable (REVIEW B): lease_age and queue_caps are DB-truth
// gauges. When the snapshot source falls back to a stamps-only snapshot (DB
// probe failed, or the DB-truth query threw mid-scrape — snapshot-source.ts),
// oldestLeaseAgeSecs/queueDepth read 0 for "unknown", not "no lease/no queue".
// Evaluating those two signals against a fallback zero would silently CLEAR a
// real stuck-lease/queue alert during exactly the DB instability that makes a
// stuck lease most likely — worse than not firing. So those two readings are
// omitted from evaluation (not zeroed) whenever databaseTruthAvailable is
// false; signer_loss is fed from process stamps (always live) regardless.
//
// Delivery is log-only (mirrors storage-pressure.ts's onEarlyAlert pattern):
// advisory only, never gates admission or releases a lease.

import {
  deriveSafetyAlertReadings,
  emptySafetyAlertMetricInput,
  type OperationalMetricsSnapshot,
  type SafetyAlertEvaluator,
  type SafetyAlertMetricInput,
  type SafetyAlertSignal,
} from "@zucoins/node-core";

/** DB-truth-only signals: must not be evaluated from a fallback (unknown) snapshot. */
const DB_TRUTH_ONLY_SIGNALS: readonly SafetyAlertSignal[] = ["lease_age", "queue_caps"];

/** Cooldown per signal/severity so a sustained condition logs once per window, not every scrape. */
export const CUSTODY_ALERT_COOLDOWN_MS = 5 * 60_000;

export function custodyAlertInputFromSnapshot(
  snapshot: OperationalMetricsSnapshot,
): SafetyAlertMetricInput {
  const receiveQueueUtilization =
    snapshot.poolCapTotal > 0 ? snapshot.queueDepth / snapshot.poolCapTotal : 0;
  // Pinned ratio — PINNED / live pool size (same basis as
  // collectPoolPressureMetrics.pinnedRatioPercent). Distinct from capUtilizationPercent
  // (total / POOL_CAP_TOTAL): a floor-sized pool with every wallet PINNED after landed
  // receives (no verifying consumer) must fire queue_caps even when minting has not
  // grown the pool toward the hard cap (alert-only pinned-ratio rule; it never auto-corrects).
  const pinnedPoolRatio =
    snapshot.totalWallets > 0 ? snapshot.pinnedWallets / snapshot.totalWallets : 0;
  return {
    ...emptySafetyAlertMetricInput(),
    oldestLeaseAgeMs: snapshot.oldestLeaseAgeSecs * 1000,
    receiveQueueUtilization,
    poolCapUtilization: snapshot.capUtilizationPercent / 100,
    pinnedPoolRatio,
    storageUtilization: snapshot.storagePressure,
    signerLeadershipHeld: snapshot.signerLeadershipHeld,
    backupAgeMs: (snapshot.backupLastSuccessAgeSecs ?? 0) * 1000,
  };
}

/**
 * Evaluate + dispatch every fired notification for one snapshot. Errors from a channel
 * are swallowed by the evaluator itself.
 *
 * `databaseTruthAvailable` (default true, for callers still on the earlier pre-DB-truth
 * shape) gates lease_age/queue_caps: when false, those two readings are omitted from
 * evaluation entirely rather than evaluated against the fallback snapshot's zeros, so a
 * real stuck lease/queue from before the DB blip keeps alerting instead of silently
 * clearing. signer_loss (process stamps) always evaluates.
 */
export async function evaluateAndDispatchCustodyAlerts(
  evaluator: SafetyAlertEvaluator,
  snapshot: OperationalMetricsSnapshot,
  databaseTruthAvailable = true,
): Promise<void> {
  const full = deriveSafetyAlertReadings(custodyAlertInputFromSnapshot(snapshot));
  const excluded: ReadonlySet<SafetyAlertSignal> = databaseTruthAvailable
    ? new Set(snapshot.backupLastSuccessAvailable === 1 ? [] : ["backup_age"])
    : new Set([
        ...DB_TRUTH_ONLY_SIGNALS,
        ...(snapshot.backupLastSuccessAvailable === 1 ? [] : ["backup_age" as const]),
      ]);
  const readings: Partial<Record<SafetyAlertSignal, number>> = {};
  for (const [signal, value] of Object.entries(full) as [SafetyAlertSignal, number][]) {
    if (!excluded.has(signal)) readings[signal] = value;
  }
  const notifications = evaluator.evaluateAll(readings);
  for (const notification of notifications) {
    await evaluator.dispatch(notification);
  }
}
