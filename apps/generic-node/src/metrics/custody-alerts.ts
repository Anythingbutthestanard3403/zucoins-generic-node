// Actionable alert rules for stuck/failed custody operations, wired
// from the /metrics DB-truth snapshot into node-core's already-built (and
// already-tested) safety-alert rule set (packages/node-core/src/operator/
// safety-alerts.ts). That evaluator covers lease_age,
// queue_caps and signer_loss with spec-cited P0/P1 severities and postures —
// it was exported but never composed anywhere in apps/generic-node.
//
// Snapshot-backed signals are fed only when their authoritative source is available:
// lease/queue/attention DB truth, live storage pressure, signer leadership, and
// process counters (invariant breach, duplicate submit, anomalies, gateway-read,
// queue-full 503, proof-budget path gaps).
//
// databaseTruthAvailable (REVIEW B): lease_age, queue_caps, attention_backlog and
// queue_oldest_age are DB-truth gauges. When the snapshot source falls back to a
// stamps-only snapshot (DB probe failed, or the DB-truth query threw mid-scrape —
// snapshot-source.ts), those readings are 0 for "unknown", not "healthy". Evaluating
// them against a fallback zero would silently CLEAR a real stuck-lease/queue alert
// during exactly the DB instability that makes a stuck lease most likely — worse than
// not firing. So those readings are omitted from evaluation (not zeroed) whenever
// databaseTruthAvailable is false; process-stamp and counter-backed signals always
// evaluate.
//
// Delivery: log always; webhook when OPERATOR_ALERT_WEBHOOK_URL is configured
// (https-only, no credentials). Advisory only — never gates admission or releases
// a lease.

import {
  deriveSafetyAlertReadings,
  emptySafetyAlertMetricInput,
  type AlertChannel,
  type AlertNotification,
  type NodeMetrics,
  type OperationalMetricsSnapshot,
  type SafetyAlertEvaluator,
  type SafetyAlertMetricInput,
  type SafetyAlertSignal,
} from "@zucoins/node-core";

/** DB-truth-only signals: must not be evaluated from a fallback (unknown) snapshot. */
const DB_TRUTH_ONLY_SIGNALS: readonly SafetyAlertSignal[] = [
  "lease_age",
  "queue_caps",
  "attention_backlog",
  "queue_oldest_age",
];

/** Cooldown per signal/severity so a sustained condition logs once per window, not every scrape. */
export const CUSTODY_ALERT_COOLDOWN_MS = 5 * 60_000;

/**
 * Normalize absolute 503 counter into [0, 1] for queue_caps max().
 * Any occurrence past 0 maps to 1 so the existing 0.9 band fires.
 */
export function normalizeReceiveQueueFull503Rate(count: number): number {
  if (!Number.isFinite(count) || count <= 0) return 0;
  return 1;
}

/** Sum every label series on a counter (process-local absolute). */
export function sumCounterSeries(
  series: ReadonlyArray<readonly [Record<string, string>, number]>,
): number {
  let total = 0;
  for (const [, value] of series) total += value;
  return total;
}

export function sumAnomalyKind(
  series: ReadonlyArray<readonly [Record<string, string>, number]>,
  kind: string,
): number {
  let total = 0;
  for (const [labels, value] of series) {
    if (labels.kind === kind) total += value;
  }
  return total;
}

/**
 * Optional process counters the composition root reads from NodeMetrics.
 * When omitted, the corresponding inputs stay at the empty default and their
 * signals stay silent (never fabricated).
 */
export interface CustodyAlertProcessCounters {
  readonly invariantBreachCount?: number;
  readonly duplicateSubmitRejectionCount?: number;
  readonly pathGapCount?: number;
  readonly regressionCount?: number;
  readonly endpointDisagreementCount?: number;
  readonly receiveQueueFull503Count?: number;
  readonly gatewayReadFailureCount?: number;
  readonly pushNoTransferCodeStreak?: number;
}

export function custodyAlertInputFromSnapshot(
  snapshot: OperationalMetricsSnapshot,
  counters: CustodyAlertProcessCounters = {},
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
    signerInFlightAmbiguous: snapshot.signerInFlightAmbiguous,
    backupAgeMs: (snapshot.backupLastSuccessAgeSecs ?? 0) * 1000,
    attentionRequiredCount: snapshot.attentionRequiredOps,
    queueOldestAgeSecs: snapshot.queueOldestAgeSecs,
    invariantBreachCount: counters.invariantBreachCount ?? 0,
    duplicateSubmitRejectionCount: counters.duplicateSubmitRejectionCount ?? 0,
    pathGapCount: counters.pathGapCount ?? 0,
    regressionCount: counters.regressionCount ?? 0,
    endpointDisagreementCount: counters.endpointDisagreementCount ?? 0,
    receiveQueueFull503Rate: normalizeReceiveQueueFull503Rate(
      counters.receiveQueueFull503Count ?? 0,
    ),
    gatewayReadFailureCount: counters.gatewayReadFailureCount ?? 0,
    pushNoTransferCodeStreak: counters.pushNoTransferCodeStreak ?? 0,
  };
}

/** Read live process counters from NodeMetrics for one scrape evaluation. */
export function custodyAlertCountersFromMetrics(metrics: NodeMetrics): CustodyAlertProcessCounters {
  return {
    invariantBreachCount: metrics.invariantBreaches.get({}),
    duplicateSubmitRejectionCount: metrics.duplicateSubmitRejections.get({}),
    pathGapCount: metrics.proofBudgetExhaustion.get({}),
    regressionCount: sumAnomalyKind(metrics.observationAnomalies.series(), "REGRESSION"),
    endpointDisagreementCount: sumAnomalyKind(
      metrics.observationAnomalies.series(),
      "ENDPOINT_DISAGREEMENT",
    ),
    receiveQueueFull503Count: metrics.receiveQueueFull503.get({}),
    gatewayReadFailureCount: metrics.t0ReadFailures.get({}),
    pushNoTransferCodeStreak: metrics.pushNoTransferCodeStreak.get({}),
  };
}

/**
 * Evaluate + dispatch every fired notification for one snapshot. Errors from a channel
 * are swallowed by the evaluator itself.
 *
 * `databaseTruthAvailable` (default true, for callers still on the earlier pre-DB-truth
 * shape) gates DB-truth signals: when false, those readings are omitted from
 * evaluation entirely rather than evaluated against the fallback snapshot's zeros, so a
 * real stuck lease/queue from before the DB blip keeps alerting instead of silently
 * clearing. Process-stamp and counter-backed signals always evaluate.
 */
export async function evaluateAndDispatchCustodyAlerts(
  evaluator: SafetyAlertEvaluator,
  snapshot: OperationalMetricsSnapshot,
  databaseTruthAvailable = true,
  counters: CustodyAlertProcessCounters = {},
): Promise<void> {
  const full = deriveSafetyAlertReadings(custodyAlertInputFromSnapshot(snapshot, counters));
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

// ---------------------------------------------------------------------------
// Webhook delivery channel (ZTR-1144)
// ---------------------------------------------------------------------------

export interface WebhookAlertChannelOptions {
  readonly url: string;
  /** Injected for tests; production uses global fetch. */
  readonly fetchImpl?: typeof fetch;
  readonly logger?: { error(message: string, err?: unknown): void };
}

/**
 * POST a closed-vocabulary JSON body to the configured operator webhook.
 * Never includes secrets, preimages, keys, or raw signed bytes.
 */
export function createWebhookAlertChannel(options: WebhookAlertChannelOptions): AlertChannel {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  return {
    kind: "webhook",
    async deliver(notification: AlertNotification): Promise<void> {
      const body = JSON.stringify({
        signal: notification.signal,
        severity: notification.severity,
        value: notification.value,
        threshold: notification.threshold,
        direction: notification.direction,
        firedAtMs: notification.firedAtMs,
        message: notification.message,
        citation: notification.citation,
        posture: notification.posture,
        diagnosticOnly: notification.diagnosticOnly,
        automaticRelease: notification.automaticRelease,
      });
      const response = await fetchImpl(options.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body,
      });
      if (!response.ok) {
        const err = new Error(
          `operator alert webhook returned HTTP ${response.status}`,
        );
        options.logger?.error(
          `node: safety-alert webhook delivery failed signal=${notification.signal}`,
          err,
        );
        throw err;
      }
    },
  };
}
