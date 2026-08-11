// Safety alerts / SLO rule set for the generic node.
//
// Ships the named signal classes bound to metrics (ten original OPS signals
// plus push_no_transfer_code_streak from ZTR-1154).
// Each rule carries a P0/P1/P2 severity and a documented playbook posture.
// Alerting is advisory only: a fire never
// advances a cursor, infers chain truth, releases a lease, or changes money
// state. Lease-age is diagnostic-only (axiom 5: "A lease heartbeat
// expiring is not a lease release.").
//
// Parent exit criterion: "Gateway or signer degradation fails closed
// without unsafe release; metrics contain no secrets." Alert labels and
// annotations are closed vocabulary + finite numbers only — never preimages,
// TOTP material, private keys, or raw signed bytes.

import {
  DEFAULT_CRITICAL_THRESHOLD,
  DEFAULT_PRESSURE_THRESHOLD,
} from "./storage-backpressure.js";

// ---------------------------------------------------------------------------
// Signal classes (exact names)
// ---------------------------------------------------------------------------

/**
 * Closed signal vocabulary (snake_case Prometheus-style labels; no secrets).
 * Ten original OPS-cited classes plus push_no_transfer_code_streak (ZTR-1154).
 */
export type SafetyAlertSignal =
  | "invariant_breach"
  | "duplicate_submit_attempt"
  | "lease_age"
  | "path_gap"
  | "regression"
  | "endpoint_disagreement"
  | "storage_pressure"
  | "queue_caps"
  | "signer_loss"
  | "backup_age"
  | "push_no_transfer_code_streak"
  | "attention_backlog"
  | "gateway_read_failure"
  | "queue_oldest_age";

export const SAFETY_ALERT_SIGNALS: readonly SafetyAlertSignal[] = [
  "invariant_breach",
  "duplicate_submit_attempt",
  "lease_age",
  "path_gap",
  "regression",
  "endpoint_disagreement",
  "storage_pressure",
  "queue_caps",
  "signer_loss",
  "backup_age",
  "push_no_transfer_code_streak",
  "attention_backlog",
  "gateway_read_failure",
  "queue_oldest_age",
] as const;

/** @deprecated Use SafetyAlertSignal — kept as an alias for call-site clarity. */
export type AlertMetric = SafetyAlertSignal;
/** @deprecated Use SAFETY_ALERT_SIGNALS. */
export const ALERT_METRICS: readonly SafetyAlertSignal[] = SAFETY_ALERT_SIGNALS;

// Ascending urgency, matching the incident-severity ladder.
export type AlertSeverity = "P2" | "P1" | "P0";

export const ALERT_SEVERITIES: readonly AlertSeverity[] = ["P2", "P1", "P0"];

export const SEVERITY_RANK: Readonly<Record<AlertSeverity, number>> = {
  P2: 0,
  P1: 1,
  P0: 2,
};

export type ThresholdDirection = "above" | "below";

/**
 * Canonical rule definition: severity + citation + posture for one signal.
 * Threshold numeric bands live separately so backup_age can take its value
 * from the cadence without hard-coding a second independent constant.
 */
export interface SafetyAlertRuleDefinition {
  readonly signal: SafetyAlertSignal;
  /** Primary severity for this signal (may be raised by a higher band). */
  readonly severity: AlertSeverity;
  /** Human-readable statement of the rule this alert enforces. */
  readonly citation: string;
  /** Required operator posture, tightened where a classification row demands it. */
  readonly posture: string;
  /**
   * When true, this alert is diagnostic only and MUST NOT drive an automatic
   * lease release or money-state change. Fixed true for lease_age: a lease
   * heartbeat expiring is not a lease release.
   */
  readonly diagnosticOnly: boolean;
}

/**
 * Frozen rule catalogue — one entry per signal.
 */
export const SAFETY_ALERT_RULES: readonly SafetyAlertRuleDefinition[] = [
  {
    signal: "invariant_breach",
    severity: "P0",
    citation:
      "INVARIANT_BREACH classification; P0 (lease uniqueness / missing exact bytes after signer use)",
    posture:
      "Stop money engines, quarantine affected wallets, preserve evidence, operator escalation.",
    diagnosticOnly: false,
  },
  {
    signal: "duplicate_submit_attempt",
    severity: "P0",
    citation:
      "Single-use submit_decision_id; the database prevents reuse. P0 (possible duplicate submit/sign over changed bytes)",
    posture:
      "Stop money engines, quarantine affected wallets, preserve evidence, operator escalation. Alert on submit_decision_id uniqueness-constraint rejection only — never on raw retry count.",
    diagnosticOnly: false,
  },
  {
    signal: "lease_age",
    severity: "P1",
    citation:
      "Lease age alert over active and pinned leases; axiom 5 — heartbeat expiry is not release",
    posture:
      "Diagnostic only: page operator on stale heartbeat_at. Never automatic lease release. Escalates to P0 only when combined with an invariant-breach classification (separate signal).",
    diagnosticOnly: true,
  },
  {
    signal: "path_gap",
    severity: "P1",
    citation:
      "INDETERMINATE on gap; P1 (persistent lineage gap)",
    posture:
      "Stop affected wallet/operation, keep other isolated lanes operating if invariants hold, operator escalation.",
    diagnosticOnly: false,
  },
  {
    signal: "regression",
    severity: "P1",
    citation:
      "REGRESSION row; P1 (regression observation)",
    posture: "Park affected operations; page operator; never release or rebuild.",
    diagnosticOnly: false,
  },
  {
    signal: "endpoint_disagreement",
    severity: "P1",
    citation:
      "Cross-endpoint disagreement fails closed; P1 (proof barrier mismatch)",
    posture:
      "Fail closed for money decisions until the configured authority policy resolves disagreement; operator escalation. Switching gateways starts a new observation stream and does not erase disagreement.",
    diagnosticOnly: false,
  },
  {
    signal: "storage_pressure",
    severity: "P1",
    citation:
      "Permanent retention of canonical containers; P1, escalating to P0 when exhaustion threatens evidence retention (storage bounds)",
    posture:
      "P1 on approach to configured storage bounds; P0 when critical/exhaustion band threatens evidence retention. Refuse new evidence at pressure; halt operations at critical (storage-backpressure).",
    diagnosticOnly: false,
  },
  {
    signal: "queue_caps",
    severity: "P1",
    citation:
      "RECEIVE_QUEUE_CAP overflow → 503 create-nothing; minting stops at POOL_CAP_TOTAL. P1 (pinned-cap exhaustion)",
    posture:
      "Stop affected admission/mint path; keep other isolated lanes operating if invariants hold; operator escalation. Alert on sustained cap utilization and on 503 receive_queue_full rate.",
    diagnosticOnly: false,
  },
  {
    signal: "signer_loss",
    severity: "P1",
    citation:
      "Signer unavailable; readiness false. P0 when in-flight signing outcome is ambiguous",
    posture:
      "P1 readiness-degraded when leadership is lost or cannot be re-acquired. P0 if loss coincides with an in-flight signing attempt whose outcome is ambiguous. Unsigned ops stay in existing public state; no alternate instance signs without leadership.",
    diagnosticOnly: false,
  },
  {
    signal: "backup_age",
    severity: "P1",
    citation:
      "Key rotation and backup; the threshold value comes from the injected backup cadence (not invented here)",
    posture:
      "Operator escalation; renew backup before retention/recovery risk. Threshold ms is injected by the caller — never hard-coded independently in this module.",
    diagnosticOnly: false,
  },
  {
    signal: "push_no_transfer_code_streak",
    severity: "P1",
    citation:
      "ZTR-1154 — consecutive no_transfer_code push receives with no intervening enqueued (delivered-envelope shape-break detector). Default threshold DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD (20)",
    posture:
      "Page operator. Compare a freshly decrypted live cleartext against goldens/push/delivered-envelope.data.v1; if the nest moved, update payload.ts precedence and refresh the golden in the same reviewed commit. Do not change the 204 discard response. Do not treat silence of other signals as an all-clear on the push channel.",
    diagnosticOnly: false,
  },
  {
    signal: "attention_backlog",
    severity: "P1",
    citation:
      "Doc 09 §9.1 — operations with attention_required accumulating past bound. P1 (operator backlog before wallet-cap exhaustion)",
    posture:
      "Page operator. Drain attention via admin recovery actions; do not release leases or rebuild. Suppress when DB-truth gauges are unavailable.",
    diagnosticOnly: false,
  },
  {
    signal: "gateway_read_failure",
    severity: "P1",
    citation:
      "Doc 09 §9.1 / ZTR-1162 — gn_t0_read_failures_total at the observation seam. P1 (gateway-read failures that close observation readiness)",
    posture:
      "Fail closed for money decisions until gateway reads recover. Do not switch endpoints to erase disagreement; page operator if failures continue past the configured budget.",
    diagnosticOnly: false,
  },
  {
    signal: "queue_oldest_age",
    severity: "P1",
    citation:
      "Doc 09 §9.1 — gn_receive_queue_oldest_age_seconds. P1 when the oldest unassigned receive exceeds RECEIVE_QUEUE_MAX_WAIT",
    posture:
      "Stop affected admission path; keep other isolated lanes operating if invariants hold; operator escalation. Suppress when DB-truth gauges are unavailable.",
    diagnosticOnly: false,
  },
] as const;

export const SAFETY_ALERT_RULE_BY_SIGNAL: Readonly<
  Record<SafetyAlertSignal, SafetyAlertRuleDefinition>
> = Object.freeze(
  Object.fromEntries(SAFETY_ALERT_RULES.map((rule) => [rule.signal, rule])) as Record<
    SafetyAlertSignal,
    SafetyAlertRuleDefinition
  >,
);

/**
 * Lease-age never triggers automatic release. Exported so reviewers can assert
 * the diagnostic-only contract by code inspection.
 */
export const LEASE_AGE_AUTOMATIC_RELEASE = false as const;

/** Source of the backup-age numeric threshold — never a local magic number. */
export const BACKUP_AGE_THRESHOLD_SOURCE = "operator-backup-cadence" as const;

// ---------------------------------------------------------------------------
// Thresholds / escalation / notifications
// ---------------------------------------------------------------------------

export interface AlertThreshold {
  readonly signal: SafetyAlertSignal;
  readonly severity: AlertSeverity;
  readonly value: number;
  /** "above" fires when reading >= value; "below" when reading <= value. */
  readonly direction: ThresholdDirection;
}

/** @deprecated Prefer `signal` — accepted as a synonym on older call sites. */
export type AlertThresholdInput = Omit<AlertThreshold, "signal"> & {
  readonly signal?: SafetyAlertSignal;
  /** @deprecated Use `signal`. */
  readonly metric?: SafetyAlertSignal;
};

export type AlertChannelKind = "log" | "webhook";

export interface LogChannelConfig {
  readonly kind: "log";
}

export interface WebhookChannelConfig {
  readonly kind: "webhook";
  readonly url: string;
}

export type AlertChannelConfig = LogChannelConfig | WebhookChannelConfig;

/** Runtime delivery port. node-core stays transport-neutral. */
export interface AlertChannel {
  readonly kind: AlertChannelKind;
  deliver(notification: AlertNotification): Promise<void>;
}

export interface EscalationStep {
  readonly severity: AlertSeverity;
  readonly channels: readonly AlertChannelKind[];
}

/**
 * Closed notification payload. Labels/annotations are signal id, severity,
 * finite numbers, and a short closed-vocabulary message — never secret material
 */
export interface AlertNotification {
  readonly signal: SafetyAlertSignal;
  /** @deprecated Alias of `signal` for older consumers. */
  readonly metric: SafetyAlertSignal;
  readonly severity: AlertSeverity;
  readonly value: number;
  readonly threshold: number;
  readonly direction: ThresholdDirection;
  readonly firedAtMs: number;
  readonly message: string;
  readonly citation: string;
  readonly posture: string;
  readonly diagnosticOnly: boolean;
  /**
   * Always false for lease_age. Present on every notification so sinks cannot
   * "upgrade" a diagnostic into an automatic release action.
   */
  readonly automaticRelease: false;
}

export class SafetyAlertConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SafetyAlertConfigurationError";
  }
}

const SIGNAL_SET: ReadonlySet<string> = new Set(SAFETY_ALERT_SIGNALS);
const SEVERITY_SET: ReadonlySet<string> = new Set(ALERT_SEVERITIES);

function normalizeThreshold(input: AlertThreshold | AlertThresholdInput): AlertThreshold {
  const signal = input.signal ?? input.metric;
  if (signal === undefined) {
    throw new SafetyAlertConfigurationError("alert threshold requires signal");
  }
  return {
    signal,
    severity: input.severity,
    value: input.value,
    direction: input.direction,
  };
}

export function validateAlertThreshold(
  threshold: AlertThreshold | AlertThresholdInput,
): AlertThreshold {
  const normalized = normalizeThreshold(threshold);
  if (!SIGNAL_SET.has(normalized.signal)) {
    throw new SafetyAlertConfigurationError(`unknown alert signal: ${String(normalized.signal)}`);
  }
  if (!SEVERITY_SET.has(normalized.severity)) {
    throw new SafetyAlertConfigurationError(`unknown alert severity: ${normalized.severity}`);
  }
  if (!Number.isFinite(normalized.value)) {
    throw new SafetyAlertConfigurationError(
      `alert threshold for ${normalized.signal} must be a finite number`,
    );
  }
  if (normalized.direction !== "above" && normalized.direction !== "below") {
    throw new SafetyAlertConfigurationError(
      `alert threshold direction must be "above" or "below"`,
    );
  }
  // backup_age value must be positive (age threshold); reject zero/negative silently-wrong configs.
  if (normalized.signal === "backup_age" && normalized.value <= 0) {
    throw new SafetyAlertConfigurationError(
      "backup_age threshold must be a finite positive ms value from the backup cadence",
    );
  }
  return normalized;
}

/**
 * Build the backup_age threshold from the injected cadence. The numeric
 * value is never invented inside this module.
 */
export function resolveBackupAgeThreshold(maxAgeMs: number): AlertThreshold {
  return validateAlertThreshold({
    signal: "backup_age",
    severity: "P1",
    value: maxAgeMs,
    direction: "above",
  });
}

// Escalation path must widen monotonically: higher severity never drops a channel.
export function validateEscalationPath(steps: readonly EscalationStep[]): readonly EscalationStep[] {
  if (steps.length === 0) {
    throw new SafetyAlertConfigurationError("escalation path must have at least one step");
  }
  const seen = new Set<string>();
  for (const step of steps) {
    if (!SEVERITY_SET.has(step.severity)) {
      throw new SafetyAlertConfigurationError(`unknown escalation severity: ${step.severity}`);
    }
    if (seen.has(step.severity)) {
      throw new SafetyAlertConfigurationError(
        `escalation path repeats severity ${step.severity}`,
      );
    }
    seen.add(step.severity);
    if (step.channels.length === 0) {
      throw new SafetyAlertConfigurationError(
        `escalation step ${step.severity} must name at least one channel`,
      );
    }
    for (const channel of step.channels) {
      if (channel !== "log" && channel !== "webhook") {
        throw new SafetyAlertConfigurationError(`unknown alert channel: ${channel}`);
      }
    }
  }
  const sorted = [...steps].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
  );
  for (let i = 1; i < sorted.length; i += 1) {
    const lower = new Set(sorted[i - 1]?.channels);
    const higher = sorted[i];
    for (const channel of lower) {
      if (!higher?.channels.includes(channel)) {
        throw new SafetyAlertConfigurationError(
          `escalation step ${higher?.severity} must include every channel of ${sorted[i - 1]?.severity}`,
        );
      }
    }
  }
  return steps;
}

/**
 * Default numeric thresholds for the nine signals whose bands are fixed by
 * adjacent modules (storage-backpressure) or by "any occurrence" count gates.
 * backup_age is intentionally absent — call {@link resolveBackupAgeThreshold}
 * with the cadence and pass it via evaluator options.
 */
export const DEFAULT_ALERT_THRESHOLDS: readonly AlertThreshold[] = [
  // 1. Any INVARIANT_BREACH classification → P0
  { signal: "invariant_breach", severity: "P0", value: 1, direction: "above" },
  // 2. Any submit_decision_id uniqueness rejection → P0
  { signal: "duplicate_submit_attempt", severity: "P0", value: 1, direction: "above" },
  // 3. Lease age (ms since heartbeat_at) — diagnostic P1; default 5 minutes
  { signal: "lease_age", severity: "P1", value: 300_000, direction: "above" },
  // 4. INDETERMINATE-by-gap accumulation past bound → P1
  { signal: "path_gap", severity: "P1", value: 1, direction: "above" },
  // 5. Any REGRESSION observation → P1
  { signal: "regression", severity: "P1", value: 1, direction: "above" },
  // 6. Any unresolved cross-endpoint disagreement → P1
  { signal: "endpoint_disagreement", severity: "P1", value: 1, direction: "above" },
  // 7. Storage utilization — pressure band P1, critical band P0 (backpressure defaults)
  {
    signal: "storage_pressure",
    severity: "P1",
    value: DEFAULT_PRESSURE_THRESHOLD,
    direction: "above",
  },
  {
    signal: "storage_pressure",
    severity: "P0",
    value: DEFAULT_CRITICAL_THRESHOLD,
    direction: "above",
  },
  // 8. Queue/pool/pinned-cap utilization and 503 rate (cap util, queue depth,
  // pinned ratio). Reading is max(queue_util, pool_util, pinned_ratio, 503_rate).
  // pinned_ratio is required so a full-but-healthy pool does not mask PINNED build-up
  // (a consumer-less node never releases via verification-complete, so the pinned
  // share climbs toward 1.0 while cap utilization still looks low).
  { signal: "queue_caps", severity: "P1", value: 0.9, direction: "above" },
  // 9. Signer loss: 1 = leadership lost (P1); 2 = lost + in-flight signing ambiguous (P0)
  { signal: "signer_loss", severity: "P1", value: 1, direction: "above" },
  { signal: "signer_loss", severity: "P0", value: 2, direction: "above" },
  // 10. Push delivered-envelope shape break — consecutive no_transfer_code streak (ZTR-1154).
  // Value is the process-local streak count; default band matches
  // DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD in packages/node-core/src/push/outcome-metrics.ts.
  { signal: "push_no_transfer_code_streak", severity: "P1", value: 20, direction: "above" },
  // 11. Attention backlog — any attention_required op past bound
  { signal: "attention_backlog", severity: "P1", value: 1, direction: "above" },
  // 12. Any T0/gateway-read failure counter increment past bound
  { signal: "gateway_read_failure", severity: "P1", value: 1, direction: "above" },
  // 13. Oldest queued receive age (seconds). Default band matches RECEIVE_QUEUE_MAX_WAIT default (30s);
  // composition root may override via thresholds when config differs.
  { signal: "queue_oldest_age", severity: "P1", value: 30, direction: "above" },
];

/** Default escalation: P2 logs; P1/P0 add webhook so the operator is paged. */
export const DEFAULT_ESCALATION_PATH: readonly EscalationStep[] = [
  { severity: "P2", channels: ["log"] },
  { severity: "P1", channels: ["log", "webhook"] },
  { severity: "P0", channels: ["log", "webhook"] },
];

/** Zero cooldown = every crossing fires; raise to suppress repeats per signal/severity. */
export const DEFAULT_ALERT_COOLDOWN_MS = 0;

function crosses(value: number, threshold: AlertThreshold): boolean {
  if (!Number.isFinite(value)) {
    // Indeterminate reading: fail closed — treat as breaching this threshold.
    return true;
  }
  return threshold.direction === "above" ? value >= threshold.value : value <= threshold.value;
}

function notificationFor(
  threshold: AlertThreshold,
  value: number,
  firedAtMs: number,
): AlertNotification {
  const rule = SAFETY_ALERT_RULE_BY_SIGNAL[threshold.signal];
  // Closed-vocabulary message: signal id + numbers + severity only. No request
  // bodies, preimages, keys, or operator secrets.
  const message = `${threshold.signal}=${value} crossed ${threshold.direction} ${threshold.value} (severity ${threshold.severity})`;
  return {
    signal: threshold.signal,
    metric: threshold.signal,
    severity: threshold.severity,
    value,
    threshold: threshold.value,
    direction: threshold.direction,
    firedAtMs,
    message,
    citation: rule.citation,
    posture: rule.posture,
    diagnosticOnly: rule.diagnosticOnly,
    automaticRelease: false,
  };
}

// ---------------------------------------------------------------------------
// Metric input → per-signal readings (bound to surfaces)
// ---------------------------------------------------------------------------

/**
 * Point-in-time inputs the composition root derives from NodeMetrics /
 * OperationalMetricsSnapshot plus seam counters. All fields are finite numbers
 * or 0|1 flags — never secret material.
 */
export interface SafetyAlertMetricInput {
  /** Count of INVARIANT_BREACH classifications observed. */
  readonly invariantBreachCount: number;
  /**
   * Count of DB uniqueness-constraint rejections on submit_decision_id
   * for one submit attempt. Do not feed raw submit retry counts here.
   */
  readonly duplicateSubmitRejectionCount: number;
  /** Oldest active lease age in ms (heartbeat_at → now). */
  readonly oldestLeaseAgeMs: number;
  /** Accumulated INDETERMINATE-by-gap classifications past the bound. */
  readonly pathGapCount: number;
  /** REGRESSION observation count (METRIC_ANOMALY_KINDS includes REGRESSION). */
  readonly regressionCount: number;
  /** Unresolved cross-endpoint disagreement count. */
  readonly endpointDisagreementCount: number;
  /** Evidence-storage utilization in [0, 1] (storage-backpressure). */
  readonly storageUtilization: number;
  /**
   * Receive-admission queue depth / RECEIVE_QUEUE_CAP (cap = pool_cap).
   * Fraction in [0, 1+].
   */
  readonly receiveQueueUtilization: number;
  /** Pool size / POOL_CAP_TOTAL fraction in [0, 1+]. */
  readonly poolCapUtilization: number;
  /**
   * PINNED wallets / current pool size fraction in [0, 1] ("pinned ratio").
   * Denominator is live pool size (AVAILABLE+PINNED+…), NOT POOL_CAP_TOTAL — matches
   * `collectPoolPressureMetrics.pinnedRatioPercent`. A healthy full pool with zero
   * PINNED reads 0; a floor-sized pool with every wallet PINNED (consumer-less node
   * never posting verification-complete) reads 1.0 and fires queue_caps. PINNED build-up signal.
   */
  readonly pinnedPoolRatio: number;
  /**
   * Normalized 503 receive_queue_full rate in [0, 1] (1 = at/above alert rate).
   * Composition root maps the raw rate onto this unit interval.
   */
  readonly receiveQueueFull503Rate: number;
  /** 1 when this process holds signer leadership, else 0. */
  readonly signerLeadershipHeld: 0 | 1;
  /**
   * 1 when an in-flight signing attempt has an ambiguous outcome while
   * leadership is absent. Raises signer_loss from P1 to P0.
   */
  readonly signerInFlightAmbiguous: 0 | 1;
  /** Age of the newest successful backup in ms (compared to max age). */
  readonly backupAgeMs: number;
  /**
   * Consecutive inbound push receives that returned no_transfer_code with no
   * intervening enqueued (ZTR-1154). Process-local; 0 after enqueue or restart.
   */
  readonly pushNoTransferCodeStreak: number;
  /** COUNT(*) WHERE attention_required (DB-truth). */
  readonly attentionRequiredCount: number;
  /** Process-local gn_t0_read_failures_total absolute count. */
  readonly gatewayReadFailureCount: number;
  /** Oldest unassigned receive age in seconds (DB-truth). */
  readonly queueOldestAgeSecs: number;
}

export function emptySafetyAlertMetricInput(): SafetyAlertMetricInput {
  return {
    invariantBreachCount: 0,
    duplicateSubmitRejectionCount: 0,
    oldestLeaseAgeMs: 0,
    pathGapCount: 0,
    regressionCount: 0,
    endpointDisagreementCount: 0,
    storageUtilization: 0,
    receiveQueueUtilization: 0,
    poolCapUtilization: 0,
    pinnedPoolRatio: 0,
    receiveQueueFull503Rate: 0,
    signerLeadershipHeld: 1,
    signerInFlightAmbiguous: 0,
    backupAgeMs: 0,
    pushNoTransferCodeStreak: 0,
    attentionRequiredCount: 0,
    gatewayReadFailureCount: 0,
    queueOldestAgeSecs: 0,
  };
}

/**
 * Collapse multi-dimensional inputs into one reading per signal.
 * queue_caps = max(queue util, pool util, pinned ratio, 503 rate).
 * signer_loss = 0 held | 1 lost | 2 lost+ambiguous.
 */
export function deriveSafetyAlertReadings(
  input: SafetyAlertMetricInput,
): Readonly<Record<SafetyAlertSignal, number>> {
  const leadershipLost = input.signerLeadershipHeld === 0 ? 1 : 0;
  const signerLossLevel =
    leadershipLost === 0
      ? 0
      : input.signerInFlightAmbiguous === 1
        ? 2
        : 1;

  const queueCapsReading = Math.max(
    input.receiveQueueUtilization,
    input.poolCapUtilization,
    input.pinnedPoolRatio,
    input.receiveQueueFull503Rate,
  );

  return {
    invariant_breach: input.invariantBreachCount,
    duplicate_submit_attempt: input.duplicateSubmitRejectionCount,
    lease_age: input.oldestLeaseAgeMs,
    path_gap: input.pathGapCount,
    regression: input.regressionCount,
    endpoint_disagreement: input.endpointDisagreementCount,
    storage_pressure: input.storageUtilization,
    queue_caps: queueCapsReading,
    signer_loss: signerLossLevel,
    backup_age: input.backupAgeMs,
    push_no_transfer_code_streak: input.pushNoTransferCodeStreak,
    attention_backlog: input.attentionRequiredCount,
    gateway_read_failure: input.gatewayReadFailureCount,
    queue_oldest_age: input.queueOldestAgeSecs,
  };
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

export interface SafetyAlertEvaluatorOptions {
  readonly thresholds?: readonly (AlertThreshold | AlertThresholdInput)[];
  /**
   * Configured max backup age (ms). When set, enables/overrides the
   * backup_age threshold via {@link resolveBackupAgeThreshold}. Required for
   * the backup_age rule to evaluate; omitted = rule defined but inactive
   * until the cadence is wired.
   */
  readonly backupMaxAgeMs?: number;
  readonly escalation?: readonly EscalationStep[];
  readonly channels?: Readonly<Partial<Record<AlertChannelKind, AlertChannel>>>;
  readonly cooldownMs?: number;
  readonly clock?: () => number;
  readonly onDeliveryError?: (channel: AlertChannelKind, error: unknown) => void;
}

export interface SafetyAlertEvaluator {
  /** Pure: at most one notification per signal (worst severity crossed). */
  evaluate(signal: SafetyAlertSignal, value: number, nowMs?: number): AlertNotification[];
  evaluateAll(
    readings: Readonly<Partial<Record<SafetyAlertSignal, number>>>,
    nowMs?: number,
  ): AlertNotification[];
  /** Evaluate from a full metric input (all catalogue signals). */
  evaluateInput(input: SafetyAlertMetricInput, nowMs?: number): AlertNotification[];
  dispatch(notification: AlertNotification): Promise<void>;
  evaluateAndDispatch(
    signal: SafetyAlertSignal,
    value: number,
    nowMs?: number,
  ): Promise<AlertNotification[]>;
  snapshot(): {
    readonly thresholds: readonly AlertThreshold[];
    readonly escalation: readonly EscalationStep[];
    readonly channels: readonly AlertChannelKind[];
    readonly rules: readonly SafetyAlertRuleDefinition[];
    readonly backupAgeThresholdSource: typeof BACKUP_AGE_THRESHOLD_SOURCE;
    readonly leaseAgeAutomaticRelease: typeof LEASE_AGE_AUTOMATIC_RELEASE;
  };
}

export function createSafetyAlertEvaluator(
  options: SafetyAlertEvaluatorOptions = {},
): SafetyAlertEvaluator {
  const baseThresholds = (options.thresholds ?? DEFAULT_ALERT_THRESHOLDS).map(validateAlertThreshold);

  // Merge backup age when supplied. Replace any pre-existing backup_age band.
  let thresholds = baseThresholds;
  if (options.backupMaxAgeMs !== undefined) {
    const backupThreshold = resolveBackupAgeThreshold(options.backupMaxAgeMs);
    thresholds = [
      ...baseThresholds.filter((t) => t.signal !== "backup_age"),
      backupThreshold,
    ];
  }

  const escalation = validateEscalationPath(options.escalation ?? DEFAULT_ESCALATION_PATH);
  const channels = options.channels ?? {};
  const cooldownMs = options.cooldownMs ?? DEFAULT_ALERT_COOLDOWN_MS;
  const clock = options.clock ?? (() => Date.now());
  const onDeliveryError = options.onDeliveryError;

  if (cooldownMs < 0 || !Number.isFinite(cooldownMs)) {
    throw new SafetyAlertConfigurationError("alert cooldown must be a finite, non-negative number");
  }

  const thresholdsBySignal = new Map<SafetyAlertSignal, AlertThreshold[]>();
  for (const threshold of thresholds) {
    const bucket = thresholdsBySignal.get(threshold.signal);
    if (bucket === undefined) {
      thresholdsBySignal.set(threshold.signal, [threshold]);
    } else {
      bucket.push(threshold);
    }
  }

  const channelsBySeverity = new Map<AlertSeverity, readonly AlertChannelKind[]>();
  for (const step of escalation) {
    channelsBySeverity.set(step.severity, step.channels);
  }

  const lastFiredAtMs = new Map<string, number>();

  const evaluate = (
    signal: SafetyAlertSignal,
    value: number,
    nowMs: number = clock(),
  ): AlertNotification[] => {
    if (!SIGNAL_SET.has(signal)) {
      return [];
    }
    const candidates = thresholdsBySignal.get(signal);
    if (candidates === undefined) {
      return [];
    }
    let worst: AlertThreshold | undefined;
    for (const threshold of candidates) {
      if (!crosses(value, threshold)) {
        continue;
      }
      if (worst === undefined || SEVERITY_RANK[threshold.severity] > SEVERITY_RANK[worst.severity]) {
        worst = threshold;
      }
    }
    if (worst === undefined) {
      return [];
    }
    const key = `${worst.signal}:${worst.severity}`;
    const last = lastFiredAtMs.get(key);
    if (last !== undefined && nowMs - last < cooldownMs) {
      return [];
    }
    lastFiredAtMs.set(key, nowMs);
    return [notificationFor(worst, value, nowMs)];
  };

  const dispatch = async (notification: AlertNotification): Promise<void> => {
    const kinds = channelsBySeverity.get(notification.severity) ?? [];
    await Promise.all(
      kinds.map(async (kind) => {
        const channel = channels[kind];
        if (channel === undefined) {
          return;
        }
        try {
          await channel.deliver(notification);
        } catch (error) {
          if (onDeliveryError !== undefined) {
            onDeliveryError(kind, error);
          }
        }
      }),
    );
  };

  return {
    evaluate,
    evaluateAll: (readings, nowMs = clock()) =>
      (Object.entries(readings) as Array<[SafetyAlertSignal, number | undefined]>).flatMap(
        ([signal, value]) => (value === undefined ? [] : evaluate(signal, value, nowMs)),
      ),
    evaluateInput: (input, nowMs = clock()) => {
      const readings = deriveSafetyAlertReadings(input);
      return (Object.entries(readings) as Array<[SafetyAlertSignal, number]>).flatMap(
        ([signal, value]) => evaluate(signal, value, nowMs),
      );
    },
    dispatch,
    evaluateAndDispatch: async (signal, value, nowMs = clock()) => {
      const fired = evaluate(signal, value, nowMs);
      for (const notification of fired) {
        await dispatch(notification);
      }
      return fired;
    },
    snapshot: () => ({
      thresholds,
      escalation,
      channels: (Object.keys(channels) as AlertChannelKind[]).filter(
        (kind) => channels[kind] !== undefined,
      ),
      rules: SAFETY_ALERT_RULES,
      backupAgeThresholdSource: BACKUP_AGE_THRESHOLD_SOURCE,
      leaseAgeAutomaticRelease: LEASE_AGE_AUTOMATIC_RELEASE,
    }),
  };
}
