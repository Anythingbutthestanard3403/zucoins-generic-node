import { describe, expect, it } from "vitest";

import {
  ALERT_METRICS,
  ALERT_SEVERITIES,
  BACKUP_AGE_THRESHOLD_SOURCE,
  DEFAULT_ALERT_COOLDOWN_MS,
  DEFAULT_ALERT_THRESHOLDS,
  DEFAULT_ESCALATION_PATH,
  LEASE_AGE_AUTOMATIC_RELEASE,
  SAFETY_ALERT_RULES,
  SAFETY_ALERT_RULE_BY_SIGNAL,
  SAFETY_ALERT_SIGNALS,
  SEVERITY_RANK,
  SafetyAlertConfigurationError,
  createSafetyAlertEvaluator,
  deriveSafetyAlertReadings,
  emptySafetyAlertMetricInput,
  resolveBackupAgeThreshold,
  validateAlertThreshold,
  validateEscalationPath,
  type AlertChannel,
  type AlertChannelKind,
  type AlertNotification,
  type AlertThreshold,
  type SafetyAlertMetricInput,
  type SafetyAlertSignal,
} from "./safety-alerts.js";

class RecordingChannel implements AlertChannel {
  readonly kind: AlertChannelKind;
  delivered: AlertNotification[] = [];
  failNext = false;

  constructor(kind: AlertChannelKind) {
    this.kind = kind;
  }

  async deliver(notification: AlertNotification): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("transient channel failure");
    }
    this.delivered.push(notification);
  }
}

const THRESHOLDS: readonly AlertThreshold[] = [
  { signal: "invariant_breach", severity: "P0", value: 1, direction: "above" },
  { signal: "queue_caps", severity: "P1", value: 0.9, direction: "above" },
  { signal: "storage_pressure", severity: "P1", value: 0.9, direction: "above" },
  { signal: "storage_pressure", severity: "P0", value: 0.95, direction: "above" },
  { signal: "signer_loss", severity: "P1", value: 1, direction: "above" },
  { signal: "signer_loss", severity: "P0", value: 2, direction: "above" },
];

/** One synthetic trigger value per signal that crosses its default band. */
const SYNTHETIC_TRIGGERS: Readonly<Record<SafetyAlertSignal, number>> = {
  invariant_breach: 1,
  duplicate_submit_attempt: 1,
  lease_age: 300_000,
  path_gap: 1,
  regression: 1,
  endpoint_disagreement: 1,
  storage_pressure: 0.9,
  queue_caps: 0.9,
  signer_loss: 1,
  backup_age: 86_400_000,
};

describe("safety alerts — ten signal classes", () => {
  describe("rule catalogue", () => {
    it("defines exactly the ten required signal classes", () => {
      expect([...SAFETY_ALERT_SIGNALS]).toEqual([
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
      ]);
      expect(SAFETY_ALERT_RULES).toHaveLength(10);
      expect(ALERT_METRICS).toEqual(SAFETY_ALERT_SIGNALS);
    });

    it("assigns each rule a P0/P1/P2 severity and a governing rule", () => {
      const expectedSeverity: Record<SafetyAlertSignal, "P0" | "P1" | "P2"> = {
        invariant_breach: "P0",
        duplicate_submit_attempt: "P0",
        lease_age: "P1",
        path_gap: "P1",
        regression: "P1",
        endpoint_disagreement: "P1",
        storage_pressure: "P1",
        queue_caps: "P1",
        signer_loss: "P1",
        backup_age: "P1",
      };
      for (const rule of SAFETY_ALERT_RULES) {
        expect(ALERT_SEVERITIES).toContain(rule.severity);
        expect(rule.severity).toBe(expectedSeverity[rule.signal]);
        expect(rule.citation.length).toBeGreaterThan(10);
        expect(rule.posture.length).toBeGreaterThan(10);
        expect(SAFETY_ALERT_RULE_BY_SIGNAL[rule.signal]).toBe(rule);
      }
    });

    it("states the governing rule for each signal", () => {
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.invariant_breach.citation).toMatch(/INVARIANT_BREACH/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.invariant_breach.citation).toMatch(/P0/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.duplicate_submit_attempt.citation).toMatch(
        /submit_decision_id/,
      );
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.lease_age.citation).toMatch(/[Ll]ease age/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.lease_age.citation).toMatch(/axiom 5/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.path_gap.citation).toMatch(/lineage gap|INDETERMINATE/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.regression.citation).toMatch(/REGRESSION/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.endpoint_disagreement.citation).toMatch(/disagreement/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.storage_pressure.citation).toMatch(/retention/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.queue_caps.citation).toMatch(
        /RECEIVE_QUEUE_CAP|POOL_CAP_TOTAL/,
      );
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.queue_caps.citation).toMatch(/503/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.signer_loss.citation).toMatch(/[Ss]igner unavailable/);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.backup_age.citation).toMatch(/backup cadence/);
    });

    it("marks lease_age diagnostic-only and never automatic release", () => {
      expect(LEASE_AGE_AUTOMATIC_RELEASE).toBe(false);
      expect(SAFETY_ALERT_RULE_BY_SIGNAL.lease_age.diagnosticOnly).toBe(true);
      for (const rule of SAFETY_ALERT_RULES) {
        if (rule.signal !== "lease_age") {
          expect(rule.diagnosticOnly).toBe(false);
        }
      }
    });

    it("sources backup_age threshold from the injected cadence, not a local constant", () => {
      expect(BACKUP_AGE_THRESHOLD_SOURCE).toBe("operator-backup-cadence");
      // Defaults deliberately omit backup_age — cadence is injected.
      expect(DEFAULT_ALERT_THRESHOLDS.some((t) => t.signal === "backup_age")).toBe(false);
      const threshold = resolveBackupAgeThreshold(7 * 24 * 60 * 60 * 1000);
      expect(threshold.signal).toBe("backup_age");
      expect(threshold.severity).toBe("P1");
      expect(threshold.value).toBe(7 * 24 * 60 * 60 * 1000);
      expect(() => resolveBackupAgeThreshold(0)).toThrow(SafetyAlertConfigurationError);
      expect(() => resolveBackupAgeThreshold(-1)).toThrow(SafetyAlertConfigurationError);
    });
  });

  describe("validateAlertThreshold", () => {
    it("accepts a well-formed threshold", () => {
      const threshold: AlertThreshold = {
        signal: "invariant_breach",
        severity: "P0",
        value: 1,
        direction: "above",
      };
      expect(validateAlertThreshold(threshold)).toEqual(threshold);
    });

    it("accepts deprecated metric alias", () => {
      const threshold = validateAlertThreshold({
        metric: "regression",
        severity: "P1",
        value: 1,
        direction: "above",
      });
      expect(threshold.signal).toBe("regression");
    });

    it("rejects an unknown signal", () => {
      expect(() =>
        validateAlertThreshold({
          signal: "bogus" as SafetyAlertSignal,
          severity: "P1",
          value: 1,
          direction: "above",
        }),
      ).toThrow(SafetyAlertConfigurationError);
    });

    it("rejects an unknown severity", () => {
      expect(() =>
        validateAlertThreshold({
          signal: "regression",
          severity: "P9" as AlertThreshold["severity"],
          value: 1,
          direction: "above",
        }),
      ).toThrow(SafetyAlertConfigurationError);
    });

    it("rejects a non-finite value", () => {
      expect(() =>
        validateAlertThreshold({
          signal: "regression",
          severity: "P1",
          value: Number.NaN,
          direction: "above",
        }),
      ).toThrow(SafetyAlertConfigurationError);
    });

    it("rejects an invalid direction", () => {
      expect(() =>
        validateAlertThreshold({
          signal: "regression",
          severity: "P1",
          value: 1,
          direction: "sideways" as AlertThreshold["direction"],
        }),
      ).toThrow(SafetyAlertConfigurationError);
    });
  });

  describe("validateEscalationPath", () => {
    it("accepts a monotonic path", () => {
      expect(validateEscalationPath(DEFAULT_ESCALATION_PATH)).toBe(DEFAULT_ESCALATION_PATH);
    });

    it("rejects an empty path", () => {
      expect(() => validateEscalationPath([])).toThrow(SafetyAlertConfigurationError);
    });

    it("rejects a repeated severity", () => {
      expect(() =>
        validateEscalationPath([
          { severity: "P2", channels: ["log"] },
          { severity: "P2", channels: ["log"] },
        ]),
      ).toThrow(SafetyAlertConfigurationError);
    });

    it("rejects a step with no channels", () => {
      expect(() => validateEscalationPath([{ severity: "P2", channels: [] }])).toThrow(
        SafetyAlertConfigurationError,
      );
    });

    it("rejects an unknown channel", () => {
      expect(() =>
        validateEscalationPath([
          { severity: "P2", channels: ["pager" as AlertChannelKind] },
        ]),
      ).toThrow(SafetyAlertConfigurationError);
    });

    it("rejects a path that narrows as severity rises", () => {
      expect(() =>
        validateEscalationPath([
          { severity: "P2", channels: ["log", "webhook"] },
          { severity: "P0", channels: ["log"] },
        ]),
      ).toThrow(SafetyAlertConfigurationError);
    });
  });

  describe("synthetic per-signal triggers", () => {
    it("fires exactly its own rule and no others for each of the ten signals", () => {
      const evaluator = createSafetyAlertEvaluator({
        backupMaxAgeMs: SYNTHETIC_TRIGGERS.backup_age,
      });

      for (const signal of SAFETY_ALERT_SIGNALS) {
        // Isolate: only this signal is above threshold; others at zero/safe.
        const readings: Partial<Record<SafetyAlertSignal, number>> = {
          invariant_breach: 0,
          duplicate_submit_attempt: 0,
          lease_age: 0,
          path_gap: 0,
          regression: 0,
          endpoint_disagreement: 0,
          storage_pressure: 0,
          queue_caps: 0,
          signer_loss: 0,
          backup_age: 0,
        };
        readings[signal] = SYNTHETIC_TRIGGERS[signal];

        const fired = evaluator.evaluateAll(readings, 0);
        expect(fired, `expected sole fire for ${signal}`).toHaveLength(1);
        expect(fired[0]?.signal).toBe(signal);
        expect(fired[0]?.metric).toBe(signal);
        expect(fired[0]?.severity).toBe(SAFETY_ALERT_RULE_BY_SIGNAL[signal].severity);
        expect(fired[0]?.automaticRelease).toBe(false);
        expect(fired[0]?.diagnosticOnly).toBe(
          SAFETY_ALERT_RULE_BY_SIGNAL[signal].diagnosticOnly,
        );
        // Citation and posture travel with the notification for playbook routing.
        expect(fired[0]?.citation).toBe(SAFETY_ALERT_RULE_BY_SIGNAL[signal].citation);
        expect(fired[0]?.posture).toBe(SAFETY_ALERT_RULE_BY_SIGNAL[signal].posture);
      }
    });

    it("raises storage_pressure to P0 at the critical band", () => {
      const evaluator = createSafetyAlertEvaluator();
      const fired = evaluator.evaluate("storage_pressure", 0.95, 0);
      expect(fired).toHaveLength(1);
      expect(fired[0]?.severity).toBe("P0");
    });

    it("raises signer_loss to P0 when leadership is lost with ambiguous in-flight sign", () => {
      const evaluator = createSafetyAlertEvaluator();
      expect(evaluator.evaluate("signer_loss", 1, 0)[0]?.severity).toBe("P1");
      expect(evaluator.evaluate("signer_loss", 2, 1)[0]?.severity).toBe("P0");
    });

    it("does not fire backup_age until cadence is wired", () => {
      const evaluator = createSafetyAlertEvaluator(); // no backupMaxAgeMs
      expect(evaluator.evaluate("backup_age", 999_999_999, 0)).toEqual([]);
    });
  });

  describe("deriveSafetyAlertReadings", () => {
    it("maps metric inputs onto the ten signals without cross-talk", () => {
      const input: SafetyAlertMetricInput = {
        ...emptySafetyAlertMetricInput(),
        invariantBreachCount: 2,
        duplicateSubmitRejectionCount: 3,
        oldestLeaseAgeMs: 400_000,
        pathGapCount: 4,
        regressionCount: 5,
        endpointDisagreementCount: 6,
        storageUtilization: 0.92,
        receiveQueueUtilization: 0.5,
        poolCapUtilization: 0.95,
        pinnedPoolRatio: 0.2,
        receiveQueueFull503Rate: 0.1,
        signerLeadershipHeld: 0,
        signerInFlightAmbiguous: 1,
        backupAgeMs: 1_000,
      };
      const readings = deriveSafetyAlertReadings(input);
      expect(readings.invariant_breach).toBe(2);
      expect(readings.duplicate_submit_attempt).toBe(3);
      expect(readings.lease_age).toBe(400_000);
      expect(readings.path_gap).toBe(4);
      expect(readings.regression).toBe(5);
      expect(readings.endpoint_disagreement).toBe(6);
      expect(readings.storage_pressure).toBe(0.92);
      // queue_caps = max(0.5, 0.95, 0.2, 0.1)
      expect(readings.queue_caps).toBe(0.95);
      expect(readings.signer_loss).toBe(2);
      expect(readings.backup_age).toBe(1_000);
    });

    it("queue_caps tracks pinned ratio so a consumer-less PINNED build-up is visible", () => {
      // Healthy full pool (cap util 1.0) with zero PINNED is a separate signal path;
      // the failure mode here is a floor-sized pool where every wallet is PINNED and cap util
      // stays low because minting has not grown toward POOL_CAP_TOTAL.
      const readings = deriveSafetyAlertReadings({
        ...emptySafetyAlertMetricInput(),
        receiveQueueUtilization: 0,
        poolCapUtilization: 0.1, // 5/50
        pinnedPoolRatio: 1.0, // 5/5 PINNED
        receiveQueueFull503Rate: 0,
      });
      expect(readings.queue_caps).toBe(1.0);
    });

    it("reports signer_loss 0 while leadership is held even if ambiguous flag is set", () => {
      const readings = deriveSafetyAlertReadings({
        ...emptySafetyAlertMetricInput(),
        signerLeadershipHeld: 1,
        signerInFlightAmbiguous: 1,
      });
      expect(readings.signer_loss).toBe(0);
    });

    it("evaluateInput fires only the signals whose readings cross thresholds", () => {
      const evaluator = createSafetyAlertEvaluator({ backupMaxAgeMs: 86_400_000 });
      const fired = evaluator.evaluateInput(
        {
          ...emptySafetyAlertMetricInput(),
          regressionCount: 1,
          // everything else at safe defaults
        },
        0,
      );
      expect(fired.map((n) => n.signal)).toEqual(["regression"]);
    });
  });

  describe("evaluate", () => {
    it("fires at the worst severity crossed for a signal", () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS });
      const fired = evaluator.evaluate("storage_pressure", 0.96, 0);
      expect(fired).toHaveLength(1);
      expect(fired[0]?.severity).toBe("P0");
      expect(fired[0]?.threshold).toBe(0.95);
    });

    it("fires the lower band when only it is crossed", () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS });
      const fired = evaluator.evaluate("storage_pressure", 0.91, 0);
      expect(fired).toHaveLength(1);
      expect(fired[0]?.severity).toBe("P1");
    });

    it("does not fire below every threshold", () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS });
      expect(evaluator.evaluate("storage_pressure", 0.5, 0)).toEqual([]);
    });

    it("treats an above crossing as inclusive at the threshold", () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS });
      expect(evaluator.evaluate("queue_caps", 0.9, 0)[0]?.severity).toBe("P1");
    });

    it("fires a below threshold when the reading falls to the value", () => {
      const evaluator = createSafetyAlertEvaluator({
        thresholds: [
          { signal: "queue_caps", severity: "P1", value: 0.2, direction: "below" },
        ],
      });
      expect(evaluator.evaluate("queue_caps", 0.2, 0)).toHaveLength(1);
      expect(evaluator.evaluate("queue_caps", 0.5, 1)).toEqual([]);
    });

    it("fails closed on a non-finite reading", () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS });
      const fired = evaluator.evaluate("invariant_breach", Number.NaN, 0);
      expect(fired).toHaveLength(1);
      expect(fired[0]?.severity).toBe("P0");
    });

    it("returns nothing for a signal with no thresholds", () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS });
      expect(evaluator.evaluate("lease_age", 999_999, 0)).toEqual([]);
    });

    it("suppresses repeats within the cooldown window", () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS, cooldownMs: 1000 });
      expect(evaluator.evaluate("invariant_breach", 1, 0)).toHaveLength(1);
      expect(evaluator.evaluate("invariant_breach", 1, 500)).toEqual([]);
      expect(evaluator.evaluate("invariant_breach", 1, 1000)).toHaveLength(1);
    });

    it("evaluates many signals at once without cross-firing", () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS });
      const fired = evaluator.evaluateAll(
        { invariant_breach: 1, queue_caps: 0.95, storage_pressure: 0.5 },
        0,
      );
      const signals = fired.map((notification) => notification.signal).sort();
      expect(signals).toEqual(["invariant_breach", "queue_caps"]);
    });
  });

  describe("dispatch", () => {
    it("routes a P1 alert to log and webhook", async () => {
      const log = new RecordingChannel("log");
      const webhook = new RecordingChannel("webhook");
      const evaluator = createSafetyAlertEvaluator({
        thresholds: THRESHOLDS,
        channels: { log, webhook },
      });
      await evaluator.evaluateAndDispatch("queue_caps", 0.95, 0);
      expect(log.delivered).toHaveLength(1);
      expect(webhook.delivered).toHaveLength(1);
      expect(log.delivered[0]?.signal).toBe("queue_caps");
    });

    it("routes a P0 alert to log and webhook", async () => {
      const log = new RecordingChannel("log");
      const webhook = new RecordingChannel("webhook");
      const evaluator = createSafetyAlertEvaluator({
        thresholds: THRESHOLDS,
        channels: { log, webhook },
      });
      const fired = evaluator.evaluate("invariant_breach", 1, 0);
      await evaluator.dispatch(fired[0]!);
      expect(log.delivered).toHaveLength(1);
      expect(webhook.delivered).toHaveLength(1);
      expect(fired[0]?.severity).toBe("P0");
    });

    it("routes delivery failures to onDeliveryError without throwing", async () => {
      const webhook = new RecordingChannel("webhook");
      webhook.failNext = true;
      const errors: Array<{ channel: AlertChannelKind; error: unknown }> = [];
      const evaluator = createSafetyAlertEvaluator({
        thresholds: THRESHOLDS,
        channels: { webhook },
        onDeliveryError: (channel, error) => errors.push({ channel, error }),
      });
      await expect(
        evaluator.evaluateAndDispatch("invariant_breach", 1, 0),
      ).resolves.toHaveLength(1);
      expect(errors).toHaveLength(1);
      expect(errors[0]?.channel).toBe("webhook");
      expect(webhook.delivered).toHaveLength(0);
    });

    it("skips a channel that is not configured", async () => {
      const evaluator = createSafetyAlertEvaluator({ thresholds: THRESHOLDS, channels: {} });
      await expect(
        evaluator.evaluateAndDispatch("invariant_breach", 1, 0),
      ).resolves.toHaveLength(1);
    });
  });

  describe("secret-free payloads", () => {
    const FORBIDDEN = [
      "preimage",
      "private_key",
      "privateKey",
      "totp",
      "seed_phrase",
      "mnemonic",
      "secret",
      "password",
      "sk_",
      "BEGIN ",
    ];

    it("rule catalogue, thresholds, messages, citations contain no secret vocabulary", () => {
      const blobs: string[] = [];
      for (const rule of SAFETY_ALERT_RULES) {
        blobs.push(rule.signal, rule.citation, rule.posture, rule.severity);
      }
      for (const threshold of DEFAULT_ALERT_THRESHOLDS) {
        blobs.push(threshold.signal, threshold.severity, String(threshold.value));
      }
      const evaluator = createSafetyAlertEvaluator({
        backupMaxAgeMs: SYNTHETIC_TRIGGERS.backup_age,
      });
      for (const signal of SAFETY_ALERT_SIGNALS) {
        const fired = evaluator.evaluate(signal, SYNTHETIC_TRIGGERS[signal], 0);
        for (const n of fired) {
          blobs.push(
            n.signal,
            n.message,
            n.citation,
            n.posture,
            n.severity,
            String(n.value),
            String(n.threshold),
          );
        }
      }
      const joined = blobs.join("\n").toLowerCase();
      for (const term of FORBIDDEN) {
        expect(joined.includes(term.toLowerCase()), `forbidden term leaked: ${term}`).toBe(
          false,
        );
      }
    });

    it("notification messages are closed vocabulary (signal=value crossed ...)", () => {
      const evaluator = createSafetyAlertEvaluator();
      const fired = evaluator.evaluate("regression", 1, 0);
      expect(fired[0]?.message).toBe(
        "regression=1 crossed above 1 (severity P1)",
      );
    });
  });

  describe("configuration surface", () => {
    it("exposes every signal in the rule catalogue and P0/P1/P2 severities", () => {
      const defaultSignals = new Set(DEFAULT_ALERT_THRESHOLDS.map((t) => t.signal));
      // Nine of ten have default bands; backup_age is cadence-injected.
      expect(defaultSignals.has("invariant_breach")).toBe(true);
      expect(defaultSignals.has("duplicate_submit_attempt")).toBe(true);
      expect(defaultSignals.has("lease_age")).toBe(true);
      expect(defaultSignals.has("path_gap")).toBe(true);
      expect(defaultSignals.has("regression")).toBe(true);
      expect(defaultSignals.has("endpoint_disagreement")).toBe(true);
      expect(defaultSignals.has("storage_pressure")).toBe(true);
      expect(defaultSignals.has("queue_caps")).toBe(true);
      expect(defaultSignals.has("signer_loss")).toBe(true);
      expect(defaultSignals.has("backup_age")).toBe(false);
      expect(ALERT_SEVERITIES).toEqual(["P2", "P1", "P0"]);
      expect(SEVERITY_RANK.P0).toBeGreaterThan(SEVERITY_RANK.P1);
      expect(SEVERITY_RANK.P1).toBeGreaterThan(SEVERITY_RANK.P2);
    });

    it("defaults the cooldown to zero", () => {
      expect(DEFAULT_ALERT_COOLDOWN_MS).toBe(0);
    });

    it("rejects a negative cooldown", () => {
      expect(() => createSafetyAlertEvaluator({ cooldownMs: -1 })).toThrow(
        SafetyAlertConfigurationError,
      );
    });

    it("snapshots the active configuration including rule catalogue", () => {
      const log = new RecordingChannel("log");
      const evaluator = createSafetyAlertEvaluator({
        thresholds: THRESHOLDS,
        channels: { log },
        backupMaxAgeMs: 86_400_000,
      });
      const snapshot = evaluator.snapshot();
      expect(snapshot.thresholds.some((t) => t.signal === "backup_age")).toBe(true);
      expect(snapshot.escalation).toEqual(DEFAULT_ESCALATION_PATH);
      expect(snapshot.channels).toEqual(["log"]);
      expect(snapshot.rules).toHaveLength(10);
      expect(snapshot.backupAgeThresholdSource).toBe("operator-backup-cadence");
      expect(snapshot.leaseAgeAutomaticRelease).toBe(false);
    });
  });
});
