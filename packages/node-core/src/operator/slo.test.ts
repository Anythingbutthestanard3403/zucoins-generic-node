import { describe, expect, it } from "vitest";

import {
  DEFAULT_SLO_DEFINITIONS,
  DEFAULT_SLO_WINDOW_MS,
  SloConfigurationError,
  createSloTracker,
  validateSloDefinition,
  type SloBreach,
  type SloDefinition,
} from "./index.js";

const WINDOW = 10_000;

const AVAILABILITY: SloDefinition = {
  id: "availability",
  metric: "availability",
  objective: 0.9,
  windowMs: WINDOW,
};

const LATENCY: SloDefinition = {
  id: "latency",
  metric: "latency",
  objective: 0.5,
  windowMs: WINDOW,
  latencyCeilingMs: 200,
};

describe("SLO tracker", () => {
  describe("validateSloDefinition", () => {
    it("accepts a well-formed definition", () => {
      expect(validateSloDefinition(AVAILABILITY)).toBe(AVAILABILITY);
      expect(validateSloDefinition(LATENCY)).toBe(LATENCY);
    });

    it("rejects an empty id", () => {
      expect(() =>
        validateSloDefinition({ ...AVAILABILITY, id: "" }),
      ).toThrow(SloConfigurationError);
    });

    it("rejects an unknown metric", () => {
      expect(() =>
        validateSloDefinition({ ...AVAILABILITY, metric: "throughput" as SloDefinition["metric"] }),
      ).toThrow(SloConfigurationError);
    });

    it("rejects an objective outside [0, 1]", () => {
      expect(() => validateSloDefinition({ ...AVAILABILITY, objective: 1.5 })).toThrow(
        SloConfigurationError,
      );
      expect(() => validateSloDefinition({ ...AVAILABILITY, objective: -0.1 })).toThrow(
        SloConfigurationError,
      );
    });

    it("rejects a non-positive window", () => {
      expect(() => validateSloDefinition({ ...AVAILABILITY, windowMs: 0 })).toThrow(
        SloConfigurationError,
      );
    });

    it("requires a ceiling for a latency SLO", () => {
      expect(() =>
        validateSloDefinition({ id: "lat", metric: "latency", objective: 0.9, windowMs: WINDOW }),
      ).toThrow(SloConfigurationError);
    });

    it("rejects a non-finite ceiling when present", () => {
      expect(() =>
        validateSloDefinition({ ...AVAILABILITY, latencyCeilingMs: Number.NaN }),
      ).toThrow(SloConfigurationError);
    });
  });

  describe("construction", () => {
    it("rejects duplicate SLO ids", () => {
      expect(() => createSloTracker({ definitions: [AVAILABILITY, AVAILABILITY] })).toThrow(
        SloConfigurationError,
      );
    });

    it("defaults to the standard SLO set", () => {
      const tracker = createSloTracker();
      const ids = tracker.definitions().map((definition) => definition.id);
      expect(ids).toEqual(["availability", "latency", "error_budget"]);
      expect(DEFAULT_SLO_DEFINITIONS).toHaveLength(3);
      expect(DEFAULT_SLO_WINDOW_MS).toBe(30 * 24 * 60 * 60 * 1000);
    });
  });

  describe("availability", () => {
    it("reports full compliance with no observations", () => {
      const tracker = createSloTracker({ definitions: [AVAILABILITY] });
      const compliance = tracker.evaluate("availability", 0);
      expect(compliance.totalEvents).toBe(0);
      expect(compliance.goodRatio).toBe(1);
      expect(compliance.compliant).toBe(true);
      expect(compliance.budgetExhausted).toBe(false);
    });

    it("tracks the good ratio across successes and failures", () => {
      const tracker = createSloTracker({ definitions: [AVAILABILITY] });
      for (let i = 0; i < 9; i += 1) {
        tracker.recordSuccess("availability", i);
      }
      tracker.recordFailure("availability", 9);
      const compliance = tracker.evaluate("availability", 9);
      expect(compliance.totalEvents).toBe(10);
      expect(compliance.goodEvents).toBe(9);
      expect(compliance.badEvents).toBe(1);
      expect(compliance.goodRatio).toBeCloseTo(0.9, 10);
      expect(compliance.compliant).toBe(true);
    });

    it("flags non-compliance when the ratio drops below the objective", () => {
      const tracker = createSloTracker({ definitions: [AVAILABILITY] });
      for (let i = 0; i < 8; i += 1) {
        tracker.recordSuccess("availability", i);
      }
      for (let i = 8; i < 10; i += 1) {
        tracker.recordFailure("availability", i);
      }
      const compliance = tracker.evaluate("availability", 9);
      expect(compliance.goodRatio).toBeCloseTo(0.8, 10);
      expect(compliance.compliant).toBe(false);
    });
  });

  describe("latency", () => {
    it("classifies an observation good iff at or below the ceiling", () => {
      const tracker = createSloTracker({ definitions: [LATENCY] });
      tracker.recordLatency("latency", 200, 0);
      tracker.recordLatency("latency", 150, 1);
      tracker.recordLatency("latency", 300, 2);
      tracker.recordLatency("latency", 500, 3);
      const compliance = tracker.evaluate("latency", 3);
      expect(compliance.totalEvents).toBe(4);
      expect(compliance.goodEvents).toBe(2);
      expect(compliance.goodRatio).toBeCloseTo(0.5, 10);
      expect(compliance.compliant).toBe(true);
    });

    it("rejects success/failure recording against a latency SLO", () => {
      const tracker = createSloTracker({ definitions: [LATENCY] });
      expect(() => tracker.recordSuccess("latency", 0)).toThrow(SloConfigurationError);
      expect(() => tracker.recordFailure("latency", 0)).toThrow(SloConfigurationError);
    });

    it("rejects a latency recording against a non-latency SLO", () => {
      const tracker = createSloTracker({ definitions: [AVAILABILITY] });
      expect(() => tracker.recordLatency("availability", 100, 0)).toThrow(SloConfigurationError);
    });

    it("rejects a non-finite latency observation", () => {
      const tracker = createSloTracker({ definitions: [LATENCY] });
      expect(() => tracker.recordLatency("latency", Number.NaN, 0)).toThrow(
        SloConfigurationError,
      );
    });
  });

  describe("error budget", () => {
    it("computes the remaining budget from the objective and traffic", () => {
      const tracker = createSloTracker({
        definitions: [{ id: "budget", metric: "error_budget", objective: 0.9, windowMs: WINDOW }],
      });
      for (let i = 0; i < 9; i += 1) {
        tracker.recordSuccess("budget", i);
      }
      tracker.recordFailure("budget", 9);
      const compliance = tracker.evaluate("budget", 9);
      // 10 events, objective 0.9 -> 1 bad event allowed, 1 seen -> 0 remaining.
      expect(compliance.errorBudgetAllowed).toBeCloseTo(1, 10);
      expect(compliance.errorBudgetRemaining).toBeCloseTo(0, 10);
      expect(compliance.budgetExhausted).toBe(true);
    });

    it("leaves budget headroom while failures stay under the allowance", () => {
      const tracker = createSloTracker({
        definitions: [{ id: "budget", metric: "error_budget", objective: 0.8, windowMs: WINDOW }],
      });
      for (let i = 0; i < 9; i += 1) {
        tracker.recordSuccess("budget", i);
      }
      tracker.recordFailure("budget", 9);
      const compliance = tracker.evaluate("budget", 9);
      // 10 events, objective 0.8 -> 2 allowed, 1 seen -> 1 remaining.
      expect(compliance.errorBudgetRemaining).toBeCloseTo(1, 10);
      expect(compliance.budgetExhausted).toBe(false);
    });
  });

  describe("rolling window", () => {
    it("evicts observations older than the window", () => {
      const tracker = createSloTracker({ definitions: [AVAILABILITY] });
      tracker.recordFailure("availability", 0);
      tracker.recordFailure("availability", 1);
      for (let i = 2; i < 12; i += 1) {
        tracker.recordSuccess("availability", i);
      }
      // Evaluate far enough ahead that the two early failures fall out of the window.
      const compliance = tracker.evaluate("availability", WINDOW + 5);
      expect(compliance.badEvents).toBe(0);
      expect(compliance.totalEvents).toBe(7);
      expect(compliance.compliant).toBe(true);
    });
  });

  describe("breach notification", () => {
    it("fires once on the transition into breach, not while sustained", () => {
      const breaches: SloBreach[] = [];
      const tracker = createSloTracker({
        definitions: [AVAILABILITY],
        onBreach: (breach) => breaches.push(breach),
      });
      tracker.recordSuccess("availability", 0);
      tracker.recordFailure("availability", 1);
      tracker.recordFailure("availability", 2);
      // 1 good / 2 total = 0.5 < 0.9 -> breach fires on the first failure.
      expect(breaches).toHaveLength(1);
      expect(breaches[0]?.sloId).toBe("availability");
      expect(breaches[0]?.goodRatio).toBeCloseTo(0.5, 10);
      // A further failure keeps the SLO breached but must not re-fire.
      tracker.recordFailure("availability", 3);
      expect(breaches).toHaveLength(1);
    });

    it("fires again only after compliance recovers and is lost again", () => {
      const breaches: SloBreach[] = [];
      const tracker = createSloTracker({
        definitions: [AVAILABILITY],
        onBreach: (breach) => breaches.push(breach),
      });
      tracker.recordFailure("availability", 0);
      expect(breaches).toHaveLength(1);
      // Recover by flooding the window with successes.
      for (let i = 1; i < 30; i += 1) {
        tracker.recordSuccess("availability", i);
      }
      const recovered = tracker.evaluate("availability", 29);
      expect(recovered.compliant).toBe(true);
      // Drive it back into breach.
      for (let i = 30; i < 60; i += 1) {
        tracker.recordFailure("availability", i);
      }
      expect(breaches).toHaveLength(2);
    });
  });

  describe("evaluateAll", () => {
    it("evaluates every configured SLO", () => {
      const tracker = createSloTracker({ definitions: [AVAILABILITY, LATENCY] });
      tracker.recordSuccess("availability", 0);
      tracker.recordLatency("latency", 100, 0);
      const all = tracker.evaluateAll(0);
      expect(all.map((compliance) => compliance.sloId).sort()).toEqual(["availability", "latency"]);
    });

    it("throws for an unknown SLO id", () => {
      const tracker = createSloTracker({ definitions: [AVAILABILITY] });
      expect(() => tracker.evaluate("missing", 0)).toThrow(SloConfigurationError);
    });
  });
});
