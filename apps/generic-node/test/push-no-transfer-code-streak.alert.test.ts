// ZTR-1154 Review B — threshold fires pageable safety-alert sink + log, and the
// published gauge matches the streak at the fire event (observe-then-set order).

import { describe, expect, it, vi } from "vitest";

import {
  createPushNoTransferCodeStreakTracker,
  createPushReceiveMetricsPort,
  createSafetyAlertEvaluator,
  DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD,
  type AlertNotification,
  type PushNoTransferCodeStreakAlert,
} from "@zucoins/node-core";

/**
 * Mirrors apps/generic-node/src/push/compose.ts streak + metrics binding without
 * bringing up pg / push API. Keeps the same observe-then-set + evaluator dispatch.
 */
function bindStreakAlert(input: {
  readonly logError: (message: string, err?: unknown) => void;
  readonly setGauge: (streak: number) => void;
  readonly evaluator: ReturnType<typeof createSafetyAlertEvaluator>;
  readonly threshold: number;
}) {
  const noCodeStreak = createPushNoTransferCodeStreakTracker({
    threshold: input.threshold,
    onAlert: (alert: PushNoTransferCodeStreakAlert) => {
      input.logError(
        `push: ALERT ${alert.kind} streak=${alert.streak} threshold=${alert.threshold} — ${alert.message}`,
      );
      void input.evaluator.evaluateAndDispatch("push_no_transfer_code_streak", alert.streak);
    },
  });
  const port = createPushReceiveMetricsPort({
    streak: noCodeStreak,
    sink: {
      onOutcome() {
        input.setGauge(noCodeStreak.streak());
      },
    },
  });
  return { port, streak: noCodeStreak };
}

describe("push no_transfer_code streak alert wiring (ZTR-1154 r2)", () => {
  it("at threshold: logs ALERT, dispatches SAFETY_ALERT push_no_transfer_code_streak, gauge == streak", async () => {
    const threshold = 3;
    const logs: string[] = [];
    const gauges: number[] = [];
    const delivered: AlertNotification[] = [];

    const evaluator = createSafetyAlertEvaluator({
      // Match the tracker threshold so evaluateAndDispatch fires at the same edge.
      thresholds: [
        {
          signal: "push_no_transfer_code_streak",
          severity: "P1",
          value: threshold,
          direction: "above",
        },
      ],
      channels: {
        log: {
          kind: "log",
          deliver: async (n) => {
            delivered.push(n);
          },
        },
      },
    });

    const { port, streak } = bindStreakAlert({
      threshold,
      logError: (m) => logs.push(m),
      setGauge: (s) => gauges.push(s),
      evaluator,
    });

    for (let i = 0; i < threshold; i += 1) {
      port.onOutcome("no_transfer_code", "none");
    }

    await vi.waitFor(() => {
      expect(delivered.length).toBeGreaterThanOrEqual(1);
    });

    expect(streak.streak()).toBe(threshold);
    expect(gauges).toEqual([1, 2, 3]);
    expect(gauges[gauges.length - 1]).toBe(threshold);
    expect(logs.some((l) => l.includes("push: ALERT push_no_transfer_code_streak"))).toBe(true);
    expect(
      delivered.some((n) => n.signal === "push_no_transfer_code_streak" && n.severity === "P1"),
    ).toBe(true);
    const fire = delivered.find((n) => n.signal === "push_no_transfer_code_streak");
    expect(fire?.value).toBe(threshold);
  });

  it("default threshold band is 20 (matches DEFAULT_ALERT_THRESHOLDS / Prom rule)", () => {
    expect(DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD).toBe(20);
  });
});
