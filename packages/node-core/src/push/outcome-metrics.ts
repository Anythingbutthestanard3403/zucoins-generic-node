// Push receive outcome metrics + consecutive no_transfer_code streak alert.
//
// ZTR-1154: the inbound push channel can stop delivering transfer codes (wallet
// envelope reshape) while every external signal stays green — the route answers
// 204 on every path by design (discard semantics), and a single no_transfer_code
// is normal (notifications we do not act on). A *run* of no_transfer_code with no
// intervening enqueued delivery is the shape-break signal.
//
// The receiver takes only an injected port (PushReceiveMetrics) so packages/node-core
// push stays free of composition-root wiring and does not import core/metrics.
// The app binds the port to gn_push_receive_* series via MetricsHooks.

/** Outcomes that participate in the push-receive counter (closed vocabulary). */
export const PUSH_RECEIVE_METRIC_OUTCOMES = [
  "enqueued",
  "no_transfer_code",
  "decrypt_failed",
] as const;

export type PushReceiveMetricOutcome = (typeof PUSH_RECEIVE_METRIC_OUTCOMES)[number];

/** Envelope shapes recorded on the enqueued path (matches ResolvedPushDelivery.shape). */
export const PUSH_RECEIVE_METRIC_SHAPES = ["aps", "data", "send_side_fallback", "none"] as const;

export type PushReceiveMetricShape = (typeof PUSH_RECEIVE_METRIC_SHAPES)[number];

/**
 * Injected metrics port for createPushReceiver.
 * Composition root binds this to Prometheus counters/gauges; tests use a recorder.
 */
export interface PushReceiveMetrics {
  /**
   * One observation of a money-path-relevant receive outcome.
   * `shape` is set on enqueued (and optionally refused) paths; use `"none"` otherwise.
   */
  onOutcome(outcome: PushReceiveMetricOutcome, shape: PushReceiveMetricShape): void;
}

/**
 * Default consecutive no_transfer_code threshold before the shape-break alert fires.
 *
 * Rationale (ZTR-1154): a single no_transfer_code is an expected discard (wallet noise,
 * non-transfer notification). On a funded node the push channel is the primary external
 * receive detection path; successful enqueues should dominate. Twenty consecutive
 * no_transfer_code results with no intervening enqueued delivery is far above ambient
 * noise for a live subscription and short enough that a wallet-side envelope reshape is
 * paged within one burst of deliveries rather than discovered by a later volume review.
 * Prefer a consecutive count over a rate: it needs no clock, survives scrape gaps, and
 * matches the failure mode (a sustained shape miss, not a transient blip).
 */
export const DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD = 20 as const;

export interface PushNoTransferCodeStreakAlert {
  readonly kind: "push_no_transfer_code_streak";
  readonly streak: number;
  readonly threshold: number;
  /** Closed-vocabulary message — never includes transfer codes or raw envelope bytes. */
  readonly message: string;
}

export interface PushNoTransferCodeStreakTrackerOptions {
  /** Fire when consecutive no_transfer_code count reaches this value (default 20). */
  readonly threshold?: number;
  /** Invoked once when the streak first crosses the threshold; again only after a reset+rebreach. */
  readonly onAlert?: (alert: PushNoTransferCodeStreakAlert) => void;
}

export interface PushNoTransferCodeStreakTracker {
  /** Current consecutive no_transfer_code count since the last enqueued. */
  readonly streak: () => number;
  /** Observe an outcome; updates streak and may fire onAlert. */
  readonly observe: (outcome: PushReceiveMetricOutcome) => void;
  readonly threshold: () => number;
}

/**
 * Consecutive-count streak over push receive outcomes.
 * - `no_transfer_code` increments the streak.
 * - `enqueued` resets the streak to 0 (healthy money path).
 * - `decrypt_failed` leaves the streak unchanged (not a shape miss, not a healthy enqueue).
 */
export function createPushNoTransferCodeStreakTracker(
  options: PushNoTransferCodeStreakTrackerOptions = {},
): PushNoTransferCodeStreakTracker {
  const threshold = options.threshold ?? DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD;
  if (!Number.isFinite(threshold) || threshold < 1) {
    throw new Error("push no_transfer_code streak threshold must be a finite integer >= 1");
  }
  const thresholdInt = Math.floor(threshold);
  let streak = 0;
  let alertedForCurrentRun = false;

  return {
    streak: () => streak,
    threshold: () => thresholdInt,
    observe(outcome) {
      if (outcome === "enqueued") {
        streak = 0;
        alertedForCurrentRun = false;
        return;
      }
      if (outcome !== "no_transfer_code") {
        return;
      }
      streak += 1;
      if (streak >= thresholdInt && !alertedForCurrentRun) {
        alertedForCurrentRun = true;
        options.onAlert?.({
          kind: "push_no_transfer_code_streak",
          streak,
          threshold: thresholdInt,
          message:
            `push receive: ${streak} consecutive no_transfer_code with no intervening enqueued ` +
            `(threshold ${thresholdInt}) — likely delivered-envelope shape break`,
        });
      }
    },
  };
}

/**
 * Bind a streak tracker + optional outer metrics sink into one PushReceiveMetrics port.
 * Streak observation runs even when the outer sink is absent.
 */
export function createPushReceiveMetricsPort(input: {
  readonly sink?: PushReceiveMetrics;
  readonly streak?: PushNoTransferCodeStreakTracker;
}): PushReceiveMetrics {
  return {
    onOutcome(outcome, shape) {
      // Observe streak first so any sink that publishes the streak gauge
      // (compose sets gn_push_no_transfer_code_streak from tracker.streak())
      // sees the post-observation value — never the pre-increment reading.
      input.streak?.observe(outcome);
      input.sink?.onOutcome(outcome, shape);
    },
  };
}
