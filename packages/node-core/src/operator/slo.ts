// Service-level objectives: rolling-window good/bad tracking for availability, latency, and
// error budget (degraded-operation posture). Every SLO reduces to
// the same model — a stream of events inside a rolling window, each classified good or bad —
// so a single tracker serves all three metrics:
// - availability: each event is a success (good) or failure (bad); objective is the minimum
// good ratio.
// - latency: each event carries an observed latency; it is good iff at or below the SLO's
// ceiling, and the objective is the minimum good ratio.
// - error_budget: the same good/bad stream as availability, but compliance is expressed as
// the remaining budget — the count of bad events the window still tolerates,
// (1 - objective) * total events, minus the bad events already seen.
//
// The tracker is advisory and never advances money state. Breach detection is edge-triggered:
// the onBreach sink fires once on the transition into breach and again only after compliance
// recovers and is lost again, so a sustained breach does not spam the sink. The application
// shell wires onBreach into the safety-alert evaluator (safety-alerts.ts) to page on breach.

export type SloMetric = "availability" | "latency" | "error_budget";

export const SLO_METRICS: readonly SloMetric[] = ["availability", "latency", "error_budget"];

export const DEFAULT_SLO_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export interface SloDefinition {
  readonly id: string;
  readonly metric: SloMetric;
  // Target good ratio in [0, 1]. For error_budget this is the availability target the budget
  // derives from (budget fraction = 1 - objective).
  readonly objective: number;
  readonly windowMs: number;
  // Required for a latency SLO: an observation is good iff its latency is at or below this.
  readonly latencyCeilingMs?: number;
}

export const DEFAULT_SLO_DEFINITIONS: readonly SloDefinition[] = [
  { id: "availability", metric: "availability", objective: 0.999, windowMs: DEFAULT_SLO_WINDOW_MS },
  {
    id: "latency",
    metric: "latency",
    objective: 0.99,
    windowMs: DEFAULT_SLO_WINDOW_MS,
    latencyCeilingMs: 250,
  },
  { id: "error_budget", metric: "error_budget", objective: 0.999, windowMs: DEFAULT_SLO_WINDOW_MS },
];

export class SloConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SloConfigurationError";
  }
}

const SLO_METRIC_SET: ReadonlySet<string> = new Set(SLO_METRICS);

export function validateSloDefinition(definition: SloDefinition): SloDefinition {
  if (definition.id.length === 0) {
    throw new SloConfigurationError("SLO id must be non-empty");
  }
  if (!SLO_METRIC_SET.has(definition.metric)) {
    throw new SloConfigurationError(`unknown SLO metric: ${definition.metric}`);
  }
  if (!Number.isFinite(definition.objective) || definition.objective < 0 || definition.objective > 1) {
    throw new SloConfigurationError(`SLO ${definition.id} objective must lie in [0, 1]`);
  }
  if (!Number.isFinite(definition.windowMs) || definition.windowMs <= 0) {
    throw new SloConfigurationError(`SLO ${definition.id} window must be a finite, positive number`);
  }
  if (definition.metric === "latency") {
    if (
      definition.latencyCeilingMs === undefined ||
      !Number.isFinite(definition.latencyCeilingMs) ||
      definition.latencyCeilingMs <= 0
    ) {
      throw new SloConfigurationError(
        `latency SLO ${definition.id} requires a finite, positive latencyCeilingMs`,
      );
    }
  } else if (
    definition.latencyCeilingMs !== undefined &&
    (!Number.isFinite(definition.latencyCeilingMs) || definition.latencyCeilingMs <= 0)
  ) {
    throw new SloConfigurationError(
      `SLO ${definition.id} latencyCeilingMs must be a finite, positive number when present`,
    );
  }
  return definition;
}

interface SloEvent {
  readonly atMs: number;
  readonly good: boolean;
}

export interface SloCompliance {
  readonly sloId: string;
  readonly metric: SloMetric;
  readonly objective: number;
  readonly windowMs: number;
  readonly totalEvents: number;
  readonly goodEvents: number;
  readonly badEvents: number;
  // good / total; 1 when the window holds no events (nothing has been observed to breach).
  readonly goodRatio: number;
  readonly compliant: boolean;
  // Bad events the window tolerates: (1 - objective) * totalEvents.
  readonly errorBudgetAllowed: number;
  readonly errorBudgetRemaining: number;
  // True once the tolerated bad count is used up (and at least one event has been observed).
  readonly budgetExhausted: boolean;
  readonly windowStartMs: number;
  readonly evaluatedAtMs: number;
}

export interface SloBreach {
  readonly sloId: string;
  readonly metric: SloMetric;
  readonly objective: number;
  readonly goodRatio: number;
  readonly errorBudgetRemaining: number;
  readonly breachedAtMs: number;
  readonly message: string;
}

export interface SloTrackerOptions {
  readonly definitions?: readonly SloDefinition[];
  readonly clock?: () => number;
  readonly onBreach?: (breach: SloBreach) => void;
}

export interface SloTracker {
  recordSuccess(sloId: string, nowMs?: number): void;
  recordFailure(sloId: string, nowMs?: number): void;
  recordLatency(sloId: string, latencyMs: number, nowMs?: number): void;
  evaluate(sloId: string, nowMs?: number): SloCompliance;
  evaluateAll(nowMs?: number): SloCompliance[];
  definitions(): readonly SloDefinition[];
}

export function createSloTracker(options: SloTrackerOptions = {}): SloTracker {
  const definitions = (options.definitions ?? DEFAULT_SLO_DEFINITIONS).map(validateSloDefinition);
  const clock = options.clock ?? (() => Date.now());
  const onBreach = options.onBreach;

  const definitionById = new Map<string, SloDefinition>();
  for (const definition of definitions) {
    if (definitionById.has(definition.id)) {
      throw new SloConfigurationError(`duplicate SLO id: ${definition.id}`);
    }
    definitionById.set(definition.id, definition);
  }

  const eventsById = new Map<string, SloEvent[]>();
  const inBreachById = new Map<string, boolean>();

  const definitionFor = (sloId: string): SloDefinition => {
    const definition = definitionById.get(sloId);
    if (definition === undefined) {
      throw new SloConfigurationError(`unknown SLO id: ${sloId}`);
    }
    return definition;
  };

  const prune = (events: SloEvent[], windowStartMs: number): SloEvent[] => {
    let first = 0;
    while (first < events.length && (events[first]?.atMs ?? 0) < windowStartMs) {
      first += 1;
    }
    if (first === 0) {
      return events;
    }
    events.splice(0, first);
    return events;
  };

  const record = (sloId: string, good: boolean, nowMs: number): void => {
    const definition = definitionFor(sloId);
    let events = eventsById.get(sloId);
    if (events === undefined) {
      events = [];
      eventsById.set(sloId, events);
    }
    events.push({ atMs: nowMs, good });
    prune(events, nowMs - definition.windowMs);
    notifyIfBreached(definition, events, nowMs);
  };

  const notifyIfBreached = (
    definition: SloDefinition,
    events: readonly SloEvent[],
    nowMs: number,
  ): void => {
    if (onBreach === undefined) {
      return;
    }
    const compliance = computeCompliance(definition, events, nowMs);
    const breached = compliance.totalEvents > 0 && !compliance.compliant;
    const wasBreached = inBreachById.get(definition.id) ?? false;
    if (breached && !wasBreached) {
      inBreachById.set(definition.id, true);
      onBreach({
        sloId: definition.id,
        metric: definition.metric,
        objective: definition.objective,
        goodRatio: compliance.goodRatio,
        errorBudgetRemaining: compliance.errorBudgetRemaining,
        breachedAtMs: nowMs,
        message: `SLO ${definition.id} breached: good ratio ${compliance.goodRatio} below objective ${definition.objective}`,
      });
    } else if (!breached && wasBreached) {
      inBreachById.set(definition.id, false);
    }
  };

  const computeCompliance = (
    definition: SloDefinition,
    events: readonly SloEvent[],
    nowMs: number,
  ): SloCompliance => {
    const totalEvents = events.length;
    let goodEvents = 0;
    for (const event of events) {
      if (event.good) {
        goodEvents += 1;
      }
    }
    const badEvents = totalEvents - goodEvents;
    const goodRatio = totalEvents === 0 ? 1 : goodEvents / totalEvents;
    const compliant = goodRatio >= definition.objective;
    const errorBudgetAllowed = (1 - definition.objective) * totalEvents;
    const errorBudgetRemaining = errorBudgetAllowed - badEvents;
    const budgetExhausted = totalEvents > 0 && errorBudgetRemaining <= 0;
    return {
      sloId: definition.id,
      metric: definition.metric,
      objective: definition.objective,
      windowMs: definition.windowMs,
      totalEvents,
      goodEvents,
      badEvents,
      goodRatio,
      compliant,
      errorBudgetAllowed,
      errorBudgetRemaining,
      budgetExhausted,
      windowStartMs: nowMs - definition.windowMs,
      evaluatedAtMs: nowMs,
    };
  };

  const evaluate = (sloId: string, nowMs: number = clock()): SloCompliance => {
    const definition = definitionFor(sloId);
    const events = prune(eventsById.get(sloId) ?? [], nowMs - definition.windowMs);
    return computeCompliance(definition, events, nowMs);
  };

  return {
    recordSuccess: (sloId, nowMs = clock()) => {
      const definition = definitionFor(sloId);
      if (definition.metric === "latency") {
        throw new SloConfigurationError(
          `latency SLO ${sloId} records observations via recordLatency`,
        );
      }
      record(sloId, true, nowMs);
    },
    recordFailure: (sloId, nowMs = clock()) => {
      const definition = definitionFor(sloId);
      if (definition.metric === "latency") {
        throw new SloConfigurationError(
          `latency SLO ${sloId} records observations via recordLatency`,
        );
      }
      record(sloId, false, nowMs);
    },
    recordLatency: (sloId, latencyMs, nowMs = clock()) => {
      const definition = definitionFor(sloId);
      if (definition.metric !== "latency") {
        throw new SloConfigurationError(
          `recordLatency requires a latency SLO; ${sloId} is ${definition.metric}`,
        );
      }
      if (!Number.isFinite(latencyMs) || latencyMs < 0) {
        throw new SloConfigurationError("latency observation must be a finite, non-negative number");
      }
      record(sloId, latencyMs <= (definition.latencyCeilingMs ?? 0), nowMs);
    },
    evaluate,
    evaluateAll: (nowMs = clock()) =>
      definitions.map((definition) => evaluate(definition.id, nowMs)),
    definitions: () => definitions,
  };
}
