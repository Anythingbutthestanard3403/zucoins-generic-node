// The production /metrics snapshot source.
//
// Fixes the completion defect left by the earlier metrics slices: main.ts previously
// hard-coded `readinessReady: 0` and spread `emptyOperationalSnapshot()` for
// every DB-truth gauge (wallets, leases, queue, operations), so the endpoint
// could never report readiness=1 and never reflected real low-storage/worker/
// auth events. `collectOperationalMetricsSnapshot` (core/metrics-snapshot.ts)
// already implements the DB-truth side correctly; this module is the missing
// composition that wires it — plus the true readiness verdict (schema ∧ db ∧
// vault ∧ observation, via the SAME evaluator/probe the health route uses) —
// into one MetricsSnapshotSource.
//
// Fail-safe: a DB outage must never turn a scrape into a 500 or a hang
// (createMetricsRoute's handler has no .catch — an unhandled rejection there
// leaves the response unwritten). When the DB probe reports unreachable, or
// the DB-truth query itself throws mid-scrape, this falls back to a
// stamps-only snapshot (every DB-truth gauge at 0) rather than propagating.
//
// REVIEW B item 3: before this, /metrics never touched the DB, so it could never
// hang. Wiring real pool.query calls opened a second hang surface: a stalled
// (non-erroring, non-rejecting) query would leave the scrape awaiting forever —
// same class of gap `/health/ready` already bounds via CachedDbProbe's TTL, but
// unaddressed here. queryTimeoutMs bounds the wait client-side (same
// Promise.race-against-a-timer idiom as reporting/snapshot-service.ts's
// SnapshotCaptureTimeoutError): a query that neither resolves nor
// rejects within budget is treated exactly like a throwing query — fall back to
// stamps-only, databaseTruthAvailable=false, respond within budget rather than
// hang. Production main.ts additionally bounds the query server-side via a
// dedicated statement_timeout-configured pool (db/client.ts) so the abandoned
// query is actually cancelled, not merely stopped-waiting-for.
//
// Honors the frozen shutdown sequence.

import {
  CachedDbProbe,
  collectOperationalMetricsSnapshot,
  emptyOperationalSnapshot,
  evaluateReadinessFromProbes,
  type MetricsProcessStamps,
  type MetricsSnapshotSource,
  type MetricsSqlExecutor,
  type MetricWorkerName,
  type OperationalMetricsSnapshot,
  type ReadinessStateInputs,
} from "@zucoins/node-core";

/** Default scrape query budget — Prometheus's own default scrape_timeout is 10s. */
export const DEFAULT_METRICS_QUERY_TIMEOUT_MS = 5_000;

export class MetricsQueryTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`/metrics DB-truth query exceeded ${timeoutMs}ms budget`);
    this.name = "MetricsQueryTimeoutError";
  }
}

/**
 * Race a promise against a budget. Never leaves a dangling unhandled rejection: if the
 * race is lost, a no-op catch is attached to the original so a late rejection is silent.
 */
function withQueryTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  promise.catch(() => {});
  let timer: ReturnType<typeof setTimeout> | undefined;
  const budget = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new MetricsQueryTimeoutError(timeoutMs)), timeoutMs);
  });
  return Promise.race([promise, budget]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

export interface ProductionMetricsSnapshotDeps {
  readonly getState: () => ReadinessStateInputs;
  /** Shared with the health route (same CachedDbProbe instance) so both surfaces agree. */
  readonly dbProbe: CachedDbProbe;
  readonly db: MetricsSqlExecutor;
  /** Production PostgreSQL transaction with server-side cancellation and release-on-settle. */
  readonly withinDbDeadline?: <T>(
    remainingBudgetMs: number,
    work: (db: MetricsSqlExecutor) => Promise<T>,
  ) => Promise<T>;
  readonly poolCapTotal: number;
  /** Live worker health by closed name. Names omitted here render 0 ("unwired"). */
  readonly workerHealth?: () => Readonly<Partial<Record<MetricWorkerName, 0 | 1>>>;
  /** Closed worker names whose state is actually observed; absence means unknown. */
  readonly workerHealthAvailable?: () => Readonly<Partial<Record<MetricWorkerName, 0 | 1>>>;
  /** Live backup scheduler state. Absence means unavailable, never a fabricated healthy zero. */
  readonly backupStatus?: () => {
    readonly enabled: boolean;
    readonly running: boolean;
    readonly lastSuccessAtMs: number | null;
    readonly rpoBreached: boolean;
    readonly ownership?: "owner" | "standby" | "disabled";
  } | null;
  readonly nowMs?: () => number;
  /** Monotonic clock for elapsed scrape budgets; never use wall time for deadlines. */
  readonly monotonicNowMs?: () => number;
  /** Budget for the DB-truth query batch. Default {@link DEFAULT_METRICS_QUERY_TIMEOUT_MS}. */
  readonly queryTimeoutMs?: number;
  /**
   * Fired with the snapshot actually served (DB-truth or stamps-only fallback), plus
   * whether the DB-truth gauges (oldestLeaseAgeSecs, queueDepth, etc.) are real readings
   * (true) or fallback zeros standing in for "unknown" (false — DB probe failed, or the
   * DB-truth query threw mid-scrape). Consumers MUST NOT treat a fallback zero as a
   * truthful "no lease/no queue" reading — see custody-alerts.ts.
   */
  readonly onSnapshot?: (
    snapshot: OperationalMetricsSnapshot,
    databaseTruthAvailable: boolean,
  ) => void;
  /** 1 when in-flight signing is tracked while leadership is absent (ZTR-1144). */
  readonly signerInFlightAmbiguous?: () => boolean;
}

function stampsFrom(
  state: ReadinessStateInputs,
  readinessReady: boolean,
  poolCapTotal: number,
  workerHealth: Readonly<Partial<Record<MetricWorkerName, 0 | 1>>>,
  signerInFlightAmbiguous = false,
): MetricsProcessStamps {
  return {
    storagePressure: state.storagePressure,
    signerLeadershipHeld: state.leadershipLockHeld,
    haltEngaged: state.halted,
    readinessReady,
    observationDegraded: state.observationDegraded,
    workerHealth,
    poolCapTotal,
    signerInFlightAmbiguous,
  };
}

/** Stamps-only snapshot: every DB-truth gauge at 0, process stamps live. Used on DB failure. */
function stampsOnlySnapshot(stamps: MetricsProcessStamps): OperationalMetricsSnapshot {
  return {
    ...emptyOperationalSnapshot(),
    storagePressure: stamps.storagePressure ? 1 : 0,
    signerLeadershipHeld: stamps.signerLeadershipHeld ? 1 : 0,
    haltEngaged: stamps.haltEngaged ? 1 : 0,
    readinessReady: stamps.readinessReady ? 1 : 0,
    observationDegraded: stamps.observationDegraded ? 1 : 0,
    workerHealth: stamps.workerHealth ?? {},
  };
}

/**
 * Build the production MetricsSnapshotSource: real readiness verdict (via the
 * same evaluateReadinessFromProbes + CachedDbProbe the health route uses) and
 * real DB-truth counters, with a fail-safe fallback so a DB outage degrades
 * the gauges to 0 rather than throwing out of the scrape handler.
 */
export function createProductionMetricsSnapshotSource(
  deps: ProductionMetricsSnapshotDeps,
): MetricsSnapshotSource {
  const monotonicNowMs = deps.monotonicNowMs ?? (() => performance.now());
  let inFlight: Promise<OperationalMetricsSnapshot> | undefined;
  const collect = async (): Promise<OperationalMetricsSnapshot> => {
    const state = deps.getState();
    const queryTimeoutMs = deps.queryTimeoutMs ?? DEFAULT_METRICS_QUERY_TIMEOUT_MS;
    const deadlineStartedAtMs = monotonicNowMs();
    const databaseReachable = await deps.dbProbe.probe();
    const verdict = evaluateReadinessFromProbes(state, databaseReachable);
    const workerHealth = deps.workerHealth?.() ?? {};
    const workerHealthAvailable = deps.workerHealthAvailable?.() ?? {};
    const backup = deps.backupStatus?.() ?? null;
    const stamps = stampsFrom(
      state,
      verdict.ready,
      deps.poolCapTotal,
      workerHealth,
      deps.signerInFlightAmbiguous?.() === true,
    );

    let snapshot: OperationalMetricsSnapshot;
    let databaseTruthAvailable: boolean;
    if (!databaseReachable) {
      snapshot = stampsOnlySnapshot(stamps);
      databaseTruthAvailable = false;
    } else {
      try {
        const remainingQueryBudgetMs = queryTimeoutMs - (monotonicNowMs() - deadlineStartedAtMs);
        if (remainingQueryBudgetMs <= 0) {
          throw new MetricsQueryTimeoutError(queryTimeoutMs);
        }
        snapshot = deps.withinDbDeadline === undefined
          ? await withQueryTimeout(
              collectOperationalMetricsSnapshot(deps.db, stamps),
              remainingQueryBudgetMs,
            )
          : await deps.withinDbDeadline(
              remainingQueryBudgetMs,
              (db) => collectOperationalMetricsSnapshot(db, stamps),
            );
        databaseTruthAvailable = true;
      } catch {
        // A query that fails, or one that neither resolves nor rejects within budget (a
        // stalled query — the same class of hang as an ordinary throw for this handler's
        // purposes), must not turn into an unhandled rejection or an indefinite wait in
        // createMetricsRoute's handler. Production uses withPostgresDeadline: one checked-out
        // connection, transaction-local statement_timeout reduced to the remaining monotonic
        // scrape budget before each serialized census statement, and release only after
        // cancellation + rollback settle. The gauges below are fallback zeros, not truthful
        // readings — databaseTruthAvailable=false tells onSnapshot consumers not to
        // alert-evaluate them as real.
        snapshot = stampsOnlySnapshot(stamps);
        databaseTruthAvailable = false;
      }
    }
    const nowMs = deps.nowMs?.() ?? Date.now();
    snapshot = {
      ...snapshot,
      databaseTruthAvailable: databaseTruthAvailable ? 1 : 0,
      workerHealthAvailable,
      backupEnabled: backup?.enabled ? 1 : 0,
      backupRunning: backup?.running ? 1 : 0,
      backupStatusAvailable: backup === null ? 0 : 1,
      backupLastSuccessAgeSecs:
        backup?.lastSuccessAtMs == null ? 0 : Math.max(0, Math.floor((nowMs - backup.lastSuccessAtMs) / 1000)),
      backupLastSuccessAvailable: backup?.lastSuccessAtMs == null ? 0 : 1,
      backupRpoBreached: backup?.rpoBreached ? 1 : 0,
    };
    deps.onSnapshot?.(snapshot, databaseTruthAvailable);
    return snapshot;
  };

  return () => {
    if (inFlight !== undefined) return inFlight;
    const current = collect();
    inFlight = current;
    const clear = (): void => {
      if (inFlight === current) inFlight = undefined;
    };
    void current.then(clear, clear);
    return current;
  };
}
