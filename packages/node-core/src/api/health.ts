// Liveness and readiness probe handlers.
//
// Readiness gating is frozen as:
// GATING: schema_migrated, database_reachable, vault_available,
// observation_read_capable
// NON-GATING (reported): signer_leadership
//
// Readiness deliberately does not gate on signer leadership: coupling the two
// re-introduces an overlap-deploy deadlock, where a new instance never binds
// /health/ready while it waits on the old instance's lock.
//
// Additional reported-only detail outside the closed check
// set: halt, storage_pressure. Neither gates the ready verdict.
//
// Two verdict-forcing inputs gate WITHOUT joining the closed check set
// (readiness-checks.contract.ts census stays frozen): `stopping` (graceful
// stop) and `eventSignerAvailable` (runtime EVENT_SIGNING authority loss —
// armed only after leadership is held, so gating it cannot reproduce the
// overlap-deploy deadlock; ZTR-1179).
//
// Liveness is zero-dependency: never touches the database or the gateway and
// must never flap on a transient dependency blip.
//
// Information-minimal: no credentials, wallets, tenants, connection strings,
// stack traces, or private configuration leak through either body.

import type { ReadinessStateInputs } from "../core/readiness-state.js";

/** Default DB-ping cache TTL — protects unauthenticated /health/ready from flood → pool exhaustion (pattern). */
export const DEFAULT_DB_PING_TTL_MS = 5_000;

/** Finite DB-ping deadline shared by readiness and other health surfaces. */
export const DEFAULT_DB_PING_TIMEOUT_MS = 5_000;

/** Gating check ids (`GATING_CHECK_IDS`). */
export const GATING_READINESS_CHECK_IDS = [
  "schema_migrated",
  "database_reachable",
  "vault_available",
  "observation_read_capable",
] as const;

export type GatingReadinessCheckId = (typeof GATING_READINESS_CHECK_IDS)[number];

/** All reported check ids (gating + non-gating detail). */
export const REPORTED_READINESS_CHECK_IDS = [
  ...GATING_READINESS_CHECK_IDS,
  "signer_leadership",
  "halt",
  "storage_pressure",
] as const;

export type ReportedReadinessCheckId = (typeof REPORTED_READINESS_CHECK_IDS)[number];

export interface LivenessResponse {
  readonly status: "alive";
  readonly version: string;
  readonly timestamp: string;
}

export interface ReadinessCheckEntry {
  readonly name: ReportedReadinessCheckId;
  readonly ready: boolean;
  /** True iff this check participates in the top-level ready verdict. */
  readonly gating: boolean;
}

export type ReadinessStatus = "ready" | "not_ready" | "degraded";

export interface ReadinessResponse {
  readonly status: ReadinessStatus;
  readonly version: string;
  readonly timestamp: string;
  readonly checks: readonly ReadinessCheckEntry[];
}

export interface HealthHttpResult {
  readonly statusCode: 200 | 503;
  readonly body: LivenessResponse | ReadinessResponse;
}

export interface ReadinessVerdict {
  readonly ready: boolean;
  readonly status: ReadinessStatus;
  readonly checks: readonly ReadinessCheckEntry[];
  readonly failing: readonly GatingReadinessCheckId[];
}

export function buildLivenessResponse(
  version: string,
  now?: () => string,
): LivenessResponse {
  return {
    status: "alive",
    version,
    timestamp: (now ?? (() => new Date().toISOString()))(),
  };
}

export function livenessHttp(version: string, now?: () => string): HealthHttpResult {
  return { statusCode: 200, body: buildLivenessResponse(version, now) };
}

/**
 * Pure readiness evaluation. `databaseReachable` is the live (or cached) probe
 * result; every other input is a stamp. Leadership / halt / storage_pressure
 * are reported but never consulted for the top-level verdict (reconcile posture).
 */
export function evaluateReadinessFromProbes(
  state: ReadinessStateInputs,
  databaseReachable: boolean,
): ReadinessVerdict {
  const vaultAvailable = state.vaultKeyRingLoaded && state.vaultCensusVerified;

  const checkValues: Record<ReportedReadinessCheckId, boolean> = {
    schema_migrated: state.schemaMigrated,
    database_reachable: databaseReachable,
    vault_available: vaultAvailable,
    observation_read_capable: state.observationReadCapable,
    // Non-gating: true means "this instance holds leadership" / "healthy".
    signer_leadership: state.leadershipLockHeld,
    // Non-gating detail: ready=true means "not halted" / "no storage pressure".
    halt: !state.halted,
    storage_pressure: !state.storagePressure,
  };

  const gatingFlags: Record<ReportedReadinessCheckId, boolean> = {
    schema_migrated: true,
    database_reachable: true,
    vault_available: true,
    observation_read_capable: true,
    signer_leadership: false,
    halt: false,
    storage_pressure: false,
  };

  const checks: ReadinessCheckEntry[] = REPORTED_READINESS_CHECK_IDS.map((name) =>
    Object.freeze({
      name,
      ready: checkValues[name],
      gating: gatingFlags[name],
    }),
  );

  const failing = GATING_READINESS_CHECK_IDS.filter((id) => !checkValues[id]);
  // eventSignerAvailable gates like `stopping`: verdict-forcing, outside the
  // frozen reported check set (see module header; ZTR-1179).
  const gatesPass = failing.length === 0 && !state.stopping && state.eventSignerAvailable;
  const ready = gatesPass;

  let status: ReadinessStatus;
  if (ready) {
    status = "ready";
  } else if (state.observationDegraded && !state.stopping) {
    // was observation-capable, then failure budget exceeded.
    status = "degraded";
  } else {
    status = "not_ready";
  }

  return Object.freeze({
    ready,
    status,
    checks: Object.freeze(checks),
    failing: Object.freeze(failing),
  });
}

export function buildReadinessResponse(
  version: string,
  verdict: ReadinessVerdict,
  now?: () => string,
): ReadinessResponse {
  return {
    status: verdict.status,
    version,
    timestamp: (now ?? (() => new Date().toISOString()))(),
    checks: verdict.checks,
  };
}

/**
 * DB-ping cache. Memoizes the last probe result for `ttlMs` so an unauthenticated
 * readiness flood cannot exhaust the pool (ticket AC).
 */
export class CachedDbProbe {
  private cachedOk: boolean | undefined;
  private cachedAtMs = Number.NEGATIVE_INFINITY;
  private inFlight: Promise<boolean> | undefined;
  private generation = 0;

  constructor(
    private readonly pingDb: () => Promise<void>,
    private readonly ttlMs: number = DEFAULT_DB_PING_TTL_MS,
    private readonly clock: () => number = () => performance.now(),
    private readonly timeoutMs: number = DEFAULT_DB_PING_TIMEOUT_MS,
  ) {
    if (!Number.isFinite(ttlMs) || ttlMs < 0) {
      throw new RangeError("CachedDbProbe: ttlMs must be a non-negative finite number");
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new RangeError("CachedDbProbe: timeoutMs must be a positive finite number");
    }
  }

  /**
   * Last completed verdict, read without probing — for synchronous consumers that must
   * not issue a query of their own (money admission; see money-path-admission.ts).
   *
   * Fail-closed on both unknown and stale: `false` before the first probe completes and
   * again once the cached verdict has aged past `ttlMs`. A consumer therefore acts on a
   * verdict at most one TTL old, and the answer re-closes on DB loss the moment the next
   * probe records a failure — it can never latch open the way a boot-time flag does.
   */
  cachedReachable(): boolean {
    if (this.cachedOk !== true) return false;
    return this.clock() - this.cachedAtMs < this.ttlMs;
  }

  /** Force the next call to re-probe (tests / post-recovery). */
  invalidate(): void {
    this.generation += 1;
    this.cachedOk = undefined;
    this.cachedAtMs = Number.NEGATIVE_INFINITY;
    this.inFlight = undefined;
  }

  async probe(): Promise<boolean> {
    const now = this.clock();
    if (this.cachedOk !== undefined && now - this.cachedAtMs < this.ttlMs) {
      return this.cachedOk;
    }
    if (this.inFlight !== undefined) {
      return this.inFlight;
    }

    const generation = this.generation;
    const pingOutcome = Promise.resolve()
      .then(() => this.pingDb())
      .then(
        () => true,
        () => false,
      );
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), this.timeoutMs);
    });
    const bounded = Promise.race([pingOutcome, timeout])
      .finally(() => {
        if (timer !== undefined) clearTimeout(timer);
      })
      .then((ok) => {
        if (this.generation === generation) {
          this.cachedOk = ok;
          this.cachedAtMs = this.clock();
        }
        return ok;
      });
    this.inFlight = bounded;
    void bounded.finally(() => {
      if (this.inFlight === bounded) this.inFlight = undefined;
    });
    return bounded;
  }
}

export interface ReadinessHandlerDeps {
  readonly version: string;
  readonly getState: () => ReadinessStateInputs;
  /** Live DB reachability probe. MUST throw (or reject) on failure. */
  readonly pingDb: () => Promise<void>;
  readonly now?: () => string;
  readonly clock?: () => number;
  readonly dbPingTtlMs?: number;
  readonly dbPingTimeoutMs?: number;
  /** Optional pre-built cache (shared across calls / tests). */
  readonly dbProbe?: CachedDbProbe;
  /**
   * Optional pre-evaluate hook (e.g. write-latency → storage_pressure stamp via
   * createWriteLatencyPressureRefresh). Runs before getState is read so the
   * readiness verdict reflects freshly stamped non-gating detail. Errors are
   * swallowed so a flaky collector cannot take readiness offline (fail-open on
   * the optional stamp only — gating probes are unaffected).
   */
  readonly onBeforeEvaluate?: () => void | Promise<void>;
}

/**
 * Build the readiness HTTP result: probes DB (cached), evaluates gates,
 * returns 200 only when every gating check passes and the process is not stopping.
 */
export async function readinessHttp(deps: ReadinessHandlerDeps): Promise<HealthHttpResult> {
  if (deps.onBeforeEvaluate !== undefined) {
    try {
      await deps.onBeforeEvaluate();
    } catch {
      // Optional stamp must not poison the readiness probe.
    }
  }
  const dbProbe =
    deps.dbProbe ??
    new CachedDbProbe(
      deps.pingDb,
      deps.dbPingTtlMs ?? DEFAULT_DB_PING_TTL_MS,
      deps.clock,
      deps.dbPingTimeoutMs ?? DEFAULT_DB_PING_TIMEOUT_MS,
    );
  const databaseReachable = await dbProbe.probe();
  const verdict = evaluateReadinessFromProbes(deps.getState(), databaseReachable);
  const body = buildReadinessResponse(deps.version, verdict, deps.now);
  return { statusCode: verdict.ready ? 200 : 503, body };
}

export interface HealthRouteHandlers {
  readonly liveness: () => HealthHttpResult;
  readonly readiness: () => Promise<HealthHttpResult>;
  readonly dbProbe: CachedDbProbe;
}

/** Convenience factory for mount points (generic-node, tests). */
export function createHealthHandlers(deps: ReadinessHandlerDeps): HealthRouteHandlers {
  const dbProbe =
    deps.dbProbe ??
    new CachedDbProbe(
      deps.pingDb,
      deps.dbPingTtlMs ?? DEFAULT_DB_PING_TTL_MS,
      deps.clock,
      deps.dbPingTimeoutMs ?? DEFAULT_DB_PING_TIMEOUT_MS,
    );
  return Object.freeze({
    liveness: () => livenessHttp(deps.version, deps.now),
    readiness: () => readinessHttp({ ...deps, dbProbe }),
    dbProbe,
  });
}
