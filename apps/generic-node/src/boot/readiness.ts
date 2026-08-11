// Readiness stamps for the v2 node shell.
//
// Delegates to `@zucoins/node-core`'s NodeCoreReadinessState, which
// implements the readiness gating policy:
//   GATING (deploy /health/ready): schema, vault, observation
//           (gateway read within failure budget), restore_hold_clear (ZTR-1172)
//   NON-GATING (reported): signer leadership, halt, storage pressure
//   MONEY-ONLY (admission, not deploy ready): event signer (ZTR-1179 /
//           ZPAY-252 — must not re-couple ready to post-leadership ensure)
//
// The shell keeps a thin compatibility facade so boot-lane / graceful-stop call
// sites stay stable while the ready conjunction itself is owned by node-core.

import {
  NodeCoreReadinessState,
  type ReadinessStateInputs,
} from "@zucoins/node-core";

export type { ReadinessStateInputs };

/** Legacy check names retained for the shell's existing probe JSON shape. */
export interface ReadinessChecks {
  readonly schema: boolean;
  readonly vault: boolean;
  readonly leadership: boolean;
  readonly gateway: boolean;
  /**
   * EVENT_SIGNING signer availability. Stamped for reporting and consumed by
   * money admission (ZTR-1179). NOT part of the shell `ready` conjunction —
   * ensure runs after leadership, so gating deploy-ready on it re-creates the
   * overlap-deploy deadlock (ZPAY-252).
   */
  readonly eventSigner: boolean;
  /** restore_hold clear — gating on /health/ready (ZTR-1172). */
  readonly restoreHoldClear: boolean;
  /** Live DB reachability is probed by the health handler, not stamped here. */
  readonly database?: boolean;
}

export interface ReadinessSnapshot {
  readonly checks: ReadinessChecks;
  readonly ready: boolean;
  readonly degraded: boolean;
  readonly stopping: boolean;
  readonly gatewayConsecutiveFailures: number;
  /** Full readiness inputs for the node-core health evaluator. */
  readonly inputs: ReadinessStateInputs;
}

/**
 * Shell-facing readiness state. Leadership is stamped for reporting and for
 * money-engine gating in the boot lane, but does NOT participate in the
 * ready conjunction.
 */
export class NodeReadiness {
  private readonly inner: NodeCoreReadinessState;

  constructor(gatewayFailureBudget: number) {
    this.inner = new NodeCoreReadinessState({
      observationFailureBudget: gatewayFailureBudget,
    });
    // This shell installs an EVENT_SIGNING authority, so the conjunct starts
    // closed: arm (event-signer-authority.ts) is the only thing that opens it.
    // Node-core's default is open only for deployments with no such authority.
    this.inner.setEventSignerAvailable(false);
  }

  /** Expose the node-core state for createHealthHandlers wiring. */
  get core(): NodeCoreReadinessState {
    return this.inner;
  }

  markSchemaChecksPassed(): void {
    this.inner.markSchemaMigrated();
  }

  setVaultAvailable(available: boolean): void {
    this.inner.setVaultAvailable(available);
  }

  setSignerLeadershipHeld(held: boolean): void {
    this.inner.setLeadershipHeld(held);
  }

  /**
   * EVENT_SIGNING signer availability. Fail-closed for money admission on
   * boot failure or runtime signer loss; must be explicitly re-armed on
   * successful (re-)ensure. Pure forwarder — node-core's readiness state is
   * the single source of truth. Money admission refuses when false; deploy
   * `/health/ready` does not (ZPAY-252).
   */
  setEventSignerAvailable(available: boolean): void {
    this.inner.setEventSignerAvailable(available);
  }

  /**
   * Stamp restore_hold_clear. Boot + live RESTORE_HOLD_PROBE re-read durable
   * reporting_restore_state; dual-gate release mutates Postgres and the next
   * probe (ready handler / keep-warm) restamps true without process restart.
   * Defaults open for greenfield boots.
   */
  setRestoreHoldClear(clear: boolean): void {
    this.inner.setRestoreHoldClear(clear);
  }

  recordGatewayReadSuccess(): void {
    this.inner.recordObservationReadSuccess();
  }

  recordGatewayReadFailure(): void {
    this.inner.recordObservationReadFailure();
  }

  setHalted(halted: boolean): void {
    this.inner.setHalted(halted);
  }

  setStoragePressure(pressure: boolean): void {
    this.inner.setStoragePressure(pressure);
  }

  beginShutdown(): void {
    this.inner.beginShutdown();
  }

  /**
   * Snapshot used by the shell health router and boot lane.
   *
   * `ready` here is the stamp-side conjunction WITHOUT the live DB probe
   * (schema ∧ vault ∧ observation ∧ restore_hold_clear ∧ !stopping). Leadership
   * is reported in checks but excluded from ready — the live DB probe is
   * applied by the health handler's CachedDbProbe.
   */
  snapshot(): ReadinessSnapshot {
    const inputs = this.inner.snapshot();
    const vault = inputs.vaultKeyRingLoaded && inputs.vaultCensusVerified;
    const checks: ReadinessChecks = {
      schema: inputs.schemaMigrated,
      vault,
      leadership: inputs.leadershipLockHeld,
      gateway: inputs.observationReadCapable,
      eventSigner: inputs.eventSignerAvailable,
      restoreHoldClear: inputs.restoreHoldClear,
    };
    // Stamp-side ready (DB probe applied by the health handler). Leadership
    // and EVENT_SIGNING deliberately excluded from deploy-ready (ZPAY-252);
    // money admission still requires eventSigner (ZTR-1179). restore_hold
    // gates deploy-ready (ZTR-1172 / RESTORE_HOLD_READINESS).
    const ready =
      !inputs.stopping &&
      checks.schema &&
      checks.vault &&
      checks.gateway &&
      checks.restoreHoldClear;
    const degraded = inputs.observationDegraded && !inputs.stopping;
    return Object.freeze({
      checks: Object.freeze(checks),
      ready,
      degraded,
      stopping: inputs.stopping,
      gatewayConsecutiveFailures: this.inner.observationConsecutiveFailures,
      inputs,
    });
  }
}

/** Default TTL for live restore_hold re-probe (matches CachedDbProbe class of freshness). */
export const DEFAULT_RESTORE_HOLD_PROBE_TTL_MS = 2_000;

export type RestoreHoldDb = {
  query: (
    text: string,
    params?: readonly unknown[],
  ) => Promise<{ rows: Array<{ restore_hold: boolean }> }>;
};

/**
 * Probe reporting_restore_state for this node and stamp restore_hold_clear.
 * Missing table or missing row → clear (greenfield). Held row → not clear.
 * Fail-closed on query errors (throws) — the live probe catches and stamps false.
 */
export async function stampRestoreHoldFromDb(
  readiness: Pick<NodeReadiness, "setRestoreHoldClear">,
  db: RestoreHoldDb,
  nodeId: string,
): Promise<{ readonly restoreHoldClear: boolean; readonly rowPresent: boolean }> {
  try {
    const result = await db.query(
      `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1::uuid`,
      [nodeId],
    );
    if (result.rows.length === 0) {
      readiness.setRestoreHoldClear(true);
      return { restoreHoldClear: true, rowPresent: false };
    }
    const held = result.rows[0]!.restore_hold === true;
    readiness.setRestoreHoldClear(!held);
    return { restoreHoldClear: !held, rowPresent: true };
  } catch (err) {
    // Undefined table (42P01) on greenfield-before-reporting-DDL → clear.
    const code =
      err !== null && typeof err === "object" && "code" in err
        ? String((err as { code?: unknown }).code)
        : "";
    if (code === "42P01") {
      readiness.setRestoreHoldClear(true);
      return { restoreHoldClear: true, rowPresent: false };
    }
    throw err;
  }
}

/**
 * Live RESTORE_HOLD_PROBE — re-reads durable restore_hold on a TTL so dual-gate
 * release (CLI or in-process) re-opens /health/ready and money admission without
 * requiring a process restart. Boot stamp warms the cache; this is the post-boot
 * authority (not an imaginary in-process release callback).
 *
 * Fail-closed: unexpected query errors stamp restoreHoldClear=false.
 */
export class CachedRestoreHoldProbe {
  private last: { restoreHoldClear: boolean; rowPresent: boolean } | undefined;
  private cachedAtMs = Number.NEGATIVE_INFINITY;
  private inFlight: Promise<{ restoreHoldClear: boolean; rowPresent: boolean }> | undefined;

  constructor(
    private readonly readiness: Pick<NodeReadiness, "setRestoreHoldClear">,
    private readonly db: RestoreHoldDb,
    private readonly nodeId: string,
    private readonly ttlMs: number = DEFAULT_RESTORE_HOLD_PROBE_TTL_MS,
    private readonly clock: () => number = () => Date.now(),
  ) {
    if (!Number.isFinite(ttlMs) || ttlMs < 0) {
      throw new RangeError("CachedRestoreHoldProbe: ttlMs must be a non-negative finite number");
    }
  }

  /** Force the next refresh to hit the database. */
  invalidate(): void {
    this.cachedAtMs = Number.NEGATIVE_INFINITY;
    this.inFlight = undefined;
  }

  /** Last completed stamp, or undefined before the first refresh settles. */
  cached(): { readonly restoreHoldClear: boolean; readonly rowPresent: boolean } | undefined {
    return this.last;
  }

  /**
   * Re-probe when TTL elapsed. Safe for onBeforeEvaluate and keep-warm timers.
   * Always leaves readiness stamped; unexpected errors stamp clear=false.
   */
  async refresh(): Promise<{ readonly restoreHoldClear: boolean; readonly rowPresent: boolean }> {
    const now = this.clock();
    if (this.last !== undefined && now - this.cachedAtMs < this.ttlMs) {
      return this.last;
    }
    if (this.inFlight !== undefined) {
      return this.inFlight;
    }
    const run = (async (): Promise<{ restoreHoldClear: boolean; rowPresent: boolean }> => {
      try {
        const stamped = await stampRestoreHoldFromDb(this.readiness, this.db, this.nodeId);
        this.last = stamped;
        this.cachedAtMs = this.clock();
        return stamped;
      } catch {
        this.readiness.setRestoreHoldClear(false);
        const failed = { restoreHoldClear: false, rowPresent: false } as const;
        this.last = failed;
        this.cachedAtMs = this.clock();
        return failed;
      } finally {
        this.inFlight = undefined;
      }
    })();
    this.inFlight = run;
    return run;
  }
}

/**
 * Compose storage-pressure + restore_hold live probe for readinessHttp.onBeforeEvaluate.
 * Restore-hold refresh runs first so a dual-gate release is visible on the same ready poll.
 */
export function composeReadinessOnBeforeEvaluate(input: {
  readonly storagePressureOnBeforeEvaluate: () => void | Promise<void>;
  readonly restoreHoldProbe: CachedRestoreHoldProbe;
}): () => Promise<void> {
  return async () => {
    await input.restoreHoldProbe.refresh();
    await input.storagePressureOnBeforeEvaluate();
  };
}
