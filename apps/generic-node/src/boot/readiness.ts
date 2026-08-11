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
   * Stamp restore_hold_clear. Post-restore force stamps false; dual-gate
   * release stamps true. Defaults open for greenfield boots.
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

/**
 * Probe reporting_restore_state for this node and stamp restore_hold_clear.
 * Missing table or missing row → clear (greenfield). Held row → not clear.
 * Fail-closed on query errors (throws).
 */
export async function stampRestoreHoldFromDb(
  readiness: Pick<NodeReadiness, "setRestoreHoldClear">,
  db: { query: (text: string, params?: readonly unknown[]) => Promise<{ rows: Array<{ restore_hold: boolean }> }> },
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
