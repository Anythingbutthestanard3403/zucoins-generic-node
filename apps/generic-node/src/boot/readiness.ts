// Readiness stamps for the v2 node shell.
//
// Delegates to `@zucoins/node-core`'s NodeCoreReadinessState, which
// implements the readiness gating policy:
//   GATING: schema, vault, observation (gateway read within failure budget),
//           event signer (verdict-forcing like `stopping`; ZTR-1179)
//   NON-GATING (reported): signer leadership, halt, storage pressure
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
   * EVENT_SIGNING signer availability. Node-core gating conjunct
   * (ReadinessStateInputs.eventSignerAvailable) — verdict-forcing like
   * `stopping`, still outside the frozen GATING_READINESS_CHECK_IDS census.
   * Safe to gate because EVENT_SIGNING ensure always runs after leadership is
   * already held, so this cannot reproduce the overlap-deploy deadlock class.
   */
  readonly eventSigner: boolean;
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
   * EVENT_SIGNING signer availability. Fail-closed: gates readiness
   * shut on boot failure or runtime signer loss; must be explicitly re-armed
   * on successful (re-)ensure. Pure forwarder — node-core's readiness state is
   * the single source of truth, so /health/ready and money admission see the
   * same conjunct (ZTR-1179).
   */
  setEventSignerAvailable(available: boolean): void {
    this.inner.setEventSignerAvailable(available);
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
   * (schema ∧ vault ∧ observation ∧ !stopping). Leadership is reported in
   * checks but excluded from ready — the live DB probe is applied by the
   * health handler's CachedDbProbe.
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
    };
    // Stamp-side ready (DB probe applied by the health handler). Leadership
    // deliberately excluded. EVENT_SIGNING gates in node-core
    // (see ReadinessChecks.eventSigner doc).
    const ready =
      !inputs.stopping &&
      checks.schema &&
      checks.vault &&
      checks.gateway &&
      checks.eventSigner;
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
