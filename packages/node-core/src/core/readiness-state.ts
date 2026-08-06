// stampable readiness state for the generic node runtime.
//
// Each gating check has exactly one stamping authority:
// schema_migrated → MIGRATION_RUNNER (markSchemaMigrated)
// database_reachable → DATABASE_HEALTH_PROBE (live CachedDbProbe; not stamped here)
// vault_available → VAULT_KEY_RING_LOADER (setVault*)
// observation_read_capable → OBSERVATION_SERVICE (recordObservation*)
// signer_leadership (report) → LEADERSHIP_LOCK_MANAGER (setLeadershipHeld)
//
// Observation gate: closed until the first validated gateway read
// succeeds; after that, consecutive failures within the configured failure
// budget keep the gate open; exceeding the budget closes it and marks
// observationDegraded so readiness reports `degraded` rather than plain
// `not_ready`. Any success resets the consecutive-failure counter.
//
// Lives in core/ (not api/) so the module graph stays acyclic: api may import
// core; core must not import api (packages/node-core/test/boundaries.test.ts).

/**
 * Stamped readiness inputs (no I/O). The live DB probe result is supplied
 * separately by the health handler's CachedDbProbe.
 */
export interface ReadinessStateInputs {
  readonly schemaMigrated: boolean;
  readonly vaultKeyRingLoaded: boolean;
  readonly vaultCensusVerified: boolean;
  readonly observationReadCapable: boolean;
  readonly leadershipLockHeld: boolean;
  /** Operator halt engaged. Reported only; non-gating. */
  readonly halted: boolean;
  /** Storage-pressure / critical band engaged. Reported only; non-gating. */
  readonly storagePressure: boolean;
  /** Graceful-stop in progress — forces not-ready. */
  readonly stopping: boolean;
  /**
   * True after at least one validated observation/gateway read succeeded and a
   * later failure budget breach closed the observation gate. Used only to
   * distinguish `degraded` from plain `not_ready`.
   */
  readonly observationDegraded: boolean;
}

export interface NodeCoreReadinessStateOptions {
  /** Consecutive observation/gateway read failures tolerated after first success. Must be ≥ 1. */
  readonly observationFailureBudget: number;
}

/**
 * Process-local readiness stamps. Pure in-memory; the live DB probe lives on
 * the health handler (CachedDbProbe) so liveness never shares that path.
 */
export class NodeCoreReadinessState {
  private schemaMigrated = false;
  private vaultKeyRingLoaded = false;
  private vaultCensusVerified = false;
  private leadershipLockHeld = false;
  private observationReadEverSucceeded = false;
  private observationFailureCount = 0;
  private halted = false;
  private storagePressure = false;
  private stopping = false;
  private readonly observationFailureBudget: number;

  constructor(options: NodeCoreReadinessStateOptions) {
    const budget = options.observationFailureBudget;
    if (!Number.isInteger(budget) || budget < 1) {
      throw new RangeError(
        "NodeCoreReadinessState: observationFailureBudget must be an integer >= 1",
      );
    }
    this.observationFailureBudget = budget;
  }

  markSchemaMigrated(): void {
    this.schemaMigrated = true;
  }

  setVaultKeyRingLoaded(loaded: boolean): void {
    this.vaultKeyRingLoaded = loaded;
  }

  setVaultCensusVerified(verified: boolean): void {
    this.vaultCensusVerified = verified;
  }

  /** Convenience: both vault conjuncts (matches vault_available evaluator). */
  setVaultAvailable(available: boolean): void {
    this.vaultKeyRingLoaded = available;
    this.vaultCensusVerified = available;
  }

  setLeadershipHeld(held: boolean): void {
    this.leadershipLockHeld = held;
  }

  recordObservationReadSuccess(): void {
    this.observationReadEverSucceeded = true;
    this.observationFailureCount = 0;
  }

  recordObservationReadFailure(): void {
    this.observationFailureCount += 1;
  }

  setHalted(halted: boolean): void {
    this.halted = halted;
  }

  setStoragePressure(pressure: boolean): void {
    this.storagePressure = pressure;
  }

  beginShutdown(): void {
    this.stopping = true;
  }

  get leadershipHeld(): boolean {
    return this.leadershipLockHeld;
  }

  get observationConsecutiveFailures(): number {
    return this.observationFailureCount;
  }

  private observationGateOpen(): boolean {
    if (!this.observationReadEverSucceeded) return false;
    return this.observationFailureCount < this.observationFailureBudget;
  }

  private isObservationDegraded(): boolean {
    return (
      this.observationReadEverSucceeded &&
      this.observationFailureCount >= this.observationFailureBudget
    );
  }

  /** Snapshot of stamped inputs for the health evaluator (no DB probe result). */
  snapshot(): ReadinessStateInputs {
    return Object.freeze({
      schemaMigrated: this.schemaMigrated,
      vaultKeyRingLoaded: this.vaultKeyRingLoaded,
      vaultCensusVerified: this.vaultCensusVerified,
      observationReadCapable: this.observationGateOpen(),
      leadershipLockHeld: this.leadershipLockHeld,
      halted: this.halted,
      storagePressure: this.storagePressure,
      stopping: this.stopping,
      observationDegraded: this.isObservationDegraded(),
    });
  }
}
