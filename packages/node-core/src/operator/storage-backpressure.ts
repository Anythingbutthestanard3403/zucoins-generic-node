// Storage backpressure: a fail-closed admission gate driven by evidence-storage
// utilization. Like the operator halt, it only ever refuses NEW work — it never aborts a
// transaction already in flight (the one-in-flight-per-wallet rule: one in-flight transaction per wallet). Two
// rising bands gate admission: at the pressure threshold new evidence is rejected; at the
// higher critical threshold all operations halt. A latched HALTED state gives recovery
// hysteresis so the gate cannot flap at the critical boundary — it auto-resumes only once
// utilization falls back below the pressure threshold. Indeterminate utilization (non-finite
// or negative) fails closed to CRITICAL.

export type PressureState = "NORMAL" | "PRESSURE" | "CRITICAL" | "HALTED";

// The instantaneous classification of a utilization reading; HALTED is only ever reached
// through the recovery latch, never by classification alone.
export type PressureBand = Exclude<PressureState, "HALTED">;

// Module-private state literals. They are not re-exported: ./halt.js already exports a
// `HALTED` constant, and star-re-exporting a second one through the operator barrel would be
// an ambiguous export. Callers use the `PressureState` type and string literals directly.
const NORMAL: PressureBand = "NORMAL";
const PRESSURE: PressureBand = "PRESSURE";
const CRITICAL: PressureBand = "CRITICAL";
const HALTED: PressureState = "HALTED";

export const DEFAULT_PRESSURE_THRESHOLD = 0.9;
export const DEFAULT_CRITICAL_THRESHOLD = 0.95;

export interface BackpressureThresholds {
  // Utilization at which new evidence is refused (fail-closed).
  readonly pressure: number;
  // Utilization at which all operations halt. Strictly above `pressure`.
  readonly critical: number;
}

export class BackpressureConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackpressureConfigurationError";
  }
}

export class StorageBackpressureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StorageBackpressureError";
  }
}

// Thrown when new evidence is refused at or above the pressure threshold.
export class EvidenceRejectedError extends StorageBackpressureError {
  constructor(message = "evidence storage backpressure is rejecting new evidence") {
    super(message);
    this.name = "EvidenceRejectedError";
  }
}

// Thrown when operations are halted at or above the critical threshold (or while latched).
export class OperationsHaltedError extends StorageBackpressureError {
  constructor(message = "evidence storage backpressure has halted operations") {
    super(message);
    this.name = "OperationsHaltedError";
  }
}

export function validateThresholds(
  thresholds: BackpressureThresholds,
): BackpressureThresholds {
  const { pressure, critical } = thresholds;
  if (!Number.isFinite(pressure) || !Number.isFinite(critical)) {
    throw new BackpressureConfigurationError("backpressure thresholds must be finite numbers");
  }
  if (pressure <= 0 || pressure >= 1) {
    throw new BackpressureConfigurationError("pressure threshold must lie in the open interval (0, 1)");
  }
  if (critical <= pressure || critical > 1) {
    throw new BackpressureConfigurationError(
      "critical threshold must be strictly greater than pressure and at most 1",
    );
  }
  return thresholds;
}

// Fail-closed band classification: a non-finite or negative reading is treated as full so an
// unreadable gauge halts admission rather than opening it.
export function classifyPressure(
  utilization: number,
  thresholds: BackpressureThresholds,
): PressureBand {
  if (!Number.isFinite(utilization) || utilization < 0) {
    return CRITICAL;
  }
  if (utilization >= thresholds.critical) {
    return CRITICAL;
  }
  if (utilization >= thresholds.pressure) {
    return PRESSURE;
  }
  return NORMAL;
}

// State-machine step. NORMAL and PRESSURE track the instantaneous band (escalation and
// recovery). CRITICAL holds while utilization stays at or above the critical threshold; once
// it drops below critical the gate enters the latched HALTED state rather than reopening
// immediately. HALTED auto-resumes to NORMAL only when utilization falls below the pressure
// threshold, which prevents flapping at the critical boundary.
export function nextPressureState(
  current: PressureState,
  band: PressureBand,
): PressureState {
  switch (current) {
    case HALTED:
      return band === NORMAL ? NORMAL : HALTED;
    case CRITICAL:
      if (band === CRITICAL) {
        return CRITICAL;
      }
      return band === NORMAL ? NORMAL : HALTED;
    default:
      return band;
  }
}

// New evidence is admitted only in NORMAL: at PRESSURE evidence is refused, and at
// CRITICAL/HALTED everything is refused.
export function canAcceptEvidenceInState(state: PressureState): boolean {
  return state === NORMAL;
}

// Operations proceed in NORMAL and PRESSURE; they halt at CRITICAL and while latched HALTED.
export function canOperateInState(state: PressureState): boolean {
  return state === NORMAL || state === PRESSURE;
}

// Convenience for callers holding byte counts. Indeterminate inputs (non-finite, or a
// non-positive capacity) yield NaN so the classifier fails closed.
export function utilizationRatio(used: number, capacity: number): number {
  if (!Number.isFinite(used) || !Number.isFinite(capacity) || capacity <= 0) {
    return Number.NaN;
  }
  return used / capacity;
}

// Polling seam for a monitor that reads global evidence-storage utilization on demand.
export interface StorageUtilizationSource {
  utilization(): Promise<number>;
}

export interface PressureReading {
  readonly state: PressureState;
  readonly utilization: number;
}

export interface BackpressureSnapshot {
  readonly global: PressureReading;
  readonly wallets: ReadonlyArray<{ readonly walletId: string } & PressureReading>;
}

export interface StorageBackpressureOptions {
  readonly thresholds?: Partial<BackpressureThresholds>;
  readonly initial?: PressureState;
  readonly source?: StorageUtilizationSource;
}

// Live gate consulted on the admission path. Backpressure is enforced both globally and
// per-wallet: a decision for a given wallet is the conjunction of the global state and that
// wallet's own state, so a single full wallet is gated even when global utilization is healthy.
export interface StorageBackpressure {
  recordGlobalSample(utilization: number): PressureState;
  recordWalletSample(walletId: string, utilization: number): PressureState;
  globalState(): PressureState;
  walletState(walletId: string): PressureState;
  canAcceptEvidence(walletId?: string): boolean;
  canOperate(walletId?: string): boolean;
  assertCanAcceptEvidence(walletId?: string): void;
  assertCanOperate(walletId?: string): void;
  forgetWallet(walletId: string): void;
  refresh(): Promise<PressureState>;
  snapshot(): BackpressureSnapshot;
}

interface Cell {
  state: PressureState;
  utilization: number;
}

export function createStorageBackpressure(
  options: StorageBackpressureOptions = {},
): StorageBackpressure {
  const thresholds = validateThresholds({
    pressure: options.thresholds?.pressure ?? DEFAULT_PRESSURE_THRESHOLD,
    critical: options.thresholds?.critical ?? DEFAULT_CRITICAL_THRESHOLD,
  });
  const initial = options.initial ?? NORMAL;
  const source = options.source;

  const global: Cell = { state: initial, utilization: 0 };
  const wallets = new Map<string, Cell>();

  const step = (cell: Cell, utilization: number): PressureState => {
    const band = classifyPressure(utilization, thresholds);
    cell.state = nextPressureState(cell.state, band);
    cell.utilization = utilization;
    return cell.state;
  };

  const walletCell = (walletId: string): Cell => {
    let cell = wallets.get(walletId);
    if (cell === undefined) {
      cell = { state: NORMAL, utilization: 0 };
      wallets.set(walletId, cell);
    }
    return cell;
  };

  return {
    recordGlobalSample: (utilization) => step(global, utilization),
    recordWalletSample: (walletId, utilization) => step(walletCell(walletId), utilization),
    globalState: () => global.state,
    walletState: (walletId) => wallets.get(walletId)?.state ?? NORMAL,

    canAcceptEvidence: (walletId) => {
      if (!canAcceptEvidenceInState(global.state)) {
        return false;
      }
      if (walletId === undefined) {
        return true;
      }
      const cell = wallets.get(walletId);
      return cell === undefined || canAcceptEvidenceInState(cell.state);
    },

    canOperate: (walletId) => {
      if (!canOperateInState(global.state)) {
        return false;
      }
      if (walletId === undefined) {
        return true;
      }
      const cell = wallets.get(walletId);
      return cell === undefined || canOperateInState(cell.state);
    },

    assertCanAcceptEvidence(walletId) {
      if (!this.canAcceptEvidence(walletId)) {
        throw new EvidenceRejectedError();
      }
    },

    assertCanOperate(walletId) {
      if (!this.canOperate(walletId)) {
        throw new OperationsHaltedError();
      }
    },

    forgetWallet: (walletId) => {
      wallets.delete(walletId);
    },

    refresh: async () => {
      if (source === undefined) {
        throw new BackpressureConfigurationError(
          "refresh requires a configured storage utilization source",
        );
      }
      let reading: number;
      try {
        reading = await source.utilization();
      } catch {
        // A failed read is indeterminate; record NaN so classification fails closed.
        reading = Number.NaN;
      }
      return step(global, reading);
    },

    snapshot: () => ({
      global: { state: global.state, utilization: global.utilization },
      wallets: [...wallets.entries()].map(([walletId, cell]) => ({
        walletId,
        state: cell.state,
        utilization: cell.utilization,
      })),
    }),
  };
}
