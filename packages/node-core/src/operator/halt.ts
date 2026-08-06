// Operator halt: a durable, fail-closed emergency stop for the node. The halt only
// ever prevents NEW work from starting — it never aborts a transaction already in
// flight (the one-in-flight-per-wallet rule: one in-flight transaction per wallet; a mid-flight abort
// would strand that wallet's single in-flight slot). Indeterminate state fails closed
// to HALTED: the gate is un-paused only when the durable store affirmatively reports a
// disengaged ("RUNNING") record — a missing, corrupt, or unreadable record is treated
// as engaged.

export type HaltState = "HALTED" | "RUNNING";

export const HALTED: HaltState = "HALTED";
export const RUNNING: HaltState = "RUNNING";

// the single source of truth for what a null `HaltStore.read` means. Every
// site that defaults a missing/corrupt record (here and in halt-evidence.ts) must derive
// from this constant, not restate a literal — restoreHaltState below and
// applyHalt/toggleHalt in halt-evidence.ts previously disagreed (HALTED vs RUNNING),
// which made a fresh node's first disengage a permanent NO_OP.
export const MISSING_HALT_RECORD_DEFAULT: HaltState = HALTED;

// Persistence port. read returns null when no affirmatively-readable record is
// available — a missing row AND a corrupt/unparseable record both map to null, so the
// boot restore fails closed on either. A thrown error is a transient read failure
// and is retried with bounded backoff before failing closed.
export interface HaltStore {
  read(): Promise<HaltState | null>;
  write(state: HaltState): Promise<void>;
}

// Live in-memory gate consulted on the hot path before any new work is admitted.
export interface HaltGate {
  isHalted(): boolean;
  engage(): void;
  release(): void;
}

export class OperatorHaltError extends Error {
  constructor(message = "operator halt is engaged; new work is refused") {
    super(message);
    this.name = "OperatorHaltError";
  }
}

export function createHaltGate(initial: HaltState = HALTED): HaltGate {
  let halted = initial === HALTED;
  return {
    isHalted: () => halted,
    engage: () => {
      halted = true;
    },
    release: () => {
      halted = false;
    },
  };
}

export interface RestoreHaltStateOptions {
  readonly maxAttempts?: number;
  readonly baseDelayMs?: number;
  readonly backoffMultiplier?: number;
  readonly sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_BASE_DELAY_MS = 50;
const DEFAULT_BACKOFF_MULTIPLIER = 2;

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

// Fail-closed boot restore. The gate is assumed HALTED until the durable store
// affirmatively reports RUNNING; any other outcome (null record, corrupt record, or a
// read error that exhausts the bounded retry budget) leaves the gate engaged. Retries
// only cover thrown transient errors, with exponential backoff. Returns the state the
// gate was left in.
export async function restoreHaltState(
  store: HaltStore,
  gate: HaltGate,
  options: RestoreHaltStateOptions = {},
): Promise<HaltState> {
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const multiplier = options.backoffMultiplier ?? DEFAULT_BACKOFF_MULTIPLIER;
  const sleep = options.sleep ?? defaultSleep;

  gate.engage();

  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const persisted = await store.read();
      if (persisted === RUNNING) {
        gate.release();
        return RUNNING;
      }
      // null (missing or corrupt record) is indeterminate -> stay halted, no retry.
      return MISSING_HALT_RECORD_DEFAULT;
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts) {
        await sleep(baseDelayMs * multiplier ** (attempt - 1));
      }
    }
  }

  // Retry budget exhausted on a thrown read error: fail closed.
  void lastError;
  gate.engage();
  return MISSING_HALT_RECORD_DEFAULT;
}

// The crash-safe toggle lives in halt-evidence.ts, NOT here: every halt-state mutation
// must append an audit row (kind-scoped operator halt), so there is deliberately no
// un-audited toggle on this module. This file owns only the durable ports, the live gate,
// and the fail-closed boot restore.

// Pre-sign guard: throws unless the gate is affirmatively un-halted. Call this at the
// start of any new signing/claim path; do NOT call it mid-flight (the one-in-flight-per-wallet rule).
export function assertNotHalted(gate: HaltGate): void {
  if (gate.isHalted()) {
    throw new OperatorHaltError();
  }
}

/**
 * Operation-kind scope for the operator kill-switch.
 *
 * Halt stops STARTING new fund-moving first formation for MOVE_INTERNAL and
 * SEND_EXTERNAL. RECEIVE_EXTERNAL inbound co-sign (revenue) is deliberately
 * exempt — a shared unscoped admission check that freezes RECEIVE contradicts
 * the decision.
 *
 * Names pinned by packages/node-core/test/halt-kind-scope.test.ts against
 * generic-node-contracts HALT_GATED_OPERATION_KINDS / HALT_EXEMPT_OPERATION_KINDS
 * (operator-halt subpath is not a package export — same posture as
 * invariant-breach.ts OPERATOR_RECOVERY_ACTION_CATALOG).
 */
export const HALT_GATED_OPERATION_KINDS = ["MOVE_INTERNAL", "SEND_EXTERNAL"] as const;
export const HALT_EXEMPT_OPERATION_KINDS = ["RECEIVE_EXTERNAL"] as const;

export type HaltGatedOperationKind = (typeof HALT_GATED_OPERATION_KINDS)[number];
export type HaltExemptOperationKind = (typeof HALT_EXEMPT_OPERATION_KINDS)[number];
export type HaltScopedOperationKind = HaltGatedOperationKind | HaltExemptOperationKind;

export function isHaltGatedOperationKind(kind: string): kind is HaltGatedOperationKind {
  return (HALT_GATED_OPERATION_KINDS as readonly string[]).includes(kind);
}

export function isHaltExemptOperationKind(kind: string): kind is HaltExemptOperationKind {
  return (HALT_EXEMPT_OPERATION_KINDS as readonly string[]).includes(kind);
}

/**
 * Kind-scoped halt consultation. RECEIVE_EXTERNAL never throws; MOVE_INTERNAL /
 * SEND_EXTERNAL call {@link assertNotHalted}. Unknown kinds fail closed (gated).
 */
export function assertHaltAdmitsKind(gate: HaltGate, kind: string): void {
  if (isHaltExemptOperationKind(kind)) {
    return;
  }
  assertNotHalted(gate);
}
