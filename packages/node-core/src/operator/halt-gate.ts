// Admission gating wrappers. The halt is enforced ONLY at admission — before a signer
// produces a signature for new work, and before a worker claims new work. Once work is
// in flight it is never gated: process runs to completion regardless of the gate, so
// a halt can never abort a transaction mid-flight (the one-in-flight-per-wallet rule).

import {
  OperatorHaltError,
  assertNotHalted,
  type HaltGate,
} from "./halt.js";

// A durable phase of the send lifecycle. pre_sign is the only admission point; the
// later phases are downstream of an already-admitted transaction and must stay
// permeable so in-flight work completes.
export type DurablePhase = "pre_sign" | "post_sign" | "pre_submit" | "post_submit";

// Phases that refuse new work when the halt is engaged.
export const HALT_GATED_PHASES: readonly DurablePhase[] = ["pre_sign"];

// Phases that proceed regardless of the halt — in-flight work is never aborted.
export const HALT_PERMEABLE_PHASES: readonly DurablePhase[] = [
  "post_sign",
  "pre_submit",
  "post_submit",
];

export function isHaltGatedPhase(phase: DurablePhase): boolean {
  return (HALT_GATED_PHASES as readonly string[]).includes(phase);
}

// The minimal signing seam the gate wraps. sign is the pre-sign admission point.
export interface Signer<Request = unknown, Signature = unknown> {
  sign(request: Request): Promise<Signature>;
}

// Wraps a signer so it refuses to produce a signature for new work while halted. The
// delegate is never invoked when the gate is engaged — zero delegate calls.
export function createGatedSigner<Request, Signature>(
  gate: HaltGate,
  delegate: Signer<Request, Signature>,
): Signer<Request, Signature> {
  return {
    sign: async (request) => {
      assertNotHalted(gate);
      return await delegate.sign(request);
    },
  };
}

// The minimal worker seam the gate wraps. claim is the admission point for new work;
// process drives already-claimed (in-flight) work to completion and is never gated.
export interface Worker<Claim = unknown, Result = unknown> {
  claim(): Promise<Claim | null>;
  process(claim: Claim): Promise<Result>;
}

// Wraps a worker so it refuses to claim NEW work while halted, but always processes
// already-claimed work to completion. claim returns null when the gate is engaged
// (no new admission); process is deliberately permeable (the one-in-flight-per-wallet rule).
export function createGatedWorker<Claim, Result>(
  gate: HaltGate,
  delegate: Worker<Claim, Result>,
): Worker<Claim, Result> {
  return {
    claim: async () => {
      if (gate.isHalted()) {
        return null;
      }
      return await delegate.claim();
    },
    process: async (claim) => await delegate.process(claim),
  };
}

// The minimal admission seam the gate wraps. admit is the entry point for new
// operations; it is refused entirely while the halt is engaged.
export interface Admission<Request = unknown, Result = unknown> {
  admit(request: Request): Promise<Result>;
}

// Wraps an admission function so new operations are rejected while halted. The
// delegate is never invoked when the gate is engaged — zero delegate calls.
export function createGatedAdmission<Request, Result>(
  gate: HaltGate,
  delegate: Admission<Request, Result>,
): Admission<Request, Result> {
  return {
    admit: async (request) => {
      assertNotHalted(gate);
      return await delegate.admit(request);
    },
  };
}

// Guard for callers that drive phases explicitly: throws only on a gated phase while
// halted; permeable phases pass through untouched.
export function assertPhaseAdmissible(gate: HaltGate, phase: DurablePhase): void {
  if (isHaltGatedPhase(phase) && gate.isHalted()) {
    throw new OperatorHaltError(`operator halt is engaged; phase "${phase}" is refused`);
  }
}
