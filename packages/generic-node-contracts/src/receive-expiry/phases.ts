import { type OperationTransactionPhase } from "./boundary.js";

// The receive expiry phase catalog for fault injection. Each phase carries the durable
// operation_transactions phase that exists at it (null = none), its pre/post-boundary
// classification, and the expected expiry outcome (terminal EXPIRED pre-boundary vs held
// non-terminal post-boundary). Frozen data; fault-injection.test.ts drives every phase over the
// .1 boundary/lifecycle and .2 sequencing contracts. CONTRACT_FREEZE.
//
// `maxTxPhase` is derived from the receive operation flow: STEP1_SIGNATURE_PERSISTED at payer
// step-1 signature persist, STEP2_PREIMAGE_PERSISTED committed before the receiver signer is
// called (so `pre_sign` sits there), then STEP2_SIGNATURE_PERSISTED. Submit and landing add no
// attempt_phase — SETTLED_BODY_PERSISTED is written in the same DB-TX that leaves READY for
// RECEIVE_LANDED, so no phase of a still-READY receive can be at it, and the phases after signing
// are indistinguishable by attempt_phase alone. That is exactly why the boundary keys off
// EXISTS(operation_transactions).

type ExpiryOutcome = "terminal" | "held";

type PhaseRow = {
  readonly phase: string;
  readonly maxTxPhase: OperationTransactionPhase | null;
  readonly pastBoundary: boolean;
  readonly expiry: ExpiryOutcome;
};

export const RECEIVE_EXPIRY_PHASES = [
  { phase: "unassigned", maxTxPhase: null, pastBoundary: false, expiry: "terminal" },
  { phase: "pre_arm", maxTxPhase: null, pastBoundary: false, expiry: "terminal" },
  { phase: "post_arm", maxTxPhase: null, pastBoundary: false, expiry: "terminal" },
  { phase: "candidate_persisted", maxTxPhase: "STEP1_SIGNATURE_PERSISTED", pastBoundary: true, expiry: "held" },
  { phase: "pre_sign", maxTxPhase: "STEP2_PREIMAGE_PERSISTED", pastBoundary: true, expiry: "held" },
  { phase: "post_sign", maxTxPhase: "STEP2_SIGNATURE_PERSISTED", pastBoundary: true, expiry: "held" },
  { phase: "ambiguous_submit", maxTxPhase: "STEP2_SIGNATURE_PERSISTED", pastBoundary: true, expiry: "held" },
  { phase: "landed_before_read", maxTxPhase: "STEP2_SIGNATURE_PERSISTED", pastBoundary: true, expiry: "held" },
] as const satisfies readonly PhaseRow[];

export type ReceiveExpiryPhase = (typeof RECEIVE_EXPIRY_PHASES)[number];

export const RECEIVE_EXPIRY_PHASE_INVARIANTS = {
  boundaryFromOperationTransactions:
    "Each phase's pre/post-boundary classification derives from EXISTS(operation_transactions) at STEP1_SIGNATURE_PERSISTED, never execution_phase.",
  postBoundaryNeverTerminalExpiry:
    "No post-boundary phase permits terminal expiry; a restart re-reads the durable operation_transactions phase and stays post-boundary.",
} as const;

export const receiveExpiryFaultInjectionContract = {
  phases: RECEIVE_EXPIRY_PHASES,
  invariants: RECEIVE_EXPIRY_PHASE_INVARIANTS,
} as const;
