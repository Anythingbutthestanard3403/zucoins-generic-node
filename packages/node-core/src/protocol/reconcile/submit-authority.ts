// make submit authority unrepresentable.
// ("Gateway transport
// boundary" — "receipt acknowledgement... do not settle from acknowledgement");
// ("Submit acknowledgement and retry adjudication");
//
// The central safety property: a SubmitAcknowledgement (evidence a request reached the
// gateway) and a SettlementAuthority (evidence a landing was proven) are DISJOINT NOMINAL
// TYPES. Each carries a private `unique symbol` brand declared and initialized only in this
// module and never exported, so no object literal written outside this file can structurally
// satisfy either interface — the only way to produce one is this module's own constructor, and
// neither constructor accepts the other's evidence as input. "Settle from a bare ACK" is a
// compile error here, not a runtime discipline.

import { isLandingPathProof, type LandingPathProof } from "./landing-proof.js";

// Real runtime symbols (not `declare`d types): `const x = Symbol(...)` gives TypeScript a
// genuine `unique symbol` type for `x` AND a real value for the `in` operator below. Kept
// module-private (never exported) — that absence is what makes the two interfaces
// unrepresentable from outside this file, not merely discouraged.
const submitAcknowledgementBrand = Symbol("submitAcknowledgementBrand");
const settlementAuthorityBrand = Symbol("settlementAuthorityBrand");

// Proves only that a submit request was transmitted and a
// response was captured. Proves nothing about the chain; carries no landing evidence.
export interface SubmitAcknowledgement {
  readonly [submitAcknowledgementBrand]: true;
  readonly attemptId: string;
  readonly gatewayStatus: boolean;
  readonly gatewayCode: string;
  readonly capturedAt: string;
}

// Authority to mark an attempt LANDED_VERIFIED. Constructible
// only via mintSettlementAuthority, whose sole evidence parameter is a LandingPathProof
// Never a SubmitAcknowledgement.
export interface SettlementAuthority {
  readonly [settlementAuthorityBrand]: true;
  readonly attemptId: string;
  readonly path: LandingPathProof;
}

// The ONLY constructor for SubmitAcknowledgement. Captures the gateway's response to the one
// authorized single-shot call (step 9: "Claim SUBMIT(attempt_1) and
// invoke once... Persist response bytes/outcome. Never submit this attempt again."). It never
// derives, accepts, or returns a LandingPathProof/SettlementAuthority.
export function captureSubmitAcknowledgement(
  attemptId: string,
  gatewayStatus: boolean,
  gatewayCode: string,
  capturedAt: string,
): SubmitAcknowledgement {
  return {
    [submitAcknowledgementBrand]: true,
    attemptId,
    gatewayStatus,
    gatewayCode,
    capturedAt,
  };
}

// The ONLY constructor for SettlementAuthority. Its evidence parameter type is LandingPathProof
// — passing a SubmitAcknowledgement (or any other shape) is a compile error, not merely
// discouraged; see submit-authority.test.ts's @ts-expect-error cases.
export function mintSettlementAuthority(
  attemptId: string,
  path: LandingPathProof,
): SettlementAuthority {
  // refuse a duck-typed impostor that only type-asserts as LandingPathProof.
  if (!isLandingPathProof(path)) {
    throw new Error("settlement authority requires an issued landing path proof");
  }
  return { [settlementAuthorityBrand]: true, attemptId, path };
}

export function isSettlementAuthority(value: unknown): value is SettlementAuthority {
  return typeof value === "object" && value !== null && settlementAuthorityBrand in value;
}

export function isSubmitAcknowledgement(value: unknown): value is SubmitAcknowledgement {
  return typeof value === "object" && value !== null && submitAcknowledgementBrand in value;
}

// A durable, persisted single-shot claim that the submitter crossed the call boundary for one
// immutable attempt (step 9; axiom 4:
// "Exact attempt identity survives crashes"). The database enforces "minted at most once per
// attempt" (a uniqueness constraint outside this pure-types package); this module's
// contribution is that every reconcile decision function in this concern (receive.ts, move.ts,
// send.ts) requires the caller to state, as durable input evidence, whether a SubmitClaim
// exists for the attempt — PROVEN_NOT_STARTED is reachable only on the branch where none does.
export interface SubmitClaim {
  readonly attemptId: string;
  readonly claimedAt: string;
}

export function mintSubmitClaim(attemptId: string, claimedAt: string): SubmitClaim {
  return { attemptId, claimedAt };
}
