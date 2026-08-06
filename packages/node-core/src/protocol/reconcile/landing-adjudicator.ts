// Landing adjudicator — the observation-evidence verdict that an operation's exact
// transaction landed, stayed indeterminate, or is determinately contradicted.
// Per-operation verdict blocks: every predicate true -> VERIFIED; a cryptographically
// determinate mismatch -> REJECTED; read failure / anomaly / gap / regression / contradiction
// > INDETERMINATE. The any-depth complete-path landing oracle applies; there is no generic
// PROVEN_NOT_LANDED verdict.
//
// This is the landing half of operation verification only. It is a pure function of
// OBSERVATION EVIDENCE — the landing-path oracle landing-proof outcome (./landing-proof.js) and the
// chain-observable economic predicate (../economic-predicates.js) plus any observation-ledger
// anomaly — never of operation/business state, lease state, or node claims. Its verdict feeds
// the operation's landing verification; it grants no retry/rebuild/resubmit/release authority
// (the never-blind-retry rule) and, an incomplete proof folds to INDETERMINATE, never to a
// negative landing verdict.

import { type ObservationAnomalyKind } from "@zucoins/generic-node-contracts/observation";

import { type DeltaEvaluation, type DeltaRejectionReason } from "../economic-predicates.js";
import {
  isLandingPathProof,
  type LandingPathProof,
  type LandingProofFault,
  type LandingProofOutcome,
} from "./landing-proof.js";

export const LANDING_VERDICTS = ["LANDED", "INDETERMINATE", "REJECTED"] as const;
export type LandingVerdict = (typeof LANDING_VERDICTS)[number];

// Why a landing adjudication could not reach a positive or negative verdict. Every member is a
// distinct observation-evidence gap; none authorizes retry/rebuild/resubmit/release.
export type LandingIndeterminateReason =
  // Landing-path oracle: the any-depth complete-path proof did not complete (missing body, gap,
  // conflict, ...). "INDETERMINATE — not not-landed."
  | { readonly source: "LANDING_PROOF_INCOMPLETE"; readonly fault: LandingProofFault }
  // The fresh read itself failed or was anomalous, so no verdict can be formed
  // from it. Fail closed: this short-circuits a determinate economic mismatch, because a mismatch
  // derived from a compromised read is not a determinate mismatch.
  | { readonly source: "OBSERVATION_ANOMALY"; readonly anomaly: ObservationAnomalyKind }
  // The economic predicate passed but no positive landing-path oracle landing proof is present
  // (e.g. the candidate is not yet the verified head). Insufficient evidence to confirm landing.
  | { readonly source: "NO_POSITIVE_LANDING_PROOF" };

// Why a landing adjudication reached REJECTED: a cryptographically determinate mismatch in the
// chain-observable economic predicate ("a cryptographically determinate mismatch ->
// REJECTED for this operation, while retaining evidence"). This is NOT a generic
// PROVEN_NOT_LANDED conclusion (landing-path oracle) — it is positive evidence that the observed candidate
// transaction cannot be this operation's landing (wrong delta, broken chain link, misbound key).
export type LandingRejectionReason = {
  readonly source: "ECONOMIC_PREDICATE_MISMATCH";
  readonly reason: DeltaRejectionReason;
  readonly detail: string;
};

export type LandingAdjudication =
  | { readonly verdict: "LANDED"; readonly proof: LandingPathProof }
  | { readonly verdict: "INDETERMINATE"; readonly reason: LandingIndeterminateReason }
  | { readonly verdict: "REJECTED"; readonly reason: LandingRejectionReason };

// The observation evidence for one operation path's landing adjudication:
// `landingProof`: the landing-path oracle outcome for the path (positive proof or incomplete fault);
// - `economic`: the chain-observable economic-predicate evaluation of the candidate transaction
// against the operation baseline (the delta/link/binding half);
// - `observationAnomaly`: present when the observation-ledger classified the fresh read as
// anomalous (relationship anomaly / fail-closed action).
export interface LandingAdjudicationEvidence {
  readonly landingProof: LandingProofOutcome;
  readonly economic: DeltaEvaluation;
  readonly observationAnomaly?: ObservationAnomalyKind;
}

// Adjudicate one operation path's landing from observation evidence alone. Precedence is
// fail-closed: a compromised read (anomaly) -> INDETERMINATE before any mismatch is trusted; a
// determinate economic mismatch -> REJECTED; a positive proof with a passing predicate ->
// LANDED; otherwise (incomplete proof, or no positive proof) -> INDETERMINATE.
export function adjudicateLanding(evidence: LandingAdjudicationEvidence): LandingAdjudication {
  if (evidence.observationAnomaly !== undefined) {
    return {
      verdict: "INDETERMINATE",
      reason: { source: "OBSERVATION_ANOMALY", anomaly: evidence.observationAnomaly },
    };
  }

  if (!evidence.economic.ok) {
    return {
      verdict: "REJECTED",
      reason: {
        source: "ECONOMIC_PREDICATE_MISMATCH",
        reason: evidence.economic.reason,
        detail: evidence.economic.detail,
      },
    };
  }

  if (evidence.landingProof.kind === "PROOF_INCOMPLETE") {
    return {
      verdict: "INDETERMINATE",
      reason: { source: "LANDING_PROOF_INCOMPLETE", fault: evidence.landingProof.fault },
    };
  }

  // a positive structural object is not authority. Only an issued oracle capability
  // (WeakSet identity + brand from landing-proof.ts) can yield LANDED. Impostors fold to
  // INDETERMINATE — never a phantom settle.
  if (!isLandingPathProof(evidence.landingProof)) {
    return {
      verdict: "INDETERMINATE",
      reason: { source: "NO_POSITIVE_LANDING_PROOF" },
    };
  }

  // The only positive landing verdict: a completed landing-path oracle proof whose candidate also satisfies the
  // chain-observable economic predicate. LANDED_EXACT (depth 0) and LANDED_COMPLETE_PATH
  // (depth >= 1) are both positive proofs; the depth is carried through on `proof`.
  return { verdict: "LANDED", proof: evidence.landingProof };
}
