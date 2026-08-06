// Landing adjudicator decision matrix.
// verdict blocks: every predicate true -> LANDED; a cryptographically determinate mismatch ->
// REJECTED; read failure / anomaly / gap / contradiction -> INDETERMINATE) and / landing-path oracle
// (an incomplete complete-path proof folds to INDETERMINATE, never to a negative verdict).

import { describe, expect, it } from "vitest";

import { type DeltaEvaluation } from "../economic-predicates.js";
import {
  adjudicateLanding,
  LANDING_VERDICTS,
  type LandingAdjudicationEvidence,
} from "./landing-adjudicator.js";
import {
  type LandingProofFailure,
} from "./landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "./landing-oracle-mint.fixture.js";

const ECONOMIC_OK: DeltaEvaluation = { ok: true };

function economicMismatch(
  reason: "balance_delta_mismatch" | "chain_link_mismatch" | "artifact_binding_mismatch",
  detail: string,
): DeltaEvaluation {
  return { ok: false, reason, detail };
}

function proofIncomplete(fault: LandingProofFailure["fault"]): LandingProofFailure {
  return { kind: "PROOF_INCOMPLETE", fault };
}

describe("landing adjudicator — observation-evidence verdict", () => {
  it("exposes exactly the closed LANDED / INDETERMINATE / REJECTED verdict set", () => {
    expect(LANDING_VERDICTS).toEqual(["LANDED", "INDETERMINATE", "REJECTED"]);
  });

  it("LANDED_EXACT (depth 0) + passing economic predicate -> LANDED, carrying the proof through", () => {
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-pub",
      expectedBodySha256: "body-sha",
      freshHeadBodySha256: "body-sha",
      freshHeadObservationId: "obs-1",
      depth: 0,
    });
    const evidence: LandingAdjudicationEvidence = { landingProof: proof, economic: ECONOMIC_OK };
    expect(adjudicateLanding(evidence)).toEqual({ verdict: "LANDED", proof });
  });

  it("LANDED_COMPLETE_PATH (depth >= 1) + passing economic predicate -> LANDED", () => {
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-pub",
      expectedBodySha256: "body-sha",
      freshHeadBodySha256: "body-sha-head",
      freshHeadObservationId: "obs-9",
      depth: 3,
    });
    const evidence: LandingAdjudicationEvidence = { landingProof: proof, economic: ECONOMIC_OK };
    expect(adjudicateLanding(evidence)).toEqual({ verdict: "LANDED", proof });
  });

  it("a determinate economic mismatch -> REJECTED even when a positive proof is present", () => {
    // "a cryptographically determinate mismatch -> REJECTED for this operation, while
    // retaining evidence." A balance that moved the wrong direction contradicts landing.
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-pub",
      expectedBodySha256: "body-sha",
      freshHeadBodySha256: "body-sha",
      freshHeadObservationId: "obs-1",
      depth: 0,
    });
    const economic = economicMismatch("balance_delta_mismatch", "expected 5, computed 4.999");
    expect(adjudicateLanding({ landingProof: proof, economic })).toEqual({
      verdict: "REJECTED",
      reason: {
        source: "ECONOMIC_PREDICATE_MISMATCH",
        reason: "balance_delta_mismatch",
        detail: "expected 5, computed 4.999",
      },
    });
  });

  it("a determinate chain-link mismatch -> REJECTED (candidate does not connect to baseline)", () => {
    const economic = economicMismatch("chain_link_mismatch", "candidate P != baseline S");
    expect(adjudicateLanding({ landingProof: proofIncomplete("GAP"), economic })).toEqual({
      verdict: "REJECTED",
      reason: {
        source: "ECONOMIC_PREDICATE_MISMATCH",
        reason: "chain_link_mismatch",
        detail: "candidate P != baseline S",
      },
    });
  });

  it.each([
    "MISSING_BODY",
    "GAP",
    "CONFLICT",
    "DUPLICATE",
    "CYCLE",
    "MALFORMED_BODY",
    "ANOMALOUS_OR_CONTRADICTORY",
    "BUDGET_EXHAUSTED",
  ] as const)("incomplete proof (%s) + passing economic predicate -> INDETERMINATE, never not-landed", (fault) => {
    // landing-path oracle: a missing back-link or intermediate body is "INDETERMINATE — not not-landed."
    const evidence: LandingAdjudicationEvidence = {
      landingProof: proofIncomplete(fault),
      economic: ECONOMIC_OK,
    };
    expect(adjudicateLanding(evidence)).toEqual({
      verdict: "INDETERMINATE",
      reason: { source: "LANDING_PROOF_INCOMPLETE", fault },
    });
  });

  it.each([
    "TRANSPORT_ERROR",
    "MALFORMED_ENVELOPE",
    "MALFORMED_TRANSACTION",
    "UNVERIFIED_SIGNATURE",
    "WALLET_ROLE_INVALID",
    "UNEXPLAINED_JUMP",
    "REGRESSION",
    "GENESIS_AFTER_HISTORY",
    "SIGNATURE_COLLISION",
  ] as const)("an observation anomaly (%s) -> INDETERMINATE (fail closed, no verdict from a bad read)", (anomaly) => {
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-pub",
      expectedBodySha256: "body-sha",
      freshHeadBodySha256: "body-sha",
      freshHeadObservationId: "obs-1",
      depth: 0,
    });
    const evidence: LandingAdjudicationEvidence = {
      landingProof: proof,
      economic: ECONOMIC_OK,
      observationAnomaly: anomaly,
    };
    expect(adjudicateLanding(evidence)).toEqual({
      verdict: "INDETERMINATE",
      reason: { source: "OBSERVATION_ANOMALY", anomaly },
    });
  });

  it("an observation anomaly short-circuits a determinate economic mismatch -> INDETERMINATE", () => {
    // A mismatch derived from a compromised read is not a determinate mismatch; fail closed.
    const economic = economicMismatch("balance_delta_mismatch", "expected 5, computed 0");
    const evidence: LandingAdjudicationEvidence = {
      landingProof: proofIncomplete("GAP"),
      economic,
      observationAnomaly: "UNVERIFIED_SIGNATURE",
    };
    expect(adjudicateLanding(evidence)).toEqual({
      verdict: "INDETERMINATE",
      reason: { source: "OBSERVATION_ANOMALY", anomaly: "UNVERIFIED_SIGNATURE" },
    });
  });

  it("no positive proof and no mismatch is still INDETERMINATE, not REJECTED (no generic not-landed verdict)", () => {
    // there is no generic PROVEN_NOT_LANDED verdict — absence of a positive proof is
    // insufficient evidence, never a negative landing conclusion.
    const evidence: LandingAdjudicationEvidence = {
      landingProof: proofIncomplete("BUDGET_EXHAUSTED"),
      economic: ECONOMIC_OK,
    };
    const result = adjudicateLanding(evidence);
    expect(result.verdict).toBe("INDETERMINATE");
  });
});
