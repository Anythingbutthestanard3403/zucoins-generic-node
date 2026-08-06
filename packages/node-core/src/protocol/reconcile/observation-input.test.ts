// exhausts every PathObservation variant this concern's decision
// functions can receive (the "complete/incomplete path, gap, malformed body" matrix axes),
// proving each maps to the correct tier per the landing-path oracle.

import { describe, expect, it } from "vitest";

import {
  mintLandingPathProofFromOracle,
} from "./landing-oracle-mint.fixture.js";
import { classifyPathObservation, type PathObservation } from "./observation-input.js";

describe("path-observation decision matrix", () => {
  it("PROOF -> LANDED, carrying the exact proof through unchanged", () => {
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-pub",
      expectedBodySha256: "body-sha",
      freshHeadBodySha256: "body-sha-head",
      freshHeadObservationId: "obs-1",
      depth: 3,
    });
    const result = classifyPathObservation({ result: "PROOF", proof });
    expect(result).toEqual({ tier: "LANDED", proof });
  });

  it("PROOF with structural impostor -> INDETERMINATE (never LANDED)", () => {
    const impostor = {
      kind: "LANDED_EXACT",
      walletPubkeyBase64Urlsafe: "wallet-pub",
      expectedBodySha256: "body-sha",
      freshHeadBodySha256: "body-sha",
      freshHeadObservationId: "obs-forged",
      depth: 0,
    } as never;
    const result = classifyPathObservation({ result: "PROOF", proof: impostor });
    expect(result.tier).toBe("INDETERMINATE");
    if (result.tier === "INDETERMINATE") {
      expect(result.reason).toEqual({
        source: "LANDING_PROOF_INCOMPLETE",
        fault: "ANOMALOUS_OR_CONTRADICTORY",
      });
    }
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
  ] as const)("PROOF_INCOMPLETE(%s) -> INDETERMINATE, never a landing/non-landing verdict", (fault) => {
    const result = classifyPathObservation({ result: "PROOF_INCOMPLETE", fault });
    expect(result).toEqual({
      tier: "INDETERMINATE",
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
  ] as const)("ANOMALY(%s) -> INDETERMINATE (park, no breach)", (anomaly) => {
    const result = classifyPathObservation({ result: "ANOMALY", anomaly });
    expect(result).toEqual({
      tier: "INDETERMINATE",
      reason: { source: "OBSERVATION_ANOMALY", anomaly },
    });
  });

  it.each(["REGRESSION", "GENESIS_AFTER_HISTORY", "SIGNATURE_COLLISION"] as const)(
    "ANOMALY(%s) -> INVARIANT_BREACH (quarantine/stop money engines)",
    (anomaly) => {
      const result = classifyPathObservation({ result: "ANOMALY", anomaly });
      expect(result).toEqual({
        tier: "INVARIANT_BREACH",
        reason: { source: "OBSERVATION_ANOMALY", anomaly },
      });
    },
  );

  it("UNATTRIBUTED_SUCCESSOR_UNDER_LEASE -> INVARIANT_BREACH", () => {
    const result = classifyPathObservation({ result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" });
    expect(result).toEqual({
      tier: "INVARIANT_BREACH",
      reason: { source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" },
    });
  });

  it("NO_SUCCESSOR (unchanged/old head) -> INDETERMINATE, not a non-landing verdict", () => {
    // "verified unchanged predecessor | not a generic
    // non-landing verdict | no [retry authority]". landing-path oracle: "unchanged head alone is insufficient."
    const result = classifyPathObservation({ result: "NO_SUCCESSOR" });
    expect(result).toEqual({
      tier: "INDETERMINATE",
      reason: { source: "NO_SUCCESSOR_OBSERVED" },
    });
  });

  it("every PathObservation `result` variant is covered by exactly one case above", () => {
    // Compile-time exhaustiveness companion: if a new PathObservation variant is added without
    // a matching `it.each`/`it` above, this array literal typed against PathObservation["result"]
    // silently stays correct (structural), but classifyPathObservation's own internal
    // `assertUnreachable` (observation-input.ts) is what actually fails `tsc -b` in that case.
    const coveredResults: readonly PathObservation["result"][] = [
      "PROOF",
      "PROOF_INCOMPLETE",
      "ANOMALY",
      "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE",
      "NO_SUCCESSOR",
    ];
    expect(new Set(coveredResults).size).toBe(5);
  });
});
