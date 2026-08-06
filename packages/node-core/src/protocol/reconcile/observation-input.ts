// Shared normalization of one wallet path's fresh observation
// evidence into the LANDED / INDETERMINATE / INVARIANT_BREACH split.
// Observation and lineage anomalies. Reused by receive.ts, move.ts, and send.ts so this split
// is defined exactly once and cannot drift between the three operation kinds.

import {
  type ObservationAnomalyKind,
} from "@zucoins/generic-node-contracts/observation";

import {
  isLandingPathProof,
  type LandingPathProof,
  type LandingProofFault,
} from "./landing-proof.js";
import {
  type InvariantBreachObservationAnomaly,
  type ReconcileIndeterminateReason,
  type ReconcileInvariantBreachReason,
  assertUnreachable,
} from "./types.js";

const INVARIANT_BREACH_ANOMALIES: readonly ObservationAnomalyKind[] = [
  "REGRESSION",
  "GENESIS_AFTER_HISTORY",
  "SIGNATURE_COLLISION",
];

function isInvariantBreachAnomaly(
  anomaly: ObservationAnomalyKind,
): anomaly is InvariantBreachObservationAnomaly {
  return (INVARIANT_BREACH_ANOMALIES as readonly string[]).includes(anomaly);
}

// What a fresh read for one wallet path yielded. `PROOF` is a completed landing-path oracle landing proof;
// `PROOF_INCOMPLETE` is a landing-oracle fault (point 10); `ANOMALY` is an
// Relationship anomaly recorded on the observation ledger;
// `UNATTRIBUTED_SUCCESSOR_UNDER_LEASE` is the "unknown or unattributed deep successor while a
// wallet remains actively leased"; `NO_SUCCESSOR` is the "verified unchanged predecessor"
// row — a clean bounded read that found no successor, no anomaly, and no contradiction.
export type PathObservation =
  | { readonly result: "PROOF"; readonly proof: LandingPathProof }
  | { readonly result: "PROOF_INCOMPLETE"; readonly fault: LandingProofFault }
  | { readonly result: "ANOMALY"; readonly anomaly: ObservationAnomalyKind }
  | { readonly result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" }
  | { readonly result: "NO_SUCCESSOR" };

export type PathClassification =
  | { readonly tier: "LANDED"; readonly proof: LandingPathProof }
  | { readonly tier: "INDETERMINATE"; readonly reason: ReconcileIndeterminateReason }
  | { readonly tier: "INVARIANT_BREACH"; readonly reason: ReconcileInvariantBreachReason };

export function classifyPathObservation(observation: PathObservation): PathClassification {
  switch (observation.result) {
    case "PROOF":
      // refuse duck-typed / unissued "proofs". Only WeakSet-issued capabilities land.
      if (!isLandingPathProof(observation.proof)) {
        return {
          tier: "INDETERMINATE",
          reason: {
            source: "LANDING_PROOF_INCOMPLETE",
            fault: "ANOMALOUS_OR_CONTRADICTORY",
          },
        };
      }
      return { tier: "LANDED", proof: observation.proof };
    case "PROOF_INCOMPLETE":
      return {
        tier: "INDETERMINATE",
        reason: { source: "LANDING_PROOF_INCOMPLETE", fault: observation.fault },
      };
    case "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE":
      return {
        tier: "INVARIANT_BREACH",
        reason: { source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" },
      };
    case "NO_SUCCESSOR":
      return { tier: "INDETERMINATE", reason: { source: "NO_SUCCESSOR_OBSERVED" } };
    case "ANOMALY":
      if (isInvariantBreachAnomaly(observation.anomaly)) {
        return {
          tier: "INVARIANT_BREACH",
          reason: { source: "OBSERVATION_ANOMALY", anomaly: observation.anomaly },
        };
      }
      return {
        tier: "INDETERMINATE",
        reason: { source: "OBSERVATION_ANOMALY", anomaly: observation.anomaly },
      };
    default:
      return assertUnreachable(observation);
  }
}
