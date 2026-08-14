import { describe, expect, it } from "vitest";
import {
  AUTOMATIC_SINK_CONJUNCTS,
  COMPOSITION_SINK_STATES,
  CUSTODY_BINDING_OBLIGATIONS,
  CUSTODY_EVIDENCE_REQUIREMENTS,
  DESTINATION_STATES,
  INTERNAL_CUSTODY_CONJUNCTS,
  WALLET_KEY_ORIGINS,
  WALLET_STATES,
  WORKER_SINK_CONJUNCTS,
} from "./predicates.contract.ts";

describe("custody predicates are frozen (the custody concern; R-03)", () => {
  it("defines internal custody as node-generated and blessed only", () => {
    expect(INTERNAL_CUSTODY_CONJUNCTS).toEqual({ keyOrigin: "node_generated", destinationState: "BLESSED" });
  });
  it("adds valid recovery and AVAILABLE/PINNED for an automatic sink", () => {
    expect(AUTOMATIC_SINK_CONJUNCTS).toEqual({
      requiresInternalCustody: true,
      requiresValidRecoveryVerifiedAt: true,
      allowedWalletStates: ["AVAILABLE", "PINNED"],
    });
  });
  it("freezes the complete known vocabularies", () => {
    expect(WALLET_KEY_ORIGINS).toEqual(["node_generated", "imported"]);
    expect(DESTINATION_STATES).toEqual(["PENDING", "BLESSED", "RETIRED", "WORKER"]);
    expect(WORKER_SINK_CONJUNCTS).toEqual({
      keyOrigin: "node_generated",
      destinationState: "WORKER",
      requiresValidRecoveryVerifiedAt: false,
      allowedWalletStates: ["AVAILABLE", "PINNED"],
    });
    expect(COMPOSITION_SINK_STATES).toEqual(["BLESSED", "WORKER"]);
    expect(WALLET_STATES).toEqual(["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"]);
  });
  it("keeps ceremony evidence separate from structural obligations", () => {
    expect(CUSTODY_EVIDENCE_REQUIREMENTS).not.toBe(CUSTODY_BINDING_OBLIGATIONS);
    expect(CUSTODY_EVIDENCE_REQUIREMENTS.recovery).toContain("AUDITED_EXPORT");
    expect(CUSTODY_BINDING_OBLIGATIONS.recoveryNeverUpgradesOrigin).toBe(true);
  });
});
