// Custody selection/commit-boundary denial proofs.
// Two denial classes beyond predicate-verifier.test.ts's per-field coverage:
// concurrently-changed facts between selection and commit, and wrong-tenant selection
// (proven tenant-blind here, closed structurally by the custody concern.2 schema contract plus
// the selection-scoping obligation recorded in CONTRACT.md).
import { describe, expect, it } from "vitest";
import {
  CUSTODY_BINDING_OBLIGATIONS,
} from "./predicates.contract.ts";
import {
  verifyAutomaticSinkEligibility,
  verifyInternalCustody,
  type CustodyPredicateFacts,
} from "./predicate-verifier.ts";

const eligibleAtSelection: CustodyPredicateFacts = {
  keyOrigin: "node_generated",
  destinationState: "BLESSED",
  recoveryVerifiedAt: "2026-07-19T10:00:00Z",
  walletState: "AVAILABLE",
};

describe("the custody selection/commit boundary selection/commit boundary (C-07 negative evidence)", () => {
  it("frozen obligation: all conjuncts re-checked at execution time", () => {
    expect(CUSTODY_BINDING_OBLIGATIONS.selectionRecheck).toBe(
      "RECHECK_ALL_CONJUNCTS_AT_EXECUTION_TIME",
    );
  });

  it("selection-time verdict is eligible for the baseline facts", () => {
    expect(verifyAutomaticSinkEligibility(eligibleAtSelection)).toEqual({
      eligible: true,
      denialReason: null,
    });
  });

  it("commit-time re-check denies a wallet quarantined after selection", () => {
    const atCommit = { ...eligibleAtSelection, walletState: "QUARANTINED" };
    expect(verifyAutomaticSinkEligibility(atCommit)).toEqual({
      eligible: false,
      denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE",
    });
  });

  it("commit-time re-check denies a destination retired after selection", () => {
    const atCommit = { ...eligibleAtSelection, destinationState: "RETIRED" };
    expect(verifyAutomaticSinkEligibility(atCommit)).toEqual({
      eligible: false,
      denialReason: "DESTINATION_NOT_BLESSED",
    });
    expect(verifyInternalCustody(atCommit).eligible).toBe(false);
  });

  it("commit-time re-check denies when recovery evidence is absent at commit", () => {
    const atCommit = { ...eligibleAtSelection, recoveryVerifiedAt: null };
    expect(verifyAutomaticSinkEligibility(atCommit)).toEqual({
      eligible: false,
      denialReason: "INVALID_RECOVERY_VERIFIED_AT",
    });
  });

  it("commit-time re-check denies a wallet retired after selection", () => {
    const atCommit = { ...eligibleAtSelection, walletState: "RETIRED" };
    expect(verifyAutomaticSinkEligibility(atCommit).eligible).toBe(false);
  });

  it("the pure predicate is tenant-blind by frozen construction", () => {
    // The frozen CustodyPredicateFacts shape carries no tenant identity, so tenant
    // isolation is not expressible here: identical facts from different tenants produce
    // identical verdicts. The denial lives at the structural layer — the custody concern.2 schema
    // contract rejects cross-tenant destination rows (CUSTODY_TENANT_MISMATCH_REJECTED)
    // and every selection query is scoped by node_id per the data model (obligation
    // recorded in CONTRACT.md).
    const foreignTenantFacts = {
      ...eligibleAtSelection,
      nodeId: "some-other-node",
      implementerId: "some-other-implementer",
    };
    expect(verifyAutomaticSinkEligibility(foreignTenantFacts)).toEqual(
      verifyAutomaticSinkEligibility(eligibleAtSelection),
    );
    const factKeys = Object.keys(eligibleAtSelection).sort();
    expect(factKeys).toEqual([
      "destinationState",
      "keyOrigin",
      "recoveryVerifiedAt",
      "walletState",
    ]);
  });

  it("consolidation negative: a merely internal-custody wallet is not a sink", () => {
    const internalOnly = { ...eligibleAtSelection, recoveryVerifiedAt: null };
    expect(verifyInternalCustody(internalOnly)).toEqual({
      eligible: true,
      denialReason: null,
    });
    expect(verifyAutomaticSinkEligibility(internalOnly).eligible).toBe(false);
  });
});
