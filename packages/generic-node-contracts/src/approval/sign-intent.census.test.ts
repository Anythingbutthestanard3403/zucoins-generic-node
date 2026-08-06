import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  FORMATION_STATES,
  FORMATION_TRANSITIONS,
  APPROVAL_CARDINALITY,
  SIGN_INTENT_BOUND_INPUTS,
  SIGN_INTENT_FROZEN_AFTER_EXISTS,
  APPROVAL_CONSUMPTION,
  REDELIVERY_RULE,
  REPLACEMENT_RULE,
  TIMER_SEPARATION,
  STRUCTURAL_UNIQUENESS,
} from "./sign-intent.contract.ts";

describe("one-approval → one-sign-intent → one-partial census", () => {
  it("freezes the formation-state sequence", () => {
    assertFieldOrder(FORMATION_STATES, [
      "APPROVED_UNSIGNED",
      "SIGNING_CLAIMED",
      "PARTIAL_PERSISTED",
      "PARTIAL_DELIVERED",
      "AWAITING_REDEMPTION",
    ]);
  });

  it("freezes a single linear forward path — no state forks into a second partial", () => {
    // Each transition's target is the next transition's source: one successor per state.
    for (let i = 0; i < FORMATION_TRANSITIONS.length - 1; i += 1) {
      expect(FORMATION_TRANSITIONS[i].to).toBe(FORMATION_TRANSITIONS[i + 1].from);
    }
    // No source state appears twice (no branching).
    const froms = FORMATION_TRANSITIONS.map((t) => t.from);
    expect(new Set(froms).size).toBe(froms.length);
    // The chain spans APPROVED_UNSIGNED → AWAITING_REDEMPTION.
    expect(FORMATION_TRANSITIONS[0].from).toBe("APPROVED_UNSIGNED");
    expect(FORMATION_TRANSITIONS[FORMATION_TRANSITIONS.length - 1].to).toBe("AWAITING_REDEMPTION");
    // The two crash-safety fences are named on the first two transitions.
    expect(FORMATION_TRANSITIONS[0].guard).toContain("persist_sign_intent_before_signer");
    expect(FORMATION_TRANSITIONS[1].guard).toContain("persist_partial_before_delivery");
  });

  it("freezes the one-approval cardinality: at most one of each downstream artifact", () => {
    expect(APPROVAL_CARDINALITY.signIntent.maxPerApproval).toBe(1);
    expect(APPROVAL_CARDINALITY.stepOneSignature.maxPerApproval).toBe(1);
    expect(APPROVAL_CARDINALITY.persistedPartial.maxPerApproval).toBe(1);
    expect(APPROVAL_CARDINALITY.externallyObservableCode.maxPerApproval).toBe(1);
  });

  it("freezes the sign-intent bound inputs", () => {
    assertFieldOrder(SIGN_INTENT_BOUND_INPUTS, [
      "consumed_approval_id",
      "source_observation_id",
      "destination_observation_id",
      "lease_group",
      "lease_epoch",
      "inner_preimage_text",
      "inner_digest",
    ]);
  });

  it("freezes the bytes immutable once a sign intent exists (no re-form of link/time/expiry)", () => {
    assertClosedSet(SIGN_INTENT_FROZEN_AFTER_EXISTS, [
      "inner_preimage_text",
      "inner_digest",
      "chain_link",
      "redemption_time",
      "redemption_expiry",
      "destination_address",
      "amount_zkz",
    ]);
  });

  it("freezes approval consumption + burn-on-failure with no restoration", () => {
    expect(APPROVAL_CONSUMPTION.consumedBeforeMutation).toBe(true);
    expect(APPROVAL_CONSUMPTION.burnOnSignerFailure).toBe(true);
    expect(APPROVAL_CONSUMPTION.burnOnPersistenceFailure).toBe(true);
    expect(APPROVAL_CONSUMPTION.burnOnDeliveryFailure).toBe(true);
    expect(APPROVAL_CONSUMPTION.burnOnGatewayFailure).toBe(true);
    expect(APPROVAL_CONSUMPTION.restoredAfterDownstreamFailure).toBe(false);
  });

  it("freezes redelivery as byte-identical-persisted-only", () => {
    expect(REDELIVERY_RULE).toBe("byte_identical_persisted_partial_only");
  });

  it("freezes the two-timer separation: approval freshness ≠ redemption deadline", () => {
    expect(TIMER_SEPARATION.t1ApprovalChallengeFreshness.source).toBe("approval_tuple.expires_at");
    expect(TIMER_SEPARATION.t1ApprovalChallengeFreshness.refreshableWhilePreConsumption).toBe(true);
    expect(TIMER_SEPARATION.t1ApprovalChallengeFreshness.frozenAtConsumption).toBe(true);
    expect(TIMER_SEPARATION.t1ApprovalChallengeFreshness.isRedemptionDeadline).toBe(false);
    expect(TIMER_SEPARATION.t2RedemptionExpiry.source).toBe("signed_splitchain_inner.expiry");
    expect(TIMER_SEPARATION.t2RedemptionExpiry.materializedAt).toBe("sign_intent_formation");
    expect(TIMER_SEPARATION.t2RedemptionExpiry.byteFrozenAfterFormation).toBe(true);
    expect(TIMER_SEPARATION.t2RedemptionExpiry.isSingleImmutableRedemptionDeadline).toBe(true);
  });

  it("rejects a second sign intent under one approval (negative: cardinality > 1)", () => {
    expectRejects(
      () => 2,
      (claimedCount) => {
        if (claimedCount > APPROVAL_CARDINALITY.signIntent.maxPerApproval) {
          throw new Error("a second sign intent under one approval violates the one-approval cardinality invariant");
        }
      },
    );
  });

  it("rejects re-forming the preimage after the sign intent exists (negative)", () => {
    // inner_preimage_text is frozen-after-exists; a frozen set that dropped it is a broken contract.
    expectRejects(
      () => SIGN_INTENT_FROZEN_AFTER_EXISTS.filter((f) => f !== "inner_preimage_text"),
      (mutated) => assertClosedSet(mutated, SIGN_INTENT_FROZEN_AFTER_EXISTS),
    );
  });

  it("rejects a second partial or a refreshed expiry under the old approval (negative)", () => {
    expect(REPLACEMENT_RULE.permitsSecondPartialUnderOldApproval).toBe(false);
    expect(REPLACEMENT_RULE.refreshesExpiryUnderOldApproval).toBe(false);
    assertClosedSet(REPLACEMENT_RULE.requires, [
      "safe_resolution_of_existing_operation",
      "new_operation",
      "fresh_approval",
    ]);
    expectRejects(
      () => true, // a hypothetical "allow a second partial under the old approval" flag
      (allowSecondPartial) => {
        if (allowSecondPartial !== REPLACEMENT_RULE.permitsSecondPartialUnderOldApproval) {
          throw new Error("a second partial under the old approval violates the one-approval cardinality invariant");
        }
      },
    );
  });

  it("freezes structural uniqueness by operation_id, not lease_epoch", () => {
    expect(STRUCTURAL_UNIQUENESS.signIntentUniqueBy).toBe("operation_id");
    expect(STRUCTURAL_UNIQUENESS.stepOnePartialUniqueBy).toBe("operation_id");
    expect(STRUCTURAL_UNIQUENESS.uniquePerLeaseEpoch).toBe(false);
  });

  it("freezes lease-epoch preservation across recovery and boot reconciliation", () => {
    expect(STRUCTURAL_UNIQUENESS.recoveryCompletesUnderOriginallyBoundLeaseEpoch).toBe(true);
    expect(STRUCTURAL_UNIQUENESS.bootReconciliationMintsNewEpochForInFlightFormation).toBe(false);
    expect(STRUCTURAL_UNIQUENESS.bootReconciliationAdoptsExistingLeaseAtExistingEpoch).toBe(true);
    // lease_epoch is one of the bound inputs recovery must complete under, unchanged.
    expect(SIGN_INTENT_BOUND_INPUTS).toContain("lease_epoch");
  });

  it("rejects minting a new lease epoch for an in-flight formation (negative)", () => {
    expectRejects(
      () => true, // a hypothetical "boot may mint a fresh epoch under an in-flight formation" flag
      (mintsNewEpoch) => {
        if (mintsNewEpoch !== STRUCTURAL_UNIQUENESS.bootReconciliationMintsNewEpochForInFlightFormation) {
          throw new Error("minting a new lease epoch under an in-flight formation violates lease-epoch preservation");
        }
      },
    );
  });
});
