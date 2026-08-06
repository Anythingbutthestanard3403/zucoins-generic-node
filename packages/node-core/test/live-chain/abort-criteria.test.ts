import { describe, expect, it } from "vitest";

import {
  MOVE_ABORT_POLICY_ID,
  abortActionFor,
  moveInternalAbortCriteria,
  type MoveAbortTrigger,
} from "./abort-criteria.js";

describe("moveInternalAbortCriteria", () => {
  it("forbids blind retry and requires the positive non-landing oracle for rebuild", () => {
    const criteria = moveInternalAbortCriteria();
    expect(criteria.policyId).toBe(MOVE_ABORT_POLICY_ID);
    expect(criteria.blindRetryForbidden).toBe(true);
    expect(criteria.rebuildRequiresPositiveNonLandingOracle).toBe(true);
  });

  it("never licenses resubmit or rebuild-without-oracle on any trigger", () => {
    const criteria = moveInternalAbortCriteria();
    for (const rule of criteria.rules) {
      expect(rule.mayResubmit).toBe(false);
      expect(rule.mayRebuildWithoutPositiveOracle).toBe(false);
    }
  });

  it("routes ambiguity to hold-both-leases-and-reconcile (the never-blind-retry rule)", () => {
    const rule = abortActionFor("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    expect(rule.action).toBe("HOLD_BOTH_LEASES_AND_RECONCILE");
    expect(rule.detail).toMatch(/positive non-landing evidence/);
    expect(rule.detail.toLowerCase()).not.toMatch(/just retry|blind.?retry and resubmit/);
  });

  it("routes invariant breach to escalate without release", () => {
    const rule = abortActionFor("INVARIANT_BREACH");
    expect(rule.action).toBe("ESCALATE_INVARIANT_BREACH");
    expect(rule.detail).toMatch(/no second submit/i);
  });

  it("covers every closed trigger", () => {
    const triggers: MoveAbortTrigger[] = [
      "SUBMIT_REJECTED",
      "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
      "INVARIANT_BREACH",
      "LANDED_VERIFIED",
      "OPERATOR_HALT",
    ];
    const criteria = moveInternalAbortCriteria();
    expect(criteria.rules.map((r) => r.trigger).sort()).toEqual([...triggers].sort());
  });
});
