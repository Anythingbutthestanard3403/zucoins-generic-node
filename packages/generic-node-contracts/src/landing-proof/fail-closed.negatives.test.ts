import { describe, expect, it } from "vitest";

import { type IndeterminateCause } from "./fail-closed.contract.ts";
import { classifyLanding, type LandingEvidence } from "./landing-determination.ts";

/** A clean, fresh-head-anchored, complete, re-verified proof — the only shape that lands. */
const LANDED_BASE: LandingEvidence = {
  freshHead: "AUTHORITATIVE",
  invariantAnomaly: false,
  indexCollisionOnPath: false,
  walkOutcome: "COMPLETE_CONTIGUOUS",
  reverify: "STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH",
  attestedPredicatesEstablished: true,
};

/** One fail-closed vector per cause class: the single axis that forces exactly that INDETERMINATE cause. */
const CAUSE_VECTORS: ReadonlyArray<{
  readonly cause: IndeterminateCause;
  readonly evidence: LandingEvidence;
}> = [
  { cause: "INVARIANT_ANOMALY", evidence: { ...LANDED_BASE, invariantAnomaly: true } },
  { cause: "ENDPOINT_CONFLICT", evidence: { ...LANDED_BASE, freshHead: "ENDPOINT_CONFLICT" } },
  { cause: "FRESH_HEAD_UNAVAILABLE", evidence: { ...LANDED_BASE, freshHead: "STALE_OR_UNVERIFIED" } },
  { cause: "WORK_BUDGET_EXHAUSTED", evidence: { ...LANDED_BASE, walkOutcome: "INCOMPLETE_BUDGET_EXHAUSTED" } },
  { cause: "WALK_CYCLE", evidence: { ...LANDED_BASE, walkOutcome: "INCOMPLETE_CYCLE" } },
  { cause: "INDEX_COLLISION", evidence: { ...LANDED_BASE, indexCollisionOnPath: true } },
  { cause: "WALK_AMBIGUOUS_HOP", evidence: { ...LANDED_BASE, walkOutcome: "INCOMPLETE_AMBIGUOUS_HOP" } },
  { cause: "WALK_MISSING_HOP", evidence: { ...LANDED_BASE, walkOutcome: "INCOMPLETE_MISSING_HOP" } },
  { cause: "EXPECTED_BODY_ABSENT_FROM_PATH", evidence: { ...LANDED_BASE, reverify: null } },
  { cause: "REVERIFY_REJECTED", evidence: { ...LANDED_BASE, reverify: "REJECTED" } },
  { cause: "PREDICATE_UNVERIFIABLE", evidence: { ...LANDED_BASE, attestedPredicatesEstablished: false } },
];

describe("the landing-proof e2e fail-closed negatives (one per cause class)", () => {
  it("the base evidence is the clean landed control", () => {
    const result = classifyLanding(LANDED_BASE);
    expect(result.outcome).toBe("LANDED_COMPLETE_PATH");
    expect(result.cause).toBeNull();
  });

  for (const { cause, evidence } of CAUSE_VECTORS) {
    it(`${cause}: fails closed to INDETERMINATE with zero authority, never a landing or a not-landing`, () => {
      const result = classifyLanding(evidence);
      expect(result.outcome).toBe("INDETERMINATE");
      expect(result.cause).toBe(cause);
      // Never a positive landing, never a (non-existent) not-landing.
      expect(result.outcome).not.toBe("LANDED_EXACT");
      expect(result.outcome).not.toBe("LANDED_COMPLETE_PATH");
      expect(result.outcome).not.toMatch(/NOT.?LANDED/i);
      // Zero authority; the lease is held for new observations.
      expect(result.authority.mayConcludeLanded).toBe(false);
      expect(result.authority.mayConcludeNotLanded).toBe(false);
      expect(result.authority.mayRetryRebuildResubmit).toBe(false);
      expect(result.authority.mayReleaseLeaseOrReuse).toBe(false);
      expect(result.authority.mustHoldLeaseAndAwaitNewObservations).toBe(true);
    });
  }

  it("a complete genesis-to-head chain lacking the expected body is INDETERMINATE, never not-landed", () => {
    const completeButAbsent: LandingEvidence = { ...LANDED_BASE, reverify: null };
    const result = classifyLanding(completeButAbsent);
    expect(result.outcome).toBe("INDETERMINATE");
    expect(result.cause).toBe("EXPECTED_BODY_ABSENT_FROM_PATH");
    expect(result.authority.mayConcludeNotLanded).toBe(false);
  });

  it("precedence fails closed: an invariant anomaly dominates even an otherwise-clean exact proof", () => {
    const anomalousButOtherwiseLanded: LandingEvidence = {
      ...LANDED_BASE,
      reverify: "STRUCTURALLY_REVERIFIED_LANDED_EXACT",
      invariantAnomaly: true,
    };
    const result = classifyLanding(anomalousButOtherwiseLanded);
    expect(result.outcome).toBe("INDETERMINATE");
    expect(result.cause).toBe("INVARIANT_ANOMALY");
  });
});

describe("the landing-proof e2e re-walk semantics", () => {
  const missingHop: LandingEvidence = { ...LANDED_BASE, walkOutcome: "INCOMPLETE_MISSING_HOP" };

  it("re-interpreting identical evidence never changes the outcome (no default to landed or not-landed)", () => {
    const first = classifyLanding(missingHop);
    const second = classifyLanding(missingHop);
    expect(second).toEqual(first);
    expect(second.outcome).toBe("INDETERMINATE");
    expect(second.cause).toBe("WALK_MISSING_HOP");
  });

  it("only a NEW observation (the missing body appearing) can flip an INDETERMINATE to a landing", () => {
    const before = classifyLanding(missingHop);
    expect(before.outcome).toBe("INDETERMINATE");
    // The previously-missing predecessor body is newly observed: the walk now completes contiguously.
    const afterNewObservation: LandingEvidence = { ...missingHop, walkOutcome: "COMPLETE_CONTIGUOUS" };
    const after = classifyLanding(afterNewObservation);
    expect(after.outcome).toBe("LANDED_COMPLETE_PATH");
    expect(after.cause).toBeNull();
  });
});
