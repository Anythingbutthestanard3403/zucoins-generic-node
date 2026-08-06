import { describe, expect, it } from "vitest";

import { assertClosedSet } from "../testkit/freeze.ts";
import { WALK_OUTCOMES } from "./linkage.contract.ts";
import { LANDING_CLASSIFICATIONS, MANIFEST_REVERIFY_FAILURES, REVERIFY_VERDICTS } from "./proof-manifest.contract.ts";
import {
  DEPTH_ONE_LANDING_IS_LANDED_COMPLETE_PATH,
  DETERMINATION_AUTHORITY,
  FAIL_CLOSED_INVARIANTS,
  FRESH_HEAD_STATUSES,
  INDETERMINATE_CAUSES,
  INDETERMINATE_CAUSE_TAXONOMY,
  INDETERMINATE_CAUSE_TO_WIRE_REASON,
  LANDING_DETERMINATIONS,
  LANDING_DETERMINATION_TO_WIRE,
  LANDING_WIRE_CLASSIFICATIONS,
  REWALK_SEMANTICS,
  WIRE_INDETERMINATE_REASONS,
  type LandingDeterminationOutcome,
} from "./fail-closed.contract.ts";
import { classifyLanding, type LandingEvidence } from "./landing-determination.ts";

/**
 * The full finite evidence input space (3·2·2·5·4·2 = 480 combinations). Budget exhaustion is no
 * longer an independent boolean axis — it is one of the five `WALK_OUTCOMES` values
 * (`INCOMPLETE_BUDGET_EXHAUSTED`), alongside `INCOMPLETE_CYCLE`, so the walk outcome carries every
 * termination mode and the drive stays exhaustive over the whole (re-derived) input type space.
 */
const ALL_EVIDENCE: readonly LandingEvidence[] = (() => {
  const out: LandingEvidence[] = [];
  const reverifyValues = [null, ...REVERIFY_VERDICTS] as const;
  for (const freshHead of FRESH_HEAD_STATUSES) {
    for (const invariantAnomaly of [false, true]) {
      for (const indexCollisionOnPath of [false, true]) {
        for (const walkOutcome of WALK_OUTCOMES) {
          for (const reverify of reverifyValues) {
            for (const attestedPredicatesEstablished of [false, true]) {
              out.push({
                freshHead,
                invariantAnomaly,
                indexCollisionOnPath,
                walkOutcome,
                reverify,
                attestedPredicatesEstablished,
              });
            }
          }
        }
      }
    }
  }
  return out;
})();

describe("the landing-proof e2e frozen vocabulary census", () => {
  it("the landing determination space is a closed 3-member set", () => {
    assertClosedSet([...LANDING_DETERMINATIONS], ["LANDED_EXACT", "LANDED_COMPLETE_PATH", "INDETERMINATE"]);
  });

  it("the positive determinations are exactly the landing-proof manifest builder's landing classifications", () => {
    const positives = LANDING_DETERMINATIONS.filter((d) => d !== "INDETERMINATE");
    assertClosedSet(positives, [...LANDING_CLASSIFICATIONS]);
  });

  it("the INDETERMINATE cause taxonomy is a closed set with no duplicates", () => {
    expect(new Set(INDETERMINATE_CAUSES).size).toBe(INDETERMINATE_CAUSES.length);
    assertClosedSet(
      [...INDETERMINATE_CAUSES],
      [
        "FRESH_HEAD_UNAVAILABLE",
        "ENDPOINT_CONFLICT",
        "WORK_BUDGET_EXHAUSTED",
        "INDEX_COLLISION",
        "WALK_AMBIGUOUS_HOP",
        "WALK_MISSING_HOP",
        "WALK_CYCLE",
        "EXPECTED_BODY_ABSENT_FROM_PATH",
        "REVERIFY_REJECTED",
        "PREDICATE_UNVERIFIABLE",
        "INVARIANT_ANOMALY",
      ],
    );
  });

  it("the fresh-head anchor statuses are a closed set", () => {
    assertClosedSet([...FRESH_HEAD_STATUSES], ["AUTHORITATIVE", "STALE_OR_UNVERIFIED", "ENDPOINT_CONFLICT"]);
  });

  it("the taxonomy documents every cause exactly once and nothing else", () => {
    const documented = INDETERMINATE_CAUSE_TAXONOMY.map((t) => t.cause);
    expect(new Set(documented).size).toBe(documented.length);
    assertClosedSet(documented, [...INDETERMINATE_CAUSES]);
    for (const entry of INDETERMINATE_CAUSE_TAXONOMY) {
      expect(entry.layer).toBe("EVIDENCE_INSUFFICIENCY");
      expect(entry.producedBy.length).toBeGreaterThan(0);
      expect(entry.source.length).toBeGreaterThan(0);
    }
  });

  it("the wire-vocabulary freeze: depth-1 is folded into LANDED_COMPLETE_PATH; wire classifications are closed", () => {
    expect(DEPTH_ONE_LANDING_IS_LANDED_COMPLETE_PATH).toBe(true);
    expect(LANDING_DETERMINATIONS).not.toContain("LANDED_DIRECT_SUCCESSOR");
    assertClosedSet([...LANDING_WIRE_CLASSIFICATIONS], ["EXPECTED_AT_HEAD", "EXPECTED_ANCESTOR"]);
    expect(LANDING_DETERMINATION_TO_WIRE.LANDED_EXACT).toBe("EXPECTED_AT_HEAD");
    expect(LANDING_DETERMINATION_TO_WIRE.LANDED_COMPLETE_PATH).toBe("EXPECTED_ANCESTOR");
  });

  it("the wire-vocabulary freeze: every INDETERMINATE cause projects to exactly one wire reason; mapping is surjective", () => {
    assertClosedSet(
      [...WIRE_INDETERMINATE_REASONS],
      ["MISSING_BODY", "LINK_GAP", "ANOMALY", "FRESH_HEAD_MISMATCH", "BUDGET_EXCEEDED"],
    );
    const projected = new Set<string>();
    for (const cause of INDETERMINATE_CAUSES) {
      const wire = INDETERMINATE_CAUSE_TO_WIRE_REASON[cause];
      expect(WIRE_INDETERMINATE_REASONS).toContain(wire);
      projected.add(wire);
    }
    assertClosedSet([...projected], [...WIRE_INDETERMINATE_REASONS]);
    expect(INDETERMINATE_CAUSE_TO_WIRE_REASON.WORK_BUDGET_EXHAUSTED).toBe("BUDGET_EXCEEDED");
    expect(INDETERMINATE_CAUSE_TO_WIRE_REASON.EXPECTED_BODY_ABSENT_FROM_PATH).toBe("MISSING_BODY");
  });
});

describe("the landing-proof e2e no PROVEN_NOT_LANDED — structurally impossible", () => {
  it("no determination or cause names a non-landing outcome", () => {
    for (const member of [...LANDING_DETERMINATIONS, ...INDETERMINATE_CAUSES]) {
      expect(member).not.toMatch(/NOT.?LANDED/i);
    }
  });

  it("the outcome type space cannot express a not-landed value (compile-time proof)", () => {
    // @ts-expect-error PROVEN_NOT_LANDED is not a member of LandingDeterminationOutcome (the complete-path landing-proof rule).
    const _notLanded: LandingDeterminationOutcome = "PROVEN_NOT_LANDED";
    expect(LANDING_DETERMINATIONS).not.toContain("PROVEN_NOT_LANDED");
  });

  it("no outcome in the entire authority contract authorizes concluding not-landed", () => {
    for (const grant of Object.values(DETERMINATION_AUTHORITY)) {
      expect(grant.mayConcludeNotLanded).toBe(false);
    }
    expect(FAIL_CLOSED_INVARIANTS.provenNotLandedExists).toBe(false);
    expect(FAIL_CLOSED_INVARIANTS.noOutcomeAuthorizesConcludingNotLanded).toBe(true);
  });
});

describe("the landing-proof e2e disjointness — INDETERMINATE causes vs the landing-proof manifest builder re-verify failures", () => {
  it("the two vocabularies share no member (census)", () => {
    const failureSet = new Set<string>(MANIFEST_REVERIFY_FAILURES);
    const overlap = INDETERMINATE_CAUSES.filter((c) => failureSet.has(c));
    expect(overlap).toEqual([]);
    expect(FAIL_CLOSED_INVARIANTS.causeVocabularyDisjointFromReverifyFailures).toBe(true);
  });

  it("REVERIFY_REJECTED is the single bridge from a structural REJECTED to an INDETERMINATE", () => {
    const clean: LandingEvidence = {
      freshHead: "AUTHORITATIVE",
      invariantAnomaly: false,
      indexCollisionOnPath: false,
      walkOutcome: "COMPLETE_CONTIGUOUS",
      reverify: "REJECTED",
      attestedPredicatesEstablished: true,
    };
    const result = classifyLanding(clean);
    expect(result.outcome).toBe("INDETERMINATE");
    expect(result.cause).toBe("REVERIFY_REJECTED");
    expect(FAIL_CLOSED_INVARIANTS.reverifyRejectedIsTheSoleBridge).toBe(true);
  });
});

describe("the landing-proof e2e consumer contract — zero authority on INDETERMINATE", () => {
  it("INDETERMINATE confers no landing, non-landing, retry, or release authority; the lease is held", () => {
    const indet = DETERMINATION_AUTHORITY.INDETERMINATE;
    expect(indet.mayConcludeLanded).toBe(false);
    expect(indet.mayConcludeNotLanded).toBe(false);
    expect(indet.mayRetryRebuildResubmit).toBe(false);
    expect(indet.mayReleaseLeaseOrReuse).toBe(false);
    expect(indet.mustHoldLeaseAndAwaitNewObservations).toBe(true);
  });

  it("a positive landing authorizes concluding landed only — never retry or lease release", () => {
    for (const outcome of ["LANDED_EXACT", "LANDED_COMPLETE_PATH"] as const) {
      const grant = DETERMINATION_AUTHORITY[outcome];
      expect(grant.mayConcludeLanded).toBe(true);
      expect(grant.mayRetryRebuildResubmit).toBe(false);
      expect(grant.mayReleaseLeaseOrReuse).toBe(false);
    }
  });

  it("re-walk semantics: only new observations may change an INDETERMINATE, and never to a default", () => {
    expect(REWALK_SEMANTICS.onlyNewObservationsCanChangeOutcome).toBe(true);
    expect(REWALK_SEMANTICS.identicalEvidenceYieldsIdenticalOutcome).toBe(true);
    expect(REWALK_SEMANTICS.indeterminateNeverDefaultsToLanded).toBe(true);
    expect(REWALK_SEMANTICS.indeterminateNeverDefaultsToNotLanded).toBe(true);
    expect(REWALK_SEMANTICS.noTimeBasedFoldToTerminal).toBe(true);
  });
});

describe("the landing-proof e2e classifier is total, deterministic, and surjective over the full input space", () => {
  it("every one of the 480 evidence combinations yields a valid outcome with correct cause discipline", () => {
    expect(ALL_EVIDENCE).toHaveLength(480);
    const determinationSet = new Set<string>(LANDING_DETERMINATIONS);
    const causeSet = new Set<string>(INDETERMINATE_CAUSES);
    for (const evidence of ALL_EVIDENCE) {
      const result = classifyLanding(evidence);
      expect(determinationSet.has(result.outcome)).toBe(true);
      expect(result.outcome).not.toMatch(/NOT.?LANDED/i);
      if (result.outcome === "INDETERMINATE") {
        expect(result.cause).not.toBeNull();
        expect(causeSet.has(result.cause as string)).toBe(true);
      } else {
        expect(result.cause).toBeNull();
      }
      expect(result.authority).toBe(DETERMINATION_AUTHORITY[result.outcome]);
    }
  });

  it("every outcome and every INDETERMINATE cause is actually reachable (surjective)", () => {
    const reachedOutcomes = new Set<string>();
    const reachedCauses = new Set<string>();
    for (const evidence of ALL_EVIDENCE) {
      const result = classifyLanding(evidence);
      reachedOutcomes.add(result.outcome);
      if (result.cause !== null) reachedCauses.add(result.cause);
    }
    assertClosedSet([...reachedOutcomes], [...LANDING_DETERMINATIONS]);
    assertClosedSet([...reachedCauses], [...INDETERMINATE_CAUSES]);
  });

  it("is deterministic — re-running identical evidence yields a deep-equal result", () => {
    for (const evidence of ALL_EVIDENCE) {
      expect(classifyLanding(evidence)).toEqual(classifyLanding(evidence));
    }
  });
});
