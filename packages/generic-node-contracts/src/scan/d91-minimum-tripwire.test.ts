import { describe, expect, it } from "vitest";

import { FORBIDDEN_TERMS } from "./forbidden-terms.ts";

/**
 * the three-generic-operation rule independent tripwire (the minimum-tripwire concern). `forbidden-terms.test.ts`'s "catches every forbidden
 * category" test derives both its stimulus and its expected count from `FORBIDDEN_TERMS`
 * itself, so removing a canonical term shrinks the scanner and that self-test in lockstep —
 * a silent narrowing neither one can catch alone. This file owns a second, independent
 * literal set sourced directly from the three-generic-operation decision (the nine frozen product
 * projections) plus the ZKZ ticker rule's banned legacy token spelling, and checks it is contained
 * in — never equal to — the live `FORBIDDEN_TERMS`, so stricter local-only terms (e.g.
 * `merchant`, `outbound`, `drain`) stay allowed. The diagnostic below is test-local; the
 * scanner never imports or compares against it.
 */

// the three-generic-operation rule: "Checkout, payment, sweep, treasury, refund, payout, withdrawal, reservation, and
// order concepts are implementer/product projections, not additional core operation kinds."
const D91_PRODUCT_PROJECTIONS = [
  "checkout",
  "payment",
  "sweep",
  "treasury",
  "refund",
  "payout",
  "withdrawal",
  "reservation",
  "order",
] as const;

// The ZKZ ticker rule: the token is ZKZ; this is the banned legacy spelling it forbids.
const GOLDEN_RULE_1_BANNED_TOKEN = "ZUC" as const;

const REQUIRED_MINIMUM_TERMS = [...D91_PRODUCT_PROJECTIONS, GOLDEN_RULE_1_BANNED_TOKEN] as const;

/**
 * Pure diagnostic owned only by this test file: returns every required term absent from a
 * supplied candidate list, in required-list order. Takes a plain string list rather than
 * `ForbiddenTerm[]` so a mutated/narrowed copy of `FORBIDDEN_TERMS` can be fed in directly for
 * the negative test below without a type error.
 */
const findMissingRequiredTerms = (
  candidateTerms: readonly string[],
  requiredTerms: readonly string[],
): readonly string[] => requiredTerms.filter((term) => !candidateTerms.includes(term));

describe("the three-generic-operation rule minimum independent tripwire (the minimum-tripwire concern)", () => {
  it("has a non-empty required set to check (guards against an empty/broken literal)", () => {
    expect(REQUIRED_MINIMUM_TERMS.length).toBe(10);
  });

  it("contains every the three-generic-operation rule product projection and the ZKZ-naming rule's banned token in the live FORBIDDEN_TERMS", () => {
    for (const term of REQUIRED_MINIMUM_TERMS) {
      expect(FORBIDDEN_TERMS as readonly string[]).toContain(term);
    }
  });

  it("diagnostic reports zero missing terms against the live FORBIDDEN_TERMS", () => {
    expect(findMissingRequiredTerms(FORBIDDEN_TERMS, REQUIRED_MINIMUM_TERMS)).toEqual([]);
  });

  it("mutation negative: diagnostic names the exact term removed from a supplied copy of the list", () => {
    const mutatedCandidate = FORBIDDEN_TERMS.filter((term) => term !== "treasury");
    const missing = findMissingRequiredTerms(mutatedCandidate, REQUIRED_MINIMUM_TERMS);
    expect(missing).toEqual(["treasury"]);
  });
});
