import { describe, expect, it } from "vitest";

import { expectRejects } from "../testkit/freeze.ts";
import {
  SPLITCHAIN_INNER_TYPE,
  SPLITCHAIN_INNER_VERSION,
  SPLITCHAIN_SIGNER_STEPS,
  SUITE_CANONICAL_VERSION,
  SUITE_PURPOSE_SUFFIX,
  VERSION_EVOLUTION_RULE,
  VERSIONS_CONTRACT_VERSION,
} from "./versions.contract.ts";

/** The A.9 rule-3 check: canonical_version accepts only the JSON number 1. */
const assertSuiteCanonicalVersion = (value: unknown): void => {
  if (value !== SUITE_CANONICAL_VERSION || typeof value !== "number") {
    throw new Error("canonical_version must be the JSON number 1");
  }
};

/** The protocol rule 3 check: the inner version accepts only the string "2". */
const assertInnerVersion = (value: unknown): void => {
  if (value !== SPLITCHAIN_INNER_VERSION || typeof value !== "string") {
    throw new Error('inner version must be the string "2"');
  }
};

describe("versions census (the fixture-provenance purposes census, A.1.1; protocol rules 1.2,3)", () => {
  it("freezes the suite canonical version as the JSON number 1", () => {
    expect(SUITE_CANONICAL_VERSION).toBe(1);
    expect(typeof SUITE_CANONICAL_VERSION).toBe("number");
  });

  it("freezes the SplitChain inner version as the string \"2\"", () => {
    expect(SPLITCHAIN_INNER_VERSION).toBe("2");
    expect(typeof SPLITCHAIN_INNER_VERSION).toBe("string");
    expect(SPLITCHAIN_INNER_TYPE).toBe("unique_combinable");
    expect(SPLITCHAIN_SIGNER_STEPS).toBe(2);
  });

  it("freezes the -v1 purpose suffix and the evolution rule", () => {
    expect(SUITE_PURPOSE_SUFFIX).toBe("-v1");
    expect(VERSION_EVOLUTION_RULE.inPlaceEditOfV1Surface).toBe(false);
    expect(VERSION_EVOLUTION_RULE.changeRequiresNewPurposeAndReviewedGoldens).toBe(true);
    expect(VERSION_EVOLUTION_RULE.enumMembershipChangeIsContractVersionChange).toBe(true);
  });

  it("rejects canonical_version as the string \"1\" (A.9 #3, negative path)", () => {
    expectRejects(
      () => "1",
      (mutated) => assertSuiteCanonicalVersion(mutated),
    );
  });

  it("rejects the inner version as the number 2 (negative path)", () => {
    expectRejects(
      () => 2,
      (mutated) => assertInnerVersion(mutated),
    );
  });

  it("the two version typings are deliberately opposite and never conflated", () => {
    expect(typeof SUITE_CANONICAL_VERSION).not.toBe(typeof SPLITCHAIN_INNER_VERSION);
  });

  it("pins the manifest version", () => {
    expect(VERSIONS_CONTRACT_VERSION).toBe(1);
  });
});
