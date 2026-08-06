// the presentation-scope concern.1 census: the closed set of origin classes, their frozen claims, and the substitution-
// proof decision function. Covers the instruction-origin identity rule.
import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  ORIGIN_CLASSES,
  ORIGIN_CLASS_CLAIMS,
  claimsForOriginClass,
  isSubstitutionProof,
  type OriginClass,
} from "./origin-classes.contract.ts";

describe("the presentation-scope concern.1 census: ORIGIN_CLASSES is the exact closed set", () => {
  it("matches the frozen membership", () => {
    assertClosedSet(ORIGIN_CLASSES, ["node-origin", "implementer-controlled-origin", "platform-hosted"]);
  });

  it("has no wallet-bound class — only the implementer-controlled-origin model is frozen", () => {
    expect(ORIGIN_CLASSES).not.toContain("wallet-bound");
  });

  it("ORIGIN_CLASS_CLAIMS covers exactly ORIGIN_CLASSES, in the same sequence", () => {
    assertFieldOrder(
      ORIGIN_CLASS_CLAIMS.map((c) => c.originClass),
      ORIGIN_CLASSES,
    );
  });
});

describe("the presentation-scope concern.1 census: platform-hosted is frozen unconditionally non-substitution-proof", () => {
  it("claimsForOriginClass(platform-hosted).canEverClaimSubstitutionProof is false", () => {
    expect(claimsForOriginClass("platform-hosted").canEverClaimSubstitutionProof).toBe(false);
  });

  it("isSubstitutionProof('platform-hosted', true) is false — a node artifact / pin check never overrides this", () => {
    expect(isSubstitutionProof("platform-hosted", true)).toBe(false);
  });

  it("isSubstitutionProof('platform-hosted', false) is false", () => {
    expect(isSubstitutionProof("platform-hosted", false)).toBe(false);
  });
});

describe("the presentation-scope concern.1 census: node-origin and implementer-controlled-origin require a verified pin", () => {
  it.each(["node-origin", "implementer-controlled-origin"] as const)(
    "%s: substitution-proof iff the pin was independently verified",
    (originClass) => {
      expect(isSubstitutionProof(originClass, true)).toBe(true);
      expect(isSubstitutionProof(originClass, false)).toBe(false);
    },
  );

  it.each(["node-origin", "implementer-controlled-origin"] as const)(
    "%s: platformControlsOriginContent is false",
    (originClass) => {
      expect(claimsForOriginClass(originClass).platformControlsOriginContent).toBe(false);
    },
  );
});

describe("the presentation-scope concern.1 mandatory negative: an unrecognized origin class is rejected", () => {
  it("claimsForOriginClass throws on a 4th, undeclared origin class", () => {
    expectRejects(
      () => "wallet-bound" as unknown as OriginClass,
      (mutated) => claimsForOriginClass(mutated),
    );
  });
});
