// Construction-site census gate: proves every construction-site rule cites a real inventoried
// literal (or is explicitly scoped to a construction with no standalone literal, e.g. the
// transfer-code digest), the replacement policy is frozen exactly as stated, and a broad
// branding substitution is recognizably NOT what the policy allows (negative path).
import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { LITERAL_CONSTRUCTION_SITES } from "./construction-sites.contract.ts";
import { REPLACEMENT_POLICY, REPLACEMENT_POLICY_RULE, REPLACEMENT_POLICY_FORBIDDEN } from "./replacement-policy.ts";
import { COMPATIBILITY_LITERAL_VALUES } from "./inventory.contract.ts";
import { isKnownCompatibilityLiteral } from "./verify.ts";

describe("construction-site census", () => {
  it("freezes exactly eight construction-site families in registration sequence", () => {
    assertFieldOrder(
      LITERAL_CONSTRUCTION_SITES.map((s) => s.family),
      [
        "suite-signed-tuple (zp-*-v1 purposes)",
        "wallet-head semantic fingerprint (zp-wallet-head-fingerprint-v1)",
        "SplitChain receive-message prefix (zp1:)",
        "transfer-code digest",
        "vault AAD (zp-wallet-secret-v1)",
        "reporting-request header set (X-ZP-Reporting-*)",
        "legacy reporting-ingest signed domain prefixes + X-ZuPay-* transport headers",
        "discovery/API route paths + package scope (zupay/zupayments names)",
      ],
    );
  });

  it("every non-empty appliesTo entry cites a real inventoried literal (no orphan citation)", () => {
    for (const site of LITERAL_CONSTRUCTION_SITES) {
      for (const literal of site.appliesTo) {
        expect(COMPATIBILITY_LITERAL_VALUES).toContain(literal);
        expect(isKnownCompatibilityLiteral(literal)).toBe(true);
      }
    }
  });

  it("every construction site declares a non-empty rule, owningConcern, and sourceDocCitation", () => {
    for (const site of LITERAL_CONSTRUCTION_SITES) {
      expect(site.rule.length).toBeGreaterThan(0);
      expect(site.owningConcern.length).toBeGreaterThan(0);
      expect(site.sourceDocCitation.length).toBeGreaterThan(0);
    }
  });

  it("every inventoried signed-purpose/wire-prefix literal is cited by at least one construction site", () => {
    const citedLiterals = new Set(LITERAL_CONSTRUCTION_SITES.flatMap((site) => site.appliesTo));
    const uncitedSignedPurposes = COMPATIBILITY_LITERAL_VALUES.filter(
      (literal) => literal.startsWith("zp-") && !citedLiterals.has(literal),
    );
    expect(uncitedSignedPurposes).toEqual([]);
  });

  it("freezes the replacement policy exactly as compat-literal-preservation states it", () => {
    expect(REPLACEMENT_POLICY_RULE).toBe("versioned-migration-only");
    expect(REPLACEMENT_POLICY_FORBIDDEN).toBe("repository-wide branding substitution");
    expect(REPLACEMENT_POLICY.rule).toBe(REPLACEMENT_POLICY_RULE);
    expect(REPLACEMENT_POLICY.forbidden).toBe(REPLACEMENT_POLICY_FORBIDDEN);
  });

  it("rejects a broad branding substitution as a valid replacement path (negative path)", () => {
    const isPermittedReplacementPath = (path: string): void => {
      expect(path).toBe(REPLACEMENT_POLICY_RULE);
    };
    // A change proposing "just rename every zupay/zp occurrence repo-wide" is proposing exactly
    // the forbidden path, not the frozen versioned-migration-only one.
    expectRejects(() => REPLACEMENT_POLICY_FORBIDDEN, isPermittedReplacementPath);
  });
});
