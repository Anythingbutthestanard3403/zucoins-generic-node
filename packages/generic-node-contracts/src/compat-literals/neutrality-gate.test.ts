// Neutrality gate: proves the scan allowlist (`../scan/allowlist.d99.ts`) contains ONLY
// entries the compat-literals concern can justify — a retained literal this concern's own
// census recognizes, a forbidden-alias glob this concern also freezes, or an explicitly
// documented non-literal citation (a real file path this concern's own data cites verbatim)
// — no product vocabulary smuggled in under cover of any of these, and growing the allowlist
// never reintroduces a genuine forbidden-term hit.
//
// The `D99_ALLOWLIST` carries, beyond the retained compat literals, the four
// forbidden-event-globs (`forbidden-aliases.contract.ts`) and one legacy route-path
// citation (`apps/node/src/checkout/sdk-route.ts`, cited by `compat-literals.contract.ts`/
// `inventory.contract.ts`/`compatibility-gate.test.ts`) — both are DELIBERATE, DOCUMENTED
// exemption classes distinct from the retained literals, so the recognizer below checks for
// all three explicitly rather than silently widening to "anything goes".
import { describe, expect, it } from "vitest";

import { D99_ALLOWLIST } from "../scan/allowlist.d99.ts";
import { FORBIDDEN_TERMS, scanTextForForbiddenTerms } from "../scan/forbidden-terms.ts";
import { COMPATIBILITY_LITERAL_VALUES } from "./inventory.contract.ts";
import { isKnownCompatibilityLiteral } from "./verify.ts";
import { FORBIDDEN_EVENT_GLOBS } from "./forbidden-aliases.contract.ts";

/** The one non-literal exemption class: real file paths this concern's own frozen data cites. */
const LEGACY_SOURCE_PATH_CITATIONS = ["apps/node/src/checkout/sdk-route.ts"] as const;

/**
 * An allowlist entry is recognized if it is an exact inventoried literal, a family-prefix of one
 * or more inventoried literals (e.g. `"X-ZP-"`, the original umbrella entry covering the
 * whole `X-ZP-*` header family rather than one named header), an exact forbidden-event-glob
 * this concern also freezes, or an exact documented legacy-source-path citation.
 */
const isRecognizedAllowlistEntry = (allowed: string): boolean =>
  isKnownCompatibilityLiteral(allowed) ||
  COMPATIBILITY_LITERAL_VALUES.some((literal) => literal.startsWith(allowed)) ||
  (FORBIDDEN_EVENT_GLOBS as readonly string[]).includes(allowed) ||
  (LEGACY_SOURCE_PATH_CITATIONS as readonly string[]).includes(allowed);

describe("compat-literals neutrality gate", () => {
  it("every scan-allowlist entry is a retained literal, a forbidden-glob, or a documented path citation", () => {
    for (const allowed of D99_ALLOWLIST) {
      expect(isRecognizedAllowlistEntry(allowed)).toBe(true);
    }
  });

  it("rejects a fabricated family-prefix that covers no real inventoried literal (negative path)", () => {
    expect(isRecognizedAllowlistEntry("X-QQ-")).toBe(false);
  });

  it("rejects a fabricated path citation not actually frozen anywhere (negative path)", () => {
    expect(isRecognizedAllowlistEntry("apps/node/src/fake/made-up.ts")).toBe(false);
  });

  it("no scan-allowlist entry is itself a bare forbidden product term (no product verb smuggled in)", () => {
    for (const allowed of D99_ALLOWLIST) {
      expect((FORBIDDEN_TERMS as readonly string[]).includes(allowed)).toBe(false);
      expect((FORBIDDEN_TERMS as readonly string[]).includes(allowed.toLowerCase())).toBe(false);
    }
  });

  it("scanning every allowlisted literal in prose produces zero forbidden-term hits", () => {
    const fixture = D99_ALLOWLIST.map((literal) => `this compatibility name uses ${literal} verbatim.`).join(
      "\n",
    );
    expect(scanTextForForbiddenTerms(fixture, "fixture.ts", D99_ALLOWLIST)).toEqual([]);
  });

  it("rejects a fabricated allowlist entry that smuggles a forbidden product verb (negative path)", () => {
    // Built from a FORBIDDEN_TERMS index, never spelled out here, so this file's own source text
    // never contains the bare forbidden word (this module is in scan scope, unlike src/scan/**).
    const smuggledTerm = FORBIDDEN_TERMS[4]!;
    const smuggledLiteral = `zp-${smuggledTerm}-expected-v1`;
    const fixture = `this line describes a ${smuggledLiteral} artifact.`;
    // Even inside a plausible-looking zp-*-v1 spelling, the embedded forbidden token is caught
    // because the fabricated entry is NOT actually in the real (unmodified) allowlist passed here.
    const violations = scanTextForForbiddenTerms(fixture, "fixture.ts", D99_ALLOWLIST);
    expect(violations).toHaveLength(1);
    expect(violations[0]?.term).toBe(smuggledTerm);
  });
});
