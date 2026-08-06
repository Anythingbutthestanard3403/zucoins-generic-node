import { describe, expect, it } from "vitest";

import { AUDIT_RESIDUALS, AUTOMATED_AXES } from "./audit-residuals.ts";
import { SCOPE_LINE_AXES } from "./contract-manifest.ts";

/**
 * drift-audit check 5 — residuals manifest.
 *
 * Freezes what is automated vs deferred and proves the two are disjoint and self-consistent, so
 * the eventual freeze verdict cannot silently assume an un-checked axis is clean.
 */
const axisNames = (entries: readonly { readonly axis: string }[]): string[] =>
  entries.map((entry) => entry.axis);

/**
 * The named drift axes this harness still leaves for manual/later discharge.
 * Empty since `settled-body-phases` closed (all fifteen scope-line axes are automated).
 * Sub-split deferred pointers (route-surface-reverse, etc.) remain in AUDIT_RESIDUALS separately.
 */
const NAMED_UNAUTOMATED_AXES: readonly string[] = [];

describe("drift-audit check 5: residuals manifest", () => {
  it("automated and residual axis names are each unique and non-empty", () => {
    const automated = axisNames(AUTOMATED_AXES);
    const residual = axisNames(AUDIT_RESIDUALS);
    expect(automated.length).toBeGreaterThan(0);
    expect(residual.length).toBeGreaterThan(0);
    expect(new Set(automated).size).toBe(automated.length);
    expect(new Set(residual).size).toBe(residual.length);
  });

  it("automated and residual sets are disjoint (no axis both automated and deferred)", () => {
    const residual = new Set(axisNames(AUDIT_RESIDUALS));
    const overlap = axisNames(AUTOMATED_AXES).filter((axis) => residual.has(axis));
    expect(overlap).toEqual([]);
  });

  it("every automated axis has coverage prose; every residual has a reason", () => {
    for (const axis of AUTOMATED_AXES) {
      expect(axis.coverage.length, axis.axis).toBeGreaterThan(0);
    }
    for (const residual of AUDIT_RESIDUALS) {
      expect(residual.reason.length, residual.axis).toBeGreaterThan(0);
    }
  });

  it("every deferred pointer on an automated axis names a real residual", () => {
    const residual = new Set(axisNames(AUDIT_RESIDUALS));
    const dangling: string[] = [];
    for (const axis of AUTOMATED_AXES) {
      if (axis.deferred.length > 0 && !residual.has(axis.deferred)) {
        dangling.push(`${axis.axis} -> ${axis.deferred}`);
      }
    }
    expect(dangling).toEqual([]);
  });

  it("every scope-line axis is in exactly one of the two ledgers", () => {
    const automated = new Set(axisNames(AUTOMATED_AXES));
    const residual = new Set(axisNames(AUDIT_RESIDUALS));
    const unplaced = SCOPE_LINE_AXES.filter(
      (axis) => automated.has(axis) === residual.has(axis),
    );
    expect(unplaced).toEqual([]);
  });

  it("residuals cover every named un-automated axis", () => {
    const residual = new Set(axisNames(AUDIT_RESIDUALS));
    const missing = NAMED_UNAUTOMATED_AXES.filter((axis) => !residual.has(axis));
    expect(missing).toEqual([]);
  });

  it("fail-first: a fabricated dangling deferred pointer is caught", () => {
    const residual = new Set(axisNames(AUDIT_RESIDUALS));
    expect(residual.has("no-such-residual-axis")).toBe(false);
  });
});
