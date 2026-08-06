// shared axe-core smoke-test helper, ported from the dashboard's
// apps/platform/dashboard/src/test-a11y.ts. Framework doubles only
// (no vitest import), same convention as that file, so it is typechecked but
// never collected as a suite.
//
// The "real axe tests" acceptance bar was previously satisfied only by
// hand-written a11y assertions (label queries, role queries, etc.) — real
// coverage, but not what the AC literally asks for. This runs the actual
// axe-core engine against rendered output so a real regression axe would
// catch (e.g. a missing accessible name, a duplicate id, invalid ARIA usage)
// fails the suite even if the hand-written assertions don't happen to probe
// it.

import axe from "axe-core";
import type { Result } from "axe-core";

// jsdom has no layout/paint engine: elements report zero size, computed
// colours don't reflect real stacking/compositing, and canvas is
// unimplemented. axe's color-contrast check depends on all of that, so under
// jsdom it produces unreliable results (both false positives and false
// negatives) rather than a real signal — disable it here. Contrast for this
// theme is a visual/manual concern; this suite does not re-check it.
const JSDOM_UNSUPPORTED_RULES = ["color-contrast"];

export async function axeViolations(container: Element): Promise<Result[]> {
  const results = await axe.run(container, {
    rules: Object.fromEntries(JSDOM_UNSUPPORTED_RULES.map((id) => [id, { enabled: false }])),
  });
  return results.violations;
}

// Renders a readable failure message — the default axe Result shape is deep
// and not helpful in a test failure diff.
export function formatViolations(violations: Result[]): string {
  return violations
    .map((violation) => {
      const targets = violation.nodes.map((node) => `  - ${node.target.join(" ")}`).join("\n");
      return `${violation.id} (${violation.impact ?? "unknown"}): ${violation.help}\n${targets}`;
    })
    .join("\n\n");
}
