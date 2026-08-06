// CSS-contract regression tests for the a11y/responsive fixes.
// jsdom has no layout/paint engine and this suite runs with no `css: true`
// vitest config, so cascade/computed-style assertions aren't available here
// (same constraint noted in apps/platform/dashboard's Button.test.tsx) —
// these assert against the raw stylesheet text instead, same convention.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "styles.css"), "utf8");

describe("global focus-visible ring (WCAG 2.4.7)", () => {
  it("defines one global :focus-visible outline reachable by every interactive element", () => {
    expect(css).toMatch(/:focus-visible\s*{\s*outline:\s*2px solid var\(--accent\)/);
  });
});

describe("table-wrap no longer clips content (WCAG 1.4.10 Reflow)", () => {
  it(".table-wrap uses overflow-x:auto, not overflow:hidden", () => {
    const rule = /\.table-wrap\s*{[^}]*}/.exec(css)?.[0] ?? "";
    expect(rule).toContain("overflow-x: auto");
    expect(rule).not.toMatch(/overflow:\s*hidden/);
  });
});

describe("narrow-viewport reflow (max-width: 720px)", () => {
  it("the top bar wraps instead of clipping controls off-screen", () => {
    expect(css).toMatch(/@media \(max-width: 720px\)[\s\S]*?\.top\s*{[^}]*flex-wrap:\s*wrap/);
  });

  it("a pinned sidebar overlays content instead of squeezing it to an unusable width", () => {
    expect(css).toMatch(
      /@media \(max-width: 720px\)[\s\S]*?\.app\.pinned\s*{[^}]*grid-template-columns:\s*var\(--side\) 1fr/,
    );
    expect(css).toMatch(/@media \(max-width: 720px\)[\s\S]*?\.app\.pinned \.side\s*{[^}]*position:\s*absolute/);
  });

  it(".search can shrink below its content width instead of forcing horizontal overflow", () => {
    const rule = /\.search\s*{[^}]*}/.exec(css)?.[0] ?? "";
    expect(rule).toContain("min-width: 0");
  });
});
