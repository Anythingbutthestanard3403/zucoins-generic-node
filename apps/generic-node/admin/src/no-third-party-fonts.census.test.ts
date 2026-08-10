// ZTR-1190: operator console must not load third-party fonts.
// Production CSP is style-src 'self' 'unsafe-inline' with no font-src / connect
// hosts for fonts.googleapis.com / fonts.gstatic.com — any re-add of those
// hosts is blocked at the browser and must fail this gate at commit time.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const adminRoot = join(here, "..");
const FORBIDDEN = ["fonts.googleapis.com", "fonts.gstatic.com"] as const;
// Named webfont families that imply an external load when paired with a
// stylesheet/preconnect. System stacks may still mention generic families.
const FORBIDDEN_FAMILY = ['"Inter"', '"IBM Plex Mono"', "IBM Plex Mono"] as const;

function collectTextFiles(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) {
      if (ent.name === "node_modules" || ent.name === "e2e") continue;
      collectTextFiles(p, out);
      continue;
    }
    if (/\.(html|css|tsx?|jsx?|webmanifest)$/.test(ent.name)) out.push(p);
  }
  return out;
}

describe("no third-party font hosts (ZTR-1190)", () => {
  it("source index.html has no Google Fonts preconnect or stylesheet", () => {
    const html = readFileSync(join(adminRoot, "index.html"), "utf8");
    for (const host of FORBIDDEN) {
      expect(html, `index.html must not reference ${host}`).not.toContain(host);
    }
    expect(html).not.toMatch(/fonts\.google/i);
  });

  it("styles.css uses system stacks only (no Inter / IBM Plex Mono primary names)", () => {
    const css = readFileSync(join(here, "styles.css"), "utf8");
    for (const host of FORBIDDEN) {
      expect(css).not.toContain(host);
    }
    for (const family of FORBIDDEN_FAMILY) {
      expect(css, `styles.css must not name ${family}`).not.toContain(family);
    }
    expect(css).toMatch(/--font:\s*ui-sans-serif/);
    expect(css).toMatch(/--mono:\s*ui-monospace/);
  });

  it("admin source tree does not reintroduce Google Font hosts", () => {
    const offenders: string[] = [];
    for (const file of collectTextFiles(adminRoot)) {
      // Skip this test file's own string literals of the forbidden hosts.
      if (file.endsWith("no-third-party-fonts.census.test.ts")) continue;
      const text = readFileSync(file, "utf8");
      for (const host of FORBIDDEN) {
        if (text.includes(host)) offenders.push(`${file}: ${host}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("built dist/index.html (when present) has no Google Font hosts", () => {
    const distHtml = join(adminRoot, "dist", "index.html");
    if (!existsSync(distHtml)) return; // build not run in this vitest project alone
    const html = readFileSync(distHtml, "utf8");
    for (const host of FORBIDDEN) {
      expect(html, `dist/index.html must not reference ${host}`).not.toContain(host);
    }
  });
});
