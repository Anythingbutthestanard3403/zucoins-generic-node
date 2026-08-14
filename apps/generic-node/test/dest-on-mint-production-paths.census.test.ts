// ZTR-1306: every production node_generated mint must go through the shared
// dest-on-mint helper. A new live INSERT INTO wallets that bypasses it
// recreates the dest-less worker that assign then 503s on.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = join(here, "../src");

function listTs(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      out.push(...listTs(full));
    } else if (name.endsWith(".ts") && !name.endsWith(".test.ts") && !name.endsWith(".d.ts")) {
      out.push(full);
    }
  }
  return out;
}

const EXEMPT_RELATIVE = new Set([
  // Throwaway restore probe: copies archive wallet_sections as-is (any key_origin).
  // Not a live mint; the restored fleet is healed by destinations-pending-backfill
  // on the next money-pack apply of the real node, not this throwaway instance.
  "ops/sql-restored-instance.ts",
]);

describe("production dest-on-mint census (ZTR-1306)", () => {
  const files = listTs(srcRoot);

  it("every live INSERT INTO wallets uses the dest-on-mint helper", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const rel = relative(srcRoot, file);
      if (EXEMPT_RELATIVE.has(rel)) continue;
      const src = readFileSync(file, "utf8");
      if (/INSERT\s+INTO\s+wallets\b/i.test(src)) {
        offenders.push(rel);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the three production mint sites import the shared helper", () => {
    const required = [
      "main.ts",
      "money-workers/start-money-workers.ts",
      "full-http-mount.ts",
    ];
    for (const rel of required) {
      const src = readFileSync(join(srcRoot, rel), "utf8");
      expect(src, rel).toContain("insertNodeGeneratedWalletWithPendingDestination");
      expect(src, rel).toContain("deleteNodeGeneratedWalletMint");
    }
  });
});
