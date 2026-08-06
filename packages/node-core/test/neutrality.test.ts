import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { D99_ALLOWLIST } from "../../generic-node-contracts/src/scan/allowlist.d99.ts";
import {
  FORBIDDEN_TERMS,
  scanTextForForbiddenTerms,
  type ScanViolation,
} from "../../generic-node-contracts/src/scan/forbidden-terms.ts";

function listScannableFiles(dir: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir, { recursive: true }) as string[];
  } catch {
    return [];
  }
  return entries
    .map((entry) => join(dir, entry))
    .filter((full) => {
      if (![".ts", ".md"].includes(extname(full))) return false;
      // A sibling test writes and deletes a probe file under src/, so a path listed
      // here can be gone by the time it is stat-ed. A vanished file is not committed
      // tree content and can hold no violation.
      try {
        return statSync(full).isFile();
      } catch {
        return false;
      }
    });
}

function scanDir(dir: string): ScanViolation[] {
  return listScannableFiles(dir).flatMap((file) => {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      return [];
    }
    return scanTextForForbiddenTerms(text, file, D99_ALLOWLIST);
  });
}

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const scannedDirs = [
  resolve(repoRoot, "packages/node-core/src"),
  resolve(repoRoot, "apps/generic-node/src"),
];

describe("canonical product-neutral source gate", () => {
  it.each(FORBIDDEN_TERMS)("detects the canonical forbidden term %s", (term) => {
    const violations = scanTextForForbiddenTerms(
      `neutral text then ${term} then neutral text`,
      "fixture.ts",
      D99_ALLOWLIST,
    );
    expect(violations.some((violation) => violation.term === term)).toBe(true);
  });

  it.each(D99_ALLOWLIST)("permits the canonical compatibility literal %s", (literal) => {
    expect(
      scanTextForForbiddenTerms(`const value = "${literal}";`, "fixture.ts", D99_ALLOWLIST),
    ).toEqual([]);
  });

  it("does not let an allowed literal hide an adjacent forbidden term", () => {
    const violations = scanTextForForbiddenTerms(
      'const value = "zupayments"; // payment state',
      "fixture.ts",
      D99_ALLOWLIST,
    );
    expect(violations.some((violation) => violation.term === "payment")).toBe(true);
  });

  for (const dir of scannedDirs) {
    it(`has source files under ${dir}`, () => {
      expect(listScannableFiles(dir).length).toBeGreaterThan(0);
    });

    it(`has zero canonical forbidden terms under ${dir}`, () => {
      expect(scanDir(dir)).toEqual([]);
    });
  }
});
