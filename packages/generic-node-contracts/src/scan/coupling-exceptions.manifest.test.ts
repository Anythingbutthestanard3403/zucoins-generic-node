import { globSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import manifest from "./coupling-exceptions.manifest.json" with { type: "json" };
import {
  countExemptionMarkers,
  FROZEN_EXEMPTION_COUNT,
  FORBIDDEN_TERMS,
  SCAN_SCOPE,
} from "./forbidden-terms.ts";
import { D99_ALLOWLIST } from "./allowlist.d99.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

const scannedFiles = SCAN_SCOPE.flatMap((scopePath) => [
  ...globSync(join(repoRoot, scopePath, "**", "*.ts")),
  ...globSync(join(repoRoot, scopePath, "**", "*.md")),
    ...globSync(join(repoRoot, scopePath, "**", "*.tsx")),

]).filter((file) => !file.includes(`${join("src", "scan")}/`));

const liveMarkerCount = scannedFiles.reduce(
  (total, file) => total + countExemptionMarkers(readFileSync(file, "utf8")),
  0,
);

/**
 * Repo-relative file -> live marker count, for the files that actually carry a marker. The
 * manifest records the same shape (one entry per marker, keyed by file), so comparing the two
 * catches a marker that moved between files or appeared/vanished inside one — drift the
 * whole-tree total in `liveMarkerCount` is blind to, because a marker moving from file A to
 * file B leaves the total untouched.
 */
const countMarkersByFile = (files: readonly string[]): Map<string, number> => {
  const counts = new Map<string, number>();
  for (const file of files) {
    const markers = countExemptionMarkers(readFileSync(file, "utf8"));
    if (markers > 0) counts.set(relative(repoRoot, file), markers);
  }
  return counts;
};

const liveMarkersByFile = countMarkersByFile(scannedFiles);

const manifestMarkersByFile = (
  entries: ReadonlyArray<{ file: string }>,
): Map<string, number> => {
  const counts = new Map<string, number>();
  for (const entry of entries) counts.set(entry.file, (counts.get(entry.file) ?? 0) + 1);
  return counts;
};

/** Comparable plain object — `Map`s with the same pairs inserted differently are still equal. */
const asSortedRecord = (counts: ReadonlyMap<string, number>): Record<string, number> =>
  Object.fromEntries([...counts].sort(([a], [b]) => a.localeCompare(b)));

const FROZEN_V1_PRODUCT_LEAVES = ["widget", "hosted-platform"] as const;

const FORBIDDEN_PACKAGE_NAMES: readonly string[] = [
  ...FORBIDDEN_TERMS.map((term) => term.toLowerCase()),
  ...FROZEN_V1_PRODUCT_LEAVES,
];

const extractPackageLeaf = (filePath: string): string => {
  const packagesIdx = filePath.indexOf("packages/");
  if (packagesIdx !== -1) {
    const rest = filePath.slice(packagesIdx + "packages/".length);
    return rest.split("/")[0] ?? "";
  }
  const appsIdx = filePath.indexOf("apps/");
  if (appsIdx !== -1) {
    const rest = filePath.slice(appsIdx + "apps/".length);
    return rest.split("/")[0] ?? "";
  }
  return "";
};

describe("coupling-exceptions manifest (the coupling-exceptions manifest)", () => {
  it("has at least one scanned file (guards against an empty/broken glob)", () => {
    expect(scannedFiles.length).toBeGreaterThan(0);
  });

  it("manifest inline entry count matches the live scan marker count", () => {
    expect(manifest.inlineMarkers.entries).toHaveLength(liveMarkerCount);
  });

  it("manifest inline entries name the same files, with the same per-file counts, as the live scan", () => {
    expect(asSortedRecord(manifestMarkersByFile(manifest.inlineMarkers.entries))).toEqual(
      asSortedRecord(liveMarkersByFile),
    );
  });

  it("no manifest entry claims a line number (v2 records file + reason only)", () => {
    const withLineNumbers = manifest.inlineMarkers.entries.filter((entry) => "line" in entry);
    expect(withLineNumbers).toEqual([]);
  });

  it("negative path: a marker moving between files breaks the per-file assertion", () => {
    const [firstFile, secondFile] = [...liveMarkersByFile.keys()];
    expect(secondFile).toBeDefined();
    const moved = new Map(liveMarkersByFile);
    moved.set(firstFile!, moved.get(firstFile!)! - 1);
    moved.set(secondFile!, moved.get(secondFile!)! + 1);
    // The whole-tree total is unchanged by the move — only the per-file map sees it.
    expect([...moved.values()].reduce((a, b) => a + b, 0)).toBe(liveMarkerCount);
    expect(asSortedRecord(moved)).not.toEqual(
      asSortedRecord(manifestMarkersByFile(manifest.inlineMarkers.entries)),
    );
  });

  it("manifest inline entry count matches FROZEN_EXEMPTION_COUNT", () => {
    expect(manifest.inlineMarkers.entries).toHaveLength(FROZEN_EXEMPTION_COUNT);
  });

  it("manifest frozenCount field matches FROZEN_EXEMPTION_COUNT", () => {
    expect(manifest.inlineMarkers.frozenCount).toBe(FROZEN_EXEMPTION_COUNT);
  });

  it("manifest D99 entry count matches D99_ALLOWLIST.length", () => {
    expect(manifest.d99Allowlist.entries).toHaveLength(D99_ALLOWLIST.length);
  });

  it("manifest D99 literals match D99_ALLOWLIST in sequence", () => {
    const manifestLiterals = manifest.d99Allowlist.entries.map((entry) => entry.literal);
    expect(manifestLiterals).toEqual([...D99_ALLOWLIST]);
  });

  it("negative path: adding a fake entry breaks the count assertion", () => {
    const inflatedCount = manifest.inlineMarkers.entries.length + 1;
    expect(inflatedCount).not.toBe(liveMarkerCount);
    expect(inflatedCount).not.toBe(FROZEN_EXEMPTION_COUNT);
  });

  it("negative path: removing an entry breaks the count assertion", () => {
    const deflatedCount = manifest.inlineMarkers.entries.length - 1;
    expect(deflatedCount).not.toBe(liveMarkerCount);
    expect(deflatedCount).not.toBe(FROZEN_EXEMPTION_COUNT);
  });

  it("no exempted file lives in a frozen-leaf product package", () => {
    const violations: Array<{ file: string; leaf: string }> = [];
    for (const entry of manifest.inlineMarkers.entries) {
      const leaf = extractPackageLeaf(entry.file);
      if (FORBIDDEN_PACKAGE_NAMES.includes(leaf.toLowerCase())) {
        violations.push({ file: entry.file, leaf });
      }
    }
    expect(violations).toEqual([]);
  });
});
