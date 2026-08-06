import { createHash } from "node:crypto";
import { existsSync, globSync, readFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { FIXTURE_PROVENANCE_REGISTRY } from "./registry.ts";
import type { FixtureProvenanceRecord } from "./types.ts";

/**
 * the fixture-provenance surface fixture provenance — the disk-verification side of the registry. This module is
 * the ONLY part of the fixture-provenance surface that reads committed bytes and hashes them;
 * `registry.ts` and `validate.ts` stay pure so the barrel remains production-path safe. Tests
 * (and later the fixture-provenance drift gate drift gate) call these functions against the package root, or
 * against an alternate root to exercise mutation/missing-file behavior without touching the
 * real tree.
 *
 * Digests are always recomputed from the actual frozen files and compared against the pinned
 * record values — the registry never trusts a hand-typed digest (byte-exact-signing adjacency).
 */

const here = dirname(fileURLToPath(import.meta.url));
/** `packages/generic-node-contracts` — two levels above `src/fixture-provenance`. */
export const packageRoot = join(here, "..", "..");

/** SHA-256 (hex) of a file addressed relative to `root`. Throws when the file is absent. */
export const sha256OfFile = (root: string, relativePath: string): string =>
  createHash("sha256").update(readFileSync(join(root, relativePath))).digest("hex");

/** One digest mismatch: the pinned record value versus what is on disk (`"missing"` when absent). */
export interface DigestMismatch {
  readonly fixtureId: string;
  readonly path: string;
  readonly expected: string;
  readonly actual: string;
}

/**
 * Recompute every digest a record pins and return the mismatches (empty when the fixture is
 * intact). A mutated, truncated, or missing family file shows up here naming its path — the
 * "known drift class" detection the build-test plan requires.
 */
export const verifyRecordDigests = (
  record: FixtureProvenanceRecord,
  root: string = packageRoot,
): readonly DigestMismatch[] => {
  const mismatches: DigestMismatch[] = [];
  for (const file of record.files) {
    if (!existsSync(join(root, file.path))) {
      mismatches.push({ fixtureId: record.fixtureId, path: file.path, expected: file.sha256, actual: "missing" });
      continue;
    }
    const actual = sha256OfFile(root, file.path);
    if (actual !== file.sha256) {
      mismatches.push({ fixtureId: record.fixtureId, path: file.path, expected: file.sha256, actual });
    }
  }
  return mismatches;
};

/** Every digest mismatch across the whole registry (empty when every fixture is intact). */
export const verifyRegistryDigests = (root: string = packageRoot): readonly DigestMismatch[] =>
  FIXTURE_PROVENANCE_REGISTRY.flatMap((record) => verifyRecordDigests(record, root));

const toPosix = (path: string): string => path.split(sep).join("/");

/**
 * The on-disk fixture index set: every `*.meta.json`, `manifest.json`, and `*.vectors.json`
 * under the package root (the reviewer's `find` pattern), as package-relative POSIX paths.
 * `node_modules` and `dist` are excluded — both are generated trees, never frozen fixtures.
 */
export const discoverFixtureIndexPaths = (root: string = packageRoot): readonly string[] => {
  const discovered = [
    ...globSync(join(root, "**", "*.meta.json")),
    ...globSync(join(root, "**", "manifest.json")),
    ...globSync(join(root, "**", "*.vectors.json")),
  ];
  return discovered
    .map((file) => toPosix(relative(root, file)))
    .filter((path) => !path.startsWith("node_modules/") && !path.startsWith("dist/"))
    .sort();
};

/** The two coverage failure directions: unregistered on-disk fixtures, and records with no file. */
export interface CoverageDiff {
  /** On-disk fixture index files no record covers — unregistered fixtures. */
  readonly orphanFixtures: readonly string[];
  /** Record index paths with no on-disk file — dangling registry references. */
  readonly danglingRecords: readonly string[];
}

/**
 * Diff registry coverage against the on-disk fixture index set. Both lists must be empty for
 * coverage to be exact — this is the machine-checkable form of the review-indicator
 * `find ... -iname '*.meta.json' -o -iname 'manifest.json' -o -iname '*.vectors.json'` diff.
 */
export const diffRegistryCoverage = (root: string = packageRoot): CoverageDiff => {
  const onDisk = new Set(discoverFixtureIndexPaths(root));
  const registered = new Set(FIXTURE_PROVENANCE_REGISTRY.map((record) => record.indexPath));
  return {
    orphanFixtures: [...onDisk].filter((path) => !registered.has(path)).sort(),
    danglingRecords: [...registered].filter((path) => !onDisk.has(path)).sort(),
  };
};
