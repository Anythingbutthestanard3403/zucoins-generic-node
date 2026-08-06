// reporting-serializer confinement census (money-path, Byte-exact-adjacent).
//
// `serializeReportRequestPayload` is the guard-free A.1.1 (`zp-report-request-v1`) signing
// serializer: it emits the byte-frozen (the byte-exact signing rule) money-path preimage WITHOUT the A.5 60s
// window guard. It confers no authority on its own (signing still needs the private reporting
// key), but a guard-free money-path signing serializer must not sit on the package's public
// API. #1019 flagged that it was re-exported from the public `.` barrel (src/index.ts,
// via reporting-tuples/index.ts). The fix confines it to the `./testkit` subpath.
//
// This census is the standing drift gate for that confinement. It is deliberately a REPO-WIDE
// filesystem grep (not a package-scoped import-resolution check): under the frozen rule CI is retired, so
// enforcement is local-only and must catch a re-introduction ANYWHERE in the tree — a re-export
// added back to a public barrel, or a new importer in any package or app — not merely a broken
// import inside this one package. The scan walks the real source tree from the repo root and
// asserts the ONLY files that may name the symbol are the three sanctioned ones below.
//
// Wired into `pnpm test:boundaries` (the named local-verify boundary gate) AND discovered by the
// generic-node-contracts scoped vitest, so it runs on both reviewer-cited verification legs.
//
// Governing contract: the security model (money-path surface minimization); the byte-exact signing rule
// (byte-exact signing — this gate does NOT touch the serializer bytes, only where the symbol is
// exported from). Prior finding:.

import { globSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { EXECUTION_TIMEOUTS } from "../testkit/executionPolicy.ts";
import { readIfPresent } from "../testkit/realTreeScan.ts";

const SYMBOL = "serializeReportRequestPayload";

// repoRoot: src/scan -> src -> generic-node-contracts -> packages -> <root> (four levels up),
// the same computation generic-core.scan-gate.test.ts uses.
const thisFile = fileURLToPath(import.meta.url);
const repoRoot = join(dirname(thisFile), "..", "..", "..", "..");

// The scan scope: the two source-bearing top-level trees. `apps/**` is included so the
// "no production app imports it" half of the verdict is enforced by the same walk.
const SCAN_SCOPE = ["packages", "apps"] as const;

const toRepoRelative = (absPath: string): string => relative(repoRoot, absPath).split(sep).join("/");

// The ONLY files permitted to name the symbol. Repo-relative, POSIX-separated.
//  - request-tuple.ts   defines it (+ one internal delegating call + one comment), byte-frozen.
//  - testkit/index.ts   the `./testkit` confinement barrel that re-exports it.
//  - test-fixtures.ts   the sole sanctioned importer (test-only; production never imports it).
const ALLOWED_FILES: readonly string[] = [
  "packages/generic-node-contracts/src/reporting-tuples/request-tuple.ts",
  "packages/generic-node-contracts/src/testkit/index.ts",
  "packages/node-core/src/reporting/test-fixtures.ts",
];

// The public barrels the symbol must NOT sit on.
const PUBLIC_BARRELS: readonly string[] = [
  "packages/generic-node-contracts/src/index.ts",
  "packages/generic-node-contracts/src/reporting-tuples/index.ts",
];

/**
 * Walked at test time, not at collect time. The walk is over a live working tree, so a
 * path captured at collect time can be gone before the read — a sibling gate's real-tree positive
 * controls used to cause exactly that, and any concurrent editor save or checkout still can.
 * fileNamesSymbol below tolerates the removal (a file that no longer exists names nothing) and the
 * empty-glob guard keeps a broken walk from passing vacuously.
 */
const walkScannedFiles = (): string[] =>
  SCAN_SCOPE.flatMap((scope) => [
    ...globSync(join(repoRoot, scope, "**", "*.ts")),
    ...globSync(join(repoRoot, scope, "**", "*.tsx")),
  ])
    .filter((file) => !file.includes(`${sep}node_modules${sep}`))
    .filter((file) => !file.includes(`${sep}dist${sep}`))
    // Self-exclude this census file: it necessarily names the symbol throughout.
    .filter((file) => file !== thisFile);

const fileNamesSymbol = (absPath: string): boolean =>
  readIfPresent(absPath)?.includes(SYMBOL) ?? false;

// Repo-wide walk of packages/** + apps/**, the widest scan in this package: the realTree class
// in ../testkit/executionPolicy.ts.
describe("reporting-serializer confinement census", { timeout: EXECUTION_TIMEOUTS.realTree }, () => {
  it("has source files to scan (guards against an empty/broken glob)", () => {
    expect(walkScannedFiles().length).toBeGreaterThan(0);
  });

  it("only the sanctioned files name serializeReportRequestPayload anywhere in the tree", () => {
    const offenders = walkScannedFiles()
      .filter(fileNamesSymbol)
      .map(toRepoRelative)
      .filter((rel) => !ALLOWED_FILES.includes(rel))
      .sort();
    expect(offenders).toEqual([]);
  });

  it("the public barrels (root . + reporting-tuples index) do NOT re-export it", () => {
    for (const barrel of PUBLIC_BARRELS) {
      const abs = join(repoRoot, barrel);
      const text = readFileSync(abs, "utf8");
      // The reporting-tuples barrel carries a confinement note that avoids the literal token,
      // so a plain substring absence check is exact here — any reappearance is a re-export.
      expect(text.includes(SYMBOL), `${barrel} must not name ${SYMBOL}`).toBe(false);
    }
  });

  it("no apps/** file references it (no production app importer)", () => {
    const appHits = globSync(join(repoRoot, "apps", "**", "*.ts"))
      .concat(globSync(join(repoRoot, "apps", "**", "*.tsx")))
      .filter((file) => !file.includes(`${sep}node_modules${sep}`) && !file.includes(`${sep}dist${sep}`))
      .filter(fileNamesSymbol)
      .map(toRepoRelative)
      .filter((rel) => !ALLOWED_FILES.includes(rel))
      .sort();
    expect(appHits).toEqual([]);
  });

  it("confinement landed: testkit barrel re-exports it and test-fixtures imports it from /testkit", () => {
    const testkit = readFileSync(
      join(repoRoot, "packages/generic-node-contracts/src/testkit/index.ts"),
      "utf8",
    );
    expect(testkit).toContain(SYMBOL);
    expect(testkit).toContain('from "../reporting-tuples/request-tuple.ts"');

    const fixtures = readFileSync(
      join(repoRoot, "packages/node-core/src/reporting/test-fixtures.ts"),
      "utf8",
    );
    expect(fixtures).toContain(`from "@zucoins/generic-node-contracts/testkit"`);
  });

  // A missing allowlisted file makes fileNamesSymbol false, so deletion still fails here loudly.
  it("every allowlisted file still exists and still names the symbol (staleness guard)", () => {
    for (const rel of ALLOWED_FILES) {
      const abs = join(repoRoot, rel);
      expect(fileNamesSymbol(abs), `allowlisted file no longer names ${SYMBOL}: ${rel}`).toBe(true);
    }
  });
});

describe("reporting-serializer confinement census: positive control (not vacuously green)", () => {
  it("the scan detects a planted reference (so a real re-introduction cannot pass silently)", () => {
    const tmp = mkdtempSync(join(tmpdir(), "reporting-serializer-confinement-"));
    try {
      const planted = join(tmp, "planted.ts");
      writeFileSync(planted, `export { ${SYMBOL} } from "@zucoins/generic-node-contracts/testkit";\n`);
      expect(fileNamesSymbol(planted)).toBe(true);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
