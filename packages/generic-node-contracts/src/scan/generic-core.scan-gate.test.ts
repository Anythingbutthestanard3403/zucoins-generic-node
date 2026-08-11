import { globSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { scanTextForForbiddenTerms, SCAN_SCOPE } from "./forbidden-terms.ts";
import { D99_ALLOWLIST } from "./allowlist.d99.ts";
import { EXECUTION_TIMEOUTS } from "../testkit/executionPolicy.ts";
import { readPresentFiles } from "../testkit/realTreeScan.ts";

/**
 * The real drift gate: walks every path in `SCAN_SCOPE` and asserts zero unmarked
 * forbidden-term hits. `src/scan/**` itself is excluded from the contracts-package entry —
 * this module's own `FORBIDDEN_TERMS` literal and its self-test fixtures necessarily contain
 * every forbidden word (`forbidden-terms.test.ts` asserts that mechanism directly instead).
 * `.md` files are scanned alongside `.ts` (the minimum-tripwire concern.2): concern CONTRACT.md docs carry the same
 * forbidden-vocabulary risk, and the `contract-allow:` marker idiom works unchanged in prose.
 */
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

/**
 * Walked at test time, not at collect time. This scan reads a live working tree, so a
 * path captured at collect time can be gone before the read; a sibling gate's real-tree positive
 * controls did exactly that until they moved to `mkdtemp`, and an editor save or checkout beside a
 * parallel worker can still do it. A late glob narrows the window and readPresentFiles closes it —
 * a file that no longer exists is not committed tree content and can hold no violation. The
 * empty-glob guard below keeps a broken walk from passing vacuously.
 */
const walkScannedFiles = (): string[] =>
  SCAN_SCOPE.flatMap((scopePath) => [
    ...globSync(join(repoRoot, scopePath, "**", "*.ts")),
    ...globSync(join(repoRoot, scopePath, "**", "*.md")),
    ...globSync(join(repoRoot, scopePath, "**", "*.tsx")),

  ]).filter((file) => !file.includes(`${join("src", "scan")}/`));

// Real-tree walk + read of ~1,200 files: the realTree class in ../testkit/executionPolicy.ts.
describe("generic-core forbidden-terms scan gate (the scan/dependency-boundary gate)", { timeout: EXECUTION_TIMEOUTS.realTree }, () => {
  it("has at least one file to scan (guards against an empty/broken glob)", () => {
    expect(walkScannedFiles().length).toBeGreaterThan(0);
  });

  it("has zero unmarked forbidden-term violations across the frozen scan scope", () => {
    const allViolations = readPresentFiles(walkScannedFiles()).flatMap(({ file, text }) =>
      scanTextForForbiddenTerms(text, file, D99_ALLOWLIST),
    );
    expect(allViolations).toEqual([]);
  });
});
