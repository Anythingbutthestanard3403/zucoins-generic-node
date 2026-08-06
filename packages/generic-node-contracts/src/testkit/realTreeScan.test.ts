import { globSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

import { readIfPresent, readPresentFiles } from "./realTreeScan.ts";
import { EXECUTION_TIMEOUTS, maxTestForks } from "./executionPolicy.ts";

/**
 *  regression proof. Two failure modes made the canonical suite load-dependent:
 *
 * 1. A real-tree gate globbing a live source tree and reading a path a sibling worker had
 *    already removed (ENOENT). Reproduced below without any timing dependency.
 * 2. The same test files running under two different timeout budgets depending on whether
 *    the run entered through the repo root or the package. Pinned below by asserting the
 *    root config routes this package to its own standalone project.
 */

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const scratch = mkdtempSync(join(tmpdir(), "real-tree-scan-real-tree-scan-"));

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

describe("readIfPresent", () => {
  it("returns the text of a file that exists", () => {
    const present = join(scratch, "present.ts");
    writeFileSync(present, "export const A = 1;\n", "utf8");
    expect(readIfPresent(present)).toBe("export const A = 1;\n");
  });

  it("returns undefined for a path removed between the glob and the read", () => {
    const transient = join(scratch, "__census-fixture-transient.ts");
    writeFileSync(transient, "export const B = 2;\n", "utf8");
    const walked = globSync(join(scratch, "**", "*.ts"));
    expect(walked).toContain(transient);

    // Exactly what a branch switch or a fixture cleanup running in another worker does mid-scan.
    rmSync(transient);
    expect(() => readFileSync(transient, "utf8")).toThrow();
    expect(readIfPresent(transient)).toBeUndefined();
  });

  it("still throws for a read failure that is not ENOENT", () => {
    // A directory read fails with EISDIR, never ENOENT — the guard must not swallow it.
    expect(() => readIfPresent(scratch)).toThrow();
  });

  it("readPresentFiles drops vanished paths and keeps the rest intact", () => {
    const kept = join(scratch, "kept.ts");
    const gone = join(scratch, "gone.ts");
    writeFileSync(kept, "export const C = 3;\n", "utf8");
    const walked = [kept, gone];
    expect(readPresentFiles(walked)).toEqual([{ file: kept, text: "export const C = 3;\n" }]);
  });
});

describe("canonical execution policy", () => {
  const packageConfig = readFileSync(
    join(repoRoot, "packages", "generic-node-contracts", "vitest.config.ts"),
    "utf8",
  );
  const rootConfig = readFileSync(join(repoRoot, "vitest.config.ts"), "utf8");

  it("the package config applies the shared policy rather than Vitest's bare defaults", () => {
    expect(packageConfig).toContain("maxTestForks");
    expect(packageConfig).toContain("EXECUTION_TIMEOUTS");
  });

  it("the root project routes this package to its own standalone project", () => {
    // A `projects` string entry runs the package's own config verbatim, so the same files
    // execute under the same policy whether the run enters through the repo root or the
    // package. The root config has no catch-all glob of its own that could re-collect these
    // files under a different budget.
    expect(rootConfig).toContain('"packages/generic-node-contracts",');
  });

  it("only the three measured classes exceed the 5 s package default", () => {
    expect([...Object.keys(EXECUTION_TIMEOUTS)].sort()).toEqual(["ed25519", "fuzz500", "realTree"]);
    for (const budget of Object.values(EXECUTION_TIMEOUTS)) {
      expect(budget).toBeGreaterThan(5_000);
      // Still fails closed: a hung verifier or unbounded scan never returns.
      expect(budget).toBeLessThanOrEqual(30_000);
    }
  });

  it("the fork pool is bounded but never serialised", () => {
    expect(maxTestForks()).toBeGreaterThanOrEqual(2);
    expect(maxTestForks()).toBeLessThanOrEqual(4);
  });
});
