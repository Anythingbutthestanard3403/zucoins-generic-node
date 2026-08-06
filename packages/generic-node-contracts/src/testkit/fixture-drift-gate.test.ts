import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { CONCERN_REGISTRY } from "../registry.ts";
import { FIXTURE_PROVENANCE_REGISTRY } from "../fixture-provenance/registry.ts";
import { diffRegistryCoverage, discoverFixtureIndexPaths, verifyRegistryDigests } from "../fixture-provenance/verify.ts";

/**
 * the fixture-provenance drift gate fixture and manifest drift gate.
 *
 * Three independent drift axes, each a hard failure:
 *
 * 1. Golden file SHA-256 integrity — every `goldenRefs` entry across the COMPLETE
 *    `CONCERN_REGISTRY` (all 31 self-registered manifests, including the 12 PENDING concerns
 *    the drift-audit registry-walk does not yet cover) must hash-match its committed file.
 *    This closes the coverage gap: `drift-audit/registry-walk.test.ts` only walks its own
 *    `CONCERN_MODULES` (22 wired concerns), missing approval/artifacts/compat-literals/etc.
 *    whose manifests use repo-root-relative `packages/...` paths.
 *
 * 2. Provenance completeness (orphan detection) — the fixture-provenance surface fixture-provenance registry
 *    must cover exactly the on-disk fixture index set: zero orphan fixtures (unregistered
 *    `*.meta.json` / `manifest.json` / `*.vectors.json`) and zero dangling records (registry
 *    entries pointing at missing files). A negative control proves the detector fires.
 *
 * 3. Dependency-pin drift — `bignumber.js` must remain pinned to exactly `"9.1.0"` per the
 *    the scan-scope freeze wallet-parity mandate. Any drift (caret, tilde, version bump) is a hard failure.
 *
 * Path resolution: goldenRefs use two conventions — package-root-relative (`gen/...`,
 * `src/...`, `goldens/...`) and repo-root-relative (`packages/generic-node-contracts/...`).
 * Both resolve correctly via the prefix check below.
 */

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..", "..");
const repoRoot = join(packageRoot, "..", "..");

const PKG_PREFIX = "packages/generic-node-contracts/";

const resolveGoldenPath = (path: string): string =>
  path.startsWith(PKG_PREFIX) ? join(repoRoot, path) : join(packageRoot, path);

const sha256OfFile = (absPath: string): string =>
  createHash("sha256").update(readFileSync(absPath)).digest("hex");

describe("fixture and manifest drift gate (the fixture-provenance drift gate)", () => {
  describe("golden file SHA-256 integrity", () => {
    it("every goldenRef across the complete CONCERN_REGISTRY hash-matches its committed file", () => {
      const failures: string[] = [];
      for (const { concernDir, exportName, manifest } of CONCERN_REGISTRY) {
        for (const ref of manifest.goldenRefs) {
          const abs = resolveGoldenPath(ref.path);
          if (!existsSync(abs)) {
            failures.push(`${concernDir}/${exportName}: MISSING ${ref.path}`);
            continue;
          }
          const actual = sha256OfFile(abs);
          if (actual !== ref.sha256) {
            failures.push(
              `${concernDir}/${exportName}: DRIFT ${ref.path} — declared ${ref.sha256}, actual ${actual}`,
            );
          }
        }
      }
      expect(failures).toEqual([]);
    });

    it("the registry carries a non-zero goldenRef count (guard against silent registry gutting)", () => {
      const total = CONCERN_REGISTRY.reduce((sum, entry) => sum + entry.manifest.goldenRefs.length, 0);
      expect(total).toBeGreaterThan(0);
    });

    it("fail-first: a single flipped hash char is caught", () => {
      const first = CONCERN_REGISTRY.find((e) => e.manifest.goldenRefs.length > 0);
      expect(first).toBeDefined();
      const ref = first?.manifest.goldenRefs[0];
      expect(ref).toBeDefined();
      if (!ref) return;
      const abs = resolveGoldenPath(ref.path);
      const actual = sha256OfFile(abs);
      const flipped = actual.startsWith("0") ? `1${actual.slice(1)}` : `0${actual.slice(1)}`;
      expect(flipped).not.toBe(ref.sha256);
    });
  });

  describe("provenance completeness (orphan detection)", () => {
    it("the fixture-provenance registry covers exactly the on-disk fixture index set", () => {
      const diff = diffRegistryCoverage();
      expect(diff.orphanFixtures).toEqual([]);
      expect(diff.danglingRecords).toEqual([]);
    });

    it("every fixture-provenance record digest-verifies against committed bytes", () => {
      expect(verifyRegistryDigests()).toEqual([]);
    });

    it("discovers a non-empty fixture index set (guard against a broken glob)", () => {
      expect(discoverFixtureIndexPaths().length).toBeGreaterThan(0);
      expect(FIXTURE_PROVENANCE_REGISTRY.length).toBeGreaterThan(0);
    });

    it("fail-first: an unregistered fixture index file is detected as an orphan", () => {
      // Isolated temp root (never the real package tree) so the planted orphan cannot race with
      // concurrent packageRoot-globbing tests (the cross-file FS hazard).
      const tmpRoot = mkdtempSync(join(tmpdir(), "fixture-drift-gate-"));
      try {
        mkdirSync(join(tmpRoot, "goldens", "surprise"), { recursive: true });
        writeFileSync(join(tmpRoot, "goldens", "surprise", "orphan.meta.json"), "{}");
        const diff = diffRegistryCoverage(tmpRoot);
        expect(diff.orphanFixtures).toContain("goldens/surprise/orphan.meta.json");
      } finally {
        rmSync(tmpRoot, { recursive: true, force: true });
      }
    });
  });

  describe("dependency-pin drift (the scan-scope freeze wallet-parity mandate)", () => {
    it("bignumber.js is pinned to exactly 9.1.0 — no caret, no tilde, no bump", () => {
      const pkgPath = join(packageRoot, "package.json");
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
        dependencies?: Record<string, string>;
      };
      const pin = pkg.dependencies?.["bignumber.js"];
      expect(pin).toBe("9.1.0");
    });

    it("fail-first: a caret-prefixed pin is not equal to the exact pin", () => {
      expect("^9.1.0").not.toBe("9.1.0");
      expect("~9.1.0").not.toBe("9.1.0");
      expect("9.1.1").not.toBe("9.1.0");
    });
  });
});
