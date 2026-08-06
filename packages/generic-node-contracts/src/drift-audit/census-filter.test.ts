import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  CONCERN_MODULES,
  concernDirsOnDisk,
  excludedFixtureDirs,
  landedButUnwiredConcernDirs,
  PENDING_CONCERN_DIRS,
  staleConcernEntries,
  unregisteredConcernDirs,
} from "./registry.ts";

/**
 * the concern-manifest registry drift-audit — census filter tests. Drives the REAL `concernDirsOnDisk`
 * `unregisteredConcernDirs()` (registry.ts) against an independent on-disk fixture tree
 * under `os.tmpdir()` (never under this package's own `src/`, avoiding a scan race with
 * dependency-boundary.test.ts's own `src/**` glob) — a local logic reimplementation or a
 * registry-seeded mock would validate the fixture against itself, not the real functions.
 *
 * 1. Positive detection: a non-zz-prefixed unwired dir IS flagged by the real classifier.
 * 2. zz-* exclusion: the `!dir.startsWith("zz-")` filter is exercised against a real
 *    planted fixture; `excludedFixtureDirs()` surfaces the excluded set.
 * 3. No FS race: fixtures live under `os.tmpdir()`, never observed by
 *    dependency-boundary.test.ts's module-load globSync over `src/**`.
 */

let scratchDir: string | undefined;

afterEach(() => {
  if (scratchDir) {
    rmSync(scratchDir, { recursive: true, force: true });
    scratchDir = undefined;
  }
});

/**
 * Plants a real `manifest.ts` under a freshly created, fully isolated scratch directory. The
 * caller passes `root` as the `srcDir` scan option — never this package's own `src/` tree.
 */
const plantConcernDir = (root: string, dir: string): void => {
  const concernPath = join(root, dir);
  mkdirSync(concernPath, { recursive: true });
  writeFileSync(join(concernPath, "manifest.ts"), `export const concern = ${JSON.stringify(dir)};\n`);
};

describe("drift-audit census filter: positive detection and fixture exclusion", () => {
  it("positive-detection: a non-zz unwired dir IS classified as unregistered by the real scan (sub-claim 2 — backported from #900)", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "filter-census-"));
    plantConcernDir(scratchDir, "some-new-unwired-concern");

    const onDisk = concernDirsOnDisk({ srcDir: scratchDir });
    expect(onDisk).toContain("some-new-unwired-concern");

    // Drives the REAL classification function, not a replica or a registry-derived mock: a
    // regression that stopped unregisteredConcernDirs() from actually detecting an unwired dir
    // now fails this test.
    expect(unregisteredConcernDirs({ srcDir: scratchDir })).toContain("some-new-unwired-concern");
  });

  it("zz-* filter: a zz-prefixed dir is removed by the real scan (sub-claim 1)", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "filter-census-"));
    plantConcernDir(scratchDir, "zz-fake-concern-test");

    expect(concernDirsOnDisk({ srcDir: scratchDir })).not.toContain("zz-fake-concern-test");
    expect(unregisteredConcernDirs({ srcDir: scratchDir })).not.toContain("zz-fake-concern-test");
  });

  it("zz-* filter does not affect non-zz names that share the prefix pattern", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "filter-census-"));
    for (const dir of ["z-single", "zzz-triple", "zz-dash", "amounts"]) {
      plantConcernDir(scratchDir, dir);
    }

    const onDisk = concernDirsOnDisk({ srcDir: scratchDir });
    // Only 'zz-dash' starts with the exact prefix 'zz-' → excluded
    expect(onDisk).not.toContain("zz-dash");
    expect(onDisk).toContain("z-single");
    expect(onDisk).toContain("zzz-triple");
    expect(onDisk).toContain("amounts");
  });

  it("excludedFixtureDirs surfaces the zz-* exclusion for observability", () => {
    // On an unmodified working tree with no planted fixtures, excludedFixtureDirs is empty.
    // If a test in another file has a fixture planted at call time, it would appear here —
    // making the silent exemption non-silent.
    const excluded = excludedFixtureDirs();
    expect(Array.isArray(excluded)).toBe(true);
    // Every entry in the excluded list MUST start with zz- (the filter invariant)
    for (const dir of excluded) {
      expect(dir.startsWith("zz-"), dir).toBe(true);
    }
  });

  it("all real concern dirs survive the fixture exclusion (no false positives)", () => {
    // concernDirsOnDisk() already applies the zz-* filter internally — confirms none of the
    // committed concern dirs are accidentally excluded by it.
    const onDisk = concernDirsOnDisk();
    expect(onDisk.every((dir) => !dir.startsWith("zz-"))).toBe(true);
    expect(onDisk.length).toBeGreaterThan(0);
  });

  it("baseline census is clean on today's main (no injected fixtures)", () => {
    // Same check as the production census — confirms the real scan (default srcDir) agrees
    // with the registered/pending registry.
    expect(unregisteredConcernDirs()).toEqual([]);
    expect(staleConcernEntries()).toEqual([]);
    expect(concernDirsOnDisk().length).toBeGreaterThan(0);
  });

  it("every known dir (CONCERN_MODULES + PENDING) passes the fixture exclusion", () => {
    // Sanity: no known concern dir accidentally starts with zz- (which would mean it's
    // silently excluded from the census — exactly the bug sub-claim 1 flags).
    for (const dir of [...Object.keys(CONCERN_MODULES), ...PENDING_CONCERN_DIRS]) {
      expect(dir.startsWith("zz-"), `${dir} starts with zz-`).toBe(false);
    }
  });
});

describe("drift-audit census: landed-but-unwired PENDING detection", () => {
  it("positive-detection: with PENDING empty, a non-pending planted dir is not landed-but-unwired", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "residual-census-"));
    //  discharged every PENDING name into CONCERN_MODULES. The detector formula is
    // onDisk ∩ PENDING − wired; with PENDING=[], the set is always empty even if a dir is planted.
    plantConcernDir(scratchDir, "synthetic-landed-name");
    expect(PENDING_CONCERN_DIRS).toEqual([]);
    expect(landedButUnwiredConcernDirs({ srcDir: scratchDir })).toEqual([]);
    // The older unregistered census still surfaces genuinely unknown dirs.
    expect(unregisteredConcernDirs({ srcDir: scratchDir })).toContain("synthetic-landed-name");
  });

  it("a wired concern dir is never reported as landed-but-unwired", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "residual-census-"));
    const wiredDir = Object.keys(CONCERN_MODULES)[0];
    plantConcernDir(scratchDir, wiredDir);

    expect(landedButUnwiredConcernDirs({ srcDir: scratchDir })).not.toContain(wiredDir);
  });

  it("zz-* fixture exclusion still applies to the landed-but-unwired detector", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "residual-census-"));
    plantConcernDir(scratchDir, "zz-pending-fixture");

    expect(landedButUnwiredConcernDirs({ srcDir: scratchDir })).toEqual([]);
  });

  it("tripwire: the landed-but-unwired set is frozen — no manifest may land under a PENDING name and escape audit silently", () => {
    // FROZEN ratchet of every concern manifest that has physically landed on disk under a name
    // still in PENDING_CONCERN_DIRS but is NOT wired into CONCERN_MODULES — i.e. manifests that
    // today receive zero structural audit. Deliberately a literal, not re-derived from
    // PENDING_CONCERN_DIRS: re-deriving would be tautological (a new dir added to PENDING that
    // lands unwired would grow both sides together and stay green — the very hole this closes).
    //
    // Ratchet semantics: the set may only shrink as each dir is wired into CONCERN_MODULES (its
    // promotion path). A NEW manifest landing under a PENDING name without being wired grows the
    // set and FAILS here loudly instead of slipping past the census unaudited. Wiring an existing
    // dir also fails until its name is removed here — forcing every change to be explicit. To
    // discharge an entry: add its static import + CONCERN_MODULES entry, then delete its name here
    // (and from PENDING_CONCERN_DIRS).
    //  discharged every entry via static import + CONCERN_MODULES + freeze backstop.
    // Ratchet may only stay empty or (if a new pending lands unwired) grow and fail loudly.
    const FROZEN_LANDED_BUT_UNWIRED: readonly string[] = [];

    expect(landedButUnwiredConcernDirs()).toEqual(FROZEN_LANDED_BUT_UNWIRED);
  });
});
