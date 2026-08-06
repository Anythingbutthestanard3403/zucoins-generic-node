import { globSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";

import {
  CONCERN_MANIFEST_COUNT,
  CONCERN_MANIFESTS,
  CONCERN_REGISTRY,
  concernByDir,
} from "./registry.ts";
import type { ConcernManifest } from "./testkit/concernManifest.ts";

/**
 * Independent structural predicate for the canonical `ConcernManifest` (testkit/concernManifest.ts).
 * Re-implemented locally — deliberately NOT imported from `src/drift-audit/` — so the closure proof
 * shares no discovery code with the auditor it is meant to cross-check. A provisional manifest of a
 * different shape fails this and is discarded from the discovered set.
 */
const isCanonicalManifest = (value: unknown): value is ConcernManifest => {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  const stringArray = (field: unknown): boolean =>
    Array.isArray(field) && field.every((item) => typeof item === "string");
  return (
    typeof candidate.concernId === "string" &&
    stringArray(candidate.decisionRefs) &&
    typeof candidate.frozenValues === "object" &&
    candidate.frozenValues !== null &&
    Array.isArray(candidate.goldenRefs) &&
    stringArray(candidate.scanRules) &&
    stringArray(candidate.sourceDocCitations)
  );
};

interface DiscoveredManifest {
  readonly concernDir: string;
  readonly exportName: string;
  readonly manifest: ConcernManifest;
}

const srcDir = dirname(fileURLToPath(import.meta.url));

/**
 * Rediscovers every self-registered `ConcernManifest` on disk without consulting the registry.
 * Mirrors the package's own manifest-file convention (the same per-concern `manifest.ts` glob the
 * drift-audit census uses, plus any `attack-manifest.ts` siblings), imports each module, and keeps
 * only exports that satisfy the canonical shape. Returned in the stable `(concernDir, exportName)`
 * sort so it can be compared position-for-position with the registry.
 */
const discoverOnDisk = async (): Promise<DiscoveredManifest[]> => {
  const manifestFiles = [
    ...globSync(join(srcDir, "*", "manifest.ts")),
    ...globSync(join(srcDir, "*", "attack-manifest.ts")),
  ];
  const discovered: DiscoveredManifest[] = [];
  for (const file of manifestFiles) {
    const moduleNamespace = (await import(pathToFileURL(file).href)) as Record<string, unknown>;
    for (const [exportName, value] of Object.entries(moduleNamespace)) {
      if (isCanonicalManifest(value)) {
        discovered.push({ concernDir: basename(dirname(file)), exportName, manifest: value });
      }
    }
  }
  return discovered.sort((a, b) =>
    a.concernDir === b.concernDir
      ? a.exportName.localeCompare(b.exportName)
      : a.concernDir.localeCompare(b.concernDir),
  );
};

const keyOf = (entry: { concernDir: string; exportName: string }): string =>
  `${entry.concernDir}::${entry.exportName}`;

describe("the concern-manifest registry concern registry closure (registry.ts)", () => {
  it("discovers a non-empty on-disk manifest set (guards against a broken glob)", async () => {
    const discovered = await discoverOnDisk();
    expect(discovered.length).toBeGreaterThan(0);
  });

  it("equals the exact set of self-registered manifests discovered on disk", async () => {
    const discovered = await discoverOnDisk();
    const registryKeys = CONCERN_REGISTRY.map((entry) => ({
      concernDir: entry.concernDir,
      exportName: entry.exportName,
      concernId: entry.manifest.concernId,
    }));
    const discoveredKeys = discovered.map((entry) => ({
      concernDir: entry.concernDir,
      exportName: entry.exportName,
      concernId: entry.manifest.concernId,
    }));
    // Position-for-position equality proves closure (no omitted or stale entry) AND the shared
    // stable sort in a single assertion.
    expect(registryKeys).toEqual(discoveredKeys);
  });

  it("wires the exact manifest object discovered for each entry", async () => {
    const discovered = await discoverOnDisk();
    const discoveredByKey = new Map(discovered.map((entry) => [keyOf(entry), entry.manifest]));
    for (const entry of CONCERN_REGISTRY) {
      expect(entry.manifest).toEqual(discoveredByKey.get(keyOf(entry)));
    }
  });

  it("holds a stable, total sort by (concernDir, exportName)", () => {
    const keys = CONCERN_REGISTRY.map(keyOf);
    const sorted = CONCERN_REGISTRY.map((entry) => ({
      concernDir: entry.concernDir,
      exportName: entry.exportName,
    }))
      .sort((a, b) =>
        a.concernDir === b.concernDir
          ? a.exportName.localeCompare(b.exportName)
          : a.concernDir.localeCompare(b.concernDir),
      )
      .map(keyOf);
    expect(keys).toEqual(sorted);
  });

  it("has a unique (concernDir, exportName) pair for every entry", () => {
    const keys = CONCERN_REGISTRY.map(keyOf);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("gives every entry the six-field canonical manifest shape", () => {
    for (const entry of CONCERN_REGISTRY) {
      expect(isCanonicalManifest(entry.manifest)).toBe(true);
      expect(Object.keys(entry.manifest).sort()).toEqual(
        ["concernId", "decisionRefs", "frozenValues", "goldenRefs", "scanRules", "sourceDocCitations"].sort(),
      );
    }
  });
});

describe("the concern-manifest registry derived accessors (registry.ts)", () => {
  it("CONCERN_MANIFESTS mirrors the registry manifests in sequence", () => {
    expect(CONCERN_MANIFESTS).toEqual(CONCERN_REGISTRY.map((entry) => entry.manifest));
  });

  it("CONCERN_MANIFEST_COUNT equals the registry length", () => {
    expect(CONCERN_MANIFEST_COUNT).toBe(CONCERN_REGISTRY.length);
  });

  it("concernByDir returns the first entry for a directory, or undefined", () => {
    expect(concernByDir("custody")?.exportName).toBe("CUSTODY_CONCERN_MANIFEST");
    expect(concernByDir("does-not-exist")).toBeUndefined();
  });
});
