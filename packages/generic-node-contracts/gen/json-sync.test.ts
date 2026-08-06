import { globSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { assertGenCoverage, GEN_SNAPSHOTS, renderSnapshot } from "../scripts/gen-registry.ts";
import type { GenSnapshot } from "../scripts/gen-registry.ts";

/**
 * gen/*.json is a review-diff convenience snapshot, never byte authority (each snapshot's own
 * `.contract.ts`/manifest source is authority). This fails if a manifest is edited without
 * re-running `pnpm --filter @zucoins/generic-node-contracts emit-json`, or if a `gen/*.json` file
 * is added/removed on disk without a matching `GEN_SNAPSHOTS` entry (the closed-set gate).
 */
const here = dirname(fileURLToPath(import.meta.url));

describe("gen/*.json sync with source manifests", () => {
  for (const snapshot of GEN_SNAPSHOTS) {
    it(`gen/${snapshot.file} byte-matches a fresh render`, () => {
      const committed = readFileSync(join(here, snapshot.file), "utf8");
      expect(committed).toBe(renderSnapshot(snapshot));
    });
  }

  it("closed-set: on-disk gen/*.json files equal the registered GEN_SNAPSHOTS set", () => {
    const onDisk = globSync(join(here, "*.json"))
      .map((file) => basename(file))
      .sort();
    const registered = [...GEN_SNAPSHOTS.map((snapshot) => snapshot.file)].sort();
    expect(() => assertGenCoverage(onDisk, registered)).not.toThrow();
    expect(onDisk).toEqual(registered);
  });

  it("rejects a stale committed snapshot (negative path)", () => {
    const target = GEN_SNAPSHOTS.find((snapshot) => snapshot.file === "operations.json");
    if (target === undefined) {
      throw new Error("operations.json snapshot missing from GEN_SNAPSHOTS");
    }
    const mutated: GenSnapshot = {
      ...target,
      value: { ...(target.value as object), WORKFLOW_GRAPH_SUPPORTED: true },
    };
    const staleCommitted = renderSnapshot(mutated);
    const fresh = renderSnapshot(target);
    expect(staleCommitted).not.toBe(fresh);
  });

  it("closed-set breach: an extra on-disk file is caught", () => {
    const registered = GEN_SNAPSHOTS.map((snapshot) => snapshot.file);
    expect(() => assertGenCoverage([...registered, "phantom.json"], registered)).toThrow();
  });

  it("closed-set breach: an extra registered file is caught", () => {
    const registered = GEN_SNAPSHOTS.map((snapshot) => snapshot.file);
    expect(() => assertGenCoverage(registered, [...registered, "phantom.json"])).toThrow();
  });

  it("byte-stability breach: neither alternate rendering matches a raw-no-nl committed file", () => {
    const target = GEN_SNAPSHOTS.find((snapshot) => snapshot.file === "wallet-state-matrix.json");
    if (target === undefined) {
      throw new Error("wallet-state-matrix.json snapshot missing from GEN_SNAPSHOTS");
    }
    const committed = readFileSync(join(here, target.file), "utf8");
    const withTrailingNewline = `${JSON.stringify(target.value, null, 2)}\n`;
    const sortedVariant = renderSnapshot({ ...target, recipe: "sorted-nl" });
    expect(withTrailingNewline).not.toBe(committed);
    expect(sortedVariant).not.toBe(committed);
  });
});
