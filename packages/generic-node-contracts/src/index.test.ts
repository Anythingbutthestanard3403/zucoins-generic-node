import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import * as entry from "./index.ts";
import type { ConcernManifest } from "./index.ts";
import {
  CONCERN_MANIFEST_COUNT,
  CONCERN_MANIFESTS,
  CONCERN_REGISTRY,
  concernByDir,
} from "./registry.ts";
import * as amounts from "./amounts/index.ts";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("the concern-manifest registry package entry surface (index.ts)", () => {
  it("re-exports the registry surface unchanged from ./registry.ts", () => {
    expect(entry.CONCERN_REGISTRY).toBe(CONCERN_REGISTRY);
    expect(entry.CONCERN_MANIFESTS).toBe(CONCERN_MANIFESTS);
    expect(entry.CONCERN_MANIFEST_COUNT).toBe(CONCERN_MANIFEST_COUNT);
    expect(entry.concernByDir).toBe(concernByDir);
  });

  it("exposes the registry surface as a subset of the barrel (observation + amounts re-exports also present)", () => {
    // The root barrel includes the registry surface plus the observation and amounts sub-barrel
    // re-exports wired on main (the observation concern/the amounts concern/the amounts downstream consumer). The registry keys must all be present;
    // per-concern runtime code beyond observation/amounts is still reached through subpaths.
    const keys = Object.keys(entry).sort();
    for (const registryKey of ["CONCERN_MANIFESTS", "CONCERN_MANIFEST_COUNT", "CONCERN_REGISTRY", "concernByDir"]) {
      expect(keys).toContain(registryKey);
    }
  });

  it("re-exports the canonical ConcernManifest type (compile-time surface)", () => {
    // A build-time proof the type is re-exported: this only type-checks if `ConcernManifest`
    // is importable from the barrel.
    const manifest: ConcernManifest = entry.CONCERN_MANIFESTS[0]!;
    expect(typeof manifest.concernId).toBe("string");
  });

  it("declares the root, ./amounts, and ./observation subpaths in package.json exports", () => {
    const packageJson = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as {
      exports?: Record<string, unknown>;
    };
    expect(packageJson.exports).toBeDefined();
    expect(Object.keys(packageJson.exports ?? {})).toEqual(
      expect.arrayContaining([".", "./amounts", "./observation"]),
    );
  });

  it("the ./amounts subpath target barrel exposes the production amount surface", () => {
    // consumes amounts through `@zucoins/generic-node-contracts/amounts`; assert the
    // subpath's source barrel carries the symbols that consumption depends on.
    for (const name of ["emitAmount", "isCanonicalAmount", "validateBalanceAmount", "validateOperationAmount"]) {
      expect(typeof (amounts as Record<string, unknown>)[name]).toBe("function");
    }
  });

  it("re-exports the observation concern barrel from the root (the observation concern, the node-core consumer/node-core consumer)", () => {
    // packages/node-core imports WALLET_OBSERVATION_ROLES directly from the package root, not
    // a subpath — assert the root barrel actually carries the observation concern's symbols.
    expect(entry.WALLET_OBSERVATION_ROLES).toEqual(["sender", "receiver", "genesis"]);
  });

  it("re-exports the amounts concern barrel from the root (the amounts concern/the amounts downstream consumer, the node-core consumer/node-core consumer)", () => {
    // packages/node-core imports compareAmounts/subtractAmounts/validateOperationAmount
    // directly from the package root — assert the root barrel exposes the amounts functions
    // too, not just the amounts subpath.
    for (const name of ["addAmounts", "emitAmount"]) {
      expect(typeof (entry as unknown as Record<string, unknown>)[name]).toBe("function");
    }
  });

  it("root-exports reporting rejection codes (/ UP-09, platform imports)", () => {
    const surface = entry as unknown as Record<string, unknown>;
    expect(Array.isArray(surface.REPORTING_REJECTION_CODES)).toBe(true);
    expect(surface.REPORTING_REJECTION_CODES).toContain("reporting_auth_hold");
    expect(
      (surface.REJECTION_STATUS as Readonly<Record<string, number>>).reporting_auth_hold,
    ).toBe(401);
  });
});

describe("root barrel reaches no test framework", () => {
  // Regression guard. `testkit/freeze.ts` imports `vitest` (a devDependency) at module top
  // level; re-exporting it from this barrel put vitest in the RUNTIME import graph of every
  // consumer. The production custody image is built with `pnpm install --prod`, so vitest is
  // absent there and `node dist/main.js` died at boot with
  // `ERR_MODULE_NOT_FOUND: Cannot find package 'vitest'`. Walk the barrel's relative-import
  // graph and assert no reached module imports a test framework.
  const TEST_FRAMEWORKS = ["vitest", "fast-check"];

  const importSpecifiers = (source: string): string[] => {
    const specs: string[] = [];
    const pattern =
      /(?:import|export)[^;]*?from\s*["']([^"']+)["']|(?:^|\s)import\s*["']([^"']+)["']/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(source)) !== null) {
      specs.push(match[1] ?? match[2]!);
    }
    return specs;
  };

  it("no module reachable from index.ts imports vitest or fast-check", () => {
    const srcRoot = join(packageRoot, "src");
    const seen = new Set<string>();
    const offenders: string[] = [];
    const queue: { file: string; chain: string[] }[] = [
      { file: join(srcRoot, "index.ts"), chain: [] },
    ];

    while (queue.length > 0) {
      const { file, chain } = queue.shift()!;
      if (seen.has(file)) continue;
      seen.add(file);

      for (const spec of importSpecifiers(readFileSync(file, "utf8"))) {
        if (TEST_FRAMEWORKS.includes(spec)) {
          offenders.push([...chain, file, spec].join(" -> "));
          continue;
        }
        // Only relative imports stay inside this package's graph; bare specifiers are
        // dependencies, and `.d.ts`/type-only edges cannot carry a runtime import.
        if (!spec.startsWith(".")) continue;
        const resolved = join(dirname(file), spec);
        if (existsSync(resolved) && statSync(resolved).isFile()) {
          queue.push({ file: resolved, chain: [...chain, file] });
        }
      }
    }

    expect(seen.size).toBeGreaterThan(1);
    expect(offenders).toEqual([]);
  });
});
