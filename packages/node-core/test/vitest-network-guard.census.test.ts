import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

import rootConfig from "../../../vitest.config.ts";

// Every project in the repo-root `projects` list must install the network-containment guard, or
// name itself here with the reason it is safe without one. Same shape as ALLOWED_INTERNAL_IMPORTS
// in boundaries.test.ts: adding an entry is an explicit, reviewed act rather than a silent gap.
//
// The hole this closes was real: the two consumer packages were declared as an INLINE project
// entry, which inherits nothing from their own configs, so the suites proving the consumer trust
// boundary were the only ones in `pnpm test` with a reachable socket.
const GUARD_EXEMPT_PROJECTS = new Map<string, string>([
  [
    "packages/generic-node-contracts",
    "Pure leaf, zero runtime deps: src/scan/dependency-boundary.test.ts bans net/db/worker imports " +
      "outright, so containment there is structural rather than runtime. Its own vitest.config.ts " +
      "documents the same exemption.",
  ],
]);

const GUARD_FILENAME = "setup-network-guard.ts";
const REPO_ROOT = new URL("../../../", import.meta.url);
// Directory projects resolve vitest.config.ts / vite.config.ts (operator SPA uses vite.config).
// File projects (packages/node-core/vitest.pg.config.ts) are the config itself.
const CONFIG_FILENAMES = ["vitest.config.ts", "vite.config.ts"];

interface ProjectConfig {
  test?: {
    setupFiles?: string | string[];
    poolOptions?: { forks?: { singleFork?: boolean } };
    include?: string[];
    exclude?: string[];
  };
}

const projectEntries = (rootConfig as { test?: { projects?: (string | ProjectConfig)[] } }).test
  ?.projects;

function resolveConfigUrl(entry: string): URL | undefined {
  const asFile = new URL(entry, REPO_ROOT);
  if (existsSync(asFile) && entry.endsWith(".ts")) return asFile;
  return CONFIG_FILENAMES.map((filename) => new URL(`${entry}/${filename}`, REPO_ROOT)).find(
    (candidate) => existsSync(candidate),
  );
}

async function loadProjectConfig(entry: string | ProjectConfig): Promise<ProjectConfig> {
  if (typeof entry !== "string") {
    // An inline entry contributes only what it spells out — exactly the shape that lost the guard.
    return entry;
  }
  const configPath = resolveConfigUrl(entry);
  if (configPath === undefined) return {};
  return ((await import(pathToFileURL(fileURLToPath(configPath)).href)) as {
    default: ProjectConfig;
  }).default;
}

async function setupFilesOf(entry: string | ProjectConfig): Promise<string[]> {
  const config = await loadProjectConfig(entry);
  const declared = config.test?.setupFiles ?? [];
  return typeof declared === "string" ? [declared] : declared;
}

describe("vitest project network-guard census", () => {
  it("declares projects as a static list this gate can enumerate", () => {
    expect(projectEntries).toBeDefined();
    expect(projectEntries?.length).toBeGreaterThan(0);
  });

  it("installs the network guard in every project that is not explicitly exempt", async () => {
    const unguarded: string[] = [];
    for (const entry of projectEntries ?? []) {
      const label = typeof entry === "string" ? entry : JSON.stringify(entry);
      if (typeof entry === "string" && GUARD_EXEMPT_PROJECTS.has(entry)) continue;
      const setupFiles = await setupFilesOf(entry);
      const guard = setupFiles.find((file) => file.endsWith(GUARD_FILENAME));
      if (guard === undefined) {
        unguarded.push(`${label}: no setup file named ${GUARD_FILENAME}`);
        continue;
      }
      if (!existsSync(guard)) unguarded.push(`${label}: ${guard} does not exist`);
    }
    expect(unguarded).toEqual([]);
  });

  it("keeps the exemption list free of projects that are no longer listed", () => {
    const listed = new Set((projectEntries ?? []).filter((entry) => typeof entry === "string"));
    expect([...GUARD_EXEMPT_PROJECTS.keys()].filter((project) => !listed.has(project))).toEqual([]);
  });
});

describe("vitest PG project concurrency bound (ZTR-1209)", () => {
  // Workspace projects cannot set maxWorkers/fileParallelism (NonProjectOptions). The only
  // per-project concurrency control Vitest honors is poolOptions.forks.singleFork.
  const PG_PROJECT_SUFFIX = "vitest.pg.config.ts";

  it("lists dedicated unit + pg config files for node-core and generic-node", () => {
    const listed = (projectEntries ?? []).filter((e): e is string => typeof e === "string");
    expect(listed).toContain("packages/node-core/vitest.unit.config.ts");
    expect(listed).toContain("packages/node-core/vitest.pg.config.ts");
    expect(listed).toContain("apps/generic-node/vitest.unit.config.ts");
    expect(listed).toContain("apps/generic-node/vitest.pg.config.ts");
    // Directory package entries would load the umbrella only — nested projects are not expanded.
    expect(listed).not.toContain("packages/node-core");
    expect(listed).not.toContain("apps/generic-node");
  });

  it("every *.pg.config.ts project serializes files via singleFork", async () => {
    const pgEntries = (projectEntries ?? []).filter(
      (e): e is string => typeof e === "string" && e.endsWith(PG_PROJECT_SUFFIX),
    );
    expect(pgEntries.length).toBeGreaterThanOrEqual(2);
    for (const entry of pgEntries) {
      const config = await loadProjectConfig(entry);
      expect(
        config.test?.poolOptions?.forks?.singleFork,
        `${entry} must set poolOptions.forks.singleFork`,
      ).toBe(true);
      const include = config.test?.include ?? [];
      expect(
        include.some((g) => g.includes(".pg.test.ts") || g.includes("pg-concurrency")),
        `${entry} include must cover PG suites`,
      ).toBe(true);
    }
  });

  // Non-suffix live-PG openers must ride the singleFork pg project, not the parallel unit pool.
  // Paths are package-relative (match vitest.pg.config.ts include entries).
  const NODE_CORE_LIVE_NON_SUFFIX = [
    "src/observation/capture.concurrency.test.ts",
    "src/observation/quarantine.integration.test.ts",
    "test/custody-eligibility-lease-pk.test.ts",
    "test/degraded-mode.fault.test.ts",
    "test/disk-db-exhaustion.fault.test.ts",
    "test/migration-integrity.test.ts",
    "test/observation-migration-integrity.test.ts",
    "test/operation-lifecycle-concurrency.test.ts",
    "test/registry-isolation-rotation.test.ts",
  ] as const;

  const GENERIC_NODE_LIVE_NON_SUFFIX = [
    "test/db/migrate-guards.test.ts",
    "test/db/migration-lock.test.ts",
    "test/db/overlap-guard.test.ts",
    "test/genesis-t0-observer.test.ts",
    "test/operations/arm-live-composition.test.ts",
    "test/reporting/durable-store.test.ts",
    "test/reporting/production-destinations-list.test.ts",
    "test/reporting/production-durable-mount.test.ts",
    "test/reporting/production-reporting-stream.test.ts",
  ] as const;

  function basenameOf(packageRelative: string): string {
    const parts = packageRelative.split("/");
    return parts[parts.length - 1] ?? packageRelative;
  }

  function excludeCovers(excludes: string[], packageRelative: string): boolean {
    const base = basenameOf(packageRelative);
    return excludes.some(
      (g) =>
        g === packageRelative ||
        g === `**/${base}` ||
        g.endsWith(`/${base}`) ||
        g === base,
    );
  }

  function includeCovers(includes: string[], packageRelative: string): boolean {
    return includes.some(
      (g) =>
        g === packageRelative ||
        g === `**/${basenameOf(packageRelative)}` ||
        g.endsWith(`/${basenameOf(packageRelative)}`),
    );
  }

  it("unit excludes and pg includes cover every known non-suffix live-PG opener", async () => {
    const pairs: { unit: string; pg: string; files: readonly string[] }[] = [
      {
        unit: "packages/node-core/vitest.unit.config.ts",
        pg: "packages/node-core/vitest.pg.config.ts",
        files: NODE_CORE_LIVE_NON_SUFFIX,
      },
      {
        unit: "apps/generic-node/vitest.unit.config.ts",
        pg: "apps/generic-node/vitest.pg.config.ts",
        files: GENERIC_NODE_LIVE_NON_SUFFIX,
      },
    ];
    const gaps: string[] = [];
    for (const { unit, pg, files } of pairs) {
      const unitCfg = await loadProjectConfig(unit);
      const pgCfg = await loadProjectConfig(pg);
      const excludes = unitCfg.test?.exclude ?? [];
      const includes = pgCfg.test?.include ?? [];
      for (const file of files) {
        if (!excludeCovers(excludes, file)) {
          gaps.push(`${unit} exclude missing ${file}`);
        }
        if (!includeCovers(includes, file)) {
          gaps.push(`${pg} include missing ${file}`);
        }
      }
      expect(
        pgCfg.test?.poolOptions?.forks?.singleFork,
        `${pg} must remain singleFork`,
      ).toBe(true);
    }
    expect(gaps).toEqual([]);
  });

  /**
   * Strong openers: a new suite that does any of these outside singleFork is a red gate.
   * Comment-only / mock-only mentions of TEST_DATABASE_URL or `import type { Pool }` do not match.
   * Deliberately omits bare `psql (` — version strings like `psql (PostgreSQL) 16.4` are not openers.
   */
  const LIVE_PG_OPENER =
    /\bnew\s+Pool\s*\(|\bnew\s+Client\s*\(|\bfrom\s+["']pg["']|\brunMigrationsOnPool\b|\bCREATE\s+DATABASE\b|\bcreatedb\b|\bexecFileSync\s*\(\s*["']psql["']|\bspawn(?:Sync)?\s*\(\s*["']psql["']|\bexecFile\s*\(\s*["']psql["']/;

  /** Files that import/mention pg machinery without opening a live server. */
  const LIVE_PG_SCAN_ALLOWLIST = new Set([
    // Mock Pool only — no TEST_DATABASE_URL / no connect.
    "apps/generic-node/test/postgres-deadline.test.ts",
    // Census / provision unit tests: pattern strings, not live connections.
    "packages/node-core/test/mandatory-database-tests.census.test.ts",
    "packages/node-core/test/vitest-global-setup-provision.test.ts",
    "packages/node-core/test/vitest-network-guard.census.test.ts",
  ]);

  function walkTestFiles(absDir: string, out: string[]): void {
    if (!existsSync(absDir)) return;
    for (const name of readdirSync(absDir)) {
      if (name === "node_modules" || name === "dist") continue;
      const full = join(absDir, name);
      const st = statSync(full);
      if (st.isDirectory()) {
        // live-chain has its own singleFork config, not part of root pnpm test.
        if (name === "live-chain") continue;
        walkTestFiles(full, out);
        continue;
      }
      if (name.endsWith(".test.ts") || name.endsWith(".test.mjs")) out.push(full);
    }
  }

  function isSuffixPg(relPosix: string): boolean {
    return (
      relPosix.endsWith(".pg.test.ts") ||
      relPosix.endsWith("-pg.test.ts") ||
      relPosix.endsWith("/pg-concurrency.test.ts")
    );
  }

  it("no live-PG opener runs outside a singleFork pg project", () => {
    const repoRootPath = fileURLToPath(REPO_ROOT);
    const knownNonSuffix = new Set(
      [
        ...NODE_CORE_LIVE_NON_SUFFIX.map((f) => `packages/node-core/${f}`),
        ...GENERIC_NODE_LIVE_NON_SUFFIX.map((f) => `apps/generic-node/${f}`),
      ].map((p) => p.replace(/\\/g, "/")),
    );

    const roots = [
      join(repoRootPath, "packages/node-core/src"),
      join(repoRootPath, "packages/node-core/test"),
      join(repoRootPath, "apps/generic-node/src"),
      join(repoRootPath, "apps/generic-node/test"),
      join(repoRootPath, "apps/generic-node/scripts"),
    ];
    const files: string[] = [];
    for (const root of roots) walkTestFiles(root, files);

    const leaks: string[] = [];
    for (const abs of files) {
      const rel = relative(repoRootPath, abs).replace(/\\/g, "/");
      if (isSuffixPg(rel)) continue;
      if (LIVE_PG_SCAN_ALLOWLIST.has(rel)) continue;
      if (knownNonSuffix.has(rel)) continue;
      const body = readFileSync(abs, "utf8");
      if (LIVE_PG_OPENER.test(body)) {
        leaks.push(rel);
      }
    }
    expect(
      leaks,
      "live-PG openers must be *.pg.test.ts or listed in NODE_CORE/GENERIC_NODE_LIVE_NON_SUFFIX + unit exclude/pg include",
    ).toEqual([]);
  });
});
