import { existsSync } from "node:fs";
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
});
