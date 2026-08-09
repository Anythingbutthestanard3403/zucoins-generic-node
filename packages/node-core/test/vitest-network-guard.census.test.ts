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

interface ProjectConfig {
  test?: { setupFiles?: string | string[] };
}

const projectEntries = (rootConfig as { test?: { projects?: (string | ProjectConfig)[] } }).test
  ?.projects;

async function setupFilesOf(entry: string | ProjectConfig): Promise<string[]> {
  let config: ProjectConfig;
  if (typeof entry === "string") {
    const configPath = new URL(`${entry}/vitest.config.ts`, REPO_ROOT);
    if (!existsSync(configPath)) return [];
    config = ((await import(pathToFileURL(fileURLToPath(configPath)).href)) as {
      default: ProjectConfig;
    }).default;
  } else {
    // An inline entry contributes only what it spells out — exactly the shape that lost the guard.
    config = entry;
  }
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
