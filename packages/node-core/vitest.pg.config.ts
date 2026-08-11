import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

import base from "./vitest.unit.config.ts";

// Real-PostgreSQL suites for this package (ZTR-1209).
//
// Workspace projects cannot set maxWorkers/fileParallelism (stripped as NonProjectOptions).
// The only per-project concurrency control Vitest honors is poolOptions.forks.singleFork,
// which serializes every file in this project onto one fork — eliminating multi-file
// parallel DDL/deadlock contention on a shared scratch Postgres while non-PG suites keep
// running in parallel under vitest.unit.config.ts.
//
// Per-run scratch DB naming stays in vitest.global-setup.ts (testdb_<pid>_<ts>).
// PG_REQUIRED semantics are unchanged (registerPgRequiredGuard + fail-closed skips).
const THIS_CONFIG_BASENAME = "vitest.pg.config.ts";

function thisConfigIsDirectCliTarget(): boolean {
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--config" || arg === "-c") {
      const value = argv[i + 1] ?? "";
      return value === THIS_CONFIG_BASENAME || value.endsWith(`/${THIS_CONFIG_BASENAME}`);
    }
  }
  return false;
}

function standaloneRunHasPathFilters(): boolean {
  const VITEST_SUBCOMMANDS = new Set(["run", "watch", "dev", "related", "bench", "list"]);
  const FLAGS_WITH_VALUE = new Set(["--config", "-c"]);
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (VITEST_SUBCOMMANDS.has(arg)) continue;
    if (FLAGS_WITH_VALUE.has(arg)) {
      i++;
      continue;
    }
    if (arg.startsWith("-")) continue;
    return true;
  }
  return false;
}

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  resolve: base.resolve,
  test: {
    name: "node-core-pg",
    passWithNoTests: !thisConfigIsDirectCliTarget() || !standaloneRunHasPathFilters(),
    include: [
      "test/**/*.pg.test.ts",
      "src/**/*.pg.test.ts",
      "test/**/*-pg.test.ts",
      "test/pg-concurrency.test.ts",
      // Live-Postgres openers that predate the *.pg.test.ts suffix convention (ZTR-1209 r5).
      // Must stay in lockstep with vitest.unit.config.ts exclude + the census inventory.
      "src/observation/capture.concurrency.test.ts",
      "src/observation/quarantine.integration.test.ts",
      "test/custody-eligibility-lease-pk.test.ts",
      "test/degraded-mode.fault.test.ts",
      "test/disk-db-exhaustion.fault.test.ts",
      "test/migration-integrity.test.ts",
      "test/observation-migration-integrity.test.ts",
      "test/operation-lifecycle-concurrency.test.ts",
      "test/registry-isolation-rotation.test.ts",
    ],
    exclude: ["**/node_modules/**", "**/dist/**"],
    pool: "forks",
    poolOptions: { forks: { singleFork: true } },
    // PG suites routinely exceed the 30s unit budget under schema apply + concurrent drills.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    setupFiles: [fileURLToPath(new URL("./test/setup-network-guard.ts", import.meta.url))],
    globalSetup: [fileURLToPath(new URL("../../vitest.global-setup.ts", import.meta.url))],
  },
});
