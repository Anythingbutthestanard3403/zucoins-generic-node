import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

import base from "./vitest.unit.config.ts";

// Real-PostgreSQL suites for this package (ZTR-1209).
// See packages/node-core/vitest.pg.config.ts for why singleFork is the concurrency bound.
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
    name: "generic-node-pg",
    passWithNoTests: !thisConfigIsDirectCliTarget() || !standaloneRunHasPathFilters(),
    include: [
      "test/**/*.pg.test.ts",
      "src/**/*.pg.test.ts",
      "test/**/*-pg.test.ts",
      "scripts/**/*.pg.test.ts",
      // Live-Postgres openers that predate the *.pg.test.ts suffix convention (ZTR-1209 r5).
      // Must stay in lockstep with vitest.unit.config.ts exclude + the census inventory.
      "test/db/migrate-guards.test.ts",
      "test/db/migration-lock.test.ts",
      "test/db/overlap-guard.test.ts",
      "test/genesis-t0-observer.test.ts",
      "test/operations/arm-live-composition.test.ts",
      "test/reporting/durable-store.test.ts",
      "test/reporting/production-destinations-list.test.ts",
      "test/reporting/production-durable-mount.test.ts",
      "test/reporting/production-reporting-stream.test.ts",
    ],
    exclude: ["**/node_modules/**", "**/dist/**"],
    pool: "forks",
    poolOptions: { forks: { singleFork: true } },
    testTimeout: 120_000,
    hookTimeout: 120_000,
    setupFiles: [fileURLToPath(new URL("./test/setup-network-guard.ts", import.meta.url))],
    globalSetup: [fileURLToPath(new URL("../../vitest.global-setup.ts", import.meta.url))],
  },
});
