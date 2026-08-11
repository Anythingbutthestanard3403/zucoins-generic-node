import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      "packages/generic-node-contracts",
      // unit + pg are sibling projects (not nested): Vitest only expands projects from the
      // root config. PG projects use poolOptions.forks.singleFork so *.pg.test.ts files never
      // run multi-file-parallel against one scratch Postgres (ZTR-1209).
      "packages/node-core/vitest.unit.config.ts",
      "packages/node-core/vitest.pg.config.ts",
      "apps/generic-node/vitest.unit.config.ts",
      "apps/generic-node/vitest.pg.config.ts",
      // The two consumer packages were declared inline here, which inherited neither their own
      // setupFiles (network containment) nor any resolve.alias — so the one suite proving the
      // consumer trust boundary ran unguarded, against a stale dist/. Referencing the packages'
      // own configs keeps those settings at the package, contributed once.
      // packages/node-core/test/vitest-network-guard.census.test.ts fails if a project entry ever
      // drops the guard again.
      "packages/generic-node-consumer",
      "packages/consumer-example",
      // The operator SPA. Its 37 test files ran only under an explicit package filter, so the
      // documented green-build gate proved nothing about any console screen. Referenced as a
      // path (not an inline entry) so the SPA keeps its own jsdom environment, react plugin and
      // setup files — folding it into apps/generic-node's include globs would run React tests
      // under the node environment instead.
      "apps/generic-node/admin",
    ],
  },
});
