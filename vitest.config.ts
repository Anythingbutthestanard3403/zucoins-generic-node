import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      "packages/generic-node-contracts",
      "packages/node-core",
      "apps/generic-node",
      // The two consumer packages were declared inline here, which inherited neither their own
      // setupFiles (network containment) nor any resolve.alias — so the one suite proving the
      // consumer trust boundary ran unguarded, against a stale dist/. Referencing the packages'
      // own configs keeps those settings at the package, contributed once.
      // packages/node-core/test/vitest-network-guard.census.test.ts fails if a project entry ever
      // drops the guard again.
      "packages/generic-node-consumer",
      "packages/consumer-example",
    ],
  },
});
