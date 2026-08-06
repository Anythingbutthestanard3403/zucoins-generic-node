import { defineConfig } from "vitest/config";

import { EXECUTION_TIMEOUTS, maxTestForks } from "./src/testkit/executionPolicy.ts";

// Scoped runner for the pure-leaf contracts package. This package has zero runtime deps and
// performs no I/O beyond reading the working tree, so it needs neither the network-containment
// guard nor the widget/dashboard global setup the repo-root suite (vitest.config.ts) carries.
//
// : this config is now the SINGLE execution policy for these test files. The root suite
// used to discover them a second time through its `packages/*/src/**` include glob and run them
// under a 30s budget, while this config set no timeouts at all and inherited vitest's 5s
// default — the same test passed one way and timed out the other. The root config now excludes
// this package and lists it as a standalone project entry instead, so every entry point lands
// here. The default timeout stays at vitest's 5s; the three classes measured to need more widen
// themselves per-test from EXECUTION_TIMEOUTS in src/testkit/executionPolicy.ts.
export default defineConfig({
  test: {
    name: "generic-node-contracts",
    passWithNoTests: true,
    // Several gates here scan the real working tree while sibling tests plant and remove real
    // fixture files inside those same trees. Forks keep each file's module state isolated; the
    // bounded pool stops every fork transpiling at once and starving the CPU-bound crypto cases.
    // File parallelism stays ON — serialising the suite would hide the cross-file interference
    // rather than fix it (that fix is readIfPresent in src/testkit/realTreeScan.ts).
    pool: "forks",
    isolate: true,
    fileParallelism: true,
    maxWorkers: maxTestForks(),
    // No blanket raise: the default stays 5s so a hung test still fails fast. Hooks get the
    // largest measured class because a beforeAll that builds fixtures for one of these suites
    // does the same work the test body does, and vitest's 10s hook default is not covered by
    // per-test timeouts.
    hookTimeout: EXECUTION_TIMEOUTS.ed25519,
  },
});
