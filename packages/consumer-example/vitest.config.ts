import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

import { packageSourceAliases } from "../../vitest.aliases.ts";

// Resolve @zucoins/generic-node-consumer, @zucoins/node-core, and
// @zucoins/generic-node-contracts to src/ rather than the dist/ their package.json `exports` point
// at. `pnpm build` and `pnpm test` are separate commands with no ordering guarantee, so a stale or
// absent dist/ let the worked example — the exit evidence for the adapter — pass or fail on
// yesterday's bytes (or fail to collect when contracts dist is missing). packageSourceAliases
// derives and orders the entries; see its doc comment. Each call sorts its own subpaths above its
// package root; contracts is listed so cold-clone consumer runs need no pre-build.
export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  resolve: {
    alias: [
      ...packageSourceAliases(new URL("../generic-node-consumer/", import.meta.url)),
      ...packageSourceAliases(new URL("../generic-node-contracts/", import.meta.url)),
      ...packageSourceAliases(new URL("../node-core/", import.meta.url)),
    ],
  },
  test: {
    // Load-bearing for the aggregate root run: `pnpm exec vitest run <a node-core test file>`
    // filters every project in vitest.config.ts, and this one legitimately matches zero files.
    passWithNoTests: true,
    testTimeout: 30_000,
    setupFiles: [fileURLToPath(new URL("./test/setup-network-guard.ts", import.meta.url))],
  },
});
