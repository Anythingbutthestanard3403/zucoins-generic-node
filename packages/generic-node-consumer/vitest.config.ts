import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

import { packageSourceAliases } from "../../vitest.aliases.ts";

// Resolve @zucoins/node-core to src/ rather than the dist/ its package.json `exports` point at.
// `pnpm build` and `pnpm test` are separate commands with no ordering guarantee, so a stale or
// absent dist/ let this suite — the one proving the consumer trust boundary — pass or fail on
// yesterday's bytes. packageSourceAliases derives and orders the entries; see its doc comment.
export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  resolve: {
    alias: packageSourceAliases(new URL("../node-core/", import.meta.url)),
  },
  test: {
    // Load-bearing for the aggregate root run: `pnpm exec vitest run <a node-core test file>`
    // filters every project in vitest.config.ts, and this one legitimately matches zero files.
    passWithNoTests: true,
    testTimeout: 30_000,
    setupFiles: [fileURLToPath(new URL("./test/setup-network-guard.ts", import.meta.url))],
  },
});
