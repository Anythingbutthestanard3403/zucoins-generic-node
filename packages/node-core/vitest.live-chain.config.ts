import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

import base from "./vitest.config.js";

// Dedicated config for the live-chain acceptance runs (`*.live.test.ts`), mirroring the
// repo-root vitest.live-chain.config.ts used by packages/splitchain.
//
// Two deliberate differences from vitest.config.ts:
// 1. NO setup-network-guard.ts. contains node-core's ordinary suite from all
// network access; a live acceptance run is the one thing that must reach the real
// gateway, so it gets its own config rather than an escape hatch inside the guard —
// the default suite stays contained with no flag that could be set wrong. (This is a
// standalone config, not a mergeConfig of the base: array options like `setupFiles`
// CONCATENATE under mergeConfig, so the guard would survive an empty-array override.)
// 2. Single file, single fork, no parallelism — a live run is serialized by definition
// (the one-in-flight-per-wallet rule: one in-flight transaction per wallet).
//
// The live files still gate themselves on their own env vars, so this config is a no-op
// (all skipped) unless the runner opts in explicitly.
export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  // Same workspace source aliases as the default config — imported, never re-listed.
  resolve: base.resolve,
  test: {
    include: ["test/live-chain/**/*.live.test.ts"],
    passWithNoTests: false,
    fileParallelism: false,
    pool: "forks",
    poolOptions: { forks: { singleFork: true } },
    testTimeout: 600_000,
    hookTimeout: 120_000,
  },
});
