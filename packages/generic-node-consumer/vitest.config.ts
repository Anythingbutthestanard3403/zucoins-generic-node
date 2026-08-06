import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

// Prefer built dist of workspace deps (package.json exports). Source-aliasing
// @zucoins/node-core pulls its entire internal import graph and every contracts
// subpath; dist already resolved that at `tsc -b` time.
export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  test: {
    passWithNoTests: true,
    testTimeout: 30_000,
    setupFiles: [fileURLToPath(new URL("./test/setup-network-guard.ts", import.meta.url))],
  },
});
