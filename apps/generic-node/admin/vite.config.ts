import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const CONFIG_DIR = fileURLToPath(new URL(".", import.meta.url)).replace(/\/$/, "");

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/admin/v1": "http://localhost:3000",
      "/v1": "http://localhost:3000",
      "/healthz": "http://localhost:3000",
      "/readyz": "http://localhost:3000",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 320,
  },
  test: {
    name: "generic-node-ui",
    environment: "jsdom",
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    // src/e2e is a real-Chromium suite driven by `playwright test` (see
    // playwright.config.ts), not vitest — its spec files import `@playwright/test`'s
    // own test/expect, which vitest must never try to collect.
    exclude: ["src/e2e/**", "**/node_modules/**"],
    // `pnpm --filter @zucoins/generic-node-ui test` cd's into this package, so cwd IS this
    // directory and zero matched files stays a failure — vitest silently drops a filter that
    // matches nothing, which has already produced false PASSes here (see CLAUDE.md). The
    // repo-root aggregate run (`pnpm exec vitest run <a node-core file>`) keeps cwd at the root
    // and legitimately matches nothing in this project, which must not fail the whole gate.
    passWithNoTests: process.cwd().replace(/\/$/, "") !== CONFIG_DIR,
    // Absolute so vitest-network-guard.census.test.ts can existsSync it from the repo root.
    setupFiles: [
      fileURLToPath(new URL("./src/setup-network-guard.ts", import.meta.url)),
      "src/test-setup.ts",
    ],
  },
});
