import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

const CONFIG_DIR = fileURLToPath(new URL(".", import.meta.url)).replace(/\/$/, "");

/**
 * ZTR-1252: stamp public/sw.js SHELL_CACHE name with a per-build id so activate
 * purges the previous shell cache after every deploy. Source keeps the
 * `__SHELL_CACHE_BUILD_ID__` token; only dist/sw.js is rewritten.
 */
function stampShellServiceWorker(): Plugin {
  const token = "__SHELL_CACHE_BUILD_ID__";
  return {
    name: "stamp-shell-service-worker",
    apply: "build",
    closeBundle() {
      const swPath = join(CONFIG_DIR, "dist", "sw.js");
      let body: string;
      try {
        body = readFileSync(swPath, "utf8");
      } catch {
        return;
      }
      if (!body.includes(token)) return;
      const stamp = createHash("sha256")
        .update(randomBytes(16))
        .update(String(Date.now()))
        .digest("hex")
        .slice(0, 12);
      writeFileSync(swPath, body.split(token).join(stamp), "utf8");
    },
  };
}

export default defineConfig({
  plugins: [react(), stampShellServiceWorker()],
  server: {
    port: 5174,
    proxy: {
      "/admin/v1": "http://localhost:3000",
      "/v1": "http://localhost:3000",
      "/health": "http://localhost:3000",
      "/healthz": "http://localhost:3000",
      "/readyz": "http://localhost:3000",
    },
  },
  // ZTR-1285: point workspace contract subpaths at src so admin vitest does not
  // require a prior `pnpm build` / contracts dist. Subpaths must precede the
  // package-root entry (prefix match). Keep in lockstep with imports under src/.
  resolve: {
    alias: [
      {
        find: "@zucoins/generic-node-contracts/operations/events",
        replacement: fileURLToPath(
          new URL(
            "../../../packages/generic-node-contracts/src/operations/events.contract.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/operations",
        replacement: fileURLToPath(
          new URL(
            "../../../packages/generic-node-contracts/src/operations/index.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/admin-inventory",
        replacement: fileURLToPath(
          new URL(
            "../../../packages/generic-node-contracts/src/admin-inventory/index.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/operator-halt",
        replacement: fileURLToPath(
          new URL(
            "../../../packages/generic-node-contracts/src/operator-halt/index.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/custody",
        replacement: fileURLToPath(
          new URL(
            "../../../packages/generic-node-contracts/src/custody/index.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts",
        replacement: fileURLToPath(
          new URL("../../../packages/generic-node-contracts/src/index.ts", import.meta.url),
        ),
      },
    ],
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
