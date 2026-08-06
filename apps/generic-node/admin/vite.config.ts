import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

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
    passWithNoTests: false,
    setupFiles: ["src/test-setup.ts"],
  },
});
