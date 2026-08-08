import { defineConfig, devices } from "@playwright/test";

// merger clearance — deterministic config for `pnpm exec playwright test`.
// Builds the real `vite build` output (never a dev server) and serves it with
// `vite preview`, matching the dashboard-prerequisite discipline documented in
// CLAUDE.md: source changes with no rebuild must fail this suite, not silently pass
// against stale output.
const PORT = 4319;
const BASE_URL = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: "./src/e2e",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: [
    ["list"],
    ["json", { outputFile: "playwright-report/results.json" }],
  ],
  outputDir: "test-results",
  use: {
    baseURL: BASE_URL,
    // The built shell registers a service worker. A request the worker forwards leaves the
    // worker context, so `page.route` never sees it: the admin fixtures were bypassed, the app
    // got a real (refused) network call, and the fixture guard passed vacuously because no
    // request reached it. Blocking workers puts every fetch back through the fixtures.
    serviceWorkers: "block",
    viewport: { width: 320, height: 640 },
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 320, height: 640 } },
    },
  ],
  webServer: {
    // --host 127.0.0.1 pins the bind address to match BASE_URL above. Without it, vite
    // preview binds whatever "localhost" resolves to first; on hosts where the resolver
    // returns ::1 before 127.0.0.1, the IPv4 health check above spins until the 60s
    // webServer timeout even though the server is up.
    command: "vite build && vite preview --port 4319 --strictPort --host 127.0.0.1",
    url: BASE_URL,
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
