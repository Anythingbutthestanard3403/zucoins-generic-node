import { defineConfig } from "vitest/config";

// Package entry for `pnpm --filter @zucoins/generic-node test`.
// Root `pnpm test` lists vitest.unit.config.ts + vitest.pg.config.ts as sibling projects
// (Vitest does not expand nested `test.projects` from a workspace package config).
export default defineConfig({
  test: {
    projects: ["./vitest.unit.config.ts", "./vitest.pg.config.ts"],
  },
});
