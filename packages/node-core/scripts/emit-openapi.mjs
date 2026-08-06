#!/usr/bin/env node
/**
 * Rewrite packages/node-core/api/openapi.yaml from the generator.
 *
 * Prefer: UPDATE_OPENAPI=1 pnpm --filter @zucoins/node-core exec vitest run test/openapi-freeze.test.ts
 * This script shells the same path so contributors have a named entrypoint.
 */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(here, "..");

const result = spawnSync(
  "pnpm",
  ["exec", "vitest", "run", "test/openapi-freeze.test.ts"],
  {
    cwd: pkgRoot,
    env: { ...process.env, UPDATE_OPENAPI: "1" },
    stdio: "inherit",
  },
);

process.exit(result.status ?? 1);
