// Copy the money-schema SQL slices into dist/ after tsc.
//
// `src/schema/money-schema-pack.ts` resolves its slices with
// `dirname(fileURLToPath(import.meta.url))`, which is `dist/schema/` in a built artifact.
// tsc only emits .js/.d.ts, so without this step the built package has no .sql on disk and
// `loadMoneySchemaMigrations()` throws ENOENT at boot — the custody entry point halts its
// boot lane at the "migrations" step and readiness never leaves 503. Tests never caught it
// because vitest runs from src/, where the .sql files sit next to the module.
//
// Fails closed: a partially-copied money schema is worse than no build at all.

import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcSchema = join(packageRoot, "src", "schema");
const distSchema = join(packageRoot, "dist", "schema");

const slices = readdirSync(srcSchema).filter((name) => name.endsWith(".sql"));
if (slices.length === 0) {
  throw new Error(`copy-schema-sql: no .sql slices found in ${srcSchema}`);
}

mkdirSync(distSchema, { recursive: true });
for (const slice of slices) {
  copyFileSync(join(srcSchema, slice), join(distSchema, slice));
}

const copied = readdirSync(distSchema).filter((name) => name.endsWith(".sql"));
if (copied.length !== slices.length) {
  throw new Error(
    `copy-schema-sql: expected ${slices.length} slices in dist/schema, found ${copied.length}`,
  );
}

console.log(`copy-schema-sql: ${copied.length} schema slices -> dist/schema`);
