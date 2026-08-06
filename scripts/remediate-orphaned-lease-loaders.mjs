// CLI-only runtime loaders for remediate-orphaned-lease.mjs, split into their own file so
// vitest's Vite transform never has to statically resolve "pg" / "@zucoins/node-core" while
// loading the test's import graph (planRelease is dependency-injected and never reaches these).
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

// Bare import works when run from within an app's own graph/deployment; otherwise resolve pg
// through generic-node's graph.
export async function loadPg() {
  try {
    const specifier = "pg";
    return await import(/* @vite-ignore */ specifier);
  } catch (error) {
    if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  }
  const genericNodeManifest = fileURLToPath(new URL("../apps/generic-node/package.json", import.meta.url));
  return createRequire(genericNodeManifest)("pg");
}

// node-core is ESM-only (no "require" export condition) so this cannot go through createRequire
// the way loadPg() does. Resolve it through generic-node's own workspace symlink instead — the
// same app that already declares "@zucoins/node-core": "workspace:*" — and import the built dist
// directly. Requires the package to be built first.
export async function loadNodeCore() {
  try {
    const specifier = "@zucoins/node-core";
    return await import(/* @vite-ignore */ specifier);
  } catch (error) {
    if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  }
  const genericNodeDir = fileURLToPath(new URL("../apps/generic-node/", import.meta.url));
  const distEntry = path.join(genericNodeDir, "node_modules/@zucoins/node-core/dist/index.js");
  try {
    const specifier = pathToFileURL(distEntry).href;
    return await import(/* @vite-ignore */ specifier);
  } catch (error) {
    if (error.code === "ERR_MODULE_NOT_FOUND") {
      throw new Error(
        `@zucoins/node-core is not built (looked for ${distEntry}). Run: ` +
          `pnpm --filter @zucoins/node-core build`,
      );
    }
    throw error;
  }
}
