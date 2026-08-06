import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CONTRACT_DRIFT_MANIFEST } from "../src/drift-audit/contract-manifest.ts";
import { renderSnapshot } from "./gen-registry.ts";

/**
 * Deterministic emitter for `gen/contract-drift-manifest.json` — folded into
 * `scripts/emit-json.ts`'s `GEN_SNAPSHOTS` loop for every subsequent run; this file exists only
 * because a bare `node scripts/*.ts` invocation errors at this SHA on `.js`-suffixed relative
 * specifier resolution (see package README/CONTRACT.md), so the committed bytes were produced
 * once via the vitest esbuild loader instead. Never runs as a side effect of import.
 */
const here = dirname(fileURLToPath(import.meta.url));
const genDir = join(here, "..", "gen");

writeFileSync(
  join(genDir, "contract-drift-manifest.json"),
  renderSnapshot({
    file: "contract-drift-manifest.json",
    value: CONTRACT_DRIFT_MANIFEST,
    recipe: "sorted-nl",
  }),
);
