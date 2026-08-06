import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { GEN_SNAPSHOTS, renderSnapshot } from "./gen-registry.ts";

/**
 * Deterministic emitter: gen-registry.ts snapshot -> gen/<file>.json. Committed gen/*.json is a
 * review-diff convenience layer (../CONTRACT.md "Manifest encoding (3 tiers)", tier 2); byte
 * authority for each tuple is its own `.contract.ts`/manifest source. `gen/json-sync.test.ts`
 * fails if this emitter's fresh output ever diverges from the committed snapshot.
 */
const here = dirname(fileURLToPath(import.meta.url));
const genDir = join(here, "..", "gen");

for (const snapshot of GEN_SNAPSHOTS) {
  writeFileSync(join(genDir, snapshot.file), renderSnapshot(snapshot));
}
