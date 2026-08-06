import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildArtifacts } from "../src/recovery-drill/emit.ts";

/**
 * Thin CLI wrapper around the pure builder in `src/recovery-drill/emit.ts` for the recovery-drill lane
 * destroy-restore / corrupt-recovery goldens under `goldens/recovery/`. The build logic lives in
 * src so the census test can invoke it in-process (no child process, no committed test writing a
 * golden — A8); this wrapper only performs the on-disk write / `--check` verification.
 *
 * USAGE
 *   node scripts/emit-recovery-golden.ts            # regenerate the committed goldens in place
 *   node scripts/emit-recovery-golden.ts --check    # verify committed bytes match a fresh build
 */
const here = dirname(fileURLToPath(import.meta.url));
/** Absolute path to the committed recovery goldens directory (the byte authority under test). */
const RECOVERY_GOLDEN_DIR = join(here, "..", "goldens", "recovery");

const checkArtifacts = (dir: string, expected: Readonly<Record<string, string>>): string[] => {
  const drift: string[] = [];
  for (const [name, expectedBody] of Object.entries(expected)) {
    const path = join(dir, name);
    if (!existsSync(path)) {
      drift.push(`${name}: missing`);
      continue;
    }
    const actual = readFileSync(path, "utf8");
    if (actual !== expectedBody) {
      drift.push(`${name}: byte drift`);
    }
  }
  return drift;
};

// CLI entrypoint — runs ONLY when this module is executed directly (`node emit-recovery-golden.ts`),
// never when it is imported.
const isDirectRun =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectRun) {
  const argv = new Set(process.argv.slice(2));
  const allowedArgs = new Set(["--check"]);
  for (const arg of argv) {
    if (!allowedArgs.has(arg)) {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  const checkOnly = argv.has("--check");
  const artifacts = await buildArtifacts();

  if (checkOnly) {
    const drift = checkArtifacts(RECOVERY_GOLDEN_DIR, artifacts);
    if (drift.length > 0) {
      throw new Error(`recovery golden check failed:\n${drift.join("\n")}`);
    }
  } else {
    mkdirSync(RECOVERY_GOLDEN_DIR, { recursive: true });
    for (const [name, body] of Object.entries(artifacts)) {
      writeFileSync(join(RECOVERY_GOLDEN_DIR, name), body, "utf8");
    }
  }
}
