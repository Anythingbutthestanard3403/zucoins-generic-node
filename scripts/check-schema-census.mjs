#!/usr/bin/env node
// Automated schema-to-spec traceability gate.
//
// Standalone runner. Builds the same census the vitest suite asserts, prints a
// machine-grepable report, and exits:
//   0 = PASS (zero failures across all four classes AND committed report fresh)
//   1 = FAIL (census failure OR committed report stale)
//   2 = usage / environment error
//
// Usage:
//   node scripts/check-schema-census.mjs
//   node scripts/check-schema-census.mjs --json
//   node scripts/check-schema-census.mjs --write-report
//
// Default schema dir: packages/node-core/src/schema
//
// Default mode also pins the committed schema-census.report.json so a
// schema .sql add/remove cannot pass the CLI without an intentional --write-report.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const censusModule = resolve(
  repoRoot,
  "packages/node-core/test/schema-census/schema-census.ts",
);
const reportPath = resolve(
  repoRoot,
  "packages/node-core/test/schema-census/schema-census.report.json",
);

/** @param {readonly string[]} live @param {readonly string[]} committed */
export const diffSchemaFiles = (live, committed) => {
  const liveSet = new Set(live);
  const committedSet = new Set(committed);
  const added = live.filter((f) => !committedSet.has(f)).sort();
  const removed = committed.filter((f) => !liveSet.has(f)).sort();
  return { added, removed, ok: added.length === 0 && removed.length === 0 };
};

/**
 * Compare live census JSON to the committed artifact.
 * Returns { ok, kind, detail } where kind is "fresh" | "missing" | "stale" | "files".
 * @param {unknown} liveReport
 * @param {string | null} committedText
 */
export const pinCommittedReport = (liveReport, committedText) => {
  const rendered = `${JSON.stringify(liveReport, null, 2)}\n`;
  if (committedText === null) {
    return {
      ok: false,
      kind: "missing",
      detail:
        "schema-census.report.json missing — run: node scripts/check-schema-census.mjs --write-report",
      rendered,
    };
  }
  if (committedText === rendered) {
    return { ok: true, kind: "fresh", detail: "committed report matches live census", rendered };
  }
  let committed;
  try {
    committed = JSON.parse(committedText);
  } catch {
    return {
      ok: false,
      kind: "stale",
      detail:
        "schema-census.report.json is not valid JSON — run: node scripts/check-schema-census.mjs --write-report and commit",
      rendered,
    };
  }
  const liveFiles = Array.isArray(liveReport?.schemaFiles) ? liveReport.schemaFiles : [];
  const committedFiles = Array.isArray(committed?.schemaFiles) ? committed.schemaFiles : [];
  const files = diffSchemaFiles(liveFiles, committedFiles);
  if (!files.ok) {
    const parts = [];
    if (files.added.length) parts.push(`added=[${files.added.join(", ")}]`);
    if (files.removed.length) parts.push(`removed=[${files.removed.join(", ")}]`);
    return {
      ok: false,
      kind: "files",
      detail:
        `schema-census.report.json schemaFiles drift (${parts.join(" ")}) — ` +
        "intentional add/remove requires: node scripts/check-schema-census.mjs --write-report and commit",
      rendered,
      files,
    };
  }
  return {
    ok: false,
    kind: "stale",
    detail:
      "schema-census.report.json is stale — run: node scripts/check-schema-census.mjs --write-report and commit",
    rendered,
  };
};

const isMain =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  if (!existsSync(censusModule)) {
    console.error(`check-schema-census: census module missing: ${censusModule}`);
    process.exit(2);
  }

  const args = new Set(process.argv.slice(2));
  if (args.has("-h") || args.has("--help")) {
    console.log(`Usage: check-schema-census.mjs [--json] [--write-report]
Exit: 0 PASS, 1 FAIL, 2 env error`);
    process.exit(0);
  }
  const wantJson = args.has("--json");
  const writeReport = args.has("--write-report");

  // Node 22+: load the TypeScript census module via --experimental-strip-types.
  const runner = `
import { buildCensus, formatReportText, CENSUS_REPORT_PATH } from ${JSON.stringify(censusModule)};
const { report, ok } = buildCensus();
const out = { ok, text: formatReportText(report), report, reportPath: CENSUS_REPORT_PATH };
process.stdout.write(JSON.stringify(out));
`;

  const res = spawnSync(
    process.execPath,
    ["--experimental-strip-types", "--input-type=module", "-e", runner],
    { encoding: "utf8", cwd: repoRoot, maxBuffer: 32 * 1024 * 1024 },
  );

  if (res.error) {
    console.error("check-schema-census: spawn failed", res.error);
    process.exit(2);
  }
  if (res.status !== 0 && !(res.stdout && res.stdout.includes('{"ok"'))) {
    console.error("check-schema-census: census execution failed");
    if (res.stderr) console.error(res.stderr.slice(0, 4000));
    if (res.stdout) console.error(res.stdout.slice(0, 2000));
    process.exit(2);
  }

  let payload;
  try {
    const out = res.stdout ?? "";
    // strip-types may emit warnings before the JSON payload
    const start = out.indexOf('{"ok"');
    const end = out.lastIndexOf("}");
    if (start === -1 || end === -1) throw new Error("no JSON payload in stdout");
    payload = JSON.parse(out.slice(start, end + 1));
  } catch (err) {
    console.error("check-schema-census: could not parse census payload:", err);
    if (res.stderr) console.error(res.stderr.slice(0, 2000));
    if (res.stdout) console.error((res.stdout ?? "").slice(0, 2000));
    process.exit(2);
  }

  if (writeReport) {
    writeFileSync(reportPath, `${JSON.stringify(payload.report, null, 2)}\n`);
    console.error(`check-schema-census: wrote ${reportPath}`);
  } else {
    let committedText = null;
    try {
      committedText = readFileSync(reportPath, "utf8");
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? /** @type {NodeJS.ErrnoException} */ (err).code
          : undefined;
      if (code !== "ENOENT") throw err;
    }
    const pin = pinCommittedReport(payload.report, committedText);
    if (!pin.ok) {
      console.error(`check-schema-census: ${pin.detail}`);
      if (wantJson) {
        process.stdout.write(`${JSON.stringify(payload.report, null, 2)}\n`);
      } else {
        process.stdout.write(payload.text);
      }
      process.exit(1);
    }
  }

  if (wantJson) {
    process.stdout.write(`${JSON.stringify(payload.report, null, 2)}\n`);
  } else {
    process.stdout.write(payload.text);
  }

  process.exit(payload.ok ? 0 : 1);
}
