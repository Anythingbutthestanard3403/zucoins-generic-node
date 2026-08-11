#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REGISTRY_REPO_PATH = "release/targets.v1.json";
const SCHEMA_REPO_PATH = "release/targets.schema.json";
const REGISTRY_PATH = resolve(REPO_ROOT, REGISTRY_REPO_PATH);
const SCHEMA_PATH = resolve(REPO_ROOT, SCHEMA_REPO_PATH);
const REQUIRED_TARGETS = [
  "backup-assurance-runner",
  "docs-site",
  "funded-manual-node",
  "generic-node",
  "hosted-platform",
  "merchant-node-artifact",
  "platform-v2",
  "public-reference-node",
  "release-drift-check-runner",
  "website",
];
const FORBIDDEN_KEY = /(?:token|credential|secret|serviceId|environmentId|deploymentId|privateUrl)$/i;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i;
const URL = /https?:\/\//i;

function fail(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  throw error;
}

export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

export function loadRegistry(path = REGISTRY_PATH) {
  return readJson(path);
}

// ---------------------------------------------------------------------------
// Registry provenance
// ---------------------------------------------------------------------------
// A classification verdict MUST be a function of its arguments alone. Reading the
// registry from the caller's checkout while classifying a --base/--head range let a
// stale tree emit a confidently wrong UNCLASSIFIED_PATH (2026-07-26: a merger refused
// PR #1385 and two sweeps filed a false gate-bypass finding, all from one tree parked
// behind the registry commit that classified the paths). So: range classification
// resolves the registry AT THE HEAD REF, and every verdict names the blob it used.
// The schema is resolved at the same ref — a stale schema enum produces the identical
// class of false INVALID_REGISTRY refusal.
// The worktree read survives only for the ref-less --paths-from-stdin mode, and says
// so in the output (`source: "worktree"`); it is never a silent fallback for a ref
// that failed to resolve.

function gitText(args, repoRoot) {
  return execFileSync("git", args, { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] }).toString("utf8");
}

function blobShaAtRef(ref, repoPath, repoRoot) {
  const sha = gitText(["rev-parse", `${ref}:${repoPath}`], repoRoot).trim();
  if (!/^[0-9a-f]{40}$/.test(sha)) fail("REGISTRY_REF_UNRESOLVED", `${repoPath} at ${ref} did not resolve to a blob`);
  return sha;
}

// Best-effort: the drift-check image and the slim-image tests ship the registry
// without a .git, and a missing worktree copy must not break a ref-pinned read.
function worktreeBlobSha(repoPath, repoRoot) {
  try {
    const sha = gitText(["hash-object", "--", resolve(repoRoot, repoPath)], repoRoot).trim();
    return /^[0-9a-f]{40}$/.test(sha) ? sha : null;
  } catch {
    return null;
  }
}

/**
 * Resolve the registry + schema either at a git ref (authoritative for a range) or from
 * the working tree (ref-less callers only). Fails loudly — never falls back.
 *
 * @param {{ ref?: string|null, repoRoot?: string }} [opts]
 * @returns {{ registry: object, schema: object, provenance: object }}
 */
export function resolveRegistry({ ref = null, repoRoot = REPO_ROOT } = {}) {
  if (!ref) {
    return {
      registry: readJson(resolve(repoRoot, REGISTRY_REPO_PATH)),
      schema: readJson(resolve(repoRoot, SCHEMA_REPO_PATH)),
      provenance: {
        source: "worktree",
        ref: null,
        path: REGISTRY_REPO_PATH,
        blobSha: worktreeBlobSha(REGISTRY_REPO_PATH, repoRoot),
        schemaBlobSha: worktreeBlobSha(SCHEMA_REPO_PATH, repoRoot),
        worktreeDiverged: false,
      },
    };
  }
  let blobSha;
  let schemaBlobSha;
  let registryText;
  let schemaText;
  try {
    blobSha = blobShaAtRef(ref, REGISTRY_REPO_PATH, repoRoot);
    schemaBlobSha = blobShaAtRef(ref, SCHEMA_REPO_PATH, repoRoot);
    registryText = gitText(["cat-file", "blob", blobSha], repoRoot);
    schemaText = gitText(["cat-file", "blob", schemaBlobSha], repoRoot);
  } catch (error) {
    if (error.code === "REGISTRY_REF_UNRESOLVED") throw error;
    fail("REGISTRY_REF_UNRESOLVED", `cannot read ${REGISTRY_REPO_PATH} at ref ${ref}: ${error.message}`, { ref });
  }
  let registry;
  let schema;
  try {
    registry = JSON.parse(registryText);
    schema = JSON.parse(schemaText);
  } catch (error) {
    fail("REGISTRY_REF_UNPARSABLE", `${REGISTRY_REPO_PATH} at ref ${ref} is not valid JSON: ${error.message}`, { ref });
  }
  const observed = worktreeBlobSha(REGISTRY_REPO_PATH, repoRoot);
  return {
    registry,
    schema,
    provenance: {
      source: "ref",
      ref,
      path: REGISTRY_REPO_PATH,
      blobSha,
      schemaBlobSha,
      // null = worktree copy unresolvable, not "in agreement". Distinguishes
      // "the classifier does not know this path" from "your checkout is old".
      worktreeDiverged: observed === null ? null : observed !== blobSha,
    },
  };
}

function globRegex(glob) {
  let source = "";
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];
    if (char === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") {
        source += "(?:.*/)?";
        index += 2;
      } else {
        source += ".*";
        index += 1;
      }
    } else if (char === "*") {
      source += "[^/]*";
    } else {
      source += char.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
    }
  }
  return new RegExp(`^${source}$`);
}

export function matchesGlob(path, glob) {
  return globRegex(glob).test(path.replaceAll("\\", "/").replace(/^\.\//, ""));
}

function assertStringArray(value, label) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    fail("INVALID_REGISTRY", `${label} must be an array of non-empty strings`);
  }
  if (new Set(value).size !== value.length) fail("INVALID_REGISTRY", `${label} contains duplicates`);
}

function inspectForSecrets(value, path = "registry") {
  if (Array.isArray(value)) return value.forEach((item, index) => inspectForSecrets(item, `${path}[${index}]`));
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_KEY.test(key)) fail("REGISTRY_SECRET_FIELD", `forbidden registry field at ${path}.${key}`);
      inspectForSecrets(child, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === "string" && (UUID.test(value) || URL.test(value))) {
    fail("REGISTRY_SECRET_VALUE", `identifier or URL is forbidden at ${path}`);
  }
}

function assertExactKeys(object, allowed, label) {
  const unknown = Object.keys(object).filter((key) => !allowed.includes(key));
  if (unknown.length) fail("INVALID_REGISTRY", `${label} has unknown fields: ${unknown.join(", ")}`);
}

function expectedRailwayConfigs(registry) {
  const byPath = new Map();
  for (const target of registry.targets) {
    if (target.provider !== "railway" || !target.configPath) continue;
    const existing = byPath.get(target.configPath);
    if (existing && stableStringify(existing) !== stableStringify(target.watchPatterns)) {
      fail("WATCH_PATTERN_AUTHORITY_DRIFT", `${target.configPath} has conflicting registry watch patterns`);
    }
    byPath.set(target.configPath, target.watchPatterns);
  }
  return byPath;
}

export function validateRegistry(registry = loadRegistry(), { checkFiles = true, schema = null } = {}) {
  assertExactKeys(registry, ["$schema", "schemaVersion", "controlGlobs", "ignoredGlobs", "targets"], "registry");
  if (registry.schemaVersion !== 1) fail("INVALID_REGISTRY", "schemaVersion must be 1");
  assertStringArray(registry.controlGlobs, "controlGlobs");
  assertStringArray(registry.ignoredGlobs, "ignoredGlobs");
  if (!Array.isArray(registry.targets)) fail("INVALID_REGISTRY", "targets must be an array");
  inspectForSecrets(registry);

  const ids = registry.targets.map((target) => target.id);
  if (stableStringify([...ids].sort()) !== stableStringify(REQUIRED_TARGETS)) {
    fail("INVALID_REGISTRY", `registry must contain exactly: ${REQUIRED_TARGETS.join(", ")}`);
  }
  if (new Set(ids).size !== ids.length) fail("INVALID_REGISTRY", "target IDs must be unique");

  // Schema resolved at the SAME revision as the registry when the caller pinned a ref
  // — a worktree schema behind the registry's enums is the same false-verdict bug.
  const resolvedSchema = schema ?? readJson(SCHEMA_PATH);
  const deployModeEnum = resolvedSchema.$defs.target.properties.deployMode.enum;
  const driftCheckEnum = resolvedSchema.$defs.externalBinding.anyOf[1].properties.driftCheck.enum;
  const approvalEnum = resolvedSchema.$defs.target.properties.approval.enum;

  for (const target of registry.targets) {
    assertExactKeys(target, ["id", "active", "provider", "deployMode", "classificationGlobs", "configPath", "dockerfilePath", "watchPatterns", "healthGate", "migrationRequired", "approval", "liveAcceptance", "rollbackRef", "externalBinding"], `target ${target.id}`);
    assertStringArray(target.classificationGlobs, `${target.id}.classificationGlobs`);
    assertStringArray(target.watchPatterns, `${target.id}.watchPatterns`);
    if (typeof target.active !== "boolean") fail("INVALID_REGISTRY", `${target.id}.active must be boolean`);
    if (typeof target.rollbackRef !== "string" || !target.rollbackRef.startsWith("release/README.md#")) fail("INVALID_REGISTRY", `${target.id}.rollbackRef must be local`);
    if (!deployModeEnum.includes(target.deployMode)) fail("INVALID_REGISTRY", `${target.id}.deployMode "${target.deployMode}" is not in schema enum [${deployModeEnum.join(", ")}]`);
    if (approvalEnum && !approvalEnum.includes(target.approval)) fail("INVALID_REGISTRY", `${target.id}.approval "${target.approval}" is not in schema enum [${approvalEnum.join(", ")}]`);
    if (target.externalBinding) {
      assertExactKeys(target.externalBinding, ["driftCheck", "logicalService", "logicalEnvironment", "sourceMode", "branch", "configPath"], `${target.id}.externalBinding`);
      if (!driftCheckEnum.includes(target.externalBinding.driftCheck)) fail("INVALID_REGISTRY", `${target.id}.externalBinding.driftCheck "${target.externalBinding.driftCheck}" is not in schema enum [${driftCheckEnum.join(", ")}]`);
    }
  }

  // Watch/classify coverage. A provider watchPattern is the literal list of paths that
  // REBUILD that target; classificationGlobs is what the merger is told a path affects.
  // The two are hand-maintained in different notation ("/apps/x/**" vs "apps/x/**"), and
  // ZPAY-264 is what happens when they diverge: apps/platform/dashboard/** rebuilt the live
  // platform-v2 service while classifying only as hosted-platform, so a dashboard merge was
  // reported with hosted-platform's deployMode instead of platform-v2's Riley gate. Every
  // watchPattern must therefore be reachable from its OWN target's classificationGlobs.
  // The controlGlobs escape hatch exists for runner targets that watch governance files
  // (release-drift-check-runner watches /release/targets.v1.json): those paths must NOT be
  // added to any classificationGlobs, because classificationGlobs are matched BEFORE
  // controlGlobs in classifyPaths and would drop the strict-dual review a control hit
  // forces — a control hit is strictly more review, never less, so this stays fail-closed.
  for (const target of registry.targets) {
    for (const pattern of target.watchPatterns) {
      const representativePath = pattern.replace(/^\//, "");
      const covered =
        target.classificationGlobs.some((glob) => matchesGlob(representativePath, glob)) ||
        registry.controlGlobs.some((glob) => matchesGlob(representativePath, glob));
      if (!covered) {
        fail("WATCH_PATTERN_UNCLASSIFIED", `${target.id} watches ${pattern} but no ${target.id} classificationGlob (or controlGlob) matches it`, { target: target.id, pattern });
      }
    }
  }

  const funded = registry.targets.find((target) => target.id === "funded-manual-node");
  // Dual-state allowlist: the funded target must match EVERY field of exactly one
  // ratified safety posture below. Mixing fields across states (a hybrid) is rejected,
  // same as any value outside both states — fail-closed is preserved either way.
  const FUNDED_SAFE_STATES = [
    // Original ratified posture: fully human-gated funded deploy, real-ZKZ-gated live acceptance.
    {
      deployMode: "manual-riley-gated",
      approval: "riley-explicit-in-session",
      liveAcceptance: (value) => value.includes("real-zkz"),
      driftCheck: "manual-riley-gated-read-only",
    },
    // Later ratified posture: agent-autonomous funded deploy, testwallet-bounded live
    // acceptance (the decision ids live inside the frozen enum literals below).
    {
      deployMode: "automatic",
      approval: "agent-autonomous-d9.47",
      liveAcceptance: (value) => value === "testwallet-bounded-d9.46",
      driftCheck: "scheduled-read-only",
    },
  ];
  const fundedMatchesState = (state) =>
    funded.deployMode === state.deployMode &&
    funded.approval === state.approval &&
    typeof funded.liveAcceptance === "string" && state.liveAcceptance(funded.liveAcceptance) &&
    funded.externalBinding?.driftCheck === state.driftCheck;
  if (funded.active && !FUNDED_SAFE_STATES.some(fundedMatchesState)) {
    fail("FUNDED_TARGET_UNSAFE", "funded target must remain manual, Riley-gated, and live-acceptance gated");
  }
  const generic = registry.targets.find((target) => target.id === "generic-node");
  // Custody tripwire (Stage 1): if generic-node is active, it must remain
  // zero-custody (liveAcceptance = "not-required-no-custody") unless the human custody
  // owner explicitly gates it for Stage 2 custody acquisition via approval = "riley-explicit-in-session".
  if (generic.active && generic.liveAcceptance !== "not-required-no-custody" && generic.approval !== "riley-explicit-in-session") {
    fail("GENERIC_NODE_CUSTODY_TRIPWIRE", "generic-node is active but lacks zero-custody guarantee: liveAcceptance must be not-required-no-custody or approval must be riley-explicit-in-session");
  }

  if (checkFiles) {
    for (const [configPath, expected] of expectedRailwayConfigs(registry)) {
      const config = readJson(resolve(REPO_ROOT, configPath));
      const observed = config?.build?.watchPatterns;
      if (stableStringify(observed) !== stableStringify(expected)) {
        fail("WATCH_PATTERN_DRIFT", `${configPath} build.watchPatterns diverges from release registry`, { configPath });
      }
    }
  }
  return registry;
}

function normalizePaths(paths) {
  return [...new Set(paths.map((path) => path.replaceAll("\\", "/").replace(/^\.\//, "")).filter(Boolean))].sort();
}

// Two-tier control-glob partition. A control-glob hit is IMPACT-DESCRIPTIVE only
// and MERGE-NEUTRAL: it is NEVER fanned into a funded deploy target's affected set,
// so a control-only-on-funded hit can never synthesize funded routing. Control paths split by
// review DEPTH:
//   benign-governance  -> merge-neutral, ordinary non-funded autonomous Done path; NOT strict.
//   funded-affecting   -> forces STRICT (dual) review before merge (manualReviewRequired).
// The partition is a review-DEPTH policy kept in CODE, not the registry, on the exact
// money-path-scan.mjs precedent (its glob set is hardcoded, registry-INDEPENDENT so a data
// edit cannot relax it) — and note release/targets.v1.json is itself a funded-affecting
// control path. FAIL-CLOSED / tightening: any control path NOT on this benign allowlist is
// funded-affecting (strict), so a newly added controlGlob defaults to more review, not less.
// docs/decisions/** is deliberately NOT here: it is not a controlGlob (it matches
// ignoredGlobs `docs/**`) and is already merge-neutral non-funded; the generated aggregate
// docs/DECISIONS.md carries the benign-governance signal for a decision change.
const BENIGN_GOVERNANCE_CONTROL_GLOBS = [
  ".claude/agents/**",
  ".codex/agents/**",
  "AGENTS.md",
  "CLAUDE.md",
  "docs/DECISIONS.md",
  // Decision-register integrity fences (build-decisions.mjs /
  // check-decision-ids.sh / check-decision-citations.sh / check-decision-pins.sh) are deliberately NOT
  // here — they are peer to verdict-integrity* / check-phantom-settles* and
  // stay funded-affecting-control (STRICT dual). Softening them under a
  // single-PASS path is a previously-exploited fail-open class.
];

function isBenignGovernanceControl(path) {
  return BENIGN_GOVERNANCE_CONTROL_GLOBS.some((glob) => matchesGlob(path, glob));
}

// An injected registry object has no revision to name; say that rather than claim the
// worktree, so a cited provenance is never misleading.
const PROVIDED_REGISTRY_PROVENANCE = Object.freeze({
  source: "provided",
  ref: null,
  path: REGISTRY_REPO_PATH,
  blobSha: null,
  schemaBlobSha: null,
  worktreeDiverged: null,
});

export function classifyPaths(paths, registry = null, options = {}) {
  const fromWorktree = registry === null ? resolveRegistry() : null;
  const resolvedRegistry = fromWorktree ? fromWorktree.registry : registry;
  const schema = options.schema ?? fromWorktree?.schema ?? null;
  const provenance =
    options.registryProvenance ?? fromWorktree?.provenance ?? PROVIDED_REGISTRY_PROVENANCE;
  validateRegistry(resolvedRegistry, { checkFiles: false, schema });
  const affected = new Map();
  const ignoredPaths = [];
  const controlPaths = [];
  const unknownPaths = [];
  let manualReviewRequired = false;

  for (const path of normalizePaths(paths)) {
    const targets = resolvedRegistry.targets.filter((target) => target.classificationGlobs.some((glob) => matchesGlob(path, glob)));
    if (targets.length) {
      for (const target of targets) {
        const reason = "SOURCE_PATH";
        const reasons = affected.get(target.id) ?? new Set();
        reasons.add(reason);
        affected.set(target.id, reasons);
      }
      continue;
    }
    if (resolvedRegistry.controlGlobs.some((glob) => matchesGlob(path, glob))) {
      controlPaths.push(path);
      if (!isBenignGovernanceControl(path)) manualReviewRequired = true;
      continue;
    }
    if (resolvedRegistry.ignoredGlobs.some((glob) => matchesGlob(path, glob))) {
      ignoredPaths.push(path);
      continue;
    }
    unknownPaths.push(path);
  }

  // AC4: the refusal names the registry it used, so the next reader can tell
  // "the classifier does not know this path" from "your checkout is old".
  if (unknownPaths.length) {
    fail("UNCLASSIFIED_PATH", "unknown non-documentation path", { paths: unknownPaths, registry: provenance });
  }
  const byId = new Map(resolvedRegistry.targets.map((target) => [target.id, target]));
  return {
    schemaVersion: 1,
    registry: provenance,
    manualReviewRequired,
    affectedTargets: [...affected.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([id, reasons]) => ({
      id,
      active: byId.get(id).active,
      deployMode: byId.get(id).deployMode,
      // ZPAY-264 AC3: deployMode alone does not tell the merger WHO has to approve.
      // A dashboard merge affects platform-v2, whose approval is riley-explicit-in-session;
      // reporting the mode without the approval is how the gate went unnoticed.
      approval: byId.get(id).approval,
      reasonCodes: [...reasons].sort(),
    })),
    controlPaths,
    ignoredPaths,
  };
}

/**
 * The single range-classification path. Both the `classify` CLI and the
 * strict-dual fence route through this, so the ref-pinned registry read cannot be
 * fixed in one and forgotten in the other. The verdict is a function of base/head
 * alone — the caller's checkout is not an input.
 *
 * @param {{ base: string, head: string, repoRoot?: string }} opts
 * @returns {object} classifyPaths result + { base, head }
 */
export function classifyRange({ base, head, repoRoot = REPO_ROOT } = {}) {
  if (!base || !head) fail("INVALID_ARGUMENT", "classifyRange requires base and head");
  const { registry, schema, provenance } = resolveRegistry({ ref: head, repoRoot });
  const diff = execFileSync("git", ["diff", "--name-status", "-z", base, head], { cwd: repoRoot });
  const paths = parseNameStatus(diff);
  return { ...classifyPaths(paths, registry, { registryProvenance: provenance, schema }), base, head };
}

export function parseNameStatus(buffer) {
  const fields = buffer.toString("utf8").split("\0").filter(Boolean);
  const paths = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!/^(?:[ACDMRTUXB][0-9]*)$/.test(status)) fail("INVALID_GIT_DIFF", `unexpected git status: ${status}`);
    if (status.startsWith("R") || status.startsWith("C")) paths.push(fields[index++], fields[index++]);
    else paths.push(fields[index++]);
  }
  return normalizePaths(paths);
}

function parseArgs(args) {
  const parsed = { _: [] };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith("--")) parsed._.push(arg);
    else if (arg === "--paths-from-stdin") parsed.pathsFromStdin = true;
    else {
      const value = args[++index];
      if (!value) fail("INVALID_ARGUMENT", `${arg} requires a value`);
      parsed[arg.slice(2)] = value;
    }
  }
  return parsed;
}

function writeResult(result, output) {
  const serialized = `${stableStringify(result)}\n`;
  process.stdout.write(serialized);
  if (output) writeFileSync(resolve(process.cwd(), output), serialized, "utf8");
}

export function validateEvidence(evidence, registry = loadRegistry()) {
  const allowed = ["schemaVersion", "target", "provider", "status", "checkedFields", "commitSha", "rollbackRef", "driftFields"];
  assertExactKeys(evidence, allowed, "provider evidence");
  if (evidence.schemaVersion !== 1 || !["MATCH", "DRIFT", "UNOBSERVABLE"].includes(evidence.status)) fail("INVALID_EVIDENCE", "invalid evidence version/status");
  const target = registry.targets.find((candidate) => candidate.id === evidence.target);
  if (!target || target.provider !== evidence.provider || target.rollbackRef !== evidence.rollbackRef) fail("INVALID_EVIDENCE", "evidence target/provider/rollback mismatch");
  if (!/^[0-9a-f]{40}$/.test(evidence.commitSha ?? "")) fail("INVALID_EVIDENCE", "commitSha must be a full lowercase SHA");
  inspectForSecrets(evidence, "evidence");
  return evidence;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];
  if (command === "validate") {
    const registry = validateRegistry();
    writeResult({ schemaVersion: 1, status: "VALID", targets: registry.targets.map((target) => target.id).sort() }, args.output);
    return;
  }
  if (command === "classify") {
    // --base/--head: registry pinned at --head. --paths-from-stdin: no ref
    // exists, so the working-tree registry is used and the output says so.
    if (args.pathsFromStdin) {
      const input = readFileSync(0);
      const paths = input.includes(0) ? input.toString("utf8").split("\0") : input.toString("utf8").split(/\r?\n/);
      writeResult({ ...classifyPaths(paths), base: "stdin", head: "stdin" }, args.output);
      return;
    }
    if (!args.base || !args.head) fail("INVALID_ARGUMENT", "classify requires --base and --head");
    writeResult(classifyRange({ base: args.base, head: args.head }), args.output);
    return;
  }
  if (command === "verify-evidence") {
    if (!args.file) fail("INVALID_ARGUMENT", "verify-evidence requires --file");
    const evidence = validateEvidence(readJson(resolve(process.cwd(), args.file)));
    writeResult({ schemaVersion: 1, status: "VALID", target: evidence.target }, args.output);
    return;
  }
  fail("INVALID_ARGUMENT", "usage: release-targets.mjs validate | classify | verify-evidence");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    // Every failure that had a registry names it: no verdict, pass or
    // fail, may be emitted without saying which registry produced it.
    const details =
      error.code === "UNCLASSIFIED_PATH"
        ? { paths: error.details.paths, registry: error.details.registry }
        : error.details?.ref
          ? { ref: error.details.ref }
          : {};
    // The message is half the verdict: without it `classify` with no arguments printed
    // a bare `{"error":{"code":"INVALID_ARGUMENT"}}` and never said WHICH argument
    // (ZPAY-216). Every refusal names both its code and its cause.
    process.stderr.write(`${stableStringify({ schemaVersion: 1, error: { code: error.code ?? "RELEASE_TARGET_ERROR", message: error.message, ...details } })}\n`);
    process.exitCode = 2;
  });
}
