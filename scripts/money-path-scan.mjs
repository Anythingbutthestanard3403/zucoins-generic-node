#!/usr/bin/env node
// MONEY-PATH SENTINEL — a review-DEPTH gate for the ZuTreasury release/QA machinery.
//
// WHY THIS EXISTS (the live hole it closes)
// -----------------------------------------
// Under the autonomy policy an ordinary non-live, NO_DEPLOY family reaches AUTONOMOUS Tier-1 Done via
// agent-owner/pr-qa-monitor after exact-SHA health proof — no human review. But the v2
// signing / custody / transfer-code / golden contracts live in packages/node-core/** and
// packages/generic-node-contracts/**, which the DEPLOY classifier (scripts/release-targets.mjs)
// maps ONLY to the inactive `generic-node` target. So a byte-exact-signing change (GOLDEN
// RULE 3) there reads as "zero active target / NO_DEPLOY" and could ride the autonomous
// auto-Done path WITHOUT deep money-path review.
//
//   Deploy-surface == 0 does NOT imply money-path-surface == 0.
//
// This scan is a SEPARATE, ground-truth, diff-derived signal (distinct from the deploy
// registry) that answers exactly one question: did this diff touch any money-path /
// golden-rule surface? If yes -> moneyPathHit:true, and the family is forced OUT of the
// autonomous auto-Done path into STRICT (dual deep-reasoner) review before it can complete.
//
// WHAT THIS IS AND IS NOT (preserve deploy-merge-neutrality)
// ----------------------------------------
// This is a review-DEPTH signal ONLY. It does NOT alter the deploy-classification rule: a release-registry / deploy
// classifier hit remains descriptive-affected and MERGE-NEUTRAL for DEPLOY, and this scan
// creates NO funded / deploy / authority requirement. It never authorizes or blocks a
// deploy; it only raises the required review depth (review_mode -> dual) for a money-path
// change. The reserved-to-the-human-custodian set is untouched (real-ZKZ submit per send; any Done
// downstream of a real-ZKZ acceptance; signing-key / private-key custody, golden rule 5).
//
// GROUND TRUTH + FAIL-CLOSED
// --------------------------
// The authoritative entry point (scanDiffFailClosed) derives changed paths from
// `git diff <merge-base(origin/main,head)>..<head>` on a CLEAN working tree, and additionally
// asserts the committed release-registry blob (origin/main:release/targets.v1.json) reads and
// parses — a liveness check on the same committed ground truth the deploy classifier uses.
// The money-path GLOB SET itself is hardcoded and registry-INDEPENDENT (it is the "separate
// glob set"); the registry read is only a fail-closed liveness assertion, never a
// classification input. A dirty tree, an unresolvable base/head, a git failure, or an
// unreadable/corrupt committed registry blob ALL resolve to moneyPathHit:true (strict). The
// scan never silently passes.
//
// THE GLOB SET (justification — precision matters both ways)
// ----------------------------------------------------------
// Too broad => needless friction (every PR forced to dual review). Too narrow => a
// laundering hole (a signing change slips through as "non-money"). The set has three layers:
//
//   DENY (evaluated FIRST; a match can never be an offender)
//     Toolchain / manifest / lockfiles are the DEPLOY classifier's concern alone, never
//     a money-path hit: **/package.json, **/package-lock.json, **/pnpm-lock.yaml,
//     pnpm-workspace.yaml, **/tsconfig*.json. This only changes behavior for a
//     toolchain-ONLY diff (the merge-neutral toolchain case). If a real money-path source is
//     co-changed in the same diff, that source still trips the scan — the deny-list removes
//     only the toolchain files from the offender set, never the whole diff.
//
//   MONEY-PATH PACKAGES, wholesale (every file under these roots is money-path surface)
//     apps/generic-node/**             the v2 node under construction — money code organized by
//                                      DIRECTORY (sweep/ vault/ pipeline/ engine/ treasury/),
//                                      generically-named files the keyword globs cannot catch.
//                                      It mirrors the inactive `generic-node` deploy target's
//                                      3rd classificationGlob member; it classifies ONLY to that
//                                      inactive target (zero active surface -> Tier-1 auto-Done
//                                      eligible) and — unlike apps/node, covered by the
//                                      funded-manual-node target — has NO funded-target backstop.
//                                      Wholesale is the only reliable cover here.
//     packages/node-core/**            v2 signing / custody / schema / vectors contracts
//     packages/generic-node-contracts/**   transfer-code / vault / signing / golden contracts
//     packages/splitchain/**           signing.ts + transfer-codes.ts (golden rule 3 core)
//     **/vault-client/**               the custody client package
//     (apps/generic-node/** + packages/node-core/** + packages/generic-node-contracts/** are
//      exactly the three classificationGlobs of the inactive `generic-node` registry target —
//      the surface that reads as zero-active-target / NO_DEPLOY and is the ORIGINAL reason this
//      sentinel exists. splitchain is intentionally wholesale too even though the deploy rule lists it as
//      a DEPLOY-merge-neutral shared path — the two axes differ, which is the whole point.)
//
//   PLATFORM-V2 MONEY SUBTREES + ROUTE FILES (ZPAY-266)
//     apps/platform-v2 is an ACTIVE deploy target, so it never had the NO_DEPLOY laundering
//     hole — but review DEPTH is an independent axis, and the platform's money LOGIC
//     (payout/refund/treasury-move validators, movement repositories, amount serializers,
//     GR2 mutation-admission, merchant wire serializers) was uncovered: PR #2060 rewrote
//     the payout amount-validation gate and read moneyPathHit:false. Deliberately NOT
//     apps/platform-v2/** wholesale — dashboard / admin / identity / ops changes must not
//     trip, or the gate becomes noise and gets routed around. Only the trees/files that
//     create, validate, compose, admit, verify, or serialize ZKZ amounts and
//     movement/session state trip. registry/** is mostly node-client transport (platform
//     holds no keys) — but mutation-admission* and node-client* are GR2 admission /
//     ungated-egress refusal, not pure transport. Per-subtree rationale on
//     MONEY_PATH_PLATFORM_V2_GLOBS below.
//
//   MONEY-PATH NAME PATTERNS, across ALL packages (catch money-path files that live in
//   otherwise-non-money packages: packages/shared, apps/*, widget)
//     **/sign*  **/vault*  **/sweep*  **/transfer-code*  **/*.golden
//     **/__vectors__/**  **/schema/**  **/migrations/**
//     Deliberately NOT packages/shared/** wholesale: a benign shared test file must NOT
//     trip. Only shared's money-path subpaths (e.g. vault-envelope.ts, contracts/sweep-
//     status.ts) trip, via these name patterns. `**/*.golden` reserves the bare `.golden`
//     extension for future golden artifacts; today's goldens are already caught via their
//     package (splitchain / generic-node-contracts wholesale) and the **/sign* / **/transfer-
//     code* name patterns.
//
// Glob semantics are shared with the deploy classifier: this module imports `matchesGlob`
// from release-targets.mjs so both scanners agree byte-for-byte on what a glob means (a `*`
// does not cross `/`; `**/` is an optional path prefix). The two scanners differ only in
// their glob SETS, never their matcher.
//
// USAGE
//   node scripts/money-path-scan.mjs scan --head <sha> [--base <sha>]   # diff-derived, fail-closed
//   node scripts/money-path-scan.mjs scan                               # base = merge-base(origin/main,HEAD)
//   node scripts/money-path-scan.mjs scan --paths-from-stdin            # classify explicit paths (NUL or newline sep)
// Exit code: 0 = no money-path surface; 3 = moneyPathHit (incl. fail-closed); 2 = usage/internal error.
// stdout is a single stable-stringified JSON line: { schemaVersion, moneyPathHit, offendingPaths, ... }.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { matchesGlob, parseNameStatus, stableStringify } from "./release-targets.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const COMMITTED_REGISTRY_REF = "origin/main:release/targets.v1.json";

// DENY — toolchain / manifest / lockfiles: the DEPLOY classifier's concern, never a
// money-path hit. Evaluated FIRST; a matched path can never be an offender.
const DEPLOY_CLASSIFIER_GLOBS = [
  "**/package.json",
  "**/package-lock.json",
  "**/pnpm-lock.yaml",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "**/tsconfig*.json",
];

// GROUP A — money-path PACKAGES, wholesale. The first three coincide with the inactive
// `generic-node` deploy target's classificationGlobs (the zero-active-target / NO_DEPLOY
// surface this sentinel was built for), but the sentinel is deliberately WIDER than that
// mirror — GROUP A2 below adds platform-v2 money logic (ZPAY-266). apps/generic-node/**
// has NO funded backstop.
const MONEY_PATH_PACKAGE_GLOBS = [
  "apps/generic-node/**",
  "packages/node-core/**",
  "packages/generic-node-contracts/**",
  "packages/splitchain/**",
  "**/vault-client/**",
];

// GROUP A2 — platform-v2 money SUBTREES + route files (ZPAY-266). Targeted, not
// apps/platform-v2/** wholesale: an over-noisy gate gets routed around or disabled.
// Included: everything that creates, validates, composes, admits (GR2), verifies, or
// serializes ZKZ amounts and movement/session state — including merchant movement/balance
// wire serializers (amount_zkz / available_zkz + GR5 platform_can_approve:false).
// registry is mostly transport (SSRF egress, rate-limit, backoff); only mutation-admission*
// (tryReserve/bind/destination-gate) and node-client* (UngatedSourceWalletEgressError +
// permit hard-require) are money decisions — file-targeted, not registry/** wholesale.
// Excluded (single review stays enough): dashboard serving, admin/identity/ops/delivery/
// ingest, app wiring (app.ts — the #2060 error-handler mapping presents an error; the
// validator in shared/http/conventions.ts decides it), non-money api/v1 routes, and
// non-money merchant serializers (metrics.ts, node-view.ts). platform-v2 schema/migrations
// were already covered by the **/schema/** and **/migrations/** name patterns.
const MONEY_PATH_PLATFORM_V2_GLOBS = [
  // Amount-bearing API route files (flat files; `*` also catches their co-located tests).
  "apps/platform-v2/src/api/v1/balances*",
  "apps/platform-v2/src/api/v1/movements-create*",
  "apps/platform-v2/src/api/v1/payment-sessions*",
  "apps/platform-v2/src/api/v1/payouts*",
  "apps/platform-v2/src/api/v1/refunds*",
  "apps/platform-v2/src/api/v1/treasury-moves*",
  // Money state machines + movement composition, wholesale — like apps/generic-node,
  // these are money trees full of generically-named files the keyword globs cannot catch.
  "apps/platform-v2/src/intents/**", // refund/payout/treasury-move status transition guards
  "apps/platform-v2/src/movements/**", // payout/refund repositories, source-wallet mutex, compose-send
  "apps/platform-v2/src/sessions/**", // receive-side payment flow: compose-receive, exact-bytes (GR3), arming
  "apps/platform-v2/src/state/**", // single-TX VERIFIED-decision / session-succeeded committer
  "apps/platform-v2/src/treasury/**", // compose-move, success-commit, node-poster, scheduler
  "apps/platform-v2/src/verifier/**", // settlement verification predicates / artifacts / balance read-models
  // Amount scalar + wire boundary, and the HTTP amount-validation gate (#2060's target).
  "apps/platform-v2/src/shared/http/amounts*",
  "apps/platform-v2/src/shared/http/conventions*",
  "apps/platform-v2/src/shared/money/**",
  // GR2 admission + ungated-egress refusal (not pure transport) + merchant wire serializers.
  // Trailing `*` (not /**): co-located tests match; non-money siblings (egress, rate-limit,
  // backoff, metrics, node-view) stay clean.
  "apps/platform-v2/src/registry/client/mutation-admission*", // GR2 tryReserve/bind/destination-gate
  "apps/platform-v2/src/registry/client/node-client*", // UngatedSourceWalletEgressError + permit hard-require
  "apps/platform-v2/src/merchants/serializers/movement*", // amount_zkz wire + GR5 platform_can_approve:false
  "apps/platform-v2/src/merchants/serializers/balance*", // available_zkz / node_claim wire
];

// GROUP B — money-path NAME PATTERNS, across all packages.
const MONEY_PATH_NAME_GLOBS = [
  "**/sign*",
  "**/vault*",
  "**/sweep*",
  "**/transfer-code*",
  // Forward-only: matches zero tracked files today (real goldens are `.golden.json`, already
  // caught via package-wholesale / **/__vectors__/**). Reserves the bare `.golden` extension.
  "**/*.golden",
  "**/__vectors__/**",
  "**/schema/**",
  "**/migrations/**",
];

const MONEY_PATH_GLOBS = [
  ...MONEY_PATH_PACKAGE_GLOBS,
  ...MONEY_PATH_PLATFORM_V2_GLOBS,
  ...MONEY_PATH_NAME_GLOBS,
];

// Exposed so tooling / tests can inspect the exact enforced globs.
export const MONEY_PATH_GLOB_SET = Object.freeze({
  deny: Object.freeze([...DEPLOY_CLASSIFIER_GLOBS]),
  packages: Object.freeze([...MONEY_PATH_PACKAGE_GLOBS]),
  platformV2: Object.freeze([...MONEY_PATH_PLATFORM_V2_GLOBS]),
  namePatterns: Object.freeze([...MONEY_PATH_NAME_GLOBS]),
});

function normalizePath(path) {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

// A single changed path is money-path iff it is NOT a deploy-classifier/toolchain path AND
// matches at least one money-path glob.
export function isMoneyPath(path) {
  const p = normalizePath(path);
  if (DEPLOY_CLASSIFIER_GLOBS.some((glob) => matchesGlob(p, glob))) return false;
  return MONEY_PATH_GLOBS.some((glob) => matchesGlob(p, glob));
}

// Pure classifier over a list of changed paths. Deterministic: offenders are normalized,
// deduped, and sorted.
export function scanPaths(paths) {
  const offendingPaths = [
    ...new Set(paths.map(normalizePath).filter(Boolean)),
  ]
    .filter(isMoneyPath)
    .sort();
  return { schemaVersion: 1, moneyPathHit: offendingPaths.length > 0, offendingPaths };
}

function failClosedError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

// Default git runner: returns a Buffer (execFileSync default), scoped to the repo root.
export function makeGit(cwd = REPO_ROOT) {
  return (args) => execFileSync("git", args, { cwd, maxBuffer: 64 * 1024 * 1024 });
}

// Canonicalize any ref/SHA/relative-rev to a full commit SHA. `--verify ...^{commit}` peels
// tags and errors (execFileSync throws -> fail closed) on an unresolvable/ambiguous rev.
function revParseCommit(git, rev) {
  return git(["rev-parse", "--verify", `${rev}^{commit}`]).toString("utf8").trim();
}

// Derive changed paths from git ground truth. THROWS on any integrity problem so callers
// fail CLOSED. `git` is injectable for hermetic testing.
export function diffPaths({ base, head, git = makeGit(), registryRef = COMMITTED_REGISTRY_REF } = {}) {
  // (1) Working tree must be clean, or the diff is not trustworthy ground truth.
  const status = git(["status", "--porcelain"]).toString("utf8");
  if (status.trim() !== "") {
    throw failClosedError("DIRTY_TREE", "working tree is not clean; refusing to trust the diff");
  }
  // (2) Canonicalize BOTH endpoints to full commit SHAs first, so the degeneracy check below is
  // meaningful even when the caller passes a symbolic ref for one side and a SHA for the other
  // (e.g. `--head origin/main`, where head stays a ref but base resolves to a SHA — a raw string
  // compare would miss the collapse). base defaults to merge-base(origin/main, head), which is
  // correct ONLY at a PRE-MERGE head; callers (the monitor / QA) MUST pass explicit
  // --base <pr_base_sha> --head <pr_head_sha> captured from frozen pre-merge values and never
  // rely on the default at or after merge.
  const headSha = revParseCommit(git, head ?? "HEAD");
  const baseSha = base
    ? revParseCommit(git, base)
    : git(["merge-base", "origin/main", headSha]).toString("utf8").trim();
  if (!headSha || !baseSha) {
    throw failClosedError("UNRESOLVABLE_RANGE", "could not resolve base/head commit range");
  }
  // Fail CLOSED on a degenerate self-range instead of clearing on an empty diff. Post-merge
  // (head is an ancestor of origin/main) the merge-base default collapses to head, yielding an
  // empty diff that would otherwise read as a legitimate moneyPathHit:false — the exact fail-OPEN
  // that would defeat the gate at re-derivation time. base===head is never a meaningful
  // change-review range, so treat it as strict.
  if (baseSha === headSha) {
    throw failClosedError(
      "DEGENERATE_RANGE",
      "base equals head (empty self-diff); refusing to clear — likely a post-merge merge-base collapse. Pass explicit --base/--head from frozen pre-merge values.",
    );
  }
  // (3) Committed-registry liveness (fail-closed on corrupt/unreadable ground truth). The
  // money-path glob set is registry-INDEPENDENT; this read is a liveness assertion only.
  JSON.parse(git(["show", registryRef]).toString("utf8"));
  // (4) The diff itself.
  const diff = git(["diff", "--name-status", "-z", baseSha, headSha]);
  const paths = parseNameStatus(Buffer.isBuffer(diff) ? diff : Buffer.from(String(diff), "utf8"));
  return { base: baseSha, head: headSha, paths };
}

// The authoritative eligibility entry point: diff-derived, FAIL-CLOSED to strict. Any
// integrity failure returns moneyPathHit:true so an unknown diff is never auto-Done.
export function scanDiffFailClosed(opts = {}) {
  try {
    const { base, head, paths } = diffPaths(opts);
    return { ...scanPaths(paths), base, head, failClosed: false };
  } catch (error) {
    return {
      schemaVersion: 1,
      moneyPathHit: true,
      offendingPaths: [],
      failClosed: true,
      reason: error.code ?? "SCAN_ERROR",
      message: error.message,
    };
  }
}

function parseArgs(argv) {
  const parsed = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) parsed._.push(arg);
    else if (arg === "--paths-from-stdin") parsed.pathsFromStdin = true;
    else {
      const value = argv[++index];
      if (!value) throw failClosedError("INVALID_ARGUMENT", `${arg} requires a value`);
      parsed[arg.slice(2)] = value;
    }
  }
  return parsed;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args._[0] !== "scan") {
    process.stderr.write(`${stableStringify({ schemaVersion: 1, error: { code: "INVALID_ARGUMENT", message: "usage: money-path-scan.mjs scan [--base <sha>] [--head <sha>] | --paths-from-stdin" } })}\n`);
    process.exitCode = 2;
    return;
  }
  let result;
  if (args.pathsFromStdin) {
    const input = readFileSync(0);
    const paths = input.includes(0)
      ? input.toString("utf8").split("\0")
      : input.toString("utf8").split(/\r?\n/);
    result = scanPaths(paths.filter(Boolean));
  } else {
    result = scanDiffFailClosed({ base: args.base, head: args.head });
  }
  process.stdout.write(`${stableStringify(result)}\n`);
  process.exitCode = result.moneyPathHit ? 3 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${stableStringify({ schemaVersion: 1, error: { code: error.code ?? "MONEY_PATH_SCAN_ERROR", message: error.message } })}\n`);
    process.exitCode = 2;
  }
}
