#!/usr/bin/env node
// STRICT dual-review MACHINE fence.
//
// WHY THIS FILE EXISTS
// --------------------
// Review depth for funded-affecting-control / money-path is NOT agent-prompt prose.
// A prior cut re-homed the dual-review rule into `.claude/agents/{reviewer,merger}.md`,
// which classify as benign-governance (`manualReviewRequired: false`). A follow-up
// single-PASS PR could delete those bullets under the ordinary Done path and leave
// subsequent funded-affecting-control PRs with no living dual-review instruction.
//
// This module is the machine consumer of `manualReviewRequired` + `moneyPathHit`.
// It lives under the `scripts/release-targets*.mjs` controlGlob, so any edit that
// weakens the gate is itself funded-affecting-control → STRICT dual. Agent prose in
// merger.md / reviewer.md documents the call site; it is not the enforcement.
//
// USAGE
// -----
//   node scripts/release-targets-strict-dual.mjs check \
//     --base <sha> --head <sha> --pr <n> [--ticket ZTR-<n>]   # verified path
//   node scripts/release-targets-strict-dual.mjs check \
//     --base <sha> --head <sha> --pass-count <n>              # OPERATOR OVERRIDE
//   node scripts/release-targets-strict-dual.mjs check \
//     --paths-from-stdin --head <sha> --pr <n>  # also takes --money-path-hit true|false
//                                               # OR derives money-path from the paths
//
// Exit codes: 0 = dual gate OK (not required, or dual satisfied);
//             3 = REFUSE_MERGE (strict dual required and unmet, or a FAIL at the head);
//             2 = usage / internal error — the gate DID NOT RUN. Includes
//                 REGISTRY_REF_UNRESOLVED, any unreachable verdict evidence, and the
//                 untrustworthy-range codes DIRTY_TREE / DEGENERATE_RANGE /
//                 UNRESOLVABLE_RANGE / BASE_NOT_MERGE_BASE. 2 IS NOT A REFUSAL and
//                 must never be read as one; the gate never degrades to trust either.
//
// ORDER: classification and the money-path scan run FIRST, and verdict evidence is
// collected after them, so a verdict lookup can never abort a gate that did not need it.
// The claim-trail read is ALWAYS ATTEMPTED — never skipped in advance — because skipping
// a check may only add refusals, and pre-emptive skipping dropped the F5 veto. It only
// DEGRADES (provenanceChecked:false) after it has actually failed, and only when dual is
// not required.
//
// REGISTRY PROVENANCE: with --base/--head the registry is read AT --head, not
// from the caller's checkout, and the `registry` field of every result (and of every
// refusal) names the blob used. A stale tree can no longer produce a false verdict.
//
// VERDICT PROVENANCE: `--pr <n>` DERIVES the pass count from the PR's verdict
// comments — head-pinned, one effective verdict per reviewer lane, FAIL at the head vetoes,
// and each counted verdict's run id must hold a claim window on the ticket covering the
// moment it was posted. See release-targets-verdict-evidence.mjs for why (PR #1794
// run-identity forgery). `--pass-count` survives only as an operator override and says so
// loudly on stderr; it verifies nothing.
//
// Governing principles: control hits stay merge-neutral; money-path depth is an
// orthogonal axis; the fence itself is adversarially reviewed.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { classifyPaths, classifyRange, stableStringify } from "./release-targets.mjs";
import { makeGit, scanDiffFailClosed, scanPaths } from "./money-path-scan.mjs";
import { collectVerdictEvidence } from "./release-targets-verdict-evidence.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Dual review is required when either funded-affecting-control (`manualReviewRequired`)
 * or the money-path sentinel trips. Orthogonal axes — either alone is enough.
 */
export function dualReviewRequired({ manualReviewRequired, moneyPathHit }) {
  return Boolean(manualReviewRequired) || Boolean(moneyPathHit);
}

/**
 * Machine preflight: refuse single-PASS merge when dual is required.
 *
 * @param {object} opts
 * @param {boolean} opts.manualReviewRequired
 * @param {boolean} opts.moneyPathHit
 * @param {number} opts.passCount  PASS verdicts at the same head SHA (opposed lenses)
 * @param {number} [opts.minOpposed=2]
 * @returns {{
 *   dualRequired: boolean,
 *   dualSatisfied: boolean,
 *   disposition: "OK" | "REFUSE_MERGE",
 *   reasonCode: string,
 *   detail: object,
 * }}
 */
export function evaluateStrictDualGate(opts = {}) {
  const passCount = Number(opts.passCount);
  const minOpposed = opts.minOpposed == null ? 2 : Number(opts.minOpposed);
  if (!Number.isFinite(passCount) || passCount < 0) {
    const err = new Error("passCount must be a non-negative number");
    err.code = "INVALID_ARGUMENT";
    throw err;
  }
  if (!Number.isFinite(minOpposed) || minOpposed < 1) {
    const err = new Error("minOpposed must be a positive number");
    err.code = "INVALID_ARGUMENT";
    throw err;
  }

  const manualReviewRequired = Boolean(opts.manualReviewRequired);
  const moneyPathHit = Boolean(opts.moneyPathHit);
  const required = dualReviewRequired({ manualReviewRequired, moneyPathHit });
  const detail = { manualReviewRequired, moneyPathHit, passCount, minOpposed };

  if (!required) {
    return {
      dualRequired: false,
      dualSatisfied: true,
      disposition: "OK",
      reasonCode: "DUAL_NOT_REQUIRED",
      detail,
    };
  }
  if (passCount >= minOpposed) {
    return {
      dualRequired: true,
      dualSatisfied: true,
      disposition: "OK",
      reasonCode: "DUAL_SATISFIED",
      detail,
    };
  }
  return {
    dualRequired: true,
    dualSatisfied: false,
    disposition: "REFUSE_MERGE",
    reasonCode: "STRICT_DUAL_INSUFFICIENT",
    detail,
  };
}

/**
 * Fold derived verdict evidence into a gate result.
 *
 * Two things the raw pass count cannot express:
 *
 *   1. A FAIL at the reviewed head VETOES, whatever the PASS count is. Two PASSes
 *      plus an unaddressed FAIL is not a dual pass, it is a disagreement. The veto
 *      fires even when dual is not required — a fence that watched a lane FAIL the
 *      head and still exited 0 would be handing the merger a green light it has no
 *      business giving. Only a LATER verdict from the SAME lane at the SAME head
 *      clears it, which deriveVerdictEvidence already resolves per lane.
 *   2. WHY a refusal happened. A refusal whose evidence was thrown out for a stale
 *      head or unproven provenance must say so — silently uncounting is the exact
 *      failure this fence exists to end (AC2).
 *
 * @param {object} result   gate result from evaluateStrictDualFor{Paths,Diff}
 * @param {object} evidence from deriveVerdictEvidence / collectVerdictEvidence
 */
export function applyVerdictEvidence(result, evidence) {
  const annotated = { ...result, passCountSource: "verdict-evidence", verdictEvidence: evidence };
  const refuse = (reasonCode) => ({ ...annotated, dualSatisfied: false, disposition: "REFUSE_MERGE", reasonCode });

  // B1: the count is derived against --head; if that is not the PR's real head the
  // whole evidence set is for the wrong head. Refuse before anything else reads it.
  if (evidence.headMatchesPrHead === false) return refuse("VERDICT_HEAD_NOT_PR_HEAD");
  // A standing FAIL at the reviewed head vetoes, whatever the PASS count.
  if (evidence.failLanes.length > 0) return refuse("VERDICT_FAIL_AT_HEAD");
  // F5: a FAIL pinned to the reviewed head that could NOT be provenance-cleared
  // (stale/forged/edited claim) must still stop the merge for human adjudication —
  // dropping it is fail-open for a veto. Fires whether or not dual is required.
  if ((evidence.unprovenFailsAtHead ?? []).length > 0) return refuse("VERDICT_UNPROVEN_FAIL_AT_HEAD");
  // F3: on a strict-required path the ticket MUST resolve so provenance is actually
  // checked. An unresolvable-ticket PR (every id source is author-controlled) that
  // slipped through with provenanceChecked:false is NOT the verified path — refuse,
  // matching the unreachable-trail path, instead of exiting 0 labelled verified.
  if (annotated.dualRequired && !evidence.provenanceChecked) return refuse("VERDICT_PROVENANCE_UNCHECKED");

  if (annotated.disposition !== "REFUSE_MERGE") return annotated;

  // Name WHY a refusal fell short of dual. Two reviewer LETTERS posted but only ONE
  // verified run (F1b) is the interim single-run-dispatch case — distinct from a
  // genuinely missing second reviewer: the merger reads both comments and uses the
  // audited --pass-count override rather than bouncing to Review. See the runbook.
  const minOpposed = annotated.detail?.minOpposed ?? 2;
  if (evidence.passLanes.length >= minOpposed && evidence.passCount < minOpposed) {
    return { ...annotated, reasonCode: "DUAL_SINGLE_RUN" };
  }
  const rejectedReasons = new Set(evidence.rejected.map((entry) => entry.reason));
  if (rejectedReasons.has("VERDICT_STALE_HEAD")) return { ...annotated, reasonCode: "VERDICT_STALE_HEAD" };
  // A comment whose own headings disagree on lane/run/head. On the FAIL side F5 above
  // already fired; this names the PASS-side case, where the gate would otherwise report a
  // bare STRICT_DUAL_INSUFFICIENT with no clue that a verdict was thrown out.
  if (rejectedReasons.has("VERDICT_HEADINGS_CONFLICT")) return { ...annotated, reasonCode: "VERDICT_HEADINGS_CONFLICT" };
  if (rejectedReasons.has("VERDICT_PROVENANCE_UNPROVEN")) return { ...annotated, reasonCode: "VERDICT_PROVENANCE_UNPROVEN" };
  return annotated;
}

/**
 * Derive classify + money-path from a path list, then evaluate the dual gate.
 * Pure (no git) — used by unit tests and --paths-from-stdin.
 */
export function evaluateStrictDualForPaths(paths, { passCount, minOpposed, moneyPathHit } = {}) {
  const classification = classifyPaths(paths);
  const money =
    moneyPathHit == null
      ? scanPaths(paths)
      : { moneyPathHit: Boolean(moneyPathHit), offendingPaths: [] };
  const gate = evaluateStrictDualGate({
    manualReviewRequired: classification.manualReviewRequired,
    moneyPathHit: money.moneyPathHit,
    passCount,
    minOpposed,
  });
  return {
    schemaVersion: 1,
    registry: classification.registry,
    ...gate,
    classification: {
      manualReviewRequired: classification.manualReviewRequired,
      controlPaths: classification.controlPaths,
      affectedTargets: classification.affectedTargets,
    },
    moneyPath: {
      moneyPathHit: money.moneyPathHit,
      offendingPaths: money.offendingPaths ?? [],
    },
  };
}

function fenceError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

/**
 * ZPAY-216: a fail-closed money-path scan is NOT a classification verdict.
 *
 * `scanDiffFailClosed` returns `moneyPathHit: true, offendingPaths: []` for a dirty
 * tree, an unresolvable range or a corrupt registry blob. Read by a lane, that is
 * indistinguishable from a real money-path hit whose offenders nobody named — and an
 * unnamed offender is exactly what pushes a merger onto `--pass-count`. Worse, it is
 * not even safe: with two PASSes on hand the gate answered OK on a diff it had never
 * successfully read. A fail-closed scan means there is no trustworthy diff, so there
 * is no verdict to give. Refuse, naming the cause.
 */
function failedClosedScanError(money, { base, head }) {
  const reason = money.reason ?? "MONEY_PATH_SCAN_FAILED_CLOSED";
  return fenceError(
    reason,
    `money-path scan could not read ${base}..${head}: ${money.message ?? reason}. ` +
      "This is NOT a money-path classification — no verdict is possible until it is fixed.",
    { base, head, reason },
  );
}

/**
 * AC4: the reviewed range must be the PR's own range. That is the whole reason.
 *
 * Both consumers of the range use a TWO-DOT diff — `classifyRange`
 * (release-targets.mjs, `git diff --name-status -z base head`) and `diffPaths`
 * (money-path-scan.mjs, same form). So a `--base` that is not an ancestor of `--head`
 * (`--base origin/main` once main has moved on is the common one) does not generally
 * SHRINK the offender set: it injects REVERSALS of main-only commits, so the set usually
 * GROWS with paths this PR never touched. It shrinks only in the narrow case where main
 * independently landed byte-identical content on a path the PR also changed. Either
 * direction misdescribes the PR, which is enough. Substituting the merge-base silently
 * would change the range the merger believes it reviewed, so name it and refuse instead.
 */
function assertBaseIsMergeBase({ base, head, git }) {
  const rev = (ref) => git(["rev-parse", "--verify", `${ref}^{commit}`]).toString("utf8").trim();
  const baseSha = rev(base);
  const headSha = rev(head);
  const mergeBase = git(["merge-base", baseSha, headSha]).toString("utf8").trim();
  if (mergeBase !== baseSha) {
    throw fenceError(
      "BASE_NOT_MERGE_BASE",
      `--base ${base} (${baseSha}) is not an ancestor of --head ${head} (${headSha}); ` +
        `the reviewed range must start at the merge-base ${mergeBase}. Re-run with --base ${mergeBase}.`,
      { base: baseSha, head: headSha, mergeBase },
    );
  }
}

/**
 * Diff-derived entry point for merger preflight.
 *
 * Classification routes through `classifyRange`, which pins the registry at `head`
 * — the caller's checkout is not an input to the verdict. `repoRoot` is a
 * test seam only.
 */
export function evaluateStrictDualForDiff({ base, head, passCount, minOpposed, repoRoot = REPO_ROOT } = {}) {
  if (!base || !head) {
    const err = new Error("evaluateStrictDualForDiff requires base and head");
    err.code = "INVALID_ARGUMENT";
    throw err;
  }
  const git = makeGit(repoRoot);
  assertBaseIsMergeBase({ base, head, git });
  const classification = classifyRange({ base, head, repoRoot });
  const money = scanDiffFailClosed({ base, head, git });
  if (money.failClosed) throw failedClosedScanError(money, { base, head });
  const gate = evaluateStrictDualGate({
    manualReviewRequired: classification.manualReviewRequired,
    moneyPathHit: money.moneyPathHit,
    passCount,
    minOpposed,
  });
  return {
    schemaVersion: 1,
    base,
    head,
    registry: classification.registry,
    ...gate,
    classification: {
      manualReviewRequired: classification.manualReviewRequired,
      controlPaths: classification.controlPaths,
      affectedTargets: classification.affectedTargets,
    },
    moneyPath: {
      moneyPathHit: money.moneyPathHit,
      offendingPaths: money.offendingPaths ?? [],
      // Always false in a RETURNED result: a fail-closed scan throws above. Kept so
      // the emitted shape is stable, and as the invariant a reader can rely on —
      // a money-path hit in a result always names at least one offender.
      failClosed: false,
    },
  };
}

function parseArgs(argv) {
  const parsed = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      parsed._.push(arg);
      continue;
    }
    if (arg === "--paths-from-stdin") {
      parsed.pathsFromStdin = true;
      continue;
    }
    const value = argv[++index];
    if (value == null) {
      const err = new Error(`${arg} requires a value`);
      err.code = "INVALID_ARGUMENT";
      throw err;
    }
    parsed[arg.slice(2)] = value;
  }
  return parsed;
}

const USAGE =
  "usage: release-targets-strict-dual.mjs check --base <sha> --head <sha> --pr <n> " +
  "[--ticket ZTR-<n>] | --paths-from-stdin --head <sha> --pr <n>; " +
  "--pass-count <n> is an operator override, not the verified path";

// Printed on stderr, unconditionally, whenever the count is taken on trust.
const OVERRIDE_AUDIT =
  "AUDIT: --pass-count is an OPERATOR OVERRIDE. This run verified NO verdict: not the head " +
  "they pin, not which lane posted them, not whether the poster held the claim. Only a MERGER " +
  "who has personally read the PR's verdict comments and confirmed two opposed PASSes at this " +
  "exact head may use it, and must paste this line and the reason for bypassing --pr into the " +
  "merge comment. Reviewers and implementers must never use it. Verified path: --pr <n>.";

function usageError(message) {
  process.stderr.write(`${stableStringify({ schemaVersion: 1, error: { code: "INVALID_ARGUMENT", message } })}\n`);
  process.exitCode = 2;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args._[0] !== "check") return usageError(USAGE);

  // F4: the per-merge grace override is REMOVED. It was a second unaudited
  // caller-supplied number the fence trusted — the exact run-identity-forgery defect class, a
  // ten-day grace producing an evidence artifact indistinguishable from a clean run.
  // The only grace is the reviewed constant DEFAULT_PROVENANCE_GRACE_MINUTES; tune it
  // through an ordinary reviewed PR, never a flag a merger passes at will.
  if (args["provenance-grace-min"] != null) {
    return usageError(
      "--provenance-grace-min was removed (it was an unaudited grace override); the grace is the reviewed constant DEFAULT_PROVENANCE_GRACE_MINUTES",
    );
  }

  // Exactly one source of truth for the count. Accepting both would leave the
  // fence's answer depending on a precedence rule nobody reads.
  const overrideGiven = args["pass-count"] != null;
  const prGiven = args.pr != null;
  if (overrideGiven && prGiven) {
    return usageError("--pr and --pass-count are mutually exclusive: --pr derives the count, --pass-count overrides it");
  }
  if (!overrideGiven && !prGiven) return usageError(USAGE);

  let overridePassCount = null;
  if (prGiven) {
    if (!args.head) return usageError("--pr requires --head: verdicts are counted only when pinned to the reviewed head");
  } else {
    overridePassCount = Number(args["pass-count"]);
    // Number.isInteger rejects NaN/Infinity AND fractions (e.g. 2.5): a
    // fractional pass-count cannot represent independent reviewer passes, and
    // Number.isFinite let 2.5 through as an operator override with passCount:2.5.
    if (!Number.isInteger(overridePassCount) || overridePassCount < 0) {
      return usageError("--pass-count <n> must be a non-negative integer");
    }
  }

  let evaluate;
  if (args.pathsFromStdin) {
    const input = readFileSync(0);
    const paths = (input.includes(0)
      ? input.toString("utf8").split("\0")
      : input.toString("utf8").split(/\r?\n/)
    ).filter(Boolean);
    const moneyPathHit =
      args["money-path-hit"] == null ? undefined : args["money-path-hit"] === "true";
    evaluate = (passCount) => evaluateStrictDualForPaths(paths, { passCount, moneyPathHit });
  } else {
    if (!args.base || !args.head) {
      process.stderr.write(
        `${stableStringify({
          schemaVersion: 1,
          error: { code: "INVALID_ARGUMENT", message: "check requires --base and --head (or --paths-from-stdin)" },
        })}\n`,
      );
      process.exitCode = 2;
      return;
    }
    evaluate = (passCount) => evaluateStrictDualForDiff({ base: args.base, head: args.head, passCount });
  }

  // ZPAY-216: CLASSIFY FIRST. Evidence collection used to run before any
  // classification, so a Linear/gh hiccup aborted the fence (exit 2 — an INTERNAL
  // ERROR, not a refusal, and lanes read it as one) on PRs whose gate never needed a
  // verdict at all. A hostile count of 0 can only over-refuse, so this first pass is
  // safe and exists to learn `dualRequired`.
  let result = evaluate(0);

  let evidence = null;
  if (prGiven) {
    // Throws (never returns a degraded count) when gh or the claim trail is
    // unreachable; the top-level handler surfaces the code and exits 2.
    evidence = collectVerdictEvidence({
      pr: args.pr,
      head: args.head,
      ticket: args.ticket,
      repoRoot: REPO_ROOT,
      // The claim trail PROVES the count, and the read is ALWAYS attempted — skipping it
      // in advance dropped the F5 veto (an unproven FAIL got counted, then superseded by
      // an unauthenticated same-lane PASS). When dual is not required an UNREADABLE trail
      // degrades to provenanceChecked:false instead of aborting the gate; that degraded
      // mode refuses more, never less. On a dual-required path nothing is optional, and
      // F3 refuses anyway if provenance somehow went unchecked.
      provenanceOptional: !result.dualRequired,
    });
    if (result.dualRequired) {
      result = { ...result, ...evaluateStrictDualGate({ ...result.detail, passCount: evidence.passCount }) };
    }
  } else {
    process.stderr.write(`${OVERRIDE_AUDIT}\n`);
    result = { ...result, ...evaluateStrictDualGate({ ...result.detail, passCount: overridePassCount }) };
  }

  const final = evidence
    ? applyVerdictEvidence(result, evidence)
    : { ...result, passCountSource: "operator-override" };

  process.stdout.write(`${stableStringify(final)}\n`);
  process.exitCode = final.disposition === "REFUSE_MERGE" ? 3 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    // A refusal must name the registry that produced it.
    process.stderr.write(
      `${stableStringify({
        schemaVersion: 1,
        error: {
          code: error.code ?? "STRICT_DUAL_ERROR",
          message: error.message,
          ...(error.details?.registry ? { registry: error.details.registry } : {}),
          ...(error.details?.paths ? { paths: error.details.paths } : {}),
          ...(error.details?.ref ? { ref: error.details.ref } : {}),
        },
      })}\n`,
    );
    process.exitCode = 2;
  }
}
