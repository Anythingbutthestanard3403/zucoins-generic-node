#!/usr/bin/env node
// Residual — machine-derived mutation battery for the SEND_EXTERNAL
// execute ceremony. Sibling of `receive-execute.mutants.mjs`, same derivation
// discipline, retargeted at `send-execute.ts`. Run pre-push; paste the table into the PR
// body (no CI, verification is prose evidence at a SHA).
//
//   node packages/node-core/test/live-chain/send-execute.mutants.mjs
//   node packages/node-core/test/live-chain/send-execute.mutants.mjs --derive-only
//
// Why this exists: shipped two HAND-WRITTEN mutation batteries and each time a
// an independently hand-written battery found the difference between the two sets
// (6 survivors, then 9 more). The enumeration was the defect, not the diligence.
// unbound-proof defect was then found on THIS file by exactly that failed method. Here the
// mutants are derived from the source text, so an independent battery and the author's
// battery are the same derivation over the same file.
//
// Families (all derived, none listed):
//   F1 guard-off      every `if (…)` whose block contains `finish(` → condition `false`
//   F2 clause-off     every top-level &&/|| operand in an F1 condition or a `const`
//                     initializer → the neutral literal for that operator
//   F3 compare-flip   every top-level `===` / `!==` inside those same spans → flipped
//   F4 catch-fault    every `catch` block → rethrow instead of handling
//
// Three deliberate divergences from the receive battery, each closing a hole that would
// have made this file's guard set under-enumerated:
//
//   * F1 keys on `finish(` rather than `finish(false`. `send-execute.ts` has THREE success
//     sites, and the LANDED_VERIFIED guard at is a decision that can wrongly fire
//     `landing !== null && innerTextMatchesPersisted && step1SignatureMatchesPersisted`
//     turned off is a false positive landing, the worst outcome this module has. Keying on
//     the rejection idiom alone would leave it, and its clauses, underived.
//   * F4 covers EVERY catch, not only catches that reject. `send-execute.ts` has one catch
//     that swallows and continues (the landing-path evidence read at) — a real
//     decision point, and invisible to a `finish(false`-keyed derivation.
//   * F3 replaces the receive battery's projection field-swap, which derives nothing here:
//     this file reads `WalletStateProjection` fields only inside trail template literals,
//     so every such mutant would be a log-text change. The decisions this ceremony makes
//     are equality tests against frozen string unions and row counts, so flipping the
//     comparison is the analogous "same shape, wrong operand" family.
//
// A mutant SURVIVES when the suite still passes. Any survivor not on the frozen accepted
// list exits 1.
//
// Self-degradation (the lesson: an analyser that breaks must redden, never pass):
//   * each family's mutant count is frozen below — an empty or shrunken family exits 2
//     before a single test runs;
//   * every `finish(false` site in the source must fall inside some derived F1 guard block
//     or F4 catch block. This is the check one level up: a rejection path the derivation
//     cannot SEE is silently green, which is the original defect, and a frozen count alone
//     would not catch it.
//
// `send-execute-guards.census.test.ts` is deliberately NOT in the mutated suite. It is a
// static-text test, so F4's injected `throw` would redden it for every mutant in the
// family and record a "kill" that proves nothing about behaviour.

import { execFileSync } from "node:child_process";
import { copyFileSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE_PATH = resolve(HERE, "send-execute.ts");
const BACKUP_PATH = resolve(HERE, "send-execute.ts.mutants-backup");
const PKG_ROOT = resolve(HERE, "../..");
const SUITE = "test/live-chain/send-execute.test.ts";
const DERIVE_ONLY = process.argv.includes("--derive-only");

/** Frozen per-family counts. A shrunken family means the derivation regressed. */
const EXPECTED_FAMILY_COUNTS = { F1: 20, F2: 16, F3: 24, F4: 14 };

/**
 * Frozen accepted-survivor list. Each entry names a clause that is NOT independently
 * falsifiable from this harness and says why in one line. The check is two-way: an unlisted
 * survivor exits 1, and a listed mutant that turns out to be killable ALSO exits 1 — so the
 * list cannot rot into a silent amnesty the way a hand-written battery did twice on.
 *
 * Keyed by the clause source text, which moves with the code rather than with line numbers.
 */
const ACCEPTED_SURVIVORS = new Map([
  [
    "compareAmounts(plan.amount, SEND_AMOUNT_HARD_CAP) > 0",
    "Defence-in-depth. `effectiveSendAmountCeiling` clamps every caller ceiling DOWN " +
      "to SEND_AMOUNT_HARD_CAP and the `amount_fixed_fractional` check fails an over-cap " +
      "amount, so `preflight.ready` is false and `preflight.plan` is null before this line " +
      "— the null-plan guard above returns first. Unreachable while the plan can only come " +
      "from preflight; kept for a future caller that builds one without it. The refusal " +
      "itself is killed at the preflight level.",
  ],
  [
    "!formed.ok",
    "Nothing performs a gated gateway read between `markLeaseAcquired` and " +
      "`markFormationStart` — they are adjacent statements — so this branch is structurally " +
      "unreachable from the ceremony. The gate's own contract IS falsifiable and is killed " +
      "by the bare-gate unit 'mutation proof: gateway read between lease and formation " +
      "reddens markFormationStart'.",
  ],
  [
    'landingProof.kind !== "LANDED_COMPLETE_PATH"',
    "TypeScript exhaustiveness over the frozen `LandingProofOutcome` union: the branch " +
      "assigns to `const unhandled: never`, so reaching it requires widening the union in " +
      "the frozen union, at which point the compile error is the guard. No fixture can produce a " +
      "fourth kind, because `proveSendLanding` — not the seam — returns it.",
  ],
  [
    "catch(err) → trailPush(trail, describe(err));",
    "The catch around the hard-cap comparison. `compareAmounts` throws only on a " +
      "malformed amount, and preflight's `amount_fixed_fractional` check rejects one before " +
      "a plan exists — so the block never executes and the rethrow never happens. Sibling of " +
      "the F1 survivor on the same guard.",
  ],
  [
    'expectedVerified.verdict === "VERIFIED"',
    "Attempt-identity binding, first conjunct. `innerPreimageText` exists ONLY on the " +
      "VERIFIED member of the verdict union (transaction-verify.ts:74-121), so for every " +
      "other verdict the second conjunct reads `undefined` and is false regardless. The two " +
      "clauses are jointly reachable and this one is individually unfalsifiable; the guard " +
      "as a whole is killed by F1 and by the F3 flip of this same comparison.",
  ],
  [
    "expectedVerified.innerPreimageText === inner.innerPreimageText",
    "Sibling of the clause above. Forcing it true needs a body that VERIFIES under the " +
      "source key while carrying an inner that is not ours — the step-1 signature is over " +
      "the inner, so no such body exists outside signature malleation. Kept rather than " +
      "collapsed because a malleated-but-verifying signature over identical bytes would be " +
      "caught only by the identity clause.",
  ],
  [
    "!step1MatchesAttempt",
    "Attempt-identity guard, second operand. Forcing it false needs a body whose inner " +
      "matches ours (which requires verdict VERIFIED, i.e. its step-1 signature verifies " +
      "over our exact inner under the source key) while its step-1 signature differs from " +
      "ours. Ed25519 over identical bytes is deterministic, so only malleation produces " +
      "that pair. The first operand IS falsifiable and has its own test.",
  ],
]);

const CODE = 0;
const STR = 1;
const COM = 2;

/**
 * Classify every byte as code / string / comment, and separately mark the full span of any
 * template literal. Bracket matching uses the first; families that must not mutate log text
 * use the second.
 */
function classify(src) {
  const mask = new Uint8Array(src.length);
  const tmpl = new Uint8Array(src.length);
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      const nl = src.indexOf("\n", i);
      const end = nl === -1 ? src.length : nl;
      mask.fill(COM, i, end);
      i = end;
      continue;
    }
    if (c === "/" && d === "*") {
      const close = src.indexOf("*/", i);
      const end = close === -1 ? src.length : close + 2;
      mask.fill(COM, i, end);
      i = end;
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === c) {
          j += 1;
          break;
        }
        j += 1;
      }
      mask.fill(STR, i, j);
      i = j;
      continue;
    }
    if (c === "`") {
      const start = i;
      mask[i] = STR;
      i += 1;
      while (i < src.length) {
        if (src[i] === "\\") {
          mask[i] = STR;
          mask[i + 1] = STR;
          i += 2;
          continue;
        }
        if (src[i] === "$" && src[i + 1] === "{") {
          // The interpolated expression is real code for bracket-matching purposes.
          mask[i] = STR;
          mask[i + 1] = STR;
          i += 2;
          let depth = 1;
          while (i < src.length && depth > 0) {
            if (src[i] === "{") depth += 1;
            else if (src[i] === "}") {
              depth -= 1;
              if (depth === 0) {
                mask[i] = STR;
                i += 1;
                break;
              }
            }
            mask[i] = CODE;
            i += 1;
          }
          continue;
        }
        if (src[i] === "`") {
          mask[i] = STR;
          i += 1;
          break;
        }
        mask[i] = STR;
        i += 1;
      }
      tmpl.fill(1, start, i);
      continue;
    }
    i += 1;
  }
  return { mask, tmpl };
}

/** Index of the bracket matching the one at `open`, counting code bytes only. */
function matchBracket(src, mask, open) {
  const closeOf = { "(": ")", "{": "}" };
  const openCh = src[open];
  const closeCh = closeOf[openCh];
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    if (mask[i] !== CODE) continue;
    if (src[i] === openCh) depth += 1;
    else if (src[i] === closeCh) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  throw new Error(`unbalanced ${openCh} at ${open}`);
}

/** Split a boolean expression span at its top-level && / || operands. */
function splitBooleanChain(src, mask, from, to) {
  const parts = [];
  let depth = 0;
  let start = from;
  let operator = null;
  for (let i = from; i < to; i += 1) {
    if (mask[i] !== CODE) continue;
    const c = src[i];
    if (c === "(" || c === "[" || c === "{") depth += 1;
    else if (c === ")" || c === "]" || c === "}") depth -= 1;
    else if (depth === 0 && (src.startsWith("&&", i) || src.startsWith("||", i))) {
      const op = src.slice(i, i + 2);
      if (operator !== null && operator !== op) return { operator: null, parts: [] };
      operator = op;
      parts.push([start, i]);
      start = i + 2;
      i += 1;
    }
  }
  if (operator === null) return { operator: null, parts: [] };
  parts.push([start, to]);
  return { operator, parts };
}

/** Every top-level `===` / `!==` occurrence inside a span, in code, outside template text. */
function topLevelComparisons(src, mask, tmpl, from, to) {
  const found = [];
  let depth = 0;
  for (let i = from; i < to; i += 1) {
    if (mask[i] !== CODE || tmpl[i] === 1) continue;
    const c = src[i];
    if (c === "(" || c === "[" || c === "{") depth += 1;
    else if (c === ")" || c === "]" || c === "}") depth -= 1;
    else if (depth === 0 && (src.startsWith("===", i) || src.startsWith("!==", i))) {
      found.push([i, src.slice(i, i + 3)]);
      i += 2;
    }
  }
  return found;
}

function lineOf(src, index) {
  return src.slice(0, index).split("\n").length;
}

function countOccurrences(haystack, needle) {
  let n = 0;
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) return n;
    n += 1;
    from = at + needle.length;
  }
}

/**
 * Every mutant, derived from the source. No hand-written list anywhere below.
 * Also returns the guard/catch block spans, used by the coverage self-check.
 */
function deriveMutants(src) {
  const { mask, tmpl } = classify(src);
  const mutants = [];
  const seen = new Set();
  /**
   * `key` is the allowlist identity: it moves with the code, unlike a line number. For the
   * span-replacing families it is the replaced source text. F4 replaces an empty span, so it
   * carries an explicit key instead — an empty-string key would make ONE accepted entry
   * amnesty every catch in the file, which is the fail-open shape this battery exists to
   * remove.
   */
  const add = (family, at, from, to, replacement, note, key) => {
    const dedupe = `${family}:${from}:${to}:${replacement}`;
    if (seen.has(dedupe)) return;
    seen.add(dedupe);
    mutants.push({
      id: `${family}-${mutants.filter((m) => m.family === family).length + 1}`,
      family,
      line: lineOf(src, at),
      note,
      key: key ?? src.slice(from, to).trim(),
      mutate: () => src.slice(0, from) + replacement + src.slice(to),
    });
  };

  /** Blocks that a rejection site may live inside; the coverage self-check reads these. */
  const rejectionHomes = [];

  // ── F1 guard-off, over every `if` whose block decides a disposition ───────
  const guardConditions = [];
  for (let i = 0; i < src.length; i += 1) {
    if (mask[i] !== CODE || !src.startsWith("if (", i)) continue;
    const condOpen = i + 3;
    const condClose = matchBracket(src, mask, condOpen);
    let j = condClose + 1;
    while (j < src.length && /\s/.test(src[j])) j += 1;
    if (src[j] !== "{") continue;
    const blockClose = matchBracket(src, mask, j);
    // `finish(`, not `finish(false` — the three success sites are decisions too, and the
    // LANDED_VERIFIED guard turned off is a false positive landing.
    if (!src.slice(j, blockClose).includes("finish(")) continue;
    guardConditions.push([condOpen + 1, condClose]);
    rejectionHomes.push([j, blockClose]);
    add("F1", i, condOpen + 1, condClose, "false", `guard at line ${lineOf(src, i)} always false`);
  }

  // ── F2 / F3 also over `const` initializers that feed a guard ──────────────
  const chainSpans = [...guardConditions];
  const constRe = /\n\s{2,}const \w+ =/g;
  for (let m = constRe.exec(src); m !== null; m = constRe.exec(src)) {
    const start = m.index + m[0].length;
    if (mask[start] !== CODE) continue;
    let end = start;
    let depth = 0;
    while (end < src.length) {
      if (mask[end] === CODE) {
        const c = src[end];
        if (c === "(" || c === "[" || c === "{") depth += 1;
        else if (c === ")" || c === "]" || c === "}") depth -= 1;
        else if (c === ";" && depth === 0) break;
      }
      end += 1;
    }
    chainSpans.push([start, end]);
  }

  // ── F2 clause-off ─────────────────────────────────────────────────────────
  for (const [from, to] of chainSpans) {
    const { operator, parts } = splitBooleanChain(src, mask, from, to);
    if (parts.length < 2) continue;
    const neutral = operator === "&&" ? "true" : "false";
    for (const [pf, pt] of parts) {
      add("F2", pf, pf, pt, ` ${neutral} `, `clause at line ${lineOf(src, pf)} → ${neutral}`);
    }
  }

  // ── F3 comparison flip ────────────────────────────────────────────────────
  // The decisions this ceremony makes are equality tests against frozen string unions
  // (`recipient.kind`, `landingProof.kind`, `statusAfter`, verifier verdicts) and against
  // row counts. Flipping the operator is "same shape, wrong operand": the guard still fires,
  // on the complement. F1 only proves the guard can fire; this proves it fires on the right
  // side. Nested comparisons are reached through their enclosing clause span, so scoping to
  // top level here costs no coverage.
  for (const [from, to] of chainSpans) {
    for (const [at, op] of topLevelComparisons(src, mask, tmpl, from, to)) {
      const flipped = op === "===" ? "!==" : "===";
      add("F3", at, at, at + 3, flipped, `${op} → ${flipped} at line ${lineOf(src, at)}`);
    }
  }

  // ── F4 catch-fault ────────────────────────────────────────────────────────
  // Every catch, not only the rejecting ones: the landing-path evidence read swallows
  // its error and continues, which is as much a decision as a refusal.
  const catchRe = /\}\s*catch\s*\((\w+)\)\s*\{/g;
  for (let m = catchRe.exec(src); m !== null; m = catchRe.exec(src)) {
    const brace = m.index + m[0].length - 1;
    if (mask[brace] !== CODE) continue;
    const close = matchBracket(src, mask, brace);
    rejectionHomes.push([brace, close]);
    const firstStatement =
      src
        .slice(brace + 1, close)
        .split("\n")
        .map((l) => l.trim())
        .find((l) => l !== "" && !l.startsWith("//")) ?? "";
    add(
      "F4",
      brace,
      brace + 1,
      brace + 1,
      ` throw ${m[1]};`,
      `catch at line ${lineOf(src, brace)} rethrows`,
      `catch(${m[1]}) → ${firstStatement}`,
    );
  }

  return { mutants, rejectionHomes, mask };
}

/**
 * The check one level up. A `finish(false, …)` the derivation cannot see is silently green,
 * which is the original defect with the enumerator swapped for a parser. Every
 * rejection site must be inside a block some F1 or F4 mutant governs.
 *
 * The terminal `finish(true, "LANDED_BURIED_COMPLETE_PATH", …)` is the function's fall-through
 * return and is intentionally not inside any guard, so success sites are out of scope here.
 */
function uncoveredRejectionSites(src, mask, rejectionHomes) {
  const uncovered = [];
  for (let i = 0; i < src.length; i += 1) {
    if (mask[i] !== CODE || !src.startsWith("finish(false", i)) continue;
    if (!rejectionHomes.some(([from, to]) => i > from && i < to)) uncovered.push(lineOf(src, i));
  }
  return uncovered;
}

function runSuite() {
  try {
    execFileSync(resolve(PKG_ROOT, "../../node_modules/.bin/vitest"), ["run", SUITE], {
      cwd: PKG_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { passed: true, reddened: [] };
  } catch (err) {
    const text = `${err.stdout ?? ""}${err.stderr ?? ""}`;
    const reddened = [
      ...new Set(
        text
          .split("\n")
          .filter((l) => /^\s*[×✗]\s/.test(l))
          .map((l) => l.replace(/^\s*[×✗]\s*/, "").replace(/\s+\d+ms$/, "").trim()),
      ),
    ];
    return { passed: false, reddened };
  }
}

const original = readFileSync(SOURCE_PATH, "utf8");
const { mutants, rejectionHomes, mask } = deriveMutants(original);
const counts = {};
for (const m of mutants) counts[m.family] = (counts[m.family] ?? 0) + 1;

console.log("derived mutants:", JSON.stringify(counts));

let derivationBroken = false;
for (const [family, expected] of Object.entries(EXPECTED_FAMILY_COUNTS)) {
  const got = counts[family] ?? 0;
  if (got === 0) {
    console.error(`DERIVATION EMPTY: family ${family} produced no mutants`);
    derivationBroken = true;
  } else if (got !== expected) {
    console.error(`DERIVATION DRIFT: family ${family} produced ${got}, frozen at ${expected}`);
    derivationBroken = true;
  }
}

const rejectionSites = countOccurrences(original, "finish(false");
const uncovered = uncoveredRejectionSites(original, mask, rejectionHomes);
console.log(`rejection sites: ${rejectionSites}  seen by the derivation: ${rejectionSites - uncovered.length}`);
if (uncovered.length > 0) {
  console.error(
    `DERIVATION BLIND: finish(false, …) at line(s) ${uncovered.join(", ")} lies outside every ` +
      `derived F1 guard block and F4 catch block — no mutant can reach it`,
  );
  derivationBroken = true;
}

if (derivationBroken) process.exit(2);
if (DERIVE_ONLY) {
  for (const m of mutants) console.log(`${m.id.padEnd(7)} L${String(m.line).padEnd(5)} ${m.note}`);
  console.log(`derive-only: ${mutants.length} mutants, derivation self-checks pass`);
  process.exit(0);
}

copyFileSync(SOURCE_PATH, BACKUP_PATH);
const restore = () => writeFileSync(SOURCE_PATH, original, "utf8");
process.on("SIGINT", () => {
  restore();
  process.exit(130);
});

const baseline = runSuite();
if (!baseline.passed) {
  console.error("BASELINE RED — fix the suite before mutating.");
  restore();
  unlinkSync(BACKUP_PATH);
  process.exit(3);
}

const survivors = [];
try {
  for (const m of mutants) {
    writeFileSync(SOURCE_PATH, m.mutate(), "utf8");
    const { passed, reddened } = runSuite();
    restore();
    if (passed) {
      survivors.push(m);
      console.log(`${m.id.padEnd(7)} L${String(m.line).padEnd(5)} SURVIVOR  ${m.note}`);
    } else {
      console.log(
        `${m.id.padEnd(7)} L${String(m.line).padEnd(5)} killed by ${reddened.length} test(s)` +
          `  ${m.note}\n            ↳ ${reddened.slice(0, 3).join(" | ")}`,
      );
    }
  }
} finally {
  restore();
  unlinkSync(BACKUP_PATH);
}

const unexpected = survivors.filter((s) => !ACCEPTED_SURVIVORS.has(s.key));
const survivorKeys = new Set(survivors.map((s) => s.key));
const wronglyAccepted = [...ACCEPTED_SURVIVORS.keys()].filter(
  (t) => !survivorKeys.has(t) && mutants.some((m) => m.key === t),
);

console.log(
  `\nmutants: ${mutants.length}  survivors: ${survivors.length}` +
    `  accepted: ${survivors.length - unexpected.length}  unexpected: ${unexpected.length}`,
);
for (const s of survivors) {
  const reason = ACCEPTED_SURVIVORS.get(s.key);
  console.log(
    `  ${s.id} L${s.line} ${reason === undefined ? "UNEXPECTED" : "accepted"} — ${s.note}` +
      `${reason === undefined ? `\n      key: ${s.key}` : ""}`,
  );
}
for (const t of wronglyAccepted) {
  console.error(`STALE ACCEPTANCE: "${t}" is on the accepted list but its mutant was killed`);
}
if (unexpected.length > 0 || wronglyAccepted.length > 0) process.exit(1);
