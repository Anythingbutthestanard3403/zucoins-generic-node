#!/usr/bin/env node
// machine-derived mutation battery for the RECEIVE_EXTERNAL execute
// ceremony. Run pre-push; paste the table into the PR body (no CI, verification is
// prose evidence at a SHA).
//
//   node packages/node-core/test/live-chain/receive-execute.mutants.mjs
//
// Why this exists: rounds 1 and 2 of this ticket each shipped a HAND-WRITTEN mutation
// battery, and each time an independently hand-written battery found the difference
// between the two sets. The enumeration was the defect, not the diligence. Here the mutants
// are derived from the source text, so an independent battery and the author's battery
// are the same derivation over the same file.
//
// Families (all derived, none listed):
//   F1 guard-off      every `if (…)` whose block contains `finish(false` → condition `false`
//   F2 clause-off     every top-level &&/|| operand in an F1 condition or a boolean `const`
//                     → the neutral literal for that operator
//   F3 field-swap     every WalletStateProjection field read in code (never in trail text)
//                     → each of the three siblings, plus the receiverLinkSource indirection
//   F4 catch-rethrow  every `catch` block containing `finish(false` → rethrow instead
//                     (binding optional: `catch {` refuses exactly like `catch (err) {`)
//   F5 helper-refusal every `return true`/`return false` inside a `: boolean` helper the
//                     ceremony branches on → the opposite literal
//
// A mutant SURVIVES when the suite still passes. Any survivor exits 1.
//
// Self-degradation guard: each family's mutant count is frozen below. A derivation that
// silently under-approximates is the same fail-open shape this battery exists to remove,
// one level up — so an empty or shrunken family fails the run before a single test is run.

import { execFileSync } from "node:child_process";
import { copyFileSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE_PATH = resolve(HERE, "receive-execute.ts");
const BACKUP_PATH = resolve(HERE, "receive-execute.ts.mutants-backup");
const PKG_ROOT = resolve(HERE, "../..");
const SUITE = "test/live-chain/receive-execute.test.ts";

/** Frozen per-family counts. A shrunken family means the derivation regressed. */
// The buried-landing walk adds seven `finish(false, …)` guards and the identity
// bind, so F1 25→32, F2 22→25, F4 17→18. F3/F5 are untouched — the walk reads no
// WalletStateProjection field and adds no boolean helper.
// identity-bind `verifySettledTransaction` gains a finish(false) catch → F4 18→19.
const EXPECTED_FAMILY_COUNTS = { F1: 32, F2: 25, F3: 19, F4: 19, F5: 1 };

/**
 * Frozen accepted-survivor list. Each entry names a clause that is NOT independently
 * falsifiable and says why in one line. The check is two-way: an unlisted survivor exits 1,
 * and a listed mutant that turns out to be killable ALSO exits 1 — so the list cannot rot
 * into a silent amnesty the way a hand-written battery did twice on this ticket.
 *
 * Keyed by `<family>@<line-content-hash-free identity>`: the clause source text, which moves
 * with the code rather than with line numbers.
 */
const ACCEPTED_SURVIVORS = new Map([
  [
    "persistedInnerPreimageText !== payerStep1.innerPreimageText",
    "STEP1_PERSIST_ROUNDTRIP: the verify at runs first and only admits a " +
      "(text, signature) pair that matches under the payer key, so no fixture can vary one " +
      "operand without the other. The two clauses are jointly reachable and individually " +
      "unfalsifiable; the guard as a whole is killed by F1. Kept rather than collapsed " +
      "because a malleated-but-verifying signature over identical bytes would be caught " +
      "only by the identity clause.",
  ],
  [
    "persistedStep1Signature !== payerStep1.step1Signature",
    "Sibling of the clause above; same reason.",
  ],
  [
    'expectedVerified.verdict === "VERIFIED"',
    "IDENTITY BIND, first operand. The second operand reads " +
      "`completedTransactionText`, which exists only on the VERIFIED arm of the verdict " +
      "union — so nothing that fails reverification can satisfy it, and turning this clause " +
      "true changes no outcome. Subsumption, not an untested guard: the guard as a whole is " +
      "killed by F1 (three decoys) and the second operand is killed by F2 on its own.",
  ],
  [
    'landingProof.kind === "PROOF_INCOMPLETE"',
    "Turning this guard off routes a PROOF_INCOMPLETE outcome into the two kind " +
      "checks below it; it matches neither, so the `never` exhaustiveness branch returns the " +
      "same LANDING_INDETERMINATE with the same abort action. Two paths to one safe " +
      "disposition — unfalsifiable by construction, and the branch is kept because it names " +
      "the fault in the trail.",
  ],
  [
    'landingProof.kind !== "LANDED_COMPLETE_PATH"',
    "Exhaustiveness guard. The frozen union has three members and the two above have " +
      "already returned, so nothing reaches it today; TypeScript's `never` binding fails the " +
      "BUILD rather than the suite if a member is added. Its purpose is that a new member " +
      "must not fall through into a positive landing, which no test can stage without faking " +
      "the oracle's return type.",
  ],
]);

const CODE = 0;
const STR = 1;
const COM = 2;

/**
 * Classify every byte as code / string / comment, and separately mark the full span of any
 * template literal. Bracket matching uses the first; F3 uses the second so that mutating a
 * projection read inside a trail message — which changes only log text — is never counted as
 * a mutant that could survive.
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

function lineOf(src, index) {
  return src.slice(0, index).split("\n").length;
}

/** Every mutant, derived from the source. No hand-written list anywhere below. */
function deriveMutants(src) {
  const { mask, tmpl } = classify(src);
  const mutants = [];
  const add = (family, at, from, to, replacement, note) =>
    mutants.push({
      id: `${family}-${mutants.filter((m) => m.family === family).length + 1}`,
      family,
      line: lineOf(src, at),
      note,
      // The span being replaced, used as the allowlist key: it moves with the code, unlike
      // a line number.
      text: src.slice(from, to).trim(),
      mutate: () => src.slice(0, from) + replacement + src.slice(to),
    });

  // ── F1 guard-off + F2 clause-off over guard conditions ────────────────────
  const guardConditions = [];
  for (let i = 0; i < src.length; i += 1) {
    if (mask[i] !== CODE || !src.startsWith("if (", i)) continue;
    const condOpen = i + 3;
    const condClose = matchBracket(src, mask, condOpen);
    let j = condClose + 1;
    while (j < src.length && /\s/.test(src[j])) j += 1;
    if (src[j] !== "{") continue;
    const blockClose = matchBracket(src, mask, j);
    if (!src.slice(j, blockClose).includes("finish(false")) continue;
    guardConditions.push([condOpen + 1, condClose]);
    add("F1", i, condOpen + 1, condClose, "false", `guard at line ${lineOf(src, i)} always false`);
  }

  // ── F2 also over boolean `const` initializers that feed a guard ───────────
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
  for (const [from, to] of chainSpans) {
    const { operator, parts } = splitBooleanChain(src, mask, from, to);
    if (parts.length < 2) continue;
    const neutral = operator === "&&" ? "true" : "false";
    for (const [pf, pt] of parts) {
      add("F2", pf, pf, pt, ` ${neutral} `, `clause at line ${lineOf(src, pf)} → ${neutral}`);
    }
  }

  // ── F3 projection field swap ──────────────────────────────────────────────
  // WalletStateProjection is a frozen four-field type; every read of it in this file goes
  // through `.projection.<field>` or the receiverLinkSource indirection. Reads inside trail
  // template literals are excluded: swapping one changes log text, not a decision.
  const fields = ["S", "P", "B", "I"];
  const projRe = /projection\.([SPBI])\b/g;
  for (let m = projRe.exec(src); m !== null; m = projRe.exec(src)) {
    if (mask[m.index] !== CODE || tmpl[m.index] === 1) continue;
    const fieldAt = m.index + "projection.".length;
    for (const to of fields) {
      if (to === m[1]) continue;
      add("F3", m.index, fieldAt, fieldAt + 1, to, `.${m[1]} → .${to} at line ${lineOf(src, m.index)}`);
    }
  }
  const linkRe = /const receiverLinkSource: "S" \| "P" = "(S|P)";/;
  const link = linkRe.exec(src);
  if (link !== null) {
    const at = link.index + link[0].lastIndexOf(`"${link[1]}"`) + 1;
    add("F3", link.index, at, at + 1, link[1] === "S" ? "P" : "S", "receiverLinkSource → P");
  }

  // ── F4 catch-rethrow ──────────────────────────────────────────────────────
  // The binding is optional in the grammar. Requiring `(err)` made every `catch {` in the
  // file invisible to this family — the blind spot round 3 found `verifyStep1Signature`'s
  // grammar gate sitting in.
  const catchRe = /\}\s*catch\s*(?:\([^)]*\))?\s*\{/g;
  for (let m = catchRe.exec(src); m !== null; m = catchRe.exec(src)) {
    const brace = m.index + m[0].length - 1;
    if (mask[brace] !== CODE) continue;
    const close = matchBracket(src, mask, brace);
    if (!src.slice(brace, close).includes("finish(false")) continue;
    add("F4", brace, brace + 1, brace + 1, " throw err;", `catch at line ${lineOf(src, brace)} rethrows`);
  }

  // ── F5 helper-boolean refusal ─────────────────────────────────────────────
  // A refusal written as `return false` inside a boolean helper is invisible to BOTH F1 and
  // F4: it is neither an `if` block containing `finish(false` nor a catch that refuses. The
  // ceremony branches on those helpers exactly as it branches on an inline condition, so a
  // flipped literal is a fail-open. This is the family that covers the sites the corrected
  // `catchRe` above reaches but the `finish(false` census cannot see.
  const boolFnRe = /\)\s*:\s*boolean\s*\{/g;
  for (let m = boolFnRe.exec(src); m !== null; m = boolFnRe.exec(src)) {
    const brace = m.index + m[0].length - 1;
    if (mask[brace] !== CODE) continue;
    const close = matchBracket(src, mask, brace);
    const body = src.slice(brace, close);
    const retRe = /return (true|false);/g;
    for (let r = retRe.exec(body); r !== null; r = retRe.exec(body)) {
      const at = brace + r.index;
      if (mask[at] !== CODE) continue;
      const flipped = r[1] === "true" ? "false" : "true";
      add(
        "F5",
        at,
        at,
        at + r[0].length,
        `return ${flipped};`,
        `boolean-helper refusal at line ${lineOf(src, at)} → ${flipped}`,
      );
    }
  }

  return mutants;
}

function runSuite() {
  try {
    const _out = execFileSync(
      resolve(PKG_ROOT, "../../node_modules/.bin/vitest"),
      ["run", SUITE],
      { cwd: PKG_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
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
copyFileSync(SOURCE_PATH, BACKUP_PATH);
const restore = () => writeFileSync(SOURCE_PATH, original, "utf8");
process.on("SIGINT", () => {
  restore();
  process.exit(130);
});

const mutants = deriveMutants(original);
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
if (derivationBroken) {
  restore();
  rmSync(BACKUP_PATH, { force: true });
  process.exit(2);
}

const baseline = runSuite();
if (!baseline.passed) {
  console.error("BASELINE RED — fix the suite before mutating.");
  restore();
  rmSync(BACKUP_PATH, { force: true });
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
  rmSync(BACKUP_PATH, { force: true });
}

const unexpected = survivors.filter((s) => !ACCEPTED_SURVIVORS.has(s.text));
const survivorTexts = new Set(survivors.map((s) => s.text));
const wronglyAccepted = [...ACCEPTED_SURVIVORS.keys()].filter(
  (t) => !survivorTexts.has(t) && mutants.some((m) => m.text === t),
);

console.log(
  `\nmutants: ${mutants.length}  survivors: ${survivors.length}` +
    `  accepted: ${survivors.length - unexpected.length}  unexpected: ${unexpected.length}`,
);
for (const s of survivors) {
  const reason = ACCEPTED_SURVIVORS.get(s.text);
  console.log(`  ${s.id} L${s.line} ${reason === undefined ? "UNEXPECTED" : "accepted"} — ${s.note}`);
}
for (const t of wronglyAccepted) {
  console.error(`STALE ACCEPTANCE: "${t}" is on the accepted list but its mutant was killed`);
}
if (unexpected.length > 0 || wronglyAccepted.length > 0) process.exit(1);
