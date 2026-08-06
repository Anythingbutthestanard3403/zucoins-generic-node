// Residual — rejection-site census for the SEND_EXTERNAL execute ceremony.
//
// Ported from `receive-execute-guards.census.test.ts`. That census exists because
// two review rounds failed for one structural reason: *which* guards got a killing test was
// decided by a person enumerating them, and every guard the enumeration missed was silently
// green. The first round listed 14 and an independent pass found 6 survivors; the second closed
// those and a larger battery found 9 more. unbound-proof defect was then found in
// THIS file by exactly that method — by hand, one level of luck away from shipping.
//
// This inverts the quantifier. `send-execute.ts` has exactly one rejection idiom —
// `finish(false, …)` — so the guard set is machine-enumerable from the file's own text with
// no heuristic. The table below must account for every site: an undeclared refusal path
// reddens this test, which is the case that produced both failures.
//
// What this proves: every rejection path is declared and named to a test that exists.
// What it does NOT prove: that the named test would fail if the guard were removed. That is
// `send-execute.mutants.mjs`, run pre-push with its output recorded in the PR body.
//
// Scope boundary, stated rather than assumed: this census covers refusals expressed IN
// `send-execute.ts`. Rejections the ceremony consumes from a seam — `captureSendBaselines`,
// `runSendExternalPreflight`, `proveSendLanding` — are each other modules' own censuses and
// suites; what is asserted here is that this file's handling of them is declared and tested.
//

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(resolve(HERE, "send-execute.ts"), "utf8");
const SUITE = readFileSync(resolve(HERE, "send-execute.test.ts"), "utf8");

interface GuardEntry {
  /** A substring occurring EXACTLY ONCE in send-execute.ts that identifies this site. */
  readonly marker: string;
  /** A test title, or `it.each` row name, present verbatim in send-execute.test.ts. */
  readonly killingTest: string | null;
  /** Required iff killingTest === null. Widening EXEMPT_KEYS is a visible diff line. */
  readonly exempt?: string;
}

/**
 * One entry per `finish(false, …)` site, in source order. Keys are stable ids, not line
 * numbers — line numbers drift, and a census keyed to them would be a maintenance tax that
 * eventually gets silenced.
 */
const SEND_GUARD_CENSUS: Readonly<Record<string, GuardEntry>> = {
  "preflight-not-ready": {
    marker: "preflight not ready — refusing execute",
    killingTest: "refuses an amount above the hard cap before consuming the approval",
  },
  "plan-null-after-ready": {
    marker: "preflight ready but plan null — refuse",
    killingTest: "refuses a null plan when the preflight gate itself is bypassed",
  },
  "amount-over-hard-cap": {
    marker: "exceeds hard cap ${SEND_AMOUNT_HARD_CAP}",
    killingTest: null,
    exempt:
      "Defence-in-depth, unreachable from this harness. effectiveSendAmountCeiling " +
      "clamps every caller ceiling DOWN to SEND_AMOUNT_HARD_CAP and the " +
      "amount_fixed_fractional check fails an over-cap amount, so preflight.ready is false " +
      "and preflight.plan — the only source of `plan` — is null; plan-null-after-ready " +
      "returns first. Kept for a future caller that builds a plan without preflight.",
  },
  "amount-compare-threw": {
    marker: "trailPush(trail, describe(err));",
    killingTest: null,
    exempt:
      "Sibling of amount-over-hard-cap: compareAmounts throws only on a malformed amount, " +
      "which the preflight amount_fixed_fractional check rejects before a plan exists.",
  },
  "approval-consume-threw": {
    marker: "approval consumption failed: ${describe(err)}",
    killingTest: "aborts before the source lease when the approval consumption throws",
  },
  "totp-consumption-not-one": {
    marker: "INVARIANT: totpConsumptionCount=",
    killingTest: "treats a reported second consumption as an invariant breach",
  },
  "source-lease-threw": {
    marker: "source lease unavailable: ${describe(err)} — remain APPROVED",
    killingTest:
      "acquires the source lease before formation gateway reads; preflight probe is counted",
  },
  "formation-read-preceded-lease": {
    marker: "preceded the source lease (total reads=",
    killingTest:
      "ceremony mutation: formation observe before lease → ESCALATE_INVARIANT_BREACH",
  },
  "read-between-lease-and-formation": {
    marker: "gateway read(s) between ",
    killingTest: null,
    exempt:
      "Structurally unreachable from the ceremony: markLeaseAcquired and markFormationStart " +
      "are adjacent statements with no gated gateway read between them. The gate contract " +
      "this branch consumes IS falsifiable and is killed by the bare-gate unit 'mutation " +
      "proof: gateway read between lease and formation reddens markFormationStart'.",
  },
  "formation-observe-threw": {
    marker: "formation observation failed: ${describe(err)}",
    killingTest: "a formation observation throws under the lease",
  },
  "baseline-rejected": {
    marker: "baseline rejected ${baseline.reason}",
    killingTest: "the baseline predicates reject the capture",
  },
  "inner-construction-threw": {
    marker: "inner construction failed: ${describe(err)}",
    killingTest: "inner construction throws on an implausible node clock",
  },
  "sign-intent-persist-threw": {
    marker: "sign-intent persist failed: ${describe(err)} — signer never called",
    killingTest: "never calls the signer before the durable sign intent commits",
  },
  "step1-sign-threw": {
    marker: "step-1 sign failed after durable sign intent: ${describe(err)}",
    killingTest: "holds the lease when the signer throws after the durable sign intent",
  },
  "partial-status-not-awaiting": {
    marker: "INVARIANT: status after partial persist = ",
    killingTest: "the partial persist reports a status other than AWAITING_REDEMPTION",
  },
  "partial-persist-threw": {
    marker: "partial persist failed: ${describe(err)} — nothing delivered",
    killingTest: "holds and reconciles when the partial persist throws",
  },
  "delivery-threw": {
    marker: "delivery failed: ${describe(err)} — persisted code remains exact",
    killingTest: "holds and reconciles when delivery throws",
  },
  "redelivery-bytes-differ": {
    marker: "INVARIANT: re-delivery returned different bytes",
    killingTest: "escalates when re-delivery returns different bytes",
  },
  "recipient-threw": {
    marker: "recipient path threw: ${describe(err)} — outcome unknown",
    killingTest: "holds and reconciles when the external recipient seam throws",
  },
  "row-count-read-threw": {
    marker: "row-count read failed: ${describe(err)}",
    killingTest: "holds and reconciles when persist.countRows throws",
  },
  "row-counts-violate": {
    marker: "INVARIANT: row counts violate the one-approval / no-node-submit rule",
    killingTest: "escalates when the row-count evidence %s violates the one-approval / no-node-submit rule",
  },
  "recipient-refused-stale": {
    marker: "recipient refused stale destination — node must NOT re-sign or refresh",
    killingTest:
      "holds the lease and never re-signs when the recipient outcome is stale-destination",
  },
  "recipient-not-submitted": {
    marker: 'recipient.kind !== "SUBMITTED"',
    killingTest: "holds and reconciles — never re-forms — on an indeterminate recipient submit",
  },
  "landing-observe-threw": {
    marker: "landing observation threw: ${describe(err)}",
    killingTest: "holds and reconciles when the independent landing read throws",
  },
  "landing-head-absent": {
    marker: "no completed transaction observed yet — AWAITING_REDEMPTION stands",
    killingTest: "stays AWAITING_REDEMPTION when the independent read shows no completed transaction",
  },
  "head-not-ours-no-path-evidence": {
    marker: "and no path evidence was retained — INDETERMINATE",
    killingTest: "no retained path evidence at all is INDETERMINATE — never an invariant breach",
  },
  "path-evidence-not-our-attempt": {
    marker: "landing-path evidence names a body that is not our attempt ",
    killingTest: "PROBE-D0: a decoy at depth 0 is INDETERMINATE — a landing proof is not OUR landing",
  },
  "landing-walk-threw": {
    marker: "landing walk threw: ${describe(err)} — INDETERMINATE",
    killingTest: "the landing walk itself throwing is INDETERMINATE, never a breach",
  },
  "landing-proof-incomplete": {
    marker: "landing walk incomplete (${landingProof.fault}) over ",
    killingTest:
      "MUTATION: a gapped path (hop 2 supplied, hop 1 missing) is INDETERMINATE, never a landing",
  },
  "landed-exact-contradicts-head-read": {
    marker: "landing walk LANDED_EXACT contradicts the head read",
    killingTest: "LANDED_EXACT against a head read that did NOT carry our attempt is a contradiction",
  },
  "unknown-landing-proof-kind": {
    marker: "unknown landing proof kind ${JSON.stringify(unhandled)}",
    killingTest: null,
    exempt:
      "TypeScript exhaustiveness over the frozen LandingProofOutcome union: the branch " +
      "assigns `const unhandled: never`, so reaching it means widening the frozen union, " +
      "at which point the compile error is the guard. No fixture can produce a fourth kind " +
      "— proveSendLanding returns it, not a seam.",
  },
};

/**
 * The three `finish(true, …)` sites. SEND_EXTERNAL has more than one because admits a
 * landing by two independent routes (head read, or the complete-path walk at depth
 * 0 or deeper), and a fourth success route must not appear unnoticed —
 * a wrongly-admitted landing releases the source lease on coins that never moved.
 */
const SEND_SUCCESS_CENSUS: Readonly<Record<string, GuardEntry>> = {
  "landed-verified-head-read": {
    marker: "LANDED_VERIFIED step_2=${truncateSig(landing.step2Signature)} ",
    killingTest: "runs the full ceremony once and lands verified",
  },
  "landed-verified-walk-depth-0": {
    marker: "landing walk LANDED_EXACT depth=0 — our attempt is the current head",
    killingTest: "a late landing the head read never saw still proves depth 0",
  },
  "landed-buried-complete-path": {
    marker: "landing walk LANDED_COMPLETE_PATH depth=${landingProof.depth}",
    killingTest:
      "a second external inbound between submit and the terminal read is a LANDING, not a breach",
  },
};

/**
 * Frozen exempt set. Every member is a refusal that no fixture reaching this module can
 * trigger, with its reason on the entry. Adding a member is one visible diff line a reader
 * must approve, which is the whole point — an exemption must cost something.
 */
const EXEMPT_KEYS: readonly string[] = [
  "amount-compare-threw",
  "amount-over-hard-cap",
  "read-between-lease-and-formation",
  "unknown-landing-proof-kind",
];

function countOccurrences(haystack: string, needle: string): number {
  let n = 0;
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) return n;
    n += 1;
    from = at + needle.length;
  }
}

/** Source with `//` and `/* *\/` comment text removed, so prose cannot trip a code check. */
const SOURCE_CODE_ONLY = SOURCE.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

describe("send-execute rejection-site census", () => {
  const entries = Object.entries(SEND_GUARD_CENSUS);
  const successEntries = Object.entries(SEND_SUCCESS_CENSUS);
  const allEntries = [...entries, ...successEntries];

  it("declares exactly one entry per finish(false, …) site", () => {
    // The inverted quantifier: adding a refusal path to the ceremony without declaring it
    // here is impossible, so "a guard nobody thought about" cannot ship.
    expect(countOccurrences(SOURCE, "finish(false")).toBe(entries.length);
  });

  it("declares exactly one entry per finish(true, …) site", () => {
    expect(countOccurrences(SOURCE, "finish(true")).toBe(successEntries.length);
  });

  it("refuses only via finish(false, …) — no bare throw escapes the ceremony", () => {
    // A refusal introduced by `throw` would leave the counts consistent and the new path
    // invisible to this census. Comment prose is stripped first so a doc line mentioning
    // the word cannot redden this and get it silenced.
    expect(/\bthrow\b/.test(SOURCE_CODE_ONLY)).toBe(false);
  });

  it("gives every declared site a marker that occurs exactly once in the source", () => {
    const missing = allEntries.filter(([, e]) => countOccurrences(SOURCE, e.marker) !== 1);
    expect(missing.map(([k]) => k)).toEqual([]);
  });

  it("keeps markers pairwise distinct", () => {
    const markers = allEntries.map(([, e]) => e.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });

  it("names, for every declared site, a killing test that exists in the suite", () => {
    const unnamed = allEntries.filter(
      ([, e]) => e.killingTest !== null && !SUITE.includes(e.killingTest),
    );
    expect(unnamed.map(([k]) => k)).toEqual([]);
  });

  it("admits an exemption only from the frozen list, and only with a reason", () => {
    const exempted = allEntries.filter(([, e]) => e.killingTest === null);
    expect(exempted.map(([k]) => k).sort()).toEqual([...EXEMPT_KEYS].sort());
    expect(exempted.every(([, e]) => typeof e.exempt === "string" && e.exempt.length > 0)).toBe(
      true,
    );
  });

  it("keeps every success site out of the exempt set", () => {
    // A success path with no killing test is strictly worse than an untested refusal: it
    // releases the source lease. There is no reason that would justify one.
    expect(successEntries.filter(([, e]) => e.killingTest === null).map(([k]) => k)).toEqual([]);
  });

  it("is not vacuous", () => {
    // An empty or unreadable source must not pass by making every count zero.
    expect(countOccurrences(SOURCE, "finish(false")).toBeGreaterThan(25);
    expect(SOURCE.split("\n").length).toBeGreaterThan(1000);
    expect(SUITE.split("\n").length).toBeGreaterThan(1000);
    expect(SOURCE_CODE_ONLY.length).toBeGreaterThan(SOURCE.length / 2);
  });
});
