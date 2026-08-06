// rejection-site census for the RECEIVE_EXTERNAL execute ceremony.
//
// Two review rounds failed for one structural reason: *which* guards got a killing test was
// decided by a person enumerating them, and every guard the enumeration missed was silently
// green. The first round listed 14 and an independent pass found 6 survivors; the second closed
// those and a larger battery found 9 more. A third list would close another finite slice of an
// unbounded set.
//
// This inverts the quantifier. `receive-execute.ts` refuses through exactly TWO idioms, and
// both are machine-enumerable from the file's own text with no heuristic:
//
//   1. `finish(false, …)` in the ceremony body                → RECEIVE_GUARD_CENSUS
//   2. a `return` from a `: boolean` helper the ceremony
//      branches on (today: `verifyStep1Signature`, two sites) → HELPER_REFUSAL_CENSUS
//
// Round 3 found the second idiom the hard way: this header used to claim there was only one,
// and on that claim `verifyStep1Signature`'s grammar gate — a live guard, reachable from a
// hostile payer — shipped twice with no killing test, invisible to a `finish(false` count.
// Each table must account for every member of its idiom: an undeclared refusal path reddens
// this test, which is the case that produced all three failures.
//
// What this proves: every rejection path is declared and named to a test that exists.
// What it does NOT prove: that the named test would fail if the guard were removed. That is
// `receive-execute.mutants.mjs`, run pre-push with its output recorded in the PR body.
//

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(resolve(HERE, "receive-execute.ts"), "utf8");
const SUITE = readFileSync(resolve(HERE, "receive-execute.test.ts"), "utf8");

interface GuardEntry {
  /** A substring occurring EXACTLY ONCE in receive-execute.ts that identifies this site. */
  readonly marker: string;
  /** A test title, or `it.each` row name, present verbatim in receive-execute.test.ts. */
  readonly killingTest: string | null;
  /** Required iff killingTest === null. Widening EXEMPT_KEYS is a visible diff line. */
  readonly exempt?: string;
}

/**
 * One entry per `finish(false, …)` site, in source order. Keys are stable ids, not line
 * numbers — line numbers drift, and a census keyed to them would be a maintenance tax that
 * eventually gets silenced.
 */
const RECEIVE_GUARD_CENSUS: Readonly<Record<string, GuardEntry>> = {
  "preflight-not-ready": {
    marker: "preflight not ready — refusing execute",
    killingTest: "refuses preflight-not-ready without any lease or submit",
  },
  "amount-over-hard-cap": {
    marker: "exceeds hard cap ${RECEIVE_AMOUNT_HARD_CAP}",
    killingTest: "refuses an over-cap amount even when preflight is bypassed",
  },
  "amount-compare-threw": {
    marker: "trailPush(trail, describe(err));",
    killingTest: "the hard-cap comparison is handed a malformed amount",
  },
  "plan-null-after-ready": {
    marker: "preflight ready but plan null — refuse",
    killingTest: "refuses a null plan even when the preflight gate itself is bypassed",
  },
  "admit-threw": {
    marker: "admit failed: ${describe(err)}",
    killingTest: "persist.admitOperation throws",
  },
  "receiver-lease-threw": {
    marker: "receiver lease unavailable: ${describe(err)}",
    killingTest: "leases.acquireReceiverLease throws",
  },
  "t0-observe-preceded-lease": {
    marker: "INVARIANT: T0 observe preceded receiver lease",
    killingTest: "ceremony mutation: T0 observe before lease → ESCALATE_INVARIANT_BREACH",
  },
  "t0-observe-threw": {
    marker: "RECEIVE_T0 observation failed: ${describe(err)}",
    killingTest: "observe.observeVerified throws on the RECEIVE_T0 read",
  },
  "transfer-code-formation-threw": {
    marker: "transfer code formation failed: ${describe(err)}",
    killingTest: "transfer-code formation throws on a malformed receiver B0",
  },
  "formation-status-not-ready": {
    marker: "INVARIANT: status after formation",
    killingTest: "formation persist reports a status other than READY",
  },
  "formation-persist-threw": {
    marker: "formation persist failed: ${describe(err)}",
    killingTest: "persist.persistFormation throws",
  },
  "arm-threw": {
    marker: "arm failed: ${describe(err)}",
    killingTest: "arm.armOnce throws",
  },
  "released-code-bytes-differ": {
    marker: "INVARIANT: released code bytes differ from persisted withheld code",
    killingTest: "arm released transfer-code bytes differ from the persisted withheld code",
  },
  "payer-step1-threw": {
    marker: "payer step-1 failed: ${describe(err)}",
    killingTest: "payer.buildAndSignStep1 throws",
  },
  "inner-parse-threw": {
    marker: "inner parse failed: ${describe(err)}",
    killingTest: "the captured step-1 inner is not parseable JSON",
  },
  "inner-not-object": {
    marker: "inner is not a JSON object: ",
    killingTest: "refuses — and returns — when the captured step-1 inner parses to $name",
  },
  "receiver-link-not-s0": {
    marker: "RECEIVER_LINK_MISMATCH: previous_step_2_state_signature",
    killingTest: "aborts a candidate linked to receiver P0 instead of S0",
  },
  "receiver-delta-mismatch": {
    marker: "receiver delta mismatch: step_2.amount=",
    killingTest: "candidate credits the receiver more than the authorized amount",
  },
  "receiver-delta-threw": {
    marker: "receiver delta check failed: ${describe(err)}",
    killingTest: "the captured step-1 inner omits step_2_state entirely",
  },
  "step2-key-role": {
    marker: "WRONG_KEY_ROLE: step_2 key is not the reserved receiver",
    killingTest: "candidate names a step-2 key that is not the reserved receiver",
  },
  "step1-key-role": {
    marker: "WRONG_KEY_ROLE: step_1 key ${parsedInner.step_1_key_public__base64urlsafe}",
    killingTest: "rejects a step-1 key that is not the authorized external payer",
  },
  "expiry-mismatch": {
    marker: "EXPIRY_MISMATCH: inner expiry=",
    killingTest: "rejects a step-1 inner carrying a stale expiry",
  },
  "message-mismatch": {
    marker: "MESSAGE_MISMATCH: inner message=",
    killingTest: "rejects a step-1 inner carrying a mutated message",
  },
  "step1-signature-invalid": {
    marker: "STEP1_SIGNATURE_INVALID: step-1 signature does not verify",
    killingTest: "rejects a forged step-1 signature (valid grammar, unauthorized signer)",
  },
  "inner-restringify-diverged": {
    marker: "inner re-serialize diverged from captured preimage",
    killingTest:
      "escalates a captured inner that does not re-serialize byte-exactly (the byte-exact signing rule)",
  },
  "sender-preflight-threw": {
    marker: "sender preflight failed: ${describe(err)}",
    killingTest: "observe.observeVerified throws on the sender preflight read",
  },
  "sender-link-not-s0": {
    marker: "SENDER_PREFLIGHT_LINK_MISMATCH",
    killingTest: "candidate links to the sender's P0 instead of its S0",
  },
  "sender-delta-mismatch": {
    marker: "sender delta mismatch: step_1.amount=",
    killingTest: "candidate debits the sender less than the authorized amount",
  },
  "sender-delta-threw": {
    marker: "sender delta check failed: ${describe(err)}",
    killingTest: "the sender delta check is handed a malformed sender balance",
  },
  "candidate-persist-threw": {
    marker: "candidate/step2-preimage persist failed: ${describe(err)}",
    killingTest: "persist.persistCandidateAndStep2Preimage throws",
  },
  "persisted-step1-signature-invalid": {
    marker: "STEP1_SIGNATURE_INVALID on post-persist revalidation",
    killingTest: "rejects persisted step-1 bytes that no longer carry a valid signature",
  },
  "persist-roundtrip-mismatch": {
    marker: "STEP1_PERSIST_ROUNDTRIP_MISMATCH: read-back",
    killingTest: "rejects a persisted candidate that is not the one validated at step 3",
  },
  "step2-sign-threw": {
    marker: "step-2 sign failed: ${describe(err)}",
    killingTest: "signer.signStep2 throws",
  },
  "signed-persist-threw": {
    marker: "signed+submit-decision persist failed: ${describe(err)}",
    killingTest: "persist.persistSignedAndSubmitDecision throws",
  },
  "row-count-read-threw": {
    marker: "row-count read failed: ${describe(err)}",
    killingTest: "persist.countRows throws",
  },
  "row-counts-not-single-shot": {
    marker: "INVARIANT: row counts violate single-shot ceremony",
    killingTest: "escalates when the single-shot row count %s is not 1",
  },
  "submit-rejected": {
    marker: 'finish(false, "SUBMIT_REJECTED", "SUBMIT_REJECTED")',
    killingTest: "classifies gateway REJECT without a second submit",
  },
  "submit-ambiguous": {
    marker: 'submitOutcome === "AMBIGUOUS"',
    killingTest: "submits exactly once and never retries on AMBIGUOUS",
  },
  "landing-observe-threw": {
    marker: "landing observation threw: ${describe(err)}",
    killingTest: "observe.observeReceiverLanding throws",
  },
  "landing-head-absent": {
    marker: "no completed transaction observed yet",
    killingTest: "holds and reconciles when the independent landing read finds nothing",
  },
  "landing-predicates-failed": {
    marker: "landing predicates failed settled=",
    // Reachable only when the head IS our attempt (identity flag true) and a
    // remaining predicate contradicts it, which is a determinate breach.
    killingTest: "a head that IS our attempt keeps its determinate breaches (balance)",
  },
  "landing-operand-mismatch": {
    marker: "LANDING_OPERAND_MISMATCH: observed step_2=",
    killingTest:
      "escalates a landing seam whose three flags are true over operands that are not ours",
  },
  // ── — the head does not name our attempt (walk) ───────────
  //
  // A landing-path read that THROWS is deliberately not a site of its own: the catch only
  // records the failure and falls through to `landing-path-absent`, so a read that fails and
  // a node that retained nothing converge on the same INDETERMINATE branch. Its killing test
  // is "MUTATION: a landing-path read that throws is INDETERMINATE, never a breach".
  "landing-path-absent": {
    marker: "and no path evidence was retained",
    killingTest: "holds INDETERMINATE when landing settled-body predicate fails (wrong head bytes)",
  },
  "landing-path-not-our-attempt": {
    marker: "landing-path evidence names a body that is not our attempt",
    killingTest:
      "DECOY-IDENTITY: a look-alike inbound offered as our attempt is refused, never settled",
  },
  // verifySettledTransaction on untrusted expectedBody can throw (no well-formed
  // inner → Object.keys(undefined) inside narrowSplitChainInner). Without its own finish(false)
  // catch the TypeError escapes and strands runnerLockHandle. Distinct from landing-walk-threw
  // (post-bind) and from the seam-read throw (pre-bind, converges on landing-path-absent).
  "landing-path-expectedbody-verify-threw": {
    marker: "landing-path expectedBody verify threw: ${describe(err)}",
    killingTest:
      "MUTATION: expectedBody with no inner is INDETERMINATE — verifySettledTransaction throw cannot strand the lock",
  },
  "landing-walk-threw": {
    marker: "landing walk threw: ${describe(err)}",
    // round 2: this was declared exempt on the claim that `proveReceiveLanding` is
    // total over its own inputs. It is not — the oracle does not wrap `readFreshHead`, so a
    // confirm-read that throws propagates straight out of the walk. The F4 battery found the
    // catch surviving a rethrow mutation, which is what an untested catch looks like.
    killingTest: "MUTATION: a landing WALK that throws is INDETERMINATE, never a breach",
  },
  "landing-walk-incomplete": {
    marker: "landing walk incomplete (",
    killingTest:
      "MUTATION: withhold the intervening body and the walk cannot bridge — INDETERMINATE",
  },
  "landing-walk-exact-contradicts-head": {
    marker: "landing walk LANDED_EXACT contradicts the head read",
    killingTest:
      "MUTATION: LANDED_EXACT that contradicts a head read which lacked our attempt is INDETERMINATE",
  },
  "landing-walk-unknown-kind": {
    marker: "unknown landing proof kind ",
    killingTest: null,
    exempt:
      "An exhaustiveness guard over the frozen LandingProofOutcome union. It " +
      "is unreachable while the union has its current three members, so no fixture can reach " +
      "it without faking the oracle's return type. The `never` binding surfaces a new member " +
      "in a type-aware pass, but NOT in root `tsc -b`, which builds `src/**` only — so treat " +
      "this branch's protection as runtime-only: whatever falls through is INDETERMINATE, " +
      "never a positive landing. That is the property being exempted, and it is the safe " +
      "direction regardless of who typechecks this file.",
  },
};

/**
 * The success sites, declared for the same reason the rejections are: a new
 * `finish(true, …)` is how a defect settles an operation that did not land, so it must not
 * be addable without a visible diff line here.
 */
const RECEIVE_SUCCESS_CENSUS: Readonly<Record<string, GuardEntry>> = {
  "landed-verified-head": {
    marker: "LANDED_VERIFIED step_2=",
    killingTest: "runs the full ceremony once and lands verified",
  },
  "landed-verified-walk-depth-0": {
    marker: "landing walk LANDED_EXACT depth=0",
    killingTest: "PROBE-D0: the walk still proves depth 0 when our attempt IS the head",
  },
  "landed-buried-complete-path": {
    marker: "landing walk LANDED_COMPLETE_PATH depth=",
    killingTest:
      "PROBE-D1: a second external inbound between submit and the terminal read is a LANDING, not a breach",
  },
};

/**
 * Idiom 2: refusals expressed as a `return` from a boolean helper the ceremony branches on.
 * `verifyStep1Signature` has exactly two return sites and both are live rejection paths — a
 * hostile payer reaches the first with any signature that is not a canonical Ed25519 scalar,
 * and the second with any signature that is one but does not verify. Neither is a
 * `finish(false, …)`, so neither appears in the census above; the enumeration below is over
 * the helper's own return statements, not over anybody's list.
 */
const HELPER_REFUSAL_CENSUS: Readonly<Record<string, GuardEntry>> = {
  "step1-signature-grammar-reject": {
    // The only literal-boolean return in the file: verifyStep1Signature's parse catch.
    marker: "return false;",
    killingTest: "rejects a step-1 signature that is not a well-formed Ed25519 scalar",
  },
  "step1-signature-crypto-reject": {
    marker: "return verifyDetachedEd25519({",
    killingTest: "rejects a forged step-1 signature (valid grammar, unauthorized signer)",
  },
};

/**
 * Frozen exempt set. Empty: every rejection path in the file is reachable and has a killing
 * test. Adding a member is one visible diff line a reader must approve, which is the whole
 * point — an exemption must cost something.
 */
const EXEMPT_KEYS: readonly string[] = [
  // An INDETERMINATE branch, never a positive landing and never a breach — an
  // exemption here cannot hide a wrong settle. The reason is on the entry itself.
  "landing-walk-unknown-kind",
];

/**
 * Every `return …;` statement inside a `): boolean {` helper, in source order. This is the
 * machine enumeration behind HELPER_REFUSAL_CENSUS: adding a return site to a boolean helper
 * — or adding a second boolean helper — without declaring it reddens the count below.
 */
function booleanHelperReturns(src: string): string[] {
  const out: string[] = [];
  const fnRe = /\)\s*:\s*boolean\s*\{/g;
  for (let m = fnRe.exec(src); m !== null; m = fnRe.exec(src)) {
    // Top-level helpers close on a brace in column 0, which is also where the next
    // declaration starts — so this span is the whole body and nothing after it.
    const end = src.indexOf("\n}\n", m.index);
    const body = src.slice(m.index, end === -1 ? src.length : end);
    for (const r of body.matchAll(/return [^;]+;/g)) out.push(r[0]);
  }
  return out;
}

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

describe("receive-execute rejection-site census", () => {
  const entries = Object.entries(RECEIVE_GUARD_CENSUS);

  it("declares exactly one entry per finish(false, …) site", () => {
    // The inverted quantifier: adding a refusal path to the ceremony without declaring it
    // here is impossible, so "a guard nobody thought about" cannot ship.
    expect(countOccurrences(SOURCE, "finish(false")).toBe(entries.length);
  });

  it("declares exactly one entry per finish(true, …) site", () => {
    // was "exactly one success site". The buried-landing walk adds two more, and a
    // hard-coded count would have to be bumped anyway; declaring them keeps the same
    // property (a new settle path cannot ship undeclared) instead of weakening it.
    expect(countOccurrences(SOURCE, "finish(true")).toBe(
      Object.keys(RECEIVE_SUCCESS_CENSUS).length,
    );
  });

  it("gives every success site a unique marker and a killing test that exists", () => {
    const success = Object.entries(RECEIVE_SUCCESS_CENSUS);
    const badMarker = success.filter(([, e]) => countOccurrences(SOURCE, e.marker) !== 1);
    expect(badMarker.map(([k]) => k)).toEqual([]);
    const unnamed = success.filter(
      ([, e]) => e.killingTest === null || !SUITE.includes(e.killingTest),
    );
    expect(unnamed.map(([k]) => k)).toEqual([]);
    expect(new Set(success.map(([, e]) => e.marker)).size).toBe(success.length);
  });

  it("refuses only via finish(false, …) — no bare throw escapes the ceremony", () => {
    // Mitigation: a refusal introduced by `throw` would leave the counts consistent
    // and the new path invisible to this census.
    const codeThrows = SOURCE.split("\n")
      .map((line) => line.split("//")[0] ?? "")
      .filter((code) => /\bthrow\b/.test(code));
    expect(codeThrows).toEqual([]);
  });

  it("gives every declared guard a marker that occurs exactly once in the source", () => {
    const missing = entries.filter(([, e]) => countOccurrences(SOURCE, e.marker) !== 1);
    expect(missing.map(([k]) => k)).toEqual([]);
  });

  it("keeps markers pairwise distinct", () => {
    const markers = entries.map(([, e]) => e.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });

  it("names, for every guard, a killing test that exists in the suite", () => {
    const unnamed = entries.filter(([, e]) => e.killingTest !== null && !SUITE.includes(e.killingTest));
    expect(unnamed.map(([k]) => k)).toEqual([]);
  });

  it("admits an exemption only from the frozen list, and only with a reason", () => {
    const exempted = entries.filter(([, e]) => e.killingTest === null);
    expect(exempted.map(([k]) => k).sort()).toEqual([...EXEMPT_KEYS].sort());
    expect(exempted.every(([, e]) => typeof e.exempt === "string" && e.exempt.length > 0)).toBe(
      true,
    );
  });

  it("is not vacuous", () => {
    // An empty or unreadable source must not pass by making every count zero.
    expect(countOccurrences(SOURCE, "finish(false")).toBeGreaterThan(30);
    expect(SOURCE.split("\n").length).toBeGreaterThan(1000);
    expect(SUITE.split("\n").length).toBeGreaterThan(500);
  });
});

describe("receive-execute boolean-helper refusal census", () => {
  const entries = Object.entries(HELPER_REFUSAL_CENSUS);
  const returns = booleanHelperReturns(SOURCE);

  it("declares exactly one entry per boolean-helper return site", () => {
    // The second quantifier. `verifyStep1Signature` refuses through `return false`, which no
    // `finish(false` count can see; adding a return site — or a whole second boolean helper —
    // without declaring it below reddens here.
    expect(returns.length).toBe(entries.length);
  });

  it("matches every enumerated return site to exactly one declared marker", () => {
    const unmatched = returns.filter(
      (statement) => entries.filter(([, e]) => statement.startsWith(e.marker)).length !== 1,
    );
    expect(unmatched).toEqual([]);
  });

  it("gives every declared helper refusal a marker that occurs exactly once in the source", () => {
    const missing = entries.filter(([, e]) => countOccurrences(SOURCE, e.marker) !== 1);
    expect(missing.map(([k]) => k)).toEqual([]);
  });

  it("names, for every helper refusal, a killing test that exists in the suite", () => {
    const unnamed = entries.filter(([, e]) => e.killingTest !== null && !SUITE.includes(e.killingTest));
    expect(unnamed.map(([k]) => k)).toEqual([]);
  });

  it("is not vacuous", () => {
    // A regex that stopped matching would make both sides zero and pass silently.
    expect(returns.length).toBeGreaterThan(1);
    expect(entries.every(([, e]) => typeof e.killingTest === "string")).toBe(true);
  });
});
