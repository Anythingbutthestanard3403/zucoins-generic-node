#!/usr/bin/env node
// Verdict evidence for the STRICT dual-review fence.
//
// WHY THIS FILE EXISTS
// --------------------
// `release-targets-strict-dual.mjs check --pass-count <n>` used to trust a bare
// caller-supplied integer, and `.claude/agents/merger.md` told the merger to plug
// one in by hand. The script performed ZERO verdict verification, so nothing
// mechanically stopped a merge on:
//
//   * a PASS posted against a STALE head (routine once a delta round rebases);
//   * two PASSes from the SAME reviewer lane counted as "dual";
//   * a FORGED verdict — PR #1794 (2026-08-01): a session holding no claim posted
//     `## Review A (lane=reviewer run=73ae4faa) — FAIL — head 0df06a61` under
//     another lane's run id. A PASS forged the same way would have counted;
//   * an honest miscount.
//
// This module derives the pass count from the PR's own verdict comments:
//
//   1. a comment counts only if its header pins the EXACT reviewed head SHA;
//   2. verdicts collapse to ONE effective verdict per reviewer LANE (latest at
//      that head wins), so one lane can never satisfy dual by posting twice;
//   3. an effective FAIL at the head vetoes, whatever the PASS count;
//   4. a verdict whose `run=` has no claim window on the ticket covering its
//      posting time is not counted — the PR #1794 forgery rule, per the
//      orchestrator's VOID notice: "verify verdict provenance (posting time
//      within the claim window recorded on the Linear ticket), not just header
//      text".
//
// Every unreachable input FAILS CLOSED. There is no path from a gh or Linear
// error to a trusted pass count; callers get a throw carrying a distinct code.
//
// WHAT THIS DOES NOT PROVE
// ------------------------
// Every agent posts under one shared GitHub account, so a comment carries no
// per-lane authorship to check. The claim window says a run HELD the ticket when
// the comment landed, not that this comment came from that process. Dual now
// requires TWO DISTINCT reviewer-role runs (F1a/F1b), so one run can no longer
// vouch for both lanes and a non-reviewer window (e.g. the PR author's own
// implementer claim) can no longer vouch for a review verdict at all. But a forger
// who can open a reviewer claim window on an idle ticket — one Linear comment on the
// shared token — can still mint the identities the fence trusts. Reviewer
// independence here is therefore only claim-window-deep: the guarantee is "no
// forgery cheaper than the shared-token ceiling," NOT "no forgery."
// Authenticating the poster needs the reserved per-role Ed25519 attestation
// (spec-only, its Phase 2 is a separate governance ticket); verdict-integrity.mjs
// carves the same one out. Head pinning, per-lane dedupe and edit rejection (B7)
// hold regardless of provenance.
//
// A COROLLARY, because provenance is routinely mistaken for the answer to it: what
// separates a reviewer's verdict from an orchestrator recap that reproduces that
// verdict's heading verbatim is NOT provenance. The recap carries the reviewer's real
// `run=`, posted while that reviewer's claim window is open, so provenanceHolds() and
// reviewerWindowBinds() both pass. Provenance answers "did some process hold the ticket
// then", never "is this comment that process's verdict". The only cheap answer to the
// second question is the comment's OWN FIRST NON-BLANK LINE (parseVerdictComment), which
// is why that rule is load-bearing and not cosmetic. A comment whose own opening line is
// a verbatim reviewer heading remains indistinguishable and sits at the shared-token
// ceiling above — unchanged, and the reason the ceiling is named here rather than fixed.
//
// This file matches the `scripts/release-targets*.mjs` controlGlob, so weakening
// it is itself funded-affecting-control -> STRICT dual.

import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// A verdict posted just after its lane released the claim is genuine; the PR
// comment and the Linear release race by seconds in practice. The PR #1794
// forgery landed 36 minutes past release, well outside this.
export const DEFAULT_PROVENANCE_GRACE_MINUTES = 10;

export class VerdictEvidenceError extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.code = code;
    this.detail = detail;
  }
}

// Headers seen in the wild, all of which must parse (or be rejected loudly):
//   ## Review A (lane=reviewer run=6d1b44ed) — PASS — head 5a54c2eb
//   ## Delta Review B (lane=reviewer run=6f45b7a8) — PASS — head abdfa671
//   ## Review A round 2 (lane=reviewer run=bb11eccc) — PASS — head be214a30
//   ## Review B (lane=reviewer run=b1e8cd38) — FAIL — 6ea7456f
//   ## Reviewer B (Adversarial) — Verdict: **PASS**
//   ## Review A — PASS
//   # ZPAY-74 Review A — PASS — head `bf6e04d9…`   (ticket-titled heading, ZPAY-216)
//
// Identity lives on a HEADING LINE or nowhere. A verdict body legitimately quotes
// other heads, other runs and the word FAIL (known-red lists, prior-round history)
// in prose, and none of that may be read as this comment's identity — but the
// heading need not be line 1. ZPAY-74 #1991 posted a titled `#` heading first and
// the canonical `## Review A (lane=… run=…)` heading two lines below it; the
// first-line-only rule dropped a genuine dual PASS SILENTLY (passCount=1), which is
// how lanes learn to reach for --pass-count. See parseVerdictComment.
const VERDICT_HEADER = /^\s*#{1,6}\s*(?:[A-Za-z]{2,8}-\d+\s+)?(?:delta\s+)?review(?:er)?\b/i;
const HEADING_LINE = /^\s*#{1,6}\s/;
const CODE_FENCE = /^\s*(?:```|~~~)/;
const INDENTED = /^(?:\t| {4,})/;
const LANE_LETTER = /\breview(?:er)?\s+([a-z])\b/i;
const RUN_ID = /\brun=([0-9a-z][0-9a-z-]{3,})/i;
const HEAD_LABELLED = /\bhead\b\s*[:=]?\s*`?([0-9a-f]{7,40})`?/i;
const HEAD_BARE = /(?:^|[\s—–\-@`])([0-9a-f]{7,40})\b/i;
const MENTIONS_VERDICT = /\b(?:PASS|FAIL)\b/;
const MENTIONS_REVIEW = /\breview(?:er)?\b/i;
// A non-heading line only counts as an attempted verdict when it OPENS like one (the
// `#` was forgotten, or the heading was quoted). Prose that merely describes a verdict
// header mid-sentence is not a format error, and reporting it would bury the real ones.
const VERDICT_TEXT = /^[\s>*_`#-]*(?:[A-Za-z]{2,8}-\d+\s+)?(?:delta\s+)?review(?:er)?\b/i;

/** Parse ONE candidate heading line into verdict fields. */
function parseVerdictLine(line) {
  const header = line.trim();
  // FAIL wins over PASS when a header somehow carries both: fail closed.
  const plain = header.replace(/\*+/g, "");
  const verdict = /\bFAIL\b/.test(plain) ? "FAIL" : /\bPASS\b/.test(plain) ? "PASS" : null;
  if (!verdict) return null;
  const runId = RUN_ID.exec(header)?.[1]?.toLowerCase() ?? null;
  const lane = LANE_LETTER.exec(header)?.[1]?.toUpperCase() ?? null;
  // Strip the identity parenthetical and any bare lane=/run= tokens before the
  // bare-SHA fallback: `run=6d1b44ed` is itself 8 hex and would otherwise be
  // mistaken for the head the verdict pins.
  const shaSearch = plain.replace(/\([^)]*\)/g, " ").replace(/\b(?:lane|run)=\S+/gi, " ");
  const headSha = (HEAD_LABELLED.exec(shaSearch)?.[1] ?? HEAD_BARE.exec(shaSearch)?.[1] ?? null)?.toLowerCase() ?? null;
  return { lane, verdict, headSha, runId, header };
}

/**
 * Fold the verdict headings of ONE comment into a single candidate.
 *
 * IDENTITY IS THE OPENING LINE. `parsed[0]` is the comment's first non-blank line
 * (parseVerdictComment refuses to parse any comment that does not open with a verdict
 * heading), and it is the only heading that may SUPPLY identity. A later heading may
 * FILL a field the opening line left absent — the ZPAY-74 #1991 shape, a titled heading
 * with no `run=` plus the canonical heading two lines below that carries one — or AGREE
 * with it. Nothing else.
 *
 * A later heading naming a DIFFERENT lane / run / head sets `conflict` (first field
 * wins) and records the offending heading. NO FIELD IS EVER NULLED. Nulling was
 * asymmetric and therefore fail-open: a nulled `headSha` KILLS a FAIL outright (the
 * record never reaches the at-head region, so F5 cannot fire) while merely downgrading a
 * PASS to a rejection. An ordinary round-2 FAIL carrying a round-1 recap heading lost its
 * veto that way. `headShas` lists every SHA any heading named and the head-pin gate tests
 * all of them; any difference between them is a conflict, and deriveVerdictEvidence
 * refuses every conflict INSIDE the at-head region, so `some()` can never mint a PASS —
 * it only ensures a conflicted FAIL is refused loudly instead of dropped silently.
 *
 * `runId` agreement is EXACT, not prefix: an abbreviated `run=aaaa1111` in one heading
 * and the full uuid in another are a conflict. That over-refuses an honest shape by one
 * re-post, which is the affordable direction; prefix-matching would let one heading
 * vouch for another heading's run. Only `headSha` prefix-matches — abbreviated-vs-full
 * head is the shape reviewers actually post — and the longer, more specific SHA wins.
 *
 * `verdict` stays FAIL-wins across all headings. A verdict disagreement is already
 * resolved fail-closed, so it is deliberately NOT a conflict.
 */
function foldVerdictLines(parsed) {
  const [first] = parsed;
  const folded = {
    lane: first.lane,
    verdict: parsed.some((p) => p.verdict === "FAIL") ? "FAIL" : "PASS",
    headSha: first.headSha,
    runId: first.runId,
    header: first.header,
    headings: parsed.length,
    headShas: [...new Set(parsed.map((p) => p.headSha).filter(Boolean))],
    conflict: null,
    conflictHeader: null,
  };
  const FIELDS = [["lane", "lane"], ["runId", "run"], ["headSha", "head"]];
  for (const later of parsed.slice(1)) {
    for (const [field, name] of FIELDS) {
      const value = later[field];
      if (!value) continue;
      if (folded[field] == null) {
        folded[field] = value; // fill-absent: the opening line said nothing about this field
        continue;
      }
      if (folded[field] === value) continue;
      if (field === "headSha" && prefixMatch(folded[field], value)) {
        if (value.length > folded[field].length) folded[field] = value;
        continue;
      }
      if (!folded.conflict) {
        folded.conflict = name;
        folded.conflictHeader = later.header;
      }
    }
  }
  return folded;
}

/**
 * Parse a comment body into a verdict candidate plus, when there is none, WHY.
 *
 * The skip reason is the ZPAY-216 half of the fix: a comment that fails to parse
 * used to vanish, leaving the merger a bare passCount with nothing to act on.
 * `skipReason` is populated only for NEAR MISSES — a comment that visibly tried to
 * be a verdict — so ordinary discussion does not flood the diagnostics.
 *
 * @param {string} body
 * @returns {{candidate: object|null, skipReason: string|null, header: string|null}}
 */
export function parseVerdictComment(body) {
  if (typeof body !== "string") return { candidate: null, skipReason: null, header: null };
  const candidates = [];
  let nearMiss = null;
  // Only the FIRST near miss is reported: one reason per comment is what a lane acts on.
  // ONE exception: VERDICT_HEADING_NOT_FIRST names a real verdict heading this comment
  // carried and the fence refused to count. That outranks a formatting near-miss on an
  // earlier line, because "your verdict was dropped" is what the poster has to act on.
  const miss = (reason, line) => {
    const outranks = reason === "VERDICT_HEADING_NOT_FIRST" && nearMiss?.reason !== reason;
    if (!nearMiss || outranks) nearMiss = { reason, header: line.trim().slice(0, 120) };
  };
  // F-C: IDENTITY LIVES ON THE COMMENT'S FIRST NON-BLANK LINE, and that line must itself
  // parse as a verdict heading. A comment that does not OPEN with one is not a verdict,
  // whatever it contains further down. The attack this refuses is routine, not exotic: an
  // orchestrator recap that reproduces a reviewer's heading verbatim (with or without a
  // line of prose or a `## Reviewer notes …` title above it) is otherwise counted as that
  // reviewer's verdict, and under latest-wins it SUPERSEDES the reviewer's real FAIL.
  // Provenance cannot separate the two — the run is real and its window is open — so this
  // line is the only thing that does. Later headings still MERGE (foldVerdictLines: the
  // ZPAY-74 #1991 titled-heading shape); they simply cannot make a non-verdict a verdict.
  const firstLine = body.split(/\r?\n/).find((line) => line.trim()) ?? "";
  const opensWithVerdict =
    !INDENTED.test(firstLine) &&
    HEADING_LINE.test(firstLine) &&
    VERDICT_HEADER.test(firstLine) &&
    Boolean(parseVerdictLine(firstLine));
  let inFence = false;
  for (const line of body.split(/\r?\n/)) {
    if (CODE_FENCE.test(line)) {
      inFence = !inFence;
      continue;
    }
    const looksLikeVerdict = MENTIONS_REVIEW.test(line) && MENTIONS_VERDICT.test(line.replace(/\*+/g, ""));
    if (inFence) {
      if (looksLikeVerdict && HEADING_LINE.test(line)) miss("VERDICT_HEADING_IN_CODE_FENCE", line);
      continue;
    }
    // B9: four-plus leading spaces or a tab make the line a Markdown code block, not a
    // heading. Check the indentation BEFORE trimming — an indented `    ## Review A —
    // PASS` is not a heading, and the indentation is invisible after a trim.
    if (INDENTED.test(line)) {
      if (looksLikeVerdict) miss("VERDICT_HEADING_INDENTED", line);
      continue;
    }
    if (!HEADING_LINE.test(line)) {
      // `> ## Review A — PASS` (quoted) also lands here: the first non-space char is
      // not `#`, so it is not this comment's own heading.
      if (looksLikeVerdict && VERDICT_TEXT.test(line)) miss("VERDICT_NOT_A_HEADING", line);
      continue;
    }
    if (!VERDICT_HEADER.test(line)) {
      // e.g. `## Orchestrator notice — the Review A FAIL above is VOID`.
      if (looksLikeVerdict) miss("HEADING_DOES_NOT_START_WITH_REVIEW", line);
      continue;
    }
    const parsed = parseVerdictLine(line);
    if (!parsed) {
      miss("VERDICT_HEADING_WITHOUT_PASS_OR_FAIL", line);
      continue;
    }
    if (!opensWithVerdict) {
      // A genuine verdict heading in a comment that does not open with one: a recap, a
      // quote or a summary — never this comment's own verdict. Loudly skipped, so the
      // poster can repost it as its own comment instead of it silently vanishing.
      miss("VERDICT_HEADING_NOT_FIRST", line);
      continue;
    }
    candidates.push(parsed);
  }
  if (candidates.length === 0) {
    return { candidate: null, skipReason: nearMiss?.reason ?? null, header: nearMiss?.header ?? null };
  }
  const candidate = foldVerdictLines(candidates);
  return { candidate, skipReason: null, header: candidate.header };
}

/**
 * Back-compatible view: the verdict candidate, or null when the comment carries none.
 *
 * @param {string} body
 * @returns {{lane: string|null, verdict: "PASS"|"FAIL", headSha: string|null, runId: string|null, header: string}|null}
 */
export function parseVerdictHeader(body) {
  return parseVerdictComment(body).candidate;
}

// Headers abbreviate SHAs (`head 5a54c2eb`) while --head is full-length, and
// claim windows record full uuids while headers abbreviate them (`run=73ae4faa`).
// Both are the same prefix relation, in either direction.
function prefixMatch(a, b, min = 7) {
  if (!a || !b) return false;
  const x = String(a).toLowerCase();
  const y = String(b).toLowerCase();
  if (x.length < min || y.length < min) return false;
  return x.startsWith(y) || y.startsWith(x);
}

/**
 * Is `at` inside a claim window belonging to `runId`?
 * An open window (never released) extends to now.
 */
export function provenanceHolds({ runId, at, windows, graceMinutes = DEFAULT_PROVENANCE_GRACE_MINUTES }) {
  if (!runId) return { held: false, reason: "NO_RUN_ID_IN_HEADER" };
  // B8: an 8-hex run prefix is ~32 bits; the old 4-hex floor (~16 bits) let a short
  // prefix collide with several windows (any match won). Headers already emit 8 hex.
  const matching = windows.filter((window) => prefixMatch(window.run, runId, 8));
  if (matching.length === 0) return { held: false, reason: "NO_CLAIM_WINDOW_FOR_RUN" };
  const stamp = Date.parse(at);
  if (!Number.isFinite(stamp)) return { held: false, reason: "UNPARSABLE_COMMENT_TIMESTAMP" };
  const grace = graceMinutes * 60_000;
  for (const window of matching) {
    const start = Date.parse(window.start);
    if (!Number.isFinite(start) || stamp < start) continue;
    const end = window.end == null ? Number.POSITIVE_INFINITY : Date.parse(window.end) + grace;
    if (stamp <= end) return { held: true, window };
  }
  return { held: false, reason: "POSTED_OUTSIDE_CLAIM_WINDOW" };
}

// A header with no lane letter collapses into ONE pseudo-lane. F6 no longer counts
// it at all: the fence cannot tell two unlabelled verdicts apart, and an ordinary
// recap ("## Review of the sweep logic — … PASS") parses as one. An honest dual
// pair that lands unlabelled undercounts and refuses; the merger's --pass-count
// override covers that, and leaves an AUDIT line behind.
const UNLABELLED_LANE = "?";

// Dual review is exactly two opposed lenses, A and B. Any other letter — or none —
// cannot contribute to the opposed pair (F6).
const RECOGNISED_LANES = new Set(["A", "B"]);

// A claim window may vouch for a review verdict only when it is a REVIEWER-role
// window (F1a). `reviewer-A` / `reviewer-B` are the per-lens sub-lanes; a letter-less
// `reviewer` window is the legacy single-reviewer claim and binds by run alone.
const REVIEWER_WINDOW_LANE = /^reviewer(?:-([ab]))?$/i;

/**
 * F1a: does `window` legitimately vouch for a verdict on lane `headerLane`? The
 * window must be a reviewer-role claim, and when it names a lane letter that letter
 * must equal the header's. A non-reviewer window (the author's own implementer
 * claim) never vouches — that is the self-approval bypass.
 */
function reviewerWindowBinds(window, headerLane) {
  const m = REVIEWER_WINDOW_LANE.exec(window?.lane ?? "");
  if (!m) return { ok: false, reason: "WINDOW_LANE_NOT_REVIEWER" };
  const windowLetter = m[1] ? m[1].toUpperCase() : null;
  if (windowLetter && windowLetter !== headerLane) {
    return { ok: false, reason: "WINDOW_LANE_LETTER_MISMATCH" };
  }
  return { ok: true };
}

/**
 * Derive the effective pass count for `head` from PR comments.
 *
 * @param {object} opts
 * @param {Array<{body: string, createdAt: string, edited?: boolean}>} opts.comments
 * @param {string} opts.head                      full head SHA under review
 * @param {Array<object>|null} [opts.claimWindows] null = provenance not checked
 * @param {number} [opts.graceMinutes]
 * @returns {{passCount: number, passLanes: string[], failLanes: string[], provenanceChecked: boolean,
 *            counted: object[], rejected: object[], skipped: object[],
 *            unprovenFailsAtHead: object[], staleHeads: string[]}}
 */
export function deriveVerdictEvidence({ comments, head, claimWindows = null, graceMinutes } = {}) {
  if (!head) {
    throw new VerdictEvidenceError("INVALID_ARGUMENT", "deriveVerdictEvidence requires head");
  }
  const provenanceChecked = Array.isArray(claimWindows);
  const counted = [];
  const rejected = [];
  const unprovenFailsAtHead = [];
  // ZPAY-216: comments that TRIED to be a verdict and could not be parsed. A bare
  // passCount with a silently-dropped verdict behind it is what teaches lanes to
  // reach for --pass-count; naming the offending comment and the format error lets
  // the reviewer repost instead.
  const skipped = [];

  // A rejection PAST the head-pin check: the verdict really is at the reviewed head,
  // it just could not be trusted. A FAIL here must not vanish (F5) — it blocks for
  // human adjudication, never silently drops (which is fail-OPEN for a veto).
  const rejectAtHead = (record, reason, extra = {}) => {
    const entry = { ...record, reason, ...extra };
    rejected.push(entry);
    if (record.verdict === "FAIL") unprovenFailsAtHead.push(entry);
  };

  for (const comment of comments ?? []) {
    const { candidate: parsed, skipReason, header } = parseVerdictComment(comment.body);
    if (!parsed) {
      if (skipReason) skipped.push({ at: comment.createdAt, reason: skipReason, header });
      continue;
    }
    const record = {
      lane: parsed.lane ?? UNLABELLED_LANE,
      verdict: parsed.verdict,
      headSha: parsed.headSha,
      runId: parsed.runId,
      at: comment.createdAt,
    };
    if (!parsed.headSha) {
      // NO heading in the comment named a head, so it is not pinned to this one.
      rejected.push({ ...record, reason: "VERDICT_HEAD_UNPINNED" });
      continue;
    }
    // Every SHA any heading named. A conflicted candidate is always refused below, so
    // `some()` cannot make a comment count; it exists so a comment that DID pin this head
    // in one heading enters the at-head region and its FAIL reaches F5 instead of being
    // dropped by an ambiguous fold. Two AGREEING stale headings still fail here.
    if (!(parsed.headShas ?? [parsed.headSha]).some((sha) => prefixMatch(sha, head))) {
      rejected.push({ ...record, reason: "VERDICT_STALE_HEAD" });
      continue;
    }
    // --- past here every rejection is a FAIL-blocking one at the reviewed head ---
    // Headings inside one comment that disagree on lane / run / head: the comment is at
    // the reviewed head but says two things about who reviewed what. Refuse it here, in
    // the FAIL-blocking region, so a FAIL cannot be erased by a fold ambiguity (the
    // round-1-recap-heading shape) — human adjudication, never a silent drop.
    if (parsed.conflict) {
      rejectAtHead(record, "VERDICT_HEADINGS_CONFLICT", {
        conflictField: parsed.conflict,
        conflictHeader: parsed.conflictHeader,
      });
      continue;
    }
    // B7: a verdict whose comment was edited after posting cannot be trusted — the
    // checked createdAt belongs to the ORIGINAL text, which may have said FAIL, or
    // pinned a stale head, before the edit rewrote it to a clean PASS at this head.
    if (comment.edited) {
      rejectAtHead(record, "VERDICT_EDITED");
      continue;
    }
    // F6: only a recognised A/B reviewer lane counts. An unlabelled (`?`) or
    // unknown-letter header can never join the opposed pair.
    if (!RECOGNISED_LANES.has(record.lane)) {
      rejectAtHead(record, "UNLABELLED_OR_UNKNOWN_LANE");
      continue;
    }
    if (provenanceChecked) {
      const provenance = provenanceHolds({
        runId: parsed.runId,
        at: comment.createdAt,
        windows: claimWindows,
        graceMinutes,
      });
      if (!provenance.held) {
        rejectAtHead(record, "VERDICT_PROVENANCE_UNPROVEN", { provenanceReason: provenance.reason });
        continue;
      }
      const laneBind = reviewerWindowBinds(provenance.window, record.lane);
      if (!laneBind.ok) {
        rejectAtHead(record, laneBind.reason);
        continue;
      }
      // The identity that counts for distinct-run dual (F1b) is the VERIFIED window
      // run, not the self-asserted header run.
      record.run = provenance.window.run;
    }
    counted.push(record);
  }

  // One effective verdict per lane letter: the latest at this head. A lane that
  // FAILs and then re-reviews the SAME head to PASS supersedes its own FAIL; a lane
  // that PASSes and then FAILs likewise vetoes. Ties on timestamp fall back to
  // document order, which gh returns oldest-first.
  const byLane = new Map();
  counted.forEach((record, index) => {
    const previous = byLane.get(record.lane);
    const rank = [Date.parse(record.at) || 0, index];
    // Without provenance, NOTHING may CLEAR a FAIL: an unproven PASS cannot vouch for the
    // lane that failed, so a later same-lane non-FAIL does not supersede a standing FAIL
    // at this head. (With provenance checked, supersession is genuine re-review and
    // stays.) Only ever adds a refusal — the degraded mode must never lose a veto.
    if (previous && !provenanceChecked && previous.record.verdict === "FAIL" && record.verdict !== "FAIL") return;
    if (!previous || rank[0] > previous.rank[0] || (rank[0] === previous.rank[0] && rank[1] > previous.rank[1])) {
      byLane.set(record.lane, { record, rank });
    }
  });

  const effective = [...byLane.values()].map((entry) => entry.record);
  const passRecords = effective.filter((r) => r.verdict === "PASS");
  const passLanes = passRecords.map((r) => r.lane).sort();
  const failLanes = effective.filter((r) => r.verdict === "FAIL").map((r) => r.lane).sort();
  const staleHeads = [...new Set(rejected.filter((r) => r.reason === "VERDICT_STALE_HEAD").map((r) => r.headSha))].sort();

  // F1b: dual means two INDEPENDENT reviewer identities, not two lane letters. With
  // provenance checked, count DISTINCT verified runs among the passing lanes — two
  // PASSes sharing one run (one run vouching for both A and B) count as ONE, so a
  // single reviewer run can no longer clear the gate. Unchecked (non-strict, or no
  // claim trail) there is nothing to distinguish runs by, so fall back to distinct
  // lanes; the strict CLI path refuses an unchecked count outright (F3).
  const passCount = provenanceChecked
    ? new Set(passRecords.map((r) => r.run)).size
    : new Set(passLanes).size;

  return {
    passCount,
    passLanes,
    failLanes,
    provenanceChecked,
    counted: effective,
    rejected,
    skipped,
    unprovenFailsAtHead,
    staleHeads,
  };
}

// --------------------------------------------------------------------------
// I/O seams. Both fail closed: a throw, never a degraded-but-usable answer.
// --------------------------------------------------------------------------

function run(command, args, { repoRoot, code, what }) {
  try {
    return execFileSync(command, args, {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (error) {
    throw new VerdictEvidenceError(code, `${what} failed: ${error.stderr?.toString().trim() || error.message}`, {
      command: `${command} ${args.join(" ")}`,
    });
  }
}

const TICKET_ID = /\b(ZTR|ZUP|ZPAY)-(\d+)\b/i;

/**
 * PR verdict surface: issue comments and submitted reviews, oldest-first, plus
 * the ticket id the PR names (title, then body, then branch).
 */
export function fetchPrEvidence({ pr, repoRoot = REPO_ROOT } = {}) {
  if (!pr) throw new VerdictEvidenceError("INVALID_ARGUMENT", "fetchPrEvidence requires pr");
  // B1: headRefOid is the PR's REAL head; --head is hand-typed and, after merger.md
  // stopped the merger counting PASSes by eye, nothing compared them. B7:
  // includesCreatedEdit flags a comment edited after posting, and gh already returns it.
  const raw = run("gh", ["pr", "view", String(pr), "--json", "comments,reviews,title,body,headRefName,headRefOid"], {
    repoRoot,
    code: "VERDICT_EVIDENCE_UNAVAILABLE",
    what: `gh pr view ${pr}`,
  });
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (error) {
    throw new VerdictEvidenceError("VERDICT_EVIDENCE_UNAVAILABLE", `gh pr view ${pr} returned unparsable JSON: ${error.message}`);
  }
  const comments = [
    ...(payload.comments ?? []).map((c) => ({ body: c.body, createdAt: c.createdAt, edited: Boolean(c.includesCreatedEdit) })),
    ...(payload.reviews ?? []).map((r) => ({ body: r.body, createdAt: r.submittedAt, edited: Boolean(r.includesCreatedEdit) })),
  ].sort((a, b) => (Date.parse(a.createdAt) || 0) - (Date.parse(b.createdAt) || 0));

  const found = TICKET_ID.exec(payload.title ?? "") ?? TICKET_ID.exec(payload.body ?? "") ?? TICKET_ID.exec(payload.headRefName ?? "");
  const ticket = found ? `${found[1].toUpperCase()}-${found[2]}` : null;
  return { comments, ticket, headRefOid: payload.headRefOid ?? null };
}

/**
 * Claim windows recorded on the Linear ticket, via claim.py — the one component
 * that already owns claim/release marker semantics (races, takeovers, run-less
 * legacy markers). Reimplementing that here would fork the rule.
 */
export function fetchClaimWindows({ ticket, repoRoot = REPO_ROOT } = {}) {
  if (!ticket) throw new VerdictEvidenceError("INVALID_ARGUMENT", "fetchClaimWindows requires ticket");
  const raw = run("python3", ["scripts/claim.py", "windows", ticket], {
    repoRoot,
    code: "CLAIM_WINDOWS_UNAVAILABLE",
    what: `claim.py windows ${ticket}`,
  });
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed.windows)) throw new Error("no windows array");
    return parsed.windows;
  } catch (error) {
    throw new VerdictEvidenceError("CLAIM_WINDOWS_UNAVAILABLE", `claim.py windows ${ticket} returned unusable output: ${error.message}`);
  }
}

/**
 * Full evidence path used by the fence: fetch, resolve the ticket, cross-check
 * provenance, derive the count.
 *
 * `ticket` may be supplied to override PR-derived resolution. When no ticket can
 * be resolved at all the provenance cross-check is SKIPPED and reported as
 * `provenanceChecked: false` — head pinning and per-lane dedupe still apply. The
 * caller's `--head` is checked against the PR's real `headRefOid` (B1) and the
 * mismatch surfaced as `headMatchesPrHead: false`, which the strict fence refuses.
 *
 * NOTHING IS SKIPPED IN ADVANCE. Every evidence source is attempted on every run; a
 * source may only be DOWNGRADED after it has actually failed. `checkProvenance: false`
 * used to skip the Linear read pre-emptively whenever dual was not required, and that
 * dropped the F5 veto: a FAIL that provenance would have routed into
 * `unprovenFailsAtHead` was instead COUNTED, where a later unauthenticated same-lane PASS
 * superseded it. Skipping a check must only ever ADD refusals.
 *
 * `provenanceOptional: true` therefore does not skip the read — it only allows a
 * CLAIM_WINDOWS_UNAVAILABLE failure to degrade to `provenanceChecked: false` instead of
 * aborting the gate (the ZPAY-216 defect-2 case: a Linear outage must not exit 2 a gate
 * that never needed a verdict). Every other error still throws. `provenanceError` names
 * why the trail was unreadable.
 *
 * CONDITIONAL, and the condition is F3 — say it plainly rather than claim the degraded
 * mode is unconditionally more refusing. It is not: unchecked mode skips the
 * `if (provenanceChecked)` block, so a PASS that would have been rejected
 * VERDICT_PROVENANCE_UNPROVEN / WINDOW_LANE_NOT_REVIEWER is counted, and `passCount`
 * falls back to distinct LANES instead of distinct verified RUNS, losing F1b. Both are
 * fail-open in the PASS direction. They are harmless ONLY because the degraded path is
 * reachable exclusively when dual is not required — where `passCount` cannot move the
 * disposition — and because `applyVerdictEvidence`'s F3 refuses
 * (`dualRequired && !provenanceChecked`) on every other route to `claimWindows === null`,
 * including an unresolvable ticket. F3 is the backstop for the single `!` at the call
 * site; if that call site ever passes `provenanceOptional` on a dual-required path, F3
 * refuses rather than the gate softening. On the FAIL side the degradation genuinely
 * refuses more: the FAIL is counted into `failLanes` (VERDICT_FAIL_AT_HEAD, same
 * REFUSE_MERGE), and deriveVerdictEvidence makes it non-supersedable.
 */
export function collectVerdictEvidence({ pr, head, ticket, repoRoot = REPO_ROOT, graceMinutes, provenanceOptional = false } = {}) {
  const { comments, ticket: derivedTicket, headRefOid } = fetchPrEvidence({ pr, repoRoot });
  const resolvedTicket = ticket ?? derivedTicket;
  let claimWindows = null;
  let provenanceError = null;
  if (resolvedTicket) {
    try {
      claimWindows = fetchClaimWindows({ ticket: resolvedTicket, repoRoot });
    } catch (error) {
      if (!(provenanceOptional && error.code === "CLAIM_WINDOWS_UNAVAILABLE")) throw error;
      provenanceError = error.message;
    }
  }
  const evidence = deriveVerdictEvidence({ comments, head, claimWindows, graceMinutes });
  // B1: a verdict counts only when `--head` IS the PR's head. Otherwise the whole
  // count is against a head the PR is not at (AC2's stale-head class, one layer out).
  const headMatchesPrHead = prefixMatch(headRefOid, head);
  return { pr: Number(pr), ticket: resolvedTicket, headRefOid, headMatchesPrHead, provenanceError, ...evidence };
}
