// STRICT dual-review machine fence tests.
// Proves: single PASS refused when mrr/moneyPathHit; dual PASS ok; fence path itself is strict.
// Also registry provenance: a range verdict follows the registry at --head, never the caller's checkout.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { classifyPaths, classifyRange, resolveRegistry } from "./release-targets.mjs";
import {
  applyVerdictEvidence,
  dualReviewRequired,
  evaluateStrictDualForDiff,
  evaluateStrictDualForPaths,
  evaluateStrictDualGate,
} from "./release-targets-strict-dual.mjs";
import {
  deriveVerdictEvidence,
  parseVerdictHeader,
  provenanceHolds,
} from "./release-targets-verdict-evidence.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("dualReviewRequired is true when either axis trips", () => {
  assert.equal(dualReviewRequired({ manualReviewRequired: false, moneyPathHit: false }), false);
  assert.equal(dualReviewRequired({ manualReviewRequired: true, moneyPathHit: false }), true);
  assert.equal(dualReviewRequired({ manualReviewRequired: false, moneyPathHit: true }), true);
  assert.equal(dualReviewRequired({ manualReviewRequired: true, moneyPathHit: true }), true);
});

test("evaluateStrictDualGate: single PASS refused when dual required", () => {
  const refused = evaluateStrictDualGate({
    manualReviewRequired: true,
    moneyPathHit: false,
    passCount: 1,
  });
  assert.equal(refused.disposition, "REFUSE_MERGE");
  assert.equal(refused.reasonCode, "STRICT_DUAL_INSUFFICIENT");
  assert.equal(refused.dualRequired, true);
  assert.equal(refused.dualSatisfied, false);

  const moneyRefused = evaluateStrictDualGate({
    manualReviewRequired: false,
    moneyPathHit: true,
    passCount: 1,
  });
  assert.equal(moneyRefused.disposition, "REFUSE_MERGE");
});

test("evaluateStrictDualGate: dual PASS satisfies; dual not required is OK at any passCount", () => {
  const dualOk = evaluateStrictDualGate({
    manualReviewRequired: true,
    moneyPathHit: false,
    passCount: 2,
  });
  assert.equal(dualOk.disposition, "OK");
  assert.equal(dualOk.reasonCode, "DUAL_SATISFIED");
  assert.equal(dualOk.dualSatisfied, true);

  const ordinary = evaluateStrictDualGate({
    manualReviewRequired: false,
    moneyPathHit: false,
    passCount: 1,
  });
  assert.equal(ordinary.disposition, "OK");
  assert.equal(ordinary.reasonCode, "DUAL_NOT_REQUIRED");
  assert.equal(ordinary.dualRequired, false);

  // Zero PASSes still OK on the dual-gate axis when dual is not required —
  // other merger checks own the "need a PASS" rule.
  const noPassOrdinary = evaluateStrictDualGate({
    manualReviewRequired: false,
    moneyPathHit: false,
    passCount: 0,
  });
  assert.equal(noPassOrdinary.disposition, "OK");
  assert.equal(noPassOrdinary.reasonCode, "DUAL_NOT_REQUIRED");
});

test("D1: machine fence path itself is funded-affecting-control (cannot be stripped under benign)", () => {
  // The dual-review rule lives here, under scripts/release-targets*.mjs.
  // Weakening it is STRICT, not a single-PASS governance edit.
  for (const path of [
    "scripts/release-targets-strict-dual.mjs",
    "scripts/release-targets-strict-dual.test.mjs",
    "scripts/release-targets.mjs",
    // Both halves of the verdict-evidence path are load-bearing for the
    // gate, so both are STRICT. claim.py owns the claim windows the forgery check
    // reads — left benign, a single-PASS edit widening a window would quietly
    // disarm provenance while this file kept passing its own tests.
    "scripts/release-targets-verdict-evidence.mjs",
    "scripts/claim.py",
    "scripts/claim.test.py",
  ]) {
    const result = classifyPaths([path]);
    assert.equal(result.manualReviewRequired, true, `expected strict: ${path}`);
    assert.deepEqual(result.affectedTargets, []);
    assert.deepEqual(result.controlPaths, [path]);
  }
  // Agent prose alone remains benign-governance — that is intentional; the machine
  // fence above is the enforcement, so deleting prose without touching the fence
  // does not open the dual gate.
  for (const path of [".claude/agents/merger.md", ".claude/agents/reviewer.md"]) {
    const result = classifyPaths([path]);
    assert.equal(result.manualReviewRequired, false, `prose stays benign: ${path}`);
  }
});

test("evaluateStrictDualForPaths: benign governance single PASS ok; release control refuses", () => {
  const benign = evaluateStrictDualForPaths(["docs/DECISIONS.md", "CLAUDE.md"], { passCount: 1 });
  assert.equal(benign.disposition, "OK");
  assert.equal(benign.dualRequired, false);
  assert.equal(benign.classification.manualReviewRequired, false);
  assert.equal(benign.moneyPath.moneyPathHit, false);

  const fundedControl = evaluateStrictDualForPaths(["release/targets.v1.json"], { passCount: 1 });
  assert.equal(fundedControl.disposition, "REFUSE_MERGE");
  assert.equal(fundedControl.dualRequired, true);
  assert.equal(fundedControl.classification.manualReviewRequired, true);

  const fundedControlDual = evaluateStrictDualForPaths(["release/targets.v1.json"], {
    passCount: 2,
  });
  assert.equal(fundedControlDual.disposition, "OK");
  assert.equal(fundedControlDual.reasonCode, "DUAL_SATISFIED");
});

test("evaluateStrictDualForPaths: decision-check scripts are STRICT", () => {
  for (const path of [
    "scripts/build-decisions.mjs",
    "scripts/check-decision-ids.sh",
    "scripts/check-decision-citations.sh",
    "scripts/check-decision-pins.sh",
    "scripts/check-decision-pins.py",
  ]) {
    const single = evaluateStrictDualForPaths([path], { passCount: 1 });
    assert.equal(single.disposition, "REFUSE_MERGE", path);
    assert.equal(single.classification.manualReviewRequired, true, path);
    assert.equal(single.moneyPath.moneyPathHit, false, path);
  }
});

// ---------------------------------------------------------------------------
// Registry provenance: the verdict follows --head, not the checkout
// ---------------------------------------------------------------------------
// The 2026-07-26 incident shape: a tree parked one commit behind the registry edit that
// classified the changed paths (81e1764f7 added packages/merchant-adapter/** to
// generic-node.classificationGlobs). The gate read the OLD registry against the NEW SHAs,
// emitted exit 2 UNCLASSIFIED_PATH, wrongly refused PR #1385 and produced two false
// gate-bypass findings. The fixture below is that shape, built synthetically so it stays
// a live regression guard independent of what the real registry happens to contain.

const FIXTURE_GLOB = "packages/ztr808-fixture/**";
const FIXTURE_PATH = "packages/ztr808-fixture/src/index.ts";
const UNOWNED_PATH = "unowned/ztr808.bin";

function makeStaleTreeRepo() {
  const dir = mkdtempSync(join(tmpdir(), "ztr808-"));
  const git = (...args) =>
    execFileSync("git", args, { cwd: dir, stdio: ["ignore", "pipe", "pipe"] }).toString("utf8").trim();
  git("init", "-q", "-b", "main");
  git("config", "user.email", "ztr808@example.invalid");
  git("config", "user.name", "ZTR-808 fixture");
  mkdirSync(join(dir, "release"), { recursive: true });
  cpSync(join(REPO_ROOT, "release/targets.schema.json"), join(dir, "release/targets.schema.json"));

  const registryFile = join(dir, "release/targets.v1.json");
  const current = JSON.parse(readFileSync(join(REPO_ROOT, "release/targets.v1.json"), "utf8"));
  const classifying = structuredClone(current);
  classifying.targets.find((target) => target.id === "generic-node").classificationGlobs.push(FIXTURE_GLOB);
  const commit = (registry, message) => {
    writeFileSync(registryFile, `${JSON.stringify(registry, null, 2)}\n`, "utf8");
    git("add", "-A");
    git("commit", "-qm", message);
    return git("rev-parse", "HEAD");
  };

  // C0: the STALE registry — does not know FIXTURE_GLOB. This is what stays on disk.
  const staleCommit = commit(current, "registry without the fixture glob");
  // C1 (base): the registry gains the glob, exactly as 81e1764f7 did.
  const base = commit(classifying, "registry classifies the fixture package");
  // C2 (head): the classified source path appears. The registry is NOT in this diff, so
  // only the ref used to READ the registry can decide the verdict.
  mkdirSync(join(dir, "packages/ztr808-fixture/src"), { recursive: true });
  writeFileSync(join(dir, FIXTURE_PATH), "export const fixture = 1;\n", "utf8");
  const head = commit(classifying, "add the classified source path");
  // C3: a genuinely unclassified path, for the AC4 provenance-in-the-refusal check.
  mkdirSync(join(dir, "unowned"), { recursive: true });
  writeFileSync(join(dir, UNOWNED_PATH), "binary-ish\n", "utf8");
  const unownedHead = commit(classifying, "add an unclassified path");

  // money-path-scan's committed-registry liveness read needs origin/main to exist.
  git("update-ref", "refs/remotes/origin/main", unownedHead);
  // Park the WORKTREE on the stale registry — the defect's precondition.
  git("checkout", "-q", "--detach", staleCommit);
  assert.equal(git("status", "--porcelain"), "", "fixture worktree must be clean");

  return {
    dir,
    base,
    head,
    unownedHead,
    staleRegistry: current,
    staleBlob: git("rev-parse", `${staleCommit}:release/targets.v1.json`),
    headBlob: git("rev-parse", `${head}:release/targets.v1.json`),
  };
}

test("registry provenance: classifyRange reads the registry at --head, not the stale worktree", () => {
  const fixture = makeStaleTreeRepo();
  try {
    // The fixture really is the defect vector: under the checked-out (stale) registry the
    // changed path is unclassifiable, which is what produced the false refusal.
    assert.notEqual(fixture.staleBlob, fixture.headBlob);
    assert.throws(
      () => classifyPaths([FIXTURE_PATH], fixture.staleRegistry),
      (error) => error.code === "UNCLASSIFIED_PATH",
      "stale registry must not classify the fixture path",
    );

    const result = classifyRange({ base: fixture.base, head: fixture.head, repoRoot: fixture.dir });
    // Only the affected IDs matter here; the target's own deploy fields are the
    // registry's business and must not make this provenance test brittle.
    assert.deepEqual(
      result.affectedTargets.map((target) => target.id),
      ["generic-node"],
      "verdict must follow the registry at --head",
    );
    // AC2: provenance names the exact blob, so any cited result is reproducible.
    assert.equal(result.registry.source, "ref");
    assert.equal(result.registry.ref, fixture.head);
    assert.equal(result.registry.blobSha, fixture.headBlob);
    // AC3: the stale checkout is reported, not silently used.
    assert.equal(result.registry.worktreeDiverged, true);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("registry provenance: strict-dual fence inherits the head-pinned registry", () => {
  const fixture = makeStaleTreeRepo();
  try {
    const result = evaluateStrictDualForDiff({
      base: fixture.base,
      head: fixture.head,
      passCount: 1,
      repoRoot: fixture.dir,
    });
    // Before the fix this run was exit 2 UNCLASSIFIED_PATH from the same stale worktree.
    assert.equal(result.classification.manualReviewRequired, false);
    assert.deepEqual(result.classification.affectedTargets.map((target) => target.id), ["generic-node"]);
    assert.equal(result.moneyPath.failClosed, false, "clean fixture tree must not fail closed");
    assert.equal(result.moneyPath.moneyPathHit, false);
    assert.equal(result.disposition, "OK");
    assert.equal(result.reasonCode, "DUAL_NOT_REQUIRED");
    assert.equal(result.registry.blobSha, fixture.headBlob);
    assert.equal(result.registry.worktreeDiverged, true);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("AC4: UNCLASSIFIED_PATH names the registry it used", () => {
  const fixture = makeStaleTreeRepo();
  try {
    assert.throws(
      () => classifyRange({ base: fixture.head, head: fixture.unownedHead, repoRoot: fixture.dir }),
      (error) => {
        assert.equal(error.code, "UNCLASSIFIED_PATH");
        assert.deepEqual(error.details.paths, [UNOWNED_PATH]);
        assert.equal(error.details.registry.source, "ref");
        assert.equal(error.details.registry.ref, fixture.unownedHead);
        assert.match(error.details.registry.blobSha, /^[0-9a-f]{40}$/);
        return true;
      },
    );
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("AC3: an unresolvable ref fails loudly, never falls back to the worktree", () => {
  assert.throws(
    () => resolveRegistry({ ref: "0000000000000000000000000000000000000000" }),
    (error) => error.code === "REGISTRY_REF_UNRESOLVED",
  );
  assert.throws(
    () => classifyRange({ base: "HEAD", head: "refs/ztr808/definitely-not-a-ref" }),
    (error) => error.code === "REGISTRY_REF_UNRESOLVED",
  );
  // Ref-less callers still get the worktree, and the output says so rather than
  // implying a pinned revision.
  const worktree = resolveRegistry();
  assert.equal(worktree.provenance.source, "worktree");
  assert.equal(worktree.provenance.ref, null);
  assert.equal(worktree.provenance.worktreeDiverged, false);
  // An injected registry object has no revision — it must not claim one.
  assert.equal(classifyPaths(["CLAUDE.md"], worktree.registry).registry.source, "provided");
});

// ---------------------------------------------------------------------------
// Verdict provenance: the pass count is DERIVED from head-pinned, provenance-checked
// verdict evidence — never taken on the caller's word.
// ---------------------------------------------------------------------------

const HEAD = "abcdef1234567890abcdef1234567890abcdef12";
const OLD_HEAD = "1111111222222223333333344444444555555556";

// The honest dual is TWO INDEPENDENT reviewer runs — reviewer-A and
// reviewer-B, each with its own claim window and run. Distinct runs are what make
// two PASSes count as two (F1b); ONE run vouching for both letters is DUAL_SINGLE_RUN.
const RUN_A = "73ae4faa-0148-49e4-b03b-d8f00241ce8e"; // the real PR #1794 reviewer run
const RUN_B = "5c9d1e2f-77aa-4bb0-9c31-0d2e4a6b8f10";
const DUAL_WINDOWS = [
  { lane: "reviewer-A", run: RUN_A, start: "2026-08-01T13:42:31.416Z", end: "2026-08-01T14:43:53.396Z" },
  { lane: "reviewer-B", run: RUN_B, start: "2026-08-01T13:44:00.000Z", end: "2026-08-01T14:50:00.000Z" },
];
// The legacy single-reviewer window: one `reviewer` claim, one run, no A/B letter.
// It satisfies F1a (reviewer role) but, being ONE run, only ever counts as one.
const REVIEWER_RUN = RUN_A;
const REVIEWER_WINDOW = [
  { lane: "reviewer", run: REVIEWER_RUN, start: "2026-08-01T13:42:31.416Z", end: "2026-08-01T14:43:53.396Z" },
];

const comment = (body, createdAt, edited = false) => ({ body, createdAt, edited });
// The header lane letter ("Review A") is what parseVerdictHeader reads; the run is
// matched against a claim window. run defaults per-lane to that lane's dual window.
const RUN_FOR = { A: RUN_A, B: RUN_B };
const verdict = (lane, outcome, head, at, run = RUN_FOR[lane]) =>
  comment(`## Review ${lane} (lane=reviewer-${lane} run=${run.slice(0, 8)}) — ${outcome} — head ${head.slice(0, 8)}\n\nbody prose`, at);

test("dual-at-head: two INDEPENDENT reviewer runs pinned to the exact head satisfy dual", () => {
  const evidence = deriveVerdictEvidence({
    comments: [
      verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z"),
      verdict("B", "PASS", HEAD, "2026-08-01T14:41:04Z"),
    ],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.equal(evidence.passCount, 2);
  assert.deepEqual(evidence.passLanes, ["A", "B"]);
  assert.deepEqual(evidence.failLanes, []);
  assert.equal(evidence.provenanceChecked, true);
  assert.deepEqual(evidence.rejected, []);

  const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: evidence.passCount });
  const final = applyVerdictEvidence(gate, evidence);
  assert.equal(final.disposition, "OK");
  assert.equal(final.passCountSource, "verdict-evidence");
});

test("F1b: two reviewer LETTERS under ONE run is DUAL_SINGLE_RUN, not dual", () => {
  const evidence = deriveVerdictEvidence({
    comments: [
      verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z", REVIEWER_RUN),
      verdict("B", "PASS", HEAD, "2026-08-01T14:41:04Z", REVIEWER_RUN), // SAME run
    ],
    head: HEAD,
    claimWindows: REVIEWER_WINDOW,
  });
  // The whole F1 defect: one run vouching for both lanes used to read as dual. It is
  // one identity, so it counts as one — the interim single-run-dispatch case.
  assert.equal(evidence.passCount, 1);
  assert.deepEqual(evidence.passLanes, ["A", "B"]);

  const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: evidence.passCount });
  const final = applyVerdictEvidence(gate, evidence);
  assert.equal(final.disposition, "REFUSE_MERGE");
  assert.equal(final.reasonCode, "DUAL_SINGLE_RUN", "distinct code: merger reads both comments, uses the audited override");
});

test("F1a: a NON-reviewer (implementer) window cannot vouch for a review verdict — self-approval", () => {
  const IMPL_RUN = "9a9a9a9a-1111-4222-8333-444455556666";
  const implWindow = [{ lane: "implementer", run: IMPL_RUN, start: "2026-08-01T13:00:00Z", end: "2026-08-01T16:00:00Z" }];
  const evidence = deriveVerdictEvidence({
    comments: [
      verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z", IMPL_RUN), // author posts both under their own impl run
      verdict("B", "PASS", HEAD, "2026-08-01T14:41:04Z", IMPL_RUN),
    ],
    head: HEAD,
    claimWindows: implWindow,
  });
  assert.equal(evidence.passCount, 0);
  assert.deepEqual(evidence.passLanes, []);
  assert.deepEqual(evidence.rejected.map((e) => e.reason), ["WINDOW_LANE_NOT_REVIEWER", "WINDOW_LANE_NOT_REVIEWER"]);
});

test("F1a: a reviewer-A window cannot vouch for a Review B header (letter binding)", () => {
  const evidence = deriveVerdictEvidence({
    comments: [verdict("B", "PASS", HEAD, "2026-08-01T14:38:30Z", RUN_A)], // Review B but run belongs to reviewer-A
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.deepEqual(evidence.rejected.map((e) => e.reason), ["WINDOW_LANE_LETTER_MISMATCH"]);
  assert.equal(evidence.passCount, 0);
});

test("AC2 stale-head: verdicts pinned to an older head are rejected by name, not silently uncounted", () => {
  const evidence = deriveVerdictEvidence({
    comments: [
      verdict("A", "PASS", OLD_HEAD, "2026-08-01T14:38:30Z"),
      verdict("B", "PASS", OLD_HEAD, "2026-08-01T14:41:04Z"),
    ],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.equal(evidence.passCount, 0);
  assert.deepEqual(evidence.staleHeads, [OLD_HEAD.slice(0, 8)]);
  assert.deepEqual(
    evidence.rejected.map((entry) => entry.reason),
    ["VERDICT_STALE_HEAD", "VERDICT_STALE_HEAD"],
  );

  // The refusal must NAME the stale head rather than reading as a plain miscount.
  const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: 0 });
  const final = applyVerdictEvidence(gate, evidence);
  assert.equal(final.disposition, "REFUSE_MERGE");
  assert.equal(final.reasonCode, "VERDICT_STALE_HEAD");
});

test("AC1 forged verdict: PR #1794 replay — a verdict outside its run's window is rejected AND, being a FAIL at head, blocks (F5)", () => {
  const comments = [
    verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z", REVIEWER_RUN),
    verdict("B", "PASS", HEAD, "2026-08-01T14:41:04Z", REVIEWER_RUN),
    // The forgery: same run id, posted 34 minutes after that run released the claim.
    verdict("A", "FAIL", HEAD, "2026-08-01T15:17:33Z", REVIEWER_RUN),
  ];

  const checked = deriveVerdictEvidence({ comments, head: HEAD, claimWindows: REVIEWER_WINDOW });
  // The two genuine PASSes share ONE run — under run-scoped counting that is passCount 1 (the
  // interim: honest dual now needs two reviewer runs; see the DUAL_SINGLE_RUN test).
  assert.equal(checked.passCount, 1);
  assert.deepEqual(checked.failLanes, [], "the forged FAIL is not counted, so it cannot veto via failLanes");
  assert.deepEqual(checked.rejected, [
    {
      lane: "A",
      verdict: "FAIL",
      headSha: HEAD.slice(0, 8),
      runId: REVIEWER_RUN.slice(0, 8),
      at: "2026-08-01T15:17:33Z",
      reason: "VERDICT_PROVENANCE_UNPROVEN",
      provenanceReason: "POSTED_OUTSIDE_CLAIM_WINDOW",
    },
  ]);
  // F5: an unprovable FAIL at the reviewed head must BLOCK for human adjudication,
  // never vanish. The old code dropped it and let the merge proceed (fail-open).
  assert.deepEqual(checked.unprovenFailsAtHead.map((e) => e.reason), ["VERDICT_PROVENANCE_UNPROVEN"]);

  // Header text alone cannot tell the forgery from the genuine verdict: with no
  // claim trail to cross-check, the forged FAIL supersedes lane A and vetoes.
  const unchecked = deriveVerdictEvidence({ comments, head: HEAD, claimWindows: null });
  assert.equal(unchecked.provenanceChecked, false);
  assert.deepEqual(unchecked.failLanes, ["A"]);
});

test("F5: a genuine FAIL at head whose claim went stale BLOCKS instead of vanishing", () => {
  // Two proven PASSes plus lane B's real FAIL, posted from a run with no covering
  // window (a long review, or a claim that lapsed mid-review).
  const STALE_RUN = "0badf00d-1111-4222-8333-444455556666";
  const comments = [
    verdict("A", "PASS", HEAD, "2026-08-01T14:00:00Z"),
    verdict("B", "PASS", HEAD, "2026-08-01T14:10:00Z"),
    verdict("B", "FAIL", HEAD, "2026-08-01T18:00:00Z", STALE_RUN), // hours later, no window
  ];
  const evidence = deriveVerdictEvidence({ comments, head: HEAD, claimWindows: DUAL_WINDOWS });
  assert.deepEqual(evidence.unprovenFailsAtHead.map((e) => e.reason), ["VERDICT_PROVENANCE_UNPROVEN"]);

  const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: evidence.passCount });
  const final = applyVerdictEvidence(gate, evidence);
  assert.equal(final.disposition, "REFUSE_MERGE");
  assert.equal(final.reasonCode, "VERDICT_UNPROVEN_FAIL_AT_HEAD");
});

test("FAIL veto: an unaddressed FAIL at the head refuses even alongside two PASSes", () => {
  const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: 2 });
  assert.equal(gate.disposition, "OK");

  const vetoed = applyVerdictEvidence(gate, {
    passCount: 2,
    passLanes: ["A", "B"],
    failLanes: ["C"],
    provenanceChecked: true,
    counted: [],
    rejected: [],
    unprovenFailsAtHead: [],
    staleHeads: [],
  });
  assert.equal(vetoed.disposition, "REFUSE_MERGE");
  assert.equal(vetoed.reasonCode, "VERDICT_FAIL_AT_HEAD");
  assert.equal(vetoed.dualSatisfied, false);

  // The veto is not conditional on dual being required: a fence that watched a
  // lane FAIL the head must not hand back a green light on a benign PR either.
  const benign = evaluateStrictDualGate({ manualReviewRequired: false, moneyPathHit: false, passCount: 0 });
  assert.equal(benign.disposition, "OK");
  assert.equal(
    applyVerdictEvidence(benign, {
      passCount: 0, passLanes: [], failLanes: ["A"], provenanceChecked: true, counted: [], rejected: [], unprovenFailsAtHead: [], staleHeads: [],
    }).reasonCode,
    "VERDICT_FAIL_AT_HEAD",
  );
});

test("one lane cannot satisfy dual by posting twice; unlabelled never counts (F6)", () => {
  const twiceSameLane = deriveVerdictEvidence({
    comments: [
      verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z"),
      verdict("A", "PASS", HEAD, "2026-08-01T14:40:00Z"),
    ],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.equal(twiceSameLane.passCount, 1);
  assert.deepEqual(twiceSameLane.passLanes, ["A"]);

  // F6: an unlabelled ("?") header is not a recognised A/B lane and can no longer
  // count — ordinary recap prose parses as one, so it must never join the pair.
  const unlabelled = deriveVerdictEvidence({
    comments: [
      comment(`## Reviewer verdict — correctness lane — PASS — head ${HEAD.slice(0, 8)}`, "2026-08-01T14:38:30Z"),
      comment(`## Reviewer verdict — adversarial lane — PASS — head ${HEAD.slice(0, 8)}`, "2026-08-01T14:40:00Z"),
    ],
    head: HEAD,
    claimWindows: null,
  });
  assert.equal(unlabelled.passCount, 0);
  assert.deepEqual(unlabelled.rejected.map((e) => e.reason), ["UNLABELLED_OR_UNKNOWN_LANE", "UNLABELLED_OR_UNKNOWN_LANE"]);
});

test("B7: a verdict whose comment was edited after posting is rejected (VERDICT_EDITED)", () => {
  const evidence = deriveVerdictEvidence({
    comments: [
      verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z"),
      { ...verdict("B", "PASS", HEAD, "2026-08-01T14:41:04Z"), edited: true },
    ],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.deepEqual(evidence.passLanes, ["A"], "the edited lane-B PASS does not count");
  assert.deepEqual(evidence.rejected.map((e) => e.reason), ["VERDICT_EDITED"]);
  assert.equal(evidence.passCount, 1);
});

test("a later same-lane verdict at the same head supersedes the earlier one", () => {
  const evidence = deriveVerdictEvidence({
    comments: [
      verdict("A", "FAIL", HEAD, "2026-08-01T13:50:00Z"),
      verdict("B", "PASS", HEAD, "2026-08-01T14:41:04Z"),
      verdict("A", "PASS", HEAD, "2026-08-01T14:42:00Z"),
    ],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.deepEqual(evidence.failLanes, [], "lane A's re-review clears its own earlier FAIL");
  assert.deepEqual(evidence.unprovenFailsAtHead, [], "a superseded, provenance-HELD FAIL is not an unproven veto");
  assert.equal(evidence.passCount, 2);
});

test("a run id is never mistaken for the head SHA it must pin", () => {
  // `run=6d1b44ed` is itself 8 hex characters sitting in the header.
  const unpinned = parseVerdictHeader("## Review A (lane=reviewer run=6d1b44ed) — PASS");
  assert.equal(unpinned.headSha, null);
  assert.equal(unpinned.runId, "6d1b44ed");
  assert.equal(unpinned.lane, "A");

  // Real headers in this repo abbreviate the head and sometimes drop the word.
  assert.equal(parseVerdictHeader("## Review B (lane=reviewer run=b1e8cd38) — FAIL — 6ea7456f").headSha, "6ea7456f");
  assert.equal(parseVerdictHeader("## Delta Review B (lane=reviewer run=6f45b7a8) — PASS — head abdfa671").headSha, "abdfa671");
  assert.equal(parseVerdictHeader("## Delta Review B (lane=reviewer run=6f45b7a8) — PASS — head abdfa671").lane, "B");

  // Non-verdict comments that merely mention a review are not verdicts.
  assert.equal(parseVerdictHeader("## Rework since Review B (6ea7456f -> be214a30)"), null);
  assert.equal(parseVerdictHeader("## Orchestrator notice — the Review A FAIL above is VOID"), null);

  // Only the first line carries identity: prose quoting other heads and the word
  // FAIL (known-red lists, prior rounds) must not change the verdict.
  const pinned = parseVerdictHeader(
    `## Review A (lane=reviewer run=6d1b44ed) — PASS — head ${HEAD.slice(0, 8)}\n\nKnown red at 5a54c2eb: FAIL.`,
  );
  assert.equal(pinned.verdict, "PASS");
  assert.equal(pinned.headSha, HEAD.slice(0, 8));
});

test("B9: a 4-space-indented (code-block) header is not a verdict", () => {
  assert.equal(parseVerdictHeader(`    ## Review A (lane=reviewer run=${RUN_A.slice(0, 8)}) — PASS — head ${HEAD.slice(0, 8)}`), null);
  assert.equal(parseVerdictHeader(`\t## Review B — PASS — head ${HEAD.slice(0, 8)}`), null);
  // Up to three leading spaces is still a Markdown heading and still parses.
  assert.equal(parseVerdictHeader(`   ## Review A — PASS — head ${HEAD.slice(0, 8)}`).lane, "A");
});

test("an unpinned verdict is reported, never counted", () => {
  const evidence = deriveVerdictEvidence({
    comments: [comment("## Review A — PASS", "2026-08-01T14:38:30Z")],
    head: HEAD,
    claimWindows: null,
  });
  assert.equal(evidence.passCount, 0);
  assert.equal(evidence.rejected[0].reason, "VERDICT_HEAD_UNPINNED");
});

test("provenance needs a run id whose window covers the posting time", () => {
  const at = "2026-08-01T14:38:30Z";
  assert.equal(provenanceHolds({ runId: "73ae4faa", at, windows: REVIEWER_WINDOW }).held, true);
  // Short header run id vs full uuid in the claim trail: prefix match, both ways.
  assert.equal(provenanceHolds({ runId: REVIEWER_RUN, at, windows: REVIEWER_WINDOW }).held, true);
  // B8: a 4-hex run prefix (~16 bits) is now too coarse to match a window.
  assert.equal(provenanceHolds({ runId: "73ae", at, windows: REVIEWER_WINDOW }).reason, "NO_CLAIM_WINDOW_FOR_RUN");
  assert.equal(
    provenanceHolds({ runId: "deadbeef", at, windows: REVIEWER_WINDOW }).reason,
    "NO_CLAIM_WINDOW_FOR_RUN",
  );
  assert.equal(provenanceHolds({ runId: null, at, windows: REVIEWER_WINDOW }).reason, "NO_RUN_ID_IN_HEADER");
  assert.equal(
    provenanceHolds({ runId: "73ae4faa", at: "2026-08-01T13:00:00Z", windows: REVIEWER_WINDOW }).held,
    false,
    "before the claim opened",
  );
  // A verdict posted moments after release is genuine; the PR comment and the
  // Linear release race by seconds.
  assert.equal(provenanceHolds({ runId: "73ae4faa", at: "2026-08-01T14:45:00Z", windows: REVIEWER_WINDOW }).held, true);
  assert.equal(provenanceHolds({ runId: "73ae4faa", at: "2026-08-01T15:17:33Z", windows: REVIEWER_WINDOW }).held, false);
});

// --- CLI contract: the override is loud, and evidence failures never soften ---

const FENCE = join(REPO_ROOT, "scripts", "release-targets-strict-dual.mjs");

// Runs the fence with `paths` on stdin so no git range is needed. `ghStub` puts a
// throwaway `gh` first on PATH, standing in for an unreachable GitHub.
function runFence(args, { paths = ["CLAUDE.md"], ghStub } = {}) {
  let env = process.env;
  if (ghStub) {
    const bin = mkdtempSync(join(tmpdir(), "ztr1064-bin-"));
    writeFileSync(join(bin, "gh"), `#!/bin/sh\n${ghStub}\n`, { mode: 0o755 });
    env = { ...process.env, PATH: `${bin}:${process.env.PATH}` };
  }
  const child = spawnSync(process.execPath, [FENCE, "check", ...args], {
    input: paths.join("\n"),
    encoding: "utf8",
    cwd: REPO_ROOT,
    env,
  });
  return { status: child.status, stdout: child.stdout, stderr: child.stderr };
}

test("AC3: --pass-count still works, and says loudly that it verified nothing", () => {
  const run = runFence(["--paths-from-stdin", "--pass-count", "2", "--money-path-hit", "false"]);
  assert.equal(run.status, 0);
  assert.match(run.stderr, /AUDIT: --pass-count is an OPERATOR OVERRIDE/);
  assert.match(run.stderr, /Only a MERGER/, "the audit line must name who may use it");
  assert.match(run.stderr, /--pr <n>/, "and point at the verified path");
  assert.equal(JSON.parse(run.stdout).passCountSource, "operator-override");
});

test("ZPAY-205: a fractional --pass-count is refused; integer overrides still work", () => {
  // Regression: Number.isFinite let 2.5 through, so the operator override
  // `--pass-count 2.5 --money-path-hit false` exited 0 with passCount:2.5 — a
  // fraction cannot represent independent reviewer passes. The guard now rejects
  // fractions at arg-parse, before any classification or scan can gate on them.
  for (const bad of ["2.5", "1.9"]) {
    const run = runFence(["--paths-from-stdin", "--pass-count", bad, "--money-path-hit", "false"]);
    assert.equal(run.status, 2, bad);
    assert.equal(run.stdout, "", bad);
    const err = JSON.parse(run.stderr).error;
    assert.equal(err.code, "INVALID_ARGUMENT", bad);
    assert.match(err.message, /non-negative integer/, bad);
  }

  // Integer overrides are unaffected: 2 is still accepted as an operator override.
  const ok = runFence(["--paths-from-stdin", "--pass-count", "2", "--money-path-hit", "false"]);
  assert.equal(ok.status, 0);
  assert.equal(JSON.parse(ok.stdout).passCountSource, "operator-override");
});

test("--pr and --pass-count cannot be combined, and --pr must pin a head", () => {
  const both = runFence(["--paths-from-stdin", "--head", HEAD, "--pr", "1810", "--pass-count", "2"]);
  assert.equal(both.status, 2);
  assert.match(JSON.parse(both.stderr).error.message, /mutually exclusive/);

  const unpinned = runFence(["--paths-from-stdin", "--pr", "1810"]);
  assert.equal(unpinned.status, 2);
  assert.match(JSON.parse(unpinned.stderr).error.message, /--pr requires --head/);

  const neither = runFence(["--paths-from-stdin"]);
  assert.equal(neither.status, 2);
});

test("unreachable verdict evidence fails CLOSED — never a silent fallback to trust", () => {
  const run = runFence(["--paths-from-stdin", "--head", HEAD, "--pr", "1810"], {
    ghStub: 'echo "gh: could not connect" >&2; exit 1',
  });
  assert.equal(run.status, 2, "usage/internal error, not a merge-able 0");
  assert.notEqual(run.status, 3);
  const error = JSON.parse(run.stderr).error;
  assert.equal(error.code, "VERDICT_EVIDENCE_UNAVAILABLE");
  assert.equal(run.stdout, "", "no gate verdict is emitted when the evidence could not be read");
});

// A gh stub that returns a fixed PR payload regardless of args. `body` is a heredoc
// so JSON quoting survives the shell. A payload with NO ticket in title/body/branch
// leaves the ticket unresolvable, so no claim.py (no Linear) call is made.
const ghPayloadStub = (payload) => `cat <<'GHJSON'\n${JSON.stringify(payload)}\nGHJSON`;
const CONTROL_PATHS = ["release/targets.v1.json"]; // classifies strict (dual required)

test("F3: a ticket-less strict PR refuses (VERDICT_PROVENANCE_UNCHECKED), not exit 0 labelled verified", () => {
  const run = runFence(["--paths-from-stdin", "--head", HEAD, "--pr", "1810"], {
    paths: CONTROL_PATHS,
    ghStub: ghPayloadStub({
      headRefOid: HEAD,
      headRefName: "tidy-fence",
      title: "chore: tidy the fence",
      body: "cleanup, no ticket reference",
      comments: [
        { body: `## Review A — PASS — head ${HEAD.slice(0, 8)}`, createdAt: "2026-08-01T14:38:30Z", includesCreatedEdit: false },
        { body: `## Review B — PASS — head ${HEAD.slice(0, 8)}`, createdAt: "2026-08-01T14:41:04Z", includesCreatedEdit: false },
      ],
      reviews: [],
    }),
  });
  assert.equal(run.status, 3);
  const out = JSON.parse(run.stdout);
  assert.equal(out.disposition, "REFUSE_MERGE");
  assert.equal(out.reasonCode, "VERDICT_PROVENANCE_UNCHECKED");
  assert.equal(out.verdictEvidence.provenanceChecked, false);
});

test("B1: --head that is not the PR's real head refuses (VERDICT_HEAD_NOT_PR_HEAD)", () => {
  const prHead = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"; // PR is really here
  const run = runFence(["--paths-from-stdin", "--head", HEAD, "--pr", "1810"], {
    paths: CONTROL_PATHS,
    ghStub: ghPayloadStub({
      headRefOid: prHead, // NOT --head HEAD
      headRefName: "some-branch",
      title: "chore: no ticket here",
      body: "no ticket",
      comments: [
        { body: `## Review A (lane=reviewer run=${RUN_A.slice(0, 8)}) — PASS — head ${HEAD.slice(0, 8)}`, createdAt: "2026-08-01T14:38:30Z", includesCreatedEdit: false },
        { body: `## Review B (lane=reviewer run=${RUN_B.slice(0, 8)}) — PASS — head ${HEAD.slice(0, 8)}`, createdAt: "2026-08-01T14:41:04Z", includesCreatedEdit: false },
      ],
      reviews: [],
    }),
  });
  assert.equal(run.status, 3);
  const out = JSON.parse(run.stdout);
  assert.equal(out.disposition, "REFUSE_MERGE");
  assert.equal(out.reasonCode, "VERDICT_HEAD_NOT_PR_HEAD");
  assert.equal(out.verdictEvidence.headMatchesPrHead, false);
});

test("F4: --provenance-grace-min was removed — supplying it is a usage error", () => {
  const run = runFence(["--paths-from-stdin", "--head", HEAD, "--pr", "1810", "--provenance-grace-min", "99999999"]);
  assert.equal(run.status, 2);
  assert.match(JSON.parse(run.stderr).error.message, /provenance-grace-min was removed/);
  assert.equal(run.stdout, "", "no gate verdict on a usage error");
});

// ---------------------------------------------------------------------------
// ZPAY-216 — merge-gate tooling defects observed across five PRs on 2026-08-06.
// ---------------------------------------------------------------------------

// AC3, the exact ZPAY-74 #1991 comment: a titled `#` heading on line 1, and the
// canonical `## Review A (lane=… run=…)` heading two lines below it. The
// first-line-only parse dropped the whole comment SILENTLY, refusing a genuine dual
// PASS at passCount=1 — the single most direct route to a lane reaching for
// --pass-count, which verifies nothing.
const ZPAY74_SHAPE = (lane, outcome, head, run) =>
  [
    `# ZPAY-74 Review ${lane} — ${outcome} — head \`${head}\``,
    "",
    `## Review ${lane} (lane=reviewer-${lane} run=${run.slice(0, 8)}) — ${outcome} — head ${head}`,
    "",
    "Scope reviewed: the full diff. Known red on main: `no-submit.scan.test.ts` FAIL.",
  ].join("\n");

test("ZPAY-216 AC3: a verdict whose canonical heading is not line 1 is COUNTED, not skipped", () => {
  const evidence = deriveVerdictEvidence({
    comments: [
      comment(ZPAY74_SHAPE("A", "PASS", HEAD, RUN_A), "2026-08-01T14:38:30Z"),
      comment(ZPAY74_SHAPE("B", "PASS", HEAD, RUN_B), "2026-08-01T14:41:04Z"),
    ],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.equal(evidence.passCount, 2, "both real ZPAY-74-shaped verdicts count");
  assert.deepEqual(evidence.passLanes, ["A", "B"]);
  assert.deepEqual(evidence.rejected, []);
  assert.deepEqual(evidence.skipped, [], "a counted verdict is not also reported as skipped");
  // The prose FAIL of a known-red test must not become this comment's verdict.
  assert.deepEqual(evidence.failLanes, []);
});

test("ZPAY-216 AC3: agreeing headings merge; disagreeing ones fail CLOSED, never pick a winner", () => {
  // The two headings state the SAME verdict; the abbreviated head is the same head.
  const merged = parseVerdictHeader(
    `# ZPAY-74 Review A — PASS — head \`${HEAD.slice(0, 8)}\`\n\n## Review A (lane=reviewer-A run=${RUN_A.slice(0, 8)}) — PASS — head ${HEAD}`,
  );
  assert.equal(merged.lane, "A");
  assert.equal(merged.headSha, HEAD, "the more specific (longer) SHA wins over its own prefix");
  assert.equal(merged.runId, RUN_A.slice(0, 8), "the run from the heading that carries one");

  // A comment quoting a PRIOR round's heading disagrees with itself: the FAIL wins.
  const conflicted = parseVerdictHeader(
    `## Review A (lane=reviewer-A run=${RUN_A.slice(0, 8)}) — PASS — head ${HEAD}\n\n## Review A — FAIL — head ${HEAD}`,
  );
  assert.equal(conflicted.verdict, "FAIL", "a disagreement may never resolve to PASS");

  // Two different lane letters in one comment: neither is taken.
  const twoLanes = parseVerdictHeader(
    `## Review A — PASS — head ${HEAD}\n\n## Review B — PASS — head ${HEAD}`,
  );
  // ZPAY-216 rework: identity is the OPENING line, so the lane is A and the second
  // heading's disagreement is a named conflict instead of a nulled field. The property
  // that matters is unchanged and asserted verbatim below: passCount 0.
  assert.equal(twoLanes.lane, "A", "identity comes from the opening line; the later heading may only agree");
  assert.equal(twoLanes.conflict, "lane", "and its disagreement is named, not silently nulled");
  const evidence = deriveVerdictEvidence({
    comments: [comment(twoLanes.header ? `## Review A — PASS — head ${HEAD}\n\n## Review B — PASS — head ${HEAD}` : "", "2026-08-01T14:38:30Z")],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.equal(evidence.passCount, 0, "one comment can never supply both opposed lenses");
  assert.equal(evidence.rejected[0].reason, "VERDICT_HEADINGS_CONFLICT");
});

test("ZPAY-216 AC3: a skipped comment reports WHY, instead of vanishing into a bare passCount", () => {
  const evidence = deriveVerdictEvidence({
    comments: [
      // forgot the `#` heading marker entirely
      comment(`Review A — PASS — head ${HEAD}`, "2026-08-01T14:30:00Z"),
      // pasted inside a fenced block (a quoted example, not a verdict)
      comment("```\n## Review B — PASS — head " + HEAD + "\n```", "2026-08-01T14:31:00Z"),
      // an orchestrator notice that merely talks about a verdict
      comment("## Orchestrator notice — the Review A FAIL above is VOID", "2026-08-01T14:32:00Z"),
      // ordinary discussion must NOT be reported: the diagnostics stay actionable
      comment("Rebased onto main; rerunning the suite.", "2026-08-01T14:33:00Z"),
    ],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.equal(evidence.passCount, 0, "none of these are verdicts");
  assert.deepEqual(
    evidence.skipped.map((s) => s.reason),
    ["VERDICT_NOT_A_HEADING", "VERDICT_HEADING_IN_CODE_FENCE", "HEADING_DOES_NOT_START_WITH_REVIEW"],
  );
  assert.match(evidence.skipped[0].header, /Review A — PASS/, "the offending line is quoted back");
  assert.ok(evidence.skipped.every((s) => s.at), "each skip names when it was posted");
});

// AC4 / defect 3: a fail-closed money-path scan is an ERROR, not a classification.
function dirtyFixture() {
  const fixture = makeStaleTreeRepo();
  writeFileSync(join(fixture.dir, "uncommitted.txt"), "a lane's scratch file\n", "utf8");
  return fixture;
}

test("ZPAY-216 AC4: a dirty tree refuses by name — never a phantom hit with zero offenders", () => {
  const fixture = dirtyFixture();
  try {
    assert.throws(
      () => evaluateStrictDualForDiff({ base: fixture.base, head: fixture.head, passCount: 2, repoRoot: fixture.dir }),
      (error) => {
        assert.equal(error.code, "DIRTY_TREE", "the cause is named, not folded into moneyPathHit");
        assert.match(error.message, /NOT a money-path classification/);
        return true;
      },
    );
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("ZPAY-216 AC4: a returned money-path hit always names at least one offender", () => {
  const fixture = makeStaleTreeRepo();
  try {
    const result = evaluateStrictDualForDiff({
      base: fixture.base,
      head: fixture.head,
      passCount: 0,
      repoRoot: fixture.dir,
    });
    assert.equal(result.moneyPath.failClosed, false, "a returned result is never fail-closed");
    assert.equal(
      result.moneyPath.moneyPathHit,
      result.moneyPath.offendingPaths.length > 0,
      "moneyPathHit and the offender list can no longer disagree",
    );
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test("ZPAY-216 AC4: a --base that is not the merge-base refuses and names the one to use", () => {
  const fixture = makeStaleTreeRepo();
  try {
    // unownedHead is a DESCENDANT of head, so as a base it is not an ancestor of head.
    assert.throws(
      () => evaluateStrictDualForDiff({ base: fixture.unownedHead, head: fixture.head, passCount: 2, repoRoot: fixture.dir }),
      (error) => {
        assert.equal(error.code, "BASE_NOT_MERGE_BASE");
        assert.match(error.message, new RegExp(`--base ${fixture.head}`), "it names the merge-base to re-run with");
        return true;
      },
    );
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

// Defect 2 (ordering): the claim-trail read is what died on every ZPAY PR. A gate that
// does not need a verdict must not be abortable by a verdict lookup — and a gate that
// DOES need one must still fail closed. `pyStub` stands in for a broken claim.py.
function runFenceWithStubs(args, { paths, ghStub, pyStub }) {
  const bin = mkdtempSync(join(tmpdir(), "zpay216-bin-"));
  writeFileSync(join(bin, "gh"), `#!/bin/sh\n${ghStub}\n`, { mode: 0o755 });
  writeFileSync(join(bin, "python3"), `#!/bin/sh\n${pyStub}\n`, { mode: 0o755 });
  const child = spawnSync(process.execPath, [FENCE, "check", ...args], {
    input: paths.join("\n"),
    encoding: "utf8",
    cwd: REPO_ROOT,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  });
  rmSync(bin, { recursive: true, force: true });
  return { status: child.status, stdout: child.stdout, stderr: child.stderr };
}

const TICKETED_PR = (comments = []) => ({
  headRefOid: HEAD,
  headRefName: "zpay-216-fixture",
  title: "fix(platform-v2): ZPAY-216 merge-gate tooling",
  body: "ZPAY-216",
  comments,
  reviews: [],
});
// The exact failure that blocked every ZPAY PR on 2026-08-06.
const BROKEN_CLAIM_PY = 'echo "resolved ZTR-216 for ZPAY-216 — wrong team, refusing" >&2; exit 1';

test("ZPAY-216 defect 2: an unreachable claim trail cannot abort a gate that does not need it", () => {
  const run = runFenceWithStubs(["--paths-from-stdin", "--head", HEAD, "--pr", "2001"], {
    paths: ["CLAUDE.md"], // benign: dual not required
    ghStub: ghPayloadStub(TICKETED_PR()),
    pyStub: BROKEN_CLAIM_PY,
  });
  assert.equal(run.status, 0, "before the fix this was exit 2 CLAIM_WINDOWS_UNAVAILABLE");
  const out = JSON.parse(run.stdout);
  assert.equal(out.reasonCode, "DUAL_NOT_REQUIRED");
  assert.equal(out.verdictEvidence.provenanceChecked, false, "the Linear read is skipped, not faked");
});

test("ZPAY-216 defect 2: skipping the claim trail does NOT skip the FAIL-at-head veto", () => {
  const run = runFenceWithStubs(["--paths-from-stdin", "--head", HEAD, "--pr", "2001"], {
    paths: ["CLAUDE.md"], // benign — the veto must fire anyway
    ghStub: ghPayloadStub(
      TICKETED_PR([
        { body: `## Review A (lane=reviewer-A run=${RUN_A.slice(0, 8)}) — FAIL — head ${HEAD.slice(0, 8)}`, createdAt: "2026-08-01T14:38:30Z", includesCreatedEdit: false },
      ]),
    ),
    pyStub: BROKEN_CLAIM_PY,
  });
  assert.equal(run.status, 3, "a reviewer FAIL at the head still refuses the merge");
  assert.equal(JSON.parse(run.stdout).reasonCode, "VERDICT_FAIL_AT_HEAD");
});

test("ZPAY-216 defect 2: a dual-REQUIRED gate still fails CLOSED on an unreachable claim trail", () => {
  const run = runFenceWithStubs(["--paths-from-stdin", "--head", HEAD, "--pr", "2001"], {
    paths: CONTROL_PATHS, // funded-affecting-control: provenance is mandatory
    ghStub: ghPayloadStub(
      TICKETED_PR([
        { body: `## Review A (lane=reviewer-A run=${RUN_A.slice(0, 8)}) — PASS — head ${HEAD.slice(0, 8)}`, createdAt: "2026-08-01T14:38:30Z", includesCreatedEdit: false },
        { body: `## Review B (lane=reviewer-B run=${RUN_B.slice(0, 8)}) — PASS — head ${HEAD.slice(0, 8)}`, createdAt: "2026-08-01T14:41:04Z", includesCreatedEdit: false },
      ]),
    ),
    pyStub: BROKEN_CLAIM_PY,
  });
  assert.equal(run.status, 2, "no verdict may be emitted when provenance is unreadable");
  assert.equal(JSON.parse(run.stderr).error.code, "CLAIM_WINDOWS_UNAVAILABLE");
  assert.equal(run.stdout, "");
});

// ---------------------------------------------------------------------------
// ZPAY-216 REWORK: the three fail-opens the first fix introduced.
//
// F-A  the claim-trail read was SKIPPED whenever dual was not required, which dropped
//      the F5 veto and let an unauthenticated same-lane PASS supersede a FAIL.
// F-B  foldVerdictLines NULLED headSha on disagreement, which killed a FAIL outright
//      (never reaching the at-head region) while only downgrading a PASS.
// F-C  identity was taken from ANY heading, so an orchestrator recap that reproduced a
//      reviewer heading became that reviewer's verdict.
// ---------------------------------------------------------------------------

// A readable claim trail. `{"windows":[]}` is READABLE and vouches for nobody — the
// distinction that F-A turns on: reading and learning nothing is not the same as not
// reading, and only the first can reject a verdict into unprovenFailsAtHead.
const WINDOWS_PY = (windows) => `cat <<'PYJSON'\n${JSON.stringify({ windows })}\nPYJSON`;
const header = (lane, outcome, head, run) =>
  `## Review ${lane} (lane=reviewer-${lane} run=${run.slice(0, 8)}) — ${outcome} — head ${head.slice(0, 8)}`;
const ghComment = (body, createdAt) => ({ body, createdAt, includesCreatedEdit: false });

test("F-A1: the claim trail is ALWAYS read, so an unproven FAIL still vetoes on a non-dual PR", () => {
  const run = runFenceWithStubs(["--paths-from-stdin", "--head", HEAD, "--pr", "2017"], {
    paths: ["CLAUDE.md"], // benign: dual NOT required — the path that used to skip the read
    ghStub: ghPayloadStub(
      TICKETED_PR([
        ghComment(header("A", "FAIL", HEAD, RUN_A), "2026-08-01T14:38:30Z"),
        ghComment(header("A", "PASS", HEAD, RUN_A), "2026-08-01T14:52:00Z"), // unauthenticated
      ]),
    ),
    pyStub: WINDOWS_PY([]),
  });
  // Pre-rework: exit 0 DUAL_NOT_REQUIRED — the read was skipped, both verdicts were
  // counted unproven, and the later PASS superseded the FAIL.
  assert.equal(run.status, 3, "a FAIL at the reviewed head may not be cleared by an unproven PASS");
  const out = JSON.parse(run.stdout);
  assert.equal(out.reasonCode, "VERDICT_UNPROVEN_FAIL_AT_HEAD");
  assert.equal(out.verdictEvidence.provenanceChecked, true, "the read happened; it just vouched for nobody");
});

test("F-A2: with NO claim trail at all, a same-lane PASS still cannot supersede a FAIL at the head", () => {
  const evidence = deriveVerdictEvidence({
    comments: [
      verdict("A", "FAIL", HEAD, "2026-08-01T14:38:30Z"),
      verdict("A", "PASS", HEAD, "2026-08-01T14:52:00Z"),
    ],
    head: HEAD,
    claimWindows: null, // unchecked: nothing here can vouch for the lane that failed
  });
  assert.deepEqual(evidence.failLanes, ["A"], "pre-rework this was [] — the veto vanished");
  assert.equal(evidence.provenanceChecked, false);

  // The same pair WITH provenance is a genuine re-review and still supersedes (:548).
  const checked = deriveVerdictEvidence({
    comments: [
      verdict("A", "FAIL", HEAD, "2026-08-01T14:38:30Z"),
      verdict("A", "PASS", HEAD, "2026-08-01T14:42:00Z"),
    ],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  assert.deepEqual(checked.failLanes, [], "the non-supersedable rule is scoped to the degraded mode only");
});

test("F-A3: a benign PR with a readable trail reports provenanceChecked TRUE (the read is not skipped)", () => {
  const run = runFenceWithStubs(["--paths-from-stdin", "--head", HEAD, "--pr", "2017"], {
    paths: ["CLAUDE.md"],
    ghStub: ghPayloadStub(TICKETED_PR([ghComment(header("A", "PASS", HEAD, RUN_A), "2026-08-01T14:38:30Z")])),
    pyStub: WINDOWS_PY(DUAL_WINDOWS),
  });
  assert.equal(run.status, 0);
  const out = JSON.parse(run.stdout);
  assert.equal(out.reasonCode, "DUAL_NOT_REQUIRED");
  assert.equal(out.verdictEvidence.provenanceChecked, true, "pre-rework: false, because the read was skipped");
  assert.equal(out.verdictEvidence.provenanceError, null);
});

test("F-A4: the degraded mode is only safe because F3 refuses it on a dual-required path", () => {
  // The unchecked mode counts unproven PASSes and falls back to lane-counting (losing
  // F1b), so it is NOT unconditionally more refusing. It is reachable only when dual is
  // not required; every other route to provenanceChecked:false must refuse. This is the
  // assertion guarding the single `!` at the call site.
  const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: 2 });
  const final = applyVerdictEvidence(gate, {
    passCount: 2, passLanes: ["A", "B"], failLanes: [], provenanceChecked: false,
    counted: [], rejected: [], unprovenFailsAtHead: [], staleHeads: [],
  });
  assert.equal(final.disposition, "REFUSE_MERGE");
  assert.equal(final.reasonCode, "VERDICT_PROVENANCE_UNCHECKED");
});

// F-B: a round-2 FAIL comment that recaps round 1 with a HEADING pinning the older head.
// Ordinary reviewer prose; pre-rework it silently erased the FAIL.
const FAIL_WITH_RECAP_HEADING = [
  header("B", "FAIL", HEAD, RUN_B),
  "",
  "Round 2 verdict. For context, round 1 was:",
  "",
  `### Review B round 1 — PASS — head ${OLD_HEAD.slice(0, 8)}`,
].join("\n");

test("F-B1: a FAIL carrying a stale recap HEADING is refused at the head, never dropped", () => {
  const evidence = deriveVerdictEvidence({
    comments: [comment(FAIL_WITH_RECAP_HEADING, "2026-08-01T14:41:04Z")],
    head: HEAD,
    claimWindows: DUAL_WINDOWS,
  });
  // Pre-rework: headSha nulled -> VERDICT_HEAD_UNPINNED, a PLAIN reject above the
  // FAIL-blocking line, so unprovenFailsAtHead was [] and the gate said OK.
  assert.deepEqual(evidence.unprovenFailsAtHead.map((e) => e.reason), ["VERDICT_HEADINGS_CONFLICT"]);
  assert.equal(evidence.rejected[0].conflictField, "head");
  assert.match(evidence.rejected[0].conflictHeader, /round 1/, "the offending heading is quoted back");

  const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: evidence.passCount });
  assert.equal(applyVerdictEvidence(gate, evidence).reasonCode, "VERDICT_UNPROVEN_FAIL_AT_HEAD");
});

test("F-B2 (standing regression): NO fold-ambiguous field may erase a veto, in either heading order", () => {
  // The invariant, not the reason code. Every row varies the HEAD as well as the row's
  // field — holding the head constant is exactly what the AC3 tests at :776 did, and why
  // F-B shipped. Any future field the fold learns to disagree on belongs in this table.
  const FAIL_AT_HEAD = header("A", "FAIL", HEAD, RUN_A);
  const rows = [
    ["lane", `### Review B round 1 — PASS — head ${OLD_HEAD.slice(0, 8)}`],
    ["run", `### Review A round 1 (run=${RUN_B.slice(0, 8)}) — PASS — head ${OLD_HEAD.slice(0, 8)}`],
    ["head", `### Review A round 1 — PASS — head ${OLD_HEAD.slice(0, 8)}`],
  ];
  for (const [field, other] of rows) {
    for (const [order, body] of [
      ["veto first", `${FAIL_AT_HEAD}\n\n${other}`],
      ["veto second", `${other}\n\n${FAIL_AT_HEAD}`],
    ]) {
      for (const claimWindows of [DUAL_WINDOWS, null]) {
        const evidence = deriveVerdictEvidence({
          comments: [comment(body, "2026-08-01T14:41:04Z")],
          head: HEAD,
          claimWindows,
        });
        assert.ok(
          evidence.failLanes.length + evidence.unprovenFailsAtHead.length > 0,
          `${field}/${order}/${claimWindows ? "checked" : "unchecked"}: the FAIL at the reviewed head was erased`,
        );
      }
    }
  }
});

test("F-B3: reviewer B's round-2 FAIL still vetoes end to end, and the fixture is not what refuses", () => {
  const gateFor = (comments) => {
    const evidence = deriveVerdictEvidence({ comments, head: HEAD, claimWindows: DUAL_WINDOWS });
    const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: evidence.passCount });
    return { evidence, final: applyVerdictEvidence(gate, evidence) };
  };
  const withRecap = gateFor([
    verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z"),
    verdict("B", "PASS", HEAD, "2026-08-01T14:39:00Z"),
    comment(FAIL_WITH_RECAP_HEADING, "2026-08-01T14:41:04Z"),
  ]);
  assert.equal(withRecap.final.disposition, "REFUSE_MERGE", "pre-rework: OK / DUAL_SATISFIED / passCount 2");

  // Control: the same three comments with the recap heading removed. Both sides refuse,
  // so the refusal is B's FAIL, not the fixture.
  const control = gateFor([
    verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z"),
    verdict("B", "PASS", HEAD, "2026-08-01T14:39:00Z"),
    verdict("B", "FAIL", HEAD, "2026-08-01T14:41:04Z"),
  ]);
  assert.deepEqual(control.evidence.failLanes, ["B"]);
  assert.equal(control.final.reasonCode, "VERDICT_FAIL_AT_HEAD");
});

// F-C: a recap that reproduces reviewer B's heading VERBATIM and unquoted. Provenance
// cannot separate it from B's own comment — the run is real and B's window is open at
// recap time — so the comment's OPENING LINE is the only thing that can. All three
// shapes are ordinary orchestrator/merger prose.
const RECAP_OF_B = header("B", "PASS", HEAD, RUN_B);
const RECAP_SHAPES = [
  ["own title heading", `## Orchestrator notice — round 2 summary\n\n${RECAP_OF_B}`],
  ["one line of prose (G1a)", `Round 2 summary for the merger.\n\n${RECAP_OF_B}`],
  ["a non-verdict Review heading (G1b)", `## Reviewer notes for the merger\n\n${RECAP_OF_B}`],
];

test("F-C1: a reproduced reviewer heading is never that reviewer's verdict, whatever leads the comment", () => {
  for (const [shape, recap] of RECAP_SHAPES) {
    const evidence = deriveVerdictEvidence({
      comments: [
        verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z"), // the one REAL verdict
        comment(recap, "2026-08-01T14:45:00Z"),
      ],
      head: HEAD,
      claimWindows: DUAL_WINDOWS,
    });
    assert.equal(evidence.passCount, 1, `${shape}: the recap minted a second PASS`);
    assert.deepEqual(evidence.passLanes, ["A"], shape);
    assert.deepEqual(evidence.skipped.map((s) => s.reason), ["VERDICT_HEADING_NOT_FIRST"], shape);
    assert.match(evidence.skipped[0].header, /Review B/, `${shape}: the reproduced heading is quoted back`);
  }
});

test("F-C2: a recap posted AFTER the real FAIL cannot supersede it", () => {
  for (const [shape, recap] of RECAP_SHAPES) {
    const evidence = deriveVerdictEvidence({
      comments: [
        verdict("A", "PASS", HEAD, "2026-08-01T14:38:30Z"),
        verdict("B", "FAIL", HEAD, "2026-08-01T14:41:04Z"), // B's real, standing veto
        comment(recap, "2026-08-01T14:45:00Z"),
      ],
      head: HEAD,
      claimWindows: DUAL_WINDOWS,
    });
    assert.deepEqual(evidence.failLanes, ["B"], `${shape}: a live reviewer FAIL was erased by a recap`);
    const gate = evaluateStrictDualGate({ manualReviewRequired: true, moneyPathHit: false, passCount: evidence.passCount });
    assert.equal(applyVerdictEvidence(gate, evidence).reasonCode, "VERDICT_FAIL_AT_HEAD", shape);
  }
});
