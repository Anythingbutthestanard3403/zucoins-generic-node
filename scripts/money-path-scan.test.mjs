import assert from "node:assert/strict";
import test from "node:test";

import {
  diffPaths,
  isMoneyPath,
  MONEY_PATH_GLOB_SET,
  scanDiffFailClosed,
  scanPaths,
} from "./money-path-scan.mjs";
import { classifyPaths } from "./release-targets.mjs";

// ---------------------------------------------------------------------------
// Sentinel (money-path) paths -> moneyPathHit:true (strict). Each entry names the
// glob layer it proves. Real repo paths where they exist; synthetic-but-realistic
// paths for the forward-sentinel globs (.golden / migrations) that have no files yet.
// ---------------------------------------------------------------------------
const SENTINELS = [
  // money-path PACKAGES wholesale
  ["packages/node-core/src/core/ledger.ts", "node-core wholesale"],
  ["packages/generic-node-contracts/src/index.ts", "generic-node-contracts wholesale"],
  ["packages/splitchain/src/signing.ts", "splitchain wholesale + **/sign*"],
  ["packages/vault-client/src/client.ts", "**/vault-client/**"],
  // apps/generic-node/** — the inactive target's 3rd classificationGlob member, no funded
  // backstop. These are directory-organized money files whose NAMES the keyword globs miss;
  // only the wholesale glob catches them.
  ["apps/generic-node/src/sweep/build-submit.ts", "apps/generic-node wholesale (name globs miss build-submit.ts)"],
  ["apps/generic-node/src/vault/crypto.ts", "apps/generic-node wholesale (name globs miss crypto.ts)"],
  ["apps/generic-node/src/pipeline/co-sign-submit.ts", "apps/generic-node wholesale (name globs miss co-sign-submit.ts)"],
  ["apps/generic-node/src/engine/outbound-transfer.ts", "apps/generic-node wholesale (name globs miss outbound-transfer.ts)"],
  // name-pattern surface in money-path packages (real files)
  ["packages/generic-node-contracts/src/transfer-code/transfer-code.contract.ts", "**/transfer-code*"],
  ["packages/splitchain/src/transfer-codes.ts", "**/transfer-code*"],
  ["packages/node-core/src/schema/transaction-material.sql", "**/schema/** + node-core wholesale"],
  ["packages/generic-node-contracts/src/amounts/__vectors__/emission.vectors.json", "**/__vectors__/**"],
  // name-pattern surface reaching into NON-money packages (shared / apps / widget) -
  // proves the name patterns are what catch these, not a package wholesale rule
  ["packages/shared/src/vault-envelope.ts", "shared -> **/vault*"],
  ["packages/shared/src/contracts/sweep-status.ts", "shared -> **/sweep*"],
  ["apps/node/src/wallet/transfer-code-builder.ts", "app -> **/transfer-code*"],
  ["apps/node/src/fixtures/tx.golden", "app -> **/*.golden (forward sentinel)"],
  ["apps/platform/src/db/migrations/001_init.sql", "app -> **/migrations/**"],
  ["packages/widget/test/__vectors__/foo.json", "widget -> **/__vectors__/**"],
  ["apps/platform/src/schema/orders.ts", "app -> **/schema/**"],
  // platform-v2 money logic (ZPAY-266) — the surface PR #2060 proved uncovered. All real
  // repo paths; each names the GROUP A2 glob that catches it.
  ["apps/platform-v2/src/shared/http/conventions.ts", "platform-v2 amount-validation gate — the PR #2060 live example"],
  ["apps/platform-v2/src/shared/http/conventions.route-sweep.test.ts", "conventions* catches its tests too"],
  ["apps/platform-v2/src/shared/http/amounts.test.ts", "platform-v2 amount serializer contract test"],
  ["apps/platform-v2/src/shared/money/zkz.ts", "platform-v2 shared/money wholesale (amount scalar)"],
  ["apps/platform-v2/src/shared/money/json-boundary.ts", "platform-v2 shared/money wholesale (amounts on the wire)"],
  ["apps/platform-v2/src/api/v1/payouts.ts", "platform-v2 money route: payouts*"],
  ["apps/platform-v2/src/api/v1/refunds.ts", "platform-v2 money route: refunds*"],
  ["apps/platform-v2/src/api/v1/refunds.test.ts", "route glob catches co-located tests"],
  ["apps/platform-v2/src/api/v1/treasury-moves.ts", "platform-v2 money route: treasury-moves*"],
  ["apps/platform-v2/src/api/v1/payment-sessions.ts", "platform-v2 money route: payment-sessions*"],
  ["apps/platform-v2/src/api/v1/balances.ts", "platform-v2 money route: balances*"],
  ["apps/platform-v2/src/api/v1/movements-create.ts", "platform-v2 money route: movements-create*"],
  ["apps/platform-v2/src/movements/repositories/payout-repository.ts", "movements/** wholesale"],
  ["apps/platform-v2/src/movements/source-wallet-mutex.ts", "movements/** wholesale (name globs miss source-wallet-mutex.ts)"],
  ["apps/platform-v2/src/treasury/compose-move.ts", "treasury/** wholesale"],
  ["apps/platform-v2/src/verifier/predicates/move.ts", "verifier/** wholesale (settlement verification)"],
  ["apps/platform-v2/src/sessions/compose-receive.ts", "sessions/** wholesale (receive-side money composition)"],
  ["apps/platform-v2/src/sessions/exact-bytes.ts", "sessions/** wholesale (GR3 byte-exact preimage)"],
  ["apps/platform-v2/src/intents/transitions.ts", "intents/** wholesale (money status transitions)"],
  ["apps/platform-v2/src/state/committer.ts", "state/** wholesale (VERIFIED/succeeded committer)"],
  // GR2 admission + merchant wire serializers (Review B D1/D2 clear) — hop-away modules
  // that covered routes/trees delegate to; solo edit must trip.
  ["apps/platform-v2/src/registry/client/mutation-admission.ts", "mutation-admission* GR2 tryReserve/bind/destination-gate"],
  ["apps/platform-v2/src/registry/client/node-client.ts", "node-client* ungated-egress refusal + permit hard-require"],
  ["apps/platform-v2/src/merchants/serializers/movement.ts", "merchants/serializers/movement* amount_zkz wire + GR5"],
  ["apps/platform-v2/src/merchants/serializers/balance.ts", "merchants/serializers/balance* available_zkz wire"],
];

test("each money-path sentinel trips moneyPathHit (strict)", () => {
  for (const [path, why] of SENTINELS) {
    assert.equal(isMoneyPath(path), true, `expected money-path (${why}): ${path}`);
    const result = scanPaths([path]);
    assert.equal(result.moneyPathHit, true, `expected hit (${why}): ${path}`);
    assert.deepEqual(result.offendingPaths, [path], `offenders (${why}): ${path}`);
  }
});

// ---------------------------------------------------------------------------
// Benign paths -> moneyPathHit:false. Includes a docs file, a shared NON-money test
// file, shared non-money source, and plain app UI files.
// ---------------------------------------------------------------------------
const BENIGN = [
  "docs/README.md",
  "docs/decisions/D9.41.md",
  "packages/shared/src/contracts/checkout-events.test.ts", // shared NON-money test file
  "packages/shared/src/contracts/session.ts", // shared non-money source
  "packages/shared/src/contracts/shape-signature.ts", // "shape-signature" != **/sign* prefix
  "apps/platform/dashboard/src/pages/Home.tsx", // plain UI
  "apps/node/admin/src/components/Button.tsx", // plain UI
  "packages/widget/src/CheckoutApp.tsx", // plain UI
  "README.md",
  ".gitignore",
  // platform-v2 NEGATIVE controls (ZPAY-266 AC2): real paths that must NOT trip, proving
  // GROUP A2 is targeted subtrees, not apps/platform-v2/** wholesale.
  "apps/platform-v2/src/serve-spa.ts", // dashboard serving — the AC2 dashboard control
  "apps/platform-v2/src/health.ts", // non-money route
  "apps/platform-v2/src/api/v1/me.ts", // non-money route
  "apps/platform-v2/src/api/v1/events.ts", // non-money route
  "apps/platform-v2/src/shared/http/pagination.ts", // shared/http is NOT wholesale; only conventions*/amounts*
  "apps/platform-v2/src/identity/auth.middleware.ts", // auth, not money
  "apps/platform-v2/src/admin/adjudication.ts", // admin surface — deliberate exclusion
  // app.ts is the #2060 co-changed file: the AmountInvalidError onError mapping PRESENTS the
  // error; the decision lives in shared/http/conventions.ts, which trips. app.ts alone must not.
  "apps/platform-v2/src/app.ts",
  // Sibling negatives: registry/merchants file-targeted globs, not wholesale trees.
  "apps/platform-v2/src/registry/client/egress.ts", // SSRF egress allowlist — transport, not money decision
  "apps/platform-v2/src/merchants/serializers/node-view.ts", // no amount/GR5 fields
];

test("apps/generic-node money code (no funded backstop) trips moneyPathHit", () => {
  // The exact class the wholesale fix covers: a directory-organized money file whose name no
  // keyword glob matches, in the app that classifies ONLY to the inactive generic-node target.
  const path = "apps/generic-node/src/sweep/build-submit.ts";
  assert.equal(isMoneyPath(path), true);
  const result = scanPaths([path]);
  assert.equal(result.moneyPathHit, true);
  assert.deepEqual(result.offendingPaths, [path]);
});

test("benign paths do not trip moneyPathHit", () => {
  for (const path of BENIGN) {
    assert.equal(isMoneyPath(path), false, `expected benign: ${path}`);
  }
  const result = scanPaths(BENIGN);
  assert.equal(result.moneyPathHit, false);
  assert.deepEqual(result.offendingPaths, []);
});

// ---------------------------------------------------------------------------
// ZPAY-266 AC2: the platform-v2 rule proven over representative changed-path lists with
// the REAL scanner, including platform-v2 paths that must NOT trip (the missing negative
// control is how this gap survived). First case is the exact PR #2060 diff shape that
// proved the gap live (base 160335ee..head 1d3c127d read moneyPathHit:false).
// ---------------------------------------------------------------------------
test("ZPAY-266: the PR #2060 diff shape now trips (conventions.ts offends; app.ts alone would not)", () => {
  const result = scanPaths([
    "apps/platform-v2/src/app.ts",
    "apps/platform-v2/src/shared/http/conventions.ts",
  ]);
  assert.equal(result.moneyPathHit, true);
  assert.deepEqual(result.offendingPaths, ["apps/platform-v2/src/shared/http/conventions.ts"]);
});

test("ZPAY-266: representative platform-v2 diff — exact money offenders, non-money stays clean", () => {
  const result = scanPaths([
    "apps/platform-v2/src/api/v1/payouts.ts",
    "apps/platform-v2/src/movements/repositories/payout-repository.ts",
    "apps/platform-v2/src/serve-spa.ts",
    "apps/platform-v2/src/api/v1/me.ts",
    "apps/platform-v2/package.json", // deny-listed (deploy classifier's concern) even in a money diff
    "docs/README.md",
  ]);
  assert.equal(result.moneyPathHit, true);
  assert.deepEqual(result.offendingPaths, [
    "apps/platform-v2/src/api/v1/payouts.ts",
    "apps/platform-v2/src/movements/repositories/payout-repository.ts",
  ]);
  // A dashboard/ops-only platform-v2 diff still reads clean — the gate must stay quiet
  // where single review is enough, or it gets routed around.
  const clean = scanPaths([
    "apps/platform-v2/src/serve-spa.ts",
    "apps/platform-v2/src/api/v1/me.ts",
    "apps/platform-v2/src/admin/adjudication.ts",
  ]);
  assert.equal(clean.moneyPathHit, false);
  assert.deepEqual(clean.offendingPaths, []);
});

// Review B D1/D2: hop-away money modules (mutation-admission, wire serializers, node-client)
// must trip solo and in mixed diffs; co-changed benign must not appear as offenders.
test("ZPAY-266: D1/D2 admission + wire-serializer solo/mixed diffs trip exact offenders only", () => {
  const d1 = "apps/platform-v2/src/registry/client/mutation-admission.ts";
  const d2Move = "apps/platform-v2/src/merchants/serializers/movement.ts";
  const d2Bal = "apps/platform-v2/src/merchants/serializers/balance.ts";
  const nodeClient = "apps/platform-v2/src/registry/client/node-client.ts";
  for (const path of [d1, d2Move, d2Bal, nodeClient]) {
    assert.equal(isMoneyPath(path), true, path);
    assert.deepEqual(scanPaths([path]).offendingPaths, [path]);
  }
  const mixed = scanPaths([
    d1,
    d2Move,
    d2Bal,
    nodeClient,
    "apps/platform-v2/src/serve-spa.ts",
    "apps/platform-v2/src/api/v1/me.ts",
    "apps/platform-v2/src/app.ts",
    "apps/platform-v2/src/registry/client/egress.ts",
    "apps/platform-v2/src/merchants/serializers/node-view.ts",
    "apps/platform-v2/package.json",
  ]);
  assert.equal(mixed.moneyPathHit, true);
  assert.deepEqual(mixed.offendingPaths, [d2Bal, d2Move, d1, nodeClient].sort());
});

// ---------------------------------------------------------------------------
// Toolchain / manifest / lockfiles are the DEPLOY classifier's concern, never a
// money-path hit - even inside a money-path package.
// ---------------------------------------------------------------------------
test("toolchain/manifest files are deploy-classifier concern, never money-path", () => {
  const toolchain = [
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "tsconfig.json",
    "tsconfig.build.json",
    "packages/node-core/package.json", // inside a money-path package, still deny-listed
    "packages/node-core/tsconfig.json",
  ];
  for (const path of toolchain) {
    assert.equal(isMoneyPath(path), false, `expected deploy-classifier (deny) path: ${path}`);
  }
  assert.equal(scanPaths(toolchain).moneyPathHit, false);
});

// The deny-list must only suppress toolchain-ONLY diffs: a co-changed real money-path
// source still trips, and the toolchain file is excluded from the offender set.
test("a co-changed money-path source still trips alongside toolchain (deny is not a whole-diff pass)", () => {
  const result = scanPaths([
    "packages/node-core/package.json",
    "packages/node-core/src/protocol/signer.ts",
  ]);
  assert.equal(result.moneyPathHit, true);
  assert.deepEqual(result.offendingPaths, ["packages/node-core/src/protocol/signer.ts"]);
});

test("scanPaths returns sorted, deduped offenders", () => {
  const result = scanPaths([
    "packages/splitchain/src/signing.ts",
    "docs/README.md",
    "packages/splitchain/src/signing.ts",
    "packages/shared/src/vault-envelope.ts",
  ]);
  assert.deepEqual(result.offendingPaths, [
    "packages/shared/src/vault-envelope.ts",
    "packages/splitchain/src/signing.ts",
  ]);
});

// ---------------------------------------------------------------------------
// FAIL-CLOSED: any integrity failure resolves to moneyPathHit:true (strict). Uses an
// injectable git runner so the tests are hermetic (no real repo state required).
// ---------------------------------------------------------------------------
test("dirty working tree fails CLOSED to strict", () => {
  const dirtyGit = (args) => {
    if (args[0] === "status") return Buffer.from(" M packages/node-core/src/x.ts\n");
    throw new Error("git must not be called past the dirty-tree gate");
  };
  const result = scanDiffFailClosed({ git: dirtyGit });
  assert.equal(result.moneyPathHit, true);
  assert.equal(result.failClosed, true);
  assert.equal(result.reason, "DIRTY_TREE");
});

test("git failure anywhere fails CLOSED to strict", () => {
  const boomGit = () => {
    throw new Error("git exploded");
  };
  const result = scanDiffFailClosed({ git: boomGit });
  assert.equal(result.moneyPathHit, true);
  assert.equal(result.failClosed, true);
});

test("unparseable committed registry blob fails CLOSED to strict", () => {
  const badRegistryGit = (args) => {
    if (args[0] === "status") return Buffer.from("");
    if (args[0] === "rev-parse") return Buffer.from("HEADSHA\n");
    if (args[0] === "merge-base") return Buffer.from("BASESHA\n");
    if (args[0] === "show") return Buffer.from("not json {{{");
    return Buffer.from("");
  };
  const result = scanDiffFailClosed({ git: badRegistryGit });
  assert.equal(result.moneyPathHit, true);
  assert.equal(result.failClosed, true);
});

test("malformed diff (bad name-status) fails CLOSED to strict", () => {
  const badDiffGit = (args) => {
    if (args[0] === "status") return Buffer.from("");
    if (args[0] === "rev-parse") return Buffer.from("HEADSHA\n");
    if (args[0] === "merge-base") return Buffer.from("BASESHA\n");
    if (args[0] === "show") return Buffer.from('{"schemaVersion":1}');
    if (args[0] === "diff") return Buffer.from("ZZZ\0not-a-real-status\0"); // invalid status token
    return Buffer.from("");
  };
  const result = scanDiffFailClosed({ git: badDiffGit });
  assert.equal(result.moneyPathHit, true);
  assert.equal(result.failClosed, true);
});

test("degenerate base==head (post-merge merge-base collapse) fails CLOSED to strict", () => {
  // Post-merge, merge-base(origin/main, mergedHead) collapses to the head -> empty diff. That
  // empty diff is a legit "clean" answer and would NOT trip any other fail-closed trigger, so it
  // would silently clear (fail-OPEN). The DEGENERATE_RANGE guard turns that into strict.
  const collapseGit = (args) => {
    if (args[0] === "status") return Buffer.from("");
    if (args[0] === "rev-parse") return Buffer.from("SAMESHA\n");
    if (args[0] === "merge-base") return Buffer.from("SAMESHA\n"); // collapses to head
    if (args[0] === "show") return Buffer.from('{"schemaVersion":1}');
    if (args[0] === "diff") throw new Error("diff must not run on a degenerate self-range");
    return Buffer.from("");
  };
  const result = scanDiffFailClosed({ git: collapseGit });
  assert.equal(result.moneyPathHit, true);
  assert.equal(result.failClosed, true);
  assert.equal(result.reason, "DEGENERATE_RANGE");
});

// ---------------------------------------------------------------------------
// Diff-derived HAPPY paths (clean tree, valid registry, well-formed diff).
// ---------------------------------------------------------------------------
test("clean diff containing a money-path file -> strict, not fail-closed", () => {
  const cleanGit = (args) => {
    if (args[0] === "status") return Buffer.from("");
    if (args[0] === "rev-parse") return Buffer.from("HEADSHA\n");
    if (args[0] === "merge-base") return Buffer.from("BASESHA\n");
    if (args[0] === "show") return Buffer.from('{"schemaVersion":1}');
    if (args[0] === "diff") return Buffer.from("M\0packages/splitchain/src/signing.ts\0");
    return Buffer.from("");
  };
  const result = scanDiffFailClosed({ git: cleanGit });
  assert.equal(result.failClosed, false);
  assert.equal(result.moneyPathHit, true);
  assert.deepEqual(result.offendingPaths, ["packages/splitchain/src/signing.ts"]);
  assert.equal(result.base, "BASESHA");
  assert.equal(result.head, "HEADSHA");
});

test("clean diff with only benign files -> not a money-path hit", () => {
  const cleanGit = (args) => {
    if (args[0] === "status") return Buffer.from("");
    if (args[0] === "rev-parse") return Buffer.from("HEADSHA\n");
    if (args[0] === "merge-base") return Buffer.from("BASESHA\n");
    if (args[0] === "show") return Buffer.from('{"schemaVersion":1}');
    if (args[0] === "diff") {
      return Buffer.from("M\0docs/README.md\0M\0apps/platform/dashboard/src/pages/Home.tsx\0");
    }
    return Buffer.from("");
  };
  const result = scanDiffFailClosed({ git: cleanGit });
  assert.equal(result.failClosed, false);
  assert.equal(result.moneyPathHit, false);
  assert.deepEqual(result.offendingPaths, []);
});

test("explicit --base/--head are canonicalized to SHAs, no merge-base", () => {
  const calls = [];
  const git = (args) => {
    calls.push(args[0]);
    if (args[0] === "status") return Buffer.from("");
    if (args[0] === "rev-parse") {
      // resolve "<ref>^{commit}" -> a deterministic fake SHA for that ref
      const ref = args[args.length - 1].replace(/\^\{commit\}$/, "");
      return Buffer.from(`${ref}-sha\n`);
    }
    if (args[0] === "show") return Buffer.from('{"schemaVersion":1}');
    if (args[0] === "diff") return Buffer.from("A\0packages/node-core/src/schema/x.sql\0");
    return Buffer.from("");
  };
  const result = diffPaths({ base: "B0", head: "H0", git });
  assert.equal(result.base, "B0-sha");
  assert.equal(result.head, "H0-sha");
  assert.deepEqual(result.paths, ["packages/node-core/src/schema/x.sql"]);
  assert.ok(!calls.includes("merge-base"), "must not compute merge-base when base is explicit");
});

// The degeneracy guard must survive ref-vs-SHA endpoint spellings (e.g. `--head origin/main`
// where head stays a ref but base resolves to a SHA). Canonicalizing both to SHAs first is what
// makes base===head detectable.
test("ref-vs-SHA endpoints that resolve to the same commit fail CLOSED (not a silent clear)", () => {
  const git = (args) => {
    if (args[0] === "status") return Buffer.from("");
    // both "origin/main^{commit}" and the merge-base resolve to the SAME sha
    if (args[0] === "rev-parse") return Buffer.from("SAME40SHA\n");
    if (args[0] === "merge-base") return Buffer.from("SAME40SHA\n");
    if (args[0] === "show") return Buffer.from('{"schemaVersion":1}');
    if (args[0] === "diff") throw new Error("diff must not run on a degenerate self-range");
    return Buffer.from("");
  };
  const result = scanDiffFailClosed({ head: "origin/main", git });
  assert.equal(result.moneyPathHit, true);
  assert.equal(result.failClosed, true);
  assert.equal(result.reason, "DEGENERATE_RANGE");
});

// ---------------------------------------------------------------------------
// Orthogonality (non-vacuous): the two review-DEPTH gates are SEPARATE and both
// axes must be asserted together. A path that is merely "not money-path" does not prove
// the control-tier partition — that would stay green if classify always-strict or
// always-benign. Each case loads both modules and checks (isMoneyPath===false) AND
// (classifyPaths.manualReviewRequired === expectedTier).
// ---------------------------------------------------------------------------
test("AC1/AC2 cross-module: money-path false AND classify tier expected", () => {
  /** @type {Array<[string, boolean]>} path -> expected manualReviewRequired */
  const cases = [
    // benign-governance: not money-path, not strict
    ["docs/DECISIONS.md", false],
    ["CLAUDE.md", false],
    ["AGENTS.md", false],
    [".claude/agents/reviewer.md", false],
    [".claude/agents/merger.md", false],
    // funded-affecting-control: not money-path, but STRICT via classifyPaths
    ["scripts/money-path-scan.mjs", true],
    ["scripts/release-targets.mjs", true],
    ["scripts/release-targets-strict-dual.mjs", true],
    ["release/targets.v1.json", true],
    ["scripts/verdict-integrity.mjs", true],
    ["scripts/check-decision-ids.sh", true],
    ["scripts/check-decision-citations.sh", true],
    ["scripts/check-decision-citation-support.sh", true],
    ["scripts/check-decision-citation-support.py", true],
    ["scripts/check-decision-pins.sh", true],
    ["scripts/check-decision-pins.py", true],
    [".github/workflows/ci.yml", true],
  ];
  for (const [path, expectedMrr] of cases) {
    assert.equal(isMoneyPath(path), false, `must not be money-path: ${path}`);
    const classified = classifyPaths([path]);
    assert.equal(
      classified.manualReviewRequired,
      expectedMrr,
      `classify mrr for ${path}: expected ${expectedMrr}`,
    );
    assert.deepEqual(classified.affectedTargets, [], `no deploy fan-out: ${path}`);
    assert.deepEqual(classified.controlPaths, [path]);
  }
  // Batch scan still clean across both tiers
  assert.equal(
    scanPaths([
      "docs/DECISIONS.md",
      "CLAUDE.md",
      "scripts/release-targets.mjs",
      "release/targets.v1.json",
      "scripts/check-decision-ids.sh",
    ]).moneyPathHit,
    false,
  );
});

test("AC3 mixed apps/node + CLAUDE.md: money-path detection unchanged by control paths", () => {
  // A plain apps/node source file + a benign-governance control path -> no money-path surface.
  assert.equal(scanPaths(["apps/node/src/server.ts", "CLAUDE.md"]).moneyPathHit, false);
  // A real apps/node money file still trips regardless of a co-changed governance doc.
  const withMoney = scanPaths(["apps/node/src/wallet/transfer-code-builder.ts", "CLAUDE.md"]);
  assert.equal(withMoney.moneyPathHit, true);
  assert.deepEqual(withMoney.offendingPaths, ["apps/node/src/wallet/transfer-code-builder.ts"]);
  // Cross-module: classify still sees SOURCE_PATH funded + benign control, no strict
  const classified = classifyPaths(["apps/node/src/server.ts", "CLAUDE.md"]);
  assert.equal(classified.manualReviewRequired, false);
  assert.ok(classified.affectedTargets.some((t) => t.id === "funded-manual-node"));
  assert.deepEqual(classified.controlPaths, ["CLAUDE.md"]);
});

// ---------------------------------------------------------------------------
// Guard the exported glob set so an accidental edit that removes a sentinel layer or
// widens shared/** wholesale is caught here.
// ---------------------------------------------------------------------------
test("glob set exposes the four layers and does not flag packages/shared or platform-v2 wholesale", () => {
  assert.ok(MONEY_PATH_GLOB_SET.packages.includes("apps/generic-node/**"));
  assert.ok(MONEY_PATH_GLOB_SET.packages.includes("packages/node-core/**"));
  assert.ok(MONEY_PATH_GLOB_SET.packages.includes("packages/generic-node-contracts/**"));
  assert.ok(MONEY_PATH_GLOB_SET.namePatterns.includes("**/sign*"));
  assert.ok(MONEY_PATH_GLOB_SET.deny.includes("**/package.json"));
  const flagsAllShared = [
    ...MONEY_PATH_GLOB_SET.packages,
    ...MONEY_PATH_GLOB_SET.platformV2,
    ...MONEY_PATH_GLOB_SET.namePatterns,
  ].some((glob) => glob === "packages/shared/**");
  assert.equal(flagsAllShared, false, "packages/shared/** must never be flagged wholesale");
  // ZPAY-266: the platform-v2 layer is targeted subtrees/files, never the app wholesale —
  // an over-noisy gate gets disabled, which is worse than a narrow one.
  assert.ok(MONEY_PATH_GLOB_SET.platformV2.length > 0, "platform-v2 layer must exist");
  assert.ok(
    MONEY_PATH_GLOB_SET.platformV2.every((glob) => glob.startsWith("apps/platform-v2/src/")),
    "platform-v2 globs stay inside apps/platform-v2/src",
  );
});

// ZPAY-266 AC3: widen, never narrow. The pre-ZPAY-266 layers are FROZEN byte-for-byte
// (append-only discipline): removing or reordering an existing glob is a sentinel
// regression this test exists to catch.
test("ZPAY-266 AC3: pre-existing package and name-pattern layers are unchanged", () => {
  assert.deepEqual(
    [...MONEY_PATH_GLOB_SET.packages],
    [
      "apps/generic-node/**",
      "packages/node-core/**",
      "packages/generic-node-contracts/**",
      "packages/splitchain/**",
      "**/vault-client/**",
    ],
  );
  assert.deepEqual(
    [...MONEY_PATH_GLOB_SET.namePatterns],
    [
      "**/sign*",
      "**/vault*",
      "**/sweep*",
      "**/transfer-code*",
      "**/*.golden",
      "**/__vectors__/**",
      "**/schema/**",
      "**/migrations/**",
    ],
  );
  assert.deepEqual(
    [...MONEY_PATH_GLOB_SET.deny],
    [
      "**/package.json",
      "**/package-lock.json",
      "**/pnpm-lock.yaml",
      "pnpm-lock.yaml",
      "pnpm-workspace.yaml",
      "**/tsconfig*.json",
    ],
  );
});
