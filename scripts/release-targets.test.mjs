// Release-targets classifier tests — Generic Node registry shape.
// Proves: validate, classify control/money/deploy paths, registry provenance basics.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  classifyPaths,
  loadRegistry,
  matchesGlob,
  stableStringify,
  validateRegistry,
} from "./release-targets.mjs";

const cloneRegistry = () => structuredClone(loadRegistry());

test("validateRegistry accepts the committed GN registry", () => {
  const registry = validateRegistry();
  assert.equal(registry.schemaVersion, 1);
  const ids = registry.targets.map((t) => t.id).sort();
  assert.deepEqual(ids, [
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
  ]);
  const gn = registry.targets.find((t) => t.id === "generic-node");
  assert.equal(gn.active, true);
  assert.equal(gn.configPath, "apps/generic-node/railway.json");
  assert.equal(gn.approval, "riley-explicit-in-session");
  assert.equal(gn.liveAcceptance, "not-required-no-custody");
});

test("generic-node source + contracts classify to the generic-node target", () => {
  const result = classifyPaths([
    "apps/generic-node/src/index.ts",
    "packages/node-core/src/sign.ts",
    "packages/generic-node-contracts/src/index.ts",
    "packages/generic-node-consumer/src/index.ts",
    "packages/consumer-example/src/index.ts",
  ]);
  assert.equal(result.manualReviewRequired, false);
  assert.deepEqual(
    result.affectedTargets.map((t) => t.id).sort(),
    ["generic-node"],
  );
  assert.deepEqual(result.controlPaths, []);
});

test("toolchain roots classify to generic-node (GN monorepo root)", () => {
  const result = classifyPaths([
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "tsconfig.json",
    "tsconfig.base.json",
  ]);
  assert.equal(result.manualReviewRequired, false);
  assert.ok(result.affectedTargets.some((t) => t.id === "generic-node"));
});

test("funded-affecting-control paths force manualReviewRequired without deploy fan-out", () => {
  for (const path of [
    "release/targets.v1.json",
    "scripts/release-targets.mjs",
    "scripts/release-targets-strict-dual.mjs",
    "scripts/money-path-scan.mjs",
    "scripts/claim.py",
    "scripts/release-targets-verdict-evidence.mjs",
    "scripts/check-decision-ids.sh",
    ".github/workflows/ci.yml",
  ]) {
    const result = classifyPaths([path]);
    assert.equal(result.manualReviewRequired, true, path);
    assert.deepEqual(result.controlPaths, [path], path);
    assert.deepEqual(result.affectedTargets, [], path);
  }
});

test("benign-governance control paths do NOT force manualReviewRequired", () => {
  for (const path of [
    "CLAUDE.md",
    "AGENTS.md",
    "docs/DECISIONS.md",
    ".claude/agents/reviewer.md",
    ".claude/agents/merger.md",
  ]) {
    const result = classifyPaths([path]);
    assert.equal(result.manualReviewRequired, false, path);
    assert.deepEqual(result.controlPaths, [path], path);
  }
});

test("ignored docs and markdown are not unclassified", () => {
  const result = classifyPaths(["docs/operations/runbook.md", "README.md", "tasks/todo.md"]);
  assert.equal(result.manualReviewRequired, false);
  assert.ok(result.ignoredPaths.length >= 2);
  assert.deepEqual(result.affectedTargets, []);
});

test("unknown non-documentation path refuses closed", () => {
  assert.throws(
    () => classifyPaths(["unowned/input.bin"]),
    (error) => error.code === "UNCLASSIFIED_PATH",
  );
});

test("generic-node watchPatterns match apps/generic-node/railway.json", () => {
  const registry = validateRegistry(); // checkFiles:true — drift fails here
  const gn = registry.targets.find((t) => t.id === "generic-node");
  assert.deepEqual(gn.watchPatterns, [
    "/apps/generic-node/**",
    "/packages/node-core/**",
    "/pnpm-lock.yaml",
    "/pnpm-workspace.yaml",
    "/tsconfig.base.json",
  ]);
});

test("custody tripwire: active generic-node without zero-custody or Riley gate fails", () => {
  const registry = cloneRegistry();
  const gn = registry.targets.find((t) => t.id === "generic-node");
  gn.liveAcceptance = "custody-present-unbounded";
  gn.approval = "normal-release-gate";
  assert.throws(
    () => validateRegistry(registry, { checkFiles: false }),
    (error) => error.code === "GENERIC_NODE_CUSTODY_TRIPWIRE",
  );
});

test("funded target hybrid posture is rejected", () => {
  const registry = cloneRegistry();
  const funded = registry.targets.find((t) => t.id === "funded-manual-node");
  // Make active with hybrid unsafe fields
  funded.active = true;
  funded.deployMode = "automatic";
  funded.approval = "riley-explicit-in-session"; // hybrid with automatic
  funded.liveAcceptance = "real-zkz-gated";
  funded.externalBinding = {
    driftCheck: "scheduled-read-only",
    logicalService: "funded-manual-node",
    logicalEnvironment: "production",
    sourceMode: "repository",
    branch: "main",
    configPath: "railway.json",
  };
  assert.throws(
    () => validateRegistry(registry, { checkFiles: false }),
    (error) => error.code === "FUNDED_TARGET_UNSAFE",
  );
});

test("stableStringify is insertion-order independent", () => {
  assert.equal(
    stableStringify({ b: 1, a: 2 }),
    stableStringify({ a: 2, b: 1 }),
  );
});

test("matchesGlob supports ** and single-segment *", () => {
  assert.equal(matchesGlob("apps/generic-node/src/x.ts", "apps/generic-node/**"), true);
  assert.equal(matchesGlob("apps/generic-node/src/x.ts", "apps/*/src/x.ts"), true);
  assert.equal(matchesGlob("apps/other/src/x.ts", "apps/generic-node/**"), false);
});

test("ORCHESTRATION.md is funded-affecting-control (gate docs cannot be stripped under benign)", () => {
  const result = classifyPaths(["ORCHESTRATION.md"]);
  assert.equal(result.manualReviewRequired, true);
  assert.deepEqual(result.controlPaths, ["ORCHESTRATION.md"]);
});

test("mixed money source + control path: control does not fan into deploy targets", () => {
  const result = classifyPaths([
    "apps/generic-node/src/index.ts",
    "release/targets.v1.json",
  ]);
  assert.equal(result.manualReviewRequired, true);
  assert.ok(result.affectedTargets.some((t) => t.id === "generic-node"));
  assert.deepEqual(result.controlPaths, ["release/targets.v1.json"]);
});
