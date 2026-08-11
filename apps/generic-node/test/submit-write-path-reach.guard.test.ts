// The app-tree half of the submit write-path reach census.
//
// Protected properties: "SEND_EXTERNAL has no node submit function in its type
// graph"; the claim-and-submit-once path belongs to MOVE_INTERNAL; the never-blind-retry rule.
//
// A sibling suite brings packages/node-core/src under a census keyed to
// core/submit-decision-claim-store.ts, and declares its
// own ceiling: it covers that package ONLY. This file stands alone and does not depend on it. apps/generic-node/src imports the @zucoins/node-core ROOT BARREL, and that barrel
// re-exports core/index.ts, which re-exports the write path — so every app module with a
// value-import path to the barrel was an undeclared cross-package reacher. This file closes
// that gap with the same mechanism, extended across the package boundary: the specifier
// `@zucoins/node-core` is RESOLVED into packages/node-core/src and the walk continues there,
// so the reacher set is measured end to end rather than stopped at the package edge.
//
// What this is NOT. Reaching the write-path MODULE is not calling it. No module in
// apps/generic-node/src names either factory, names either ledger, is SEND-named, or
// mentions SEND_EXTERNAL — all four are asserted below. This is a LATENT gap being brought
// under declaration, not a live breach being fixed.
//
// Why the census shape rather than "prove no SEND app module reaches the sink": that
// question needs a derived membership set (which app modules are SEND), and a derivation
// that under-approximates makes every downstream assertion pass vacuously — the exact
// defect three review rounds were spent fixing. The census asks instead which modules
// have the sink in their value-import closure and asserts that set EXACTLY. A new reacher
// enters the computed side and reddens unconditionally; a degraded analyser empties the
// computed side and reddens against the non-empty declared side, rather than passing.
//
// Declared ceilings. This file does NOT prove:
//   * anything about the OTHER consumers of @zucoins/node-core, or about test files in
//     this tree. Production `src` of this app only.
//   * that a SECOND submit write path is unreachable. The census is keyed to
//     core/submit-decision-claim-store.ts.
//   * that raw-SQL ledger writes are impossible. That is structural work, not a test:
//     deferred structural work.
//
// Dynamic require-minting that would leave a silent non-edge is FAIL-CLOSED here (thrown
// on, not followed): `eval`, `new Function`, bare/aliased `createRequire`, any import of
// `node:module`/`module`, and `process.getBuiltinModule(...)` (which can hand out
// createRequire under an arbitrary binding without a node:module import). Other runtime
// reflection not named above remains a ceiling — this file does not attempt to close it.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const here = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = resolve(here, "../../..");
const APP_SRC = resolve(repoRoot, "apps/generic-node/src");
const CORE_SRC = resolve(repoRoot, "packages/node-core/src");

const APP_PREFIX = "apps/generic-node/src/";
const CORE_BARREL = "packages/node-core/src/index.ts";
const WRITE_PATH_MODULE = "packages/node-core/src/core/submit-decision-claim-store.ts";
// The RECEIVE_EXTERNAL submit-once service and its one production caller.
const RECEIVE_SUBMIT_ONCE_MODULE = "packages/node-core/src/core/receive-submit-once.ts";
const RECEIVE_SETTLE_MODULE = "packages/node-core/src/core/receive-settle.ts";
const CANDIDATE_INTAKE_MODULE = "packages/node-core/src/receive/candidate-intake.ts";
const CANDIDATE_INTAKE_APP_MODULE = `${APP_PREFIX}money-workers/receive-candidate-intake-step.ts`;

/**
 * The app modules permitted to name a write-path factory or submit ledger. The flow
 * contract gives RECEIVE_EXTERNAL a node submit, so the settle step legitimately builds the
 * claim store and attempt recorder. A second entry here needs the same justification against
 * the no-SEND-submit property.
 */
const RECEIVE_WRITE_PATH_CALLERS = ["money-workers/receive-settle-step.ts"] as const;

/**
 * The flow contract gives MOVE_INTERNAL a node submit (the one-shot claim + gateway
 * submit), so move-advanced-ports.ts legitimately builds the claim store and attempt recorder
 * via bindExecuteMoveSubmitClaimOnce. Same No-blind-retry claim-before-submit gate as RECEIVE.
 */
const MOVE_WRITE_PATH_CALLERS = ["money-workers/move-advanced-ports.ts"] as const;

/**
 * The recovery fact-gatherer reads
 * gateway_submit_attempts (SELECT only, no factory) to derive noAnomalyOrSubmitReconcileDebt.
 * This is reconciliation READ access, not a submit write-path caller — distinct from the two
 * lists above, which build claim/attempt factories to WRITE the ledger.
 */
const RECOVERY_READ_CALLERS = ["operations/sql-recovery-store.ts"] as const;

// The two factories and the two ledgers. Asserted
// absent from the whole app tree below: reaching the barrel is not calling the write path,
// and today no app module does either.
const WRITE_PATH_MARKERS = [
  "makeSubmitDecisionClaimStore",
  "makeSubmitAttemptRecorder",
  "submit_decisions",
  "gateway_submit_attempts",
] as const;

function listTsFiles(dir: string): string[] {
  return (readdirSync(dir, { recursive: true }) as string[])
    .map((entry) => join(dir, entry))
    .filter((file) => extname(file) === ".ts" && statSync(file).isFile());
}

// Import/export specifiers that survive compilation, i.e. real runtime edges. PARSED, not
// matched: a prior measurement showed regex source pre-processing over-stripping real code inside
// string literals in 278/2133 files, and a regex has anchors a comment or a newline can
// slip past — a silently dropped edge is exactly how a reach check goes vacuous. A parser
// has no anchors. Shared shape with packages/node-core/test/submit-write-path.guard.test.ts
//  by design: one mechanism, applied on both sides of the package boundary.
//
// `import type` / `export type`, and brace lists whose every element is `type`-prefixed,
// are erased by tsc and are not edges. apps/generic-node/src has real instances
// of this — reporting/row-mappers.ts imports five node-core types and nothing else — so
// following them would flag modules the runtime never loads.
function valueImportEdges(text: string, fileLabel = "<inline>"): string[] {
  const source = ts.createSourceFile(fileLabel, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const specifiers: string[] = [];
  const firstLine = (node: ts.Node): string => node.getText(source).split("\n")[0] as string;

  const clauseIsValue = (clause: ts.ImportClause): boolean => {
    if (clause.isTypeOnly) return false;
    if (clause.name !== undefined) return true; // default binding
    const bindings = clause.namedBindings;
    if (bindings === undefined) return false;
    if (ts.isNamespaceImport(bindings)) return true;
    return bindings.elements.some((element) => !element.isTypeOnly);
  };

  // A module specifier that is not a string literal cannot be followed. Throwing rather
  // than dropping is the doctrine for every unresolvable edge in this file.
  const specifierOf = (node: ts.ImportDeclaration | ts.ExportDeclaration): string => {
    const moduleSpecifier = node.moduleSpecifier;
    if (moduleSpecifier === undefined || !ts.isStringLiteralLike(moduleSpecifier)) {
      throw new Error(`non-literal module specifier: ${firstLine(node)}`);
    }
    return moduleSpecifier.text;
  };

  // Every edge is pushed through here, because `node:module` has to be caught wherever it
  // arrives. It hands out `createRequire`, and the callable it mints can be bound under ANY
  // name — `import { createRequire as cr }`, `import * as m` then `m.createRequire`,
  // `const { createRequire: alias } = await import("node:module")`. A check keyed on the
  // SPELLING of the callee is defeated by the first and third with no throw and no edge: the
  // require() call silently becomes a non-edge, which is the vacuity mode this whole file
  // exists to prevent (found by round-4 adversarial review). The SPECIFIER is the
  // one thing every aliasing form has in common, so that is where it is caught.
  const push = (specifier: string, node: ts.Node): void => {
    if (specifier === "node:module" || specifier === "module") {
      throw new Error(`node:module mints require() under an arbitrary name: ${firstLine(node)}`);
    }
    specifiers.push(specifier);
  };

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      // A side-effect import (`import "./x.js";`) carries no binding but does load the module.
      if (node.importClause === undefined || clauseIsValue(node.importClause)) {
        push(specifierOf(node), node);
      }
    } else if (ts.isImportEqualsDeclaration(node)) {
      // `import legacy = require("./x.js")` is a real runtime edge, and its module reference is
      // an ExternalModuleReference — NOT a CallExpression — so the call arm below never sees it
      // and tsc's own child walk yields no node any other arm matches. Before this arm the edge
      // was dropped in silence (round-4 review). A type-only one is erased, as ever.
      const reference = node.moduleReference;
      if (!node.isTypeOnly && ts.isExternalModuleReference(reference)) {
        if (!ts.isStringLiteralLike(reference.expression)) {
          throw new Error(`unresolvable import-equals reference: ${firstLine(node)}`);
        }
        push(reference.expression.text, node);
      }
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) {
      const clause = node.exportClause;
      if (
        !node.isTypeOnly &&
        (clause === undefined || // `export * from "./x.js"`
          ts.isNamespaceExport(clause) || // `export * as ns from "./x.js"`
          clause.elements.some((element) => !element.isTypeOnly))
      ) {
        push(specifierOf(node), node);
      }
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const argument = node.arguments[0];
      const isLiteralArgument = argument !== undefined && ts.isStringLiteralLike(argument);
      if (callee.kind === ts.SyntaxKind.ImportKeyword) {
        if (!isLiteralArgument) {
          throw new Error(`computed dynamic import() is not statically resolvable: ${firstLine(node)}`);
        }
        push(argument.text, node);
      } else {
        const name = ts.isIdentifier(callee)
          ? callee.text
          : ts.isPropertyAccessExpression(callee)
            ? callee.name.text
            : undefined;
        // eval("require") and friends mint a callable under an unknown name with no import
        // edge — silent non-edge if dropped. Throw rather than follow (r2 adversarial).
        if (name === "eval") {
          throw new Error(`eval is not statically resolvable: ${firstLine(node)}`);
        }
        // process.getBuiltinModule("node:module") hands out createRequire without any
        // node:module import specifier for `push` to catch. Alias-destructure then escapes
        // the createRequire spelling check (r2 adversarial).
        if (name === "getBuiltinModule") {
          throw new Error(
            `process.getBuiltinModule mints builtins under an arbitrary name: ${firstLine(node)}`,
          );
        }
        // A second line of defence for the un-aliased spellings, kept for the precise message.
        // The specifier rule in `push` is what actually closes the aliased forms.
        if (name === "createRequire" || (name === "require" && !isLiteralArgument)) {
          throw new Error(`unresolvable require() edge: ${firstLine(node)}`);
        }
        if (name === "require" && isLiteralArgument) push(argument.text, node);
      }
    } else if (ts.isNewExpression(node)) {
      // `new Function("return require")()` is the constructor form of the same eval class.
      const ctor = node.expression;
      if (ts.isIdentifier(ctor) && ctor.text === "Function") {
        throw new Error(`new Function is not statically resolvable: ${firstLine(node)}`);
      }
    }
    ts.forEachChild(node, visit);
  };

  ts.forEachChild(source, visit);
  return specifiers;
}

// The cross-package half — the whole point of this file. `@zucoins/node-core` is a real
// runtime edge into another package's source, and stopping the walk at it is precisely the
// blindness the node-core census declared. The mapping mirrors packages/node-core/package.json
// `exports` (`.` -> dist/index.js, `./x` -> dist/x/index.js) back onto the .ts sources it
// compiles from, which is the same mapping apps/generic-node/vitest.config.ts already
// aliases at runtime. Anything unresolvable throws rather than pruning the walk.
function resolveModule(fromFile: string, specifier: string): string | null {
  if (specifier === "@zucoins/node-core") return resolve(CORE_SRC, "index.ts");
  if (specifier.startsWith("@zucoins/node-core/")) {
    const candidate = resolve(CORE_SRC, specifier.slice("@zucoins/node-core/".length), "index.ts");
    if (existsSync(candidate)) return candidate;
    throw new Error(`unresolvable node-core subpath "${specifier}" in ${relative(repoRoot, fromFile)}`);
  }
  if (!specifier.startsWith(".")) return null; // node: builtins and other packages
  const target = resolve(dirname(fromFile), specifier);
  for (const candidate of [target.replace(/\.js$/, ".ts"), `${target}.ts`, join(target, "index.ts")]) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  throw new Error(`unresolvable import "${specifier}" in ${relative(repoRoot, fromFile)}`);
}

// Both trees, because the path from an app module to the sink runs through node-core.
function productionSourceFiles(): string[] {
  return [...listTsFiles(APP_SRC), ...listTsFiles(CORE_SRC)]
    .filter((file) => !file.endsWith(".test.ts"))
    .map((file) => relative(repoRoot, file))
    .sort();
}

function crossPackageImportGraph(): Map<string, string[]> {
  const graph = new Map<string, string[]>();
  for (const rel of productionSourceFiles()) {
    const file = resolve(repoRoot, rel);
    const edges = valueImportEdges(readFileSync(file, "utf8"), rel)
      .map((specifier) => resolveModule(file, specifier))
      .filter((resolved): resolved is string => resolved !== null)
      .map((resolved) => relative(repoRoot, resolved));
    graph.set(rel, edges);
  }
  return graph;
}

// Which modules have `sink` in their value-import closure. Walked BACKWARDS over the
// reversed graph rather than forwards from a derived entry set, which also makes the walk
// trivially cycle-safe. Pure, so the proofs below drive it on in-memory graphs.
function submitReachers(graph: ReadonlyMap<string, readonly string[]>, sink: string): string[] {
  const importers = new Map<string, string[]>();
  for (const [from, targets] of graph) {
    for (const target of targets) {
      const list = importers.get(target);
      if (list === undefined) importers.set(target, [from]);
      else list.push(from);
    }
  }
  const reachers = new Set<string>();
  const queue = [sink];
  while (queue.length > 0) {
    const module = queue.pop() as string;
    for (const importer of importers.get(module) ?? []) {
      if (reachers.has(importer)) continue;
      reachers.add(importer);
      queue.push(importer);
    }
  }
  reachers.delete(sink); // a cycle through the sink must not make it its own reacher
  return [...reachers].sort();
}

// The declared set: 26 of the app's 53 production modules, keyed relative to
// apps/generic-node/src. The value names the EDGE that puts each one in the set — either
// the line of its own `@zucoins/node-core` import, or the first hop of its path — so
// adding a line to this list means naming the import that caused it, and a reviewer can
// check the claim in one grep.
//
// The expected failure mode is barrel churn: any app module that starts importing
// @zucoins/node-core for an entirely unrelated reason joins this list, and a benign
// failure that gets rubber-stamped is how a list like this rots. The substantive
// assertions are the four below it — no factory name, no ledger name, no SEND-named
// module, no SEND_EXTERNAL mention anywhere in this tree — and those are what a new entry
// must be checked against.
//
// The remaining 27 modules do NOT reach: the whole dr/ subtree, db/, config/constants,
// issues and placeholders, stage1-*, boot/graceful-stop, reporting/pg-client and
// reporting/row-mappers (type-only import of five node-core types, erased by tsc).
const APP_SUBMIT_WRITE_PATH_REACHERS: Readonly<Record<string, string>> = {
  "admin-inventory/index.ts":
    "-> admin-inventory/store.ts (inventory barrel; no submit write call site)",
  "admin-inventory/store.ts":
    "@zucoins/node-core (inventory reads; no submit write call site)",
  "admin-inventory/types.ts":
    "@zucoins/node-core:WALLET_CUSTODY_VIEW_FIELDS (allowlist; no submit write call site)",
  "admin-router.ts": "@zucoins/node-core:1 (admin money mount; no submit write call site)",
  "boot/boot-lane.ts": "@zucoins/node-core:57",
  "boot/index.ts": "-> boot/readiness.ts (./readiness.js:1)",
  "boot/readiness.ts": "@zucoins/node-core:11",
  "boot/shutdown-registry.ts": "@zucoins/node-core:34",
  "boot/signer-leadership-retry.ts":
    "@zucoins/node-core:15 (acquireSignerLeadership bounded-retry wrapper; no submit write call site)",
  "boot/sql-boot-recovery.ts":
    "@zucoins/node-core:7 (SUBMIT_LEDGER_TABLES read-only table-name constant for the boot recovery inventory query; no submit write call site)",
  "bootstrap/genesis.ts": "@zucoins/node-core:1 (genesis; admin/credential bootstrap — no submit write call site)",
  "bootstrap/reporting-key-enrol.ts":
    "@zucoins/node-core:1 (reporting-key enrol; buildReportingRegister only — no submit write call site)",
  "config/env-fields.ts": "@zucoins/node-core:5",
  "config/env-schema.ts": "@zucoins/node-core:30",
  "config/index.ts": "-> config/env-schema.ts (./env-schema.js:2)",
  "config/load.ts": "-> config/env-schema.ts (./env-schema.js:7)",
  "config/mutable.ts": "@zucoins/node-core:28",
  "dr/cli.ts":
    "@zucoins/node-core:1 (DR CLI entry; latent barrel reach — no submit write call site)",
  "dr/drill.ts":
    "@zucoins/node-core:1 (DR drill orchestration; no submit write call site)",
  "dr/index.ts":
    "-> dr/drill.ts (DR barrel; no submit write call site)",
  // Node-origin embed shell. Value-imports buildCheckoutCsp + computeSecurityHeaders
  // (response security headers) from the barrel; serves static embed HTML only —
  // latent barrel reach, no submit factory or ledger call site.
  "embed-spa.ts":
    "@zucoins/node-core:21 (embed CSP + security headers; no submit write call site)",
  "gateway/observed-read.ts":
    "@zucoins/node-core:1 (gateway observed-read adapter; OBSERVE only — no submit write call site)",
  "health/index.ts": "-> health/routes.ts (./routes.js:1)",
  "health/routes.ts": "@zucoins/node-core:18",
  "http-adapter.ts": "@zucoins/node-core:18",
  "index.ts": "@zucoins/node-core:4",
  "main.ts": "@zucoins/node-core:45",
  "lab-receive.ts": "@zucoins/node-core:1 (lab receive; no submit write call site)",
  // composition-root wiring for the /metrics snapshot source (readiness verdict +
  // DB-truth counters) and its safety-alert evaluation. Both are read-only: neither names a
  // submit factory or the submit ledger; latent barrel reach only.
  "metrics/custody-alerts.ts":
    "@zucoins/node-core:1 (safety-alert evaluator composition; log-only delivery — no submit write call site)",
  "metrics/routes.ts": "@zucoins/node-core:12",
  "metrics/snapshot-source.ts":
    "@zucoins/node-core:1 (/metrics DB-truth snapshot + readiness verdict; read-only — no submit write call site)",
  // Money worker loops + gateway T0 OBSERVE +
  // recovery ceremony + SEND post-approve formation. Latent barrel reach only (no submit
  // factory/ledger markers). SEND formation never submits (privilege tests assert).
  "money-workers/gateway-t0-observer.ts":
    "@zucoins/node-core:1 (get_transaction__v1 OBSERVE; no submit write call site)",
  "money-workers/genesis-t0-observer.ts": "@zucoins/node-core:1 (T0 stub observe; no submit write call site)",
  "money-workers/index.ts": "-> money-workers/start-money-workers.ts (./start-money-workers.js:1)",
  // Land-time access-window open. Called from landing stores after durable
  // land; issues verification_material_access_windows OPEN row. No submit factory or ledger.
  "money-workers/issue-landed-access-window.ts":
    "@zucoins/node-core:1 (land access-window open; no submit write call site)",
  "money-workers/move-internal-worker.ts":
    "@zucoins/node-core:1 (MOVE_INTERNAL worker shell; progress loader + acquireMoveLeases; no app-local ledger SQL / no submit write call site)",
  // MOVE_INTERNAL advanced ports (baseline/form/sign/submit/land). The submitOnce
  // port uses bindExecuteMoveSubmitClaimOnce (node-core helper) — same claim-before-submit
  // gate as RECEIVE settle (No-blind-retry). The module itself is a composition root, not a direct caller.
  "money-workers/move-advanced-ports.ts":
    "@zucoins/node-core:1 (MOVE_INTERNAL advanced ports; submitOnce via bindExecuteMoveSubmitClaimOnce; same claim gate as RECEIVE settle)",
  // The receive landing walk. Read-only get_transaction OBSERVE plus the
  // landing DB-TX; latent barrel reach only, and the landing store names no submit factory or
  // ledger. Nothing on this path can submit: it is reached only after the single submit is
  // already durable, and it reconciles by observation (the never-blind-retry rule).
  "money-workers/receive-child-handoff-step.ts":
    "continuous handoff after RECEIVE_LANDED; structural reach only",
  "money-workers/receive-landing-step.ts":
    "@zucoins/node-core:1 (landing oracle + commit; no submit write call site)",
  "money-workers/receive-lease-port.ts": "@zucoins/node-core:1 (lease port bind; no submit write call site)",
  // Durable receive.ready event append. Latent barrel reach only:
  // this module writes node_events + implementer_events inside the caller's READY transaction
  // and names no submit factory, no gateway and no ledger. It cannot submit.
  "money-workers/receive-ready-event-appender.ts":
    "@zucoins/node-core:1 (dual-chain event append; no submit write call site)",
  "money-workers/receive-candidate-intake-step.ts":
    "@zucoins/node-core:1 (candidate intake; no submit write call site)",
  // The one declared RECEIVE write-path caller (see RECEIVE_WRITE_PATH_CALLERS).
  "money-workers/receive-settle-step.ts":
    "@zucoins/node-core:1 (settle steps; the declared RECEIVE write-path caller)",
  "money-workers/send-formation-observer.ts":
    "@zucoins/node-core:1 (SEND OBSERVE compose; no submit write call site)",
  "money-workers/send-signer-deps.ts":
    "@zucoins/node-core:1 (SEND signer dependency wiring; no submit write call site)",
  "money-workers/send-sql-ports.ts":
    "@zucoins/node-core:1 (SEND claim/lease/form SQL ports; no submit write call site)",
  // SEND completion observe-lander. Read-only get_transaction OBSERVE plus the
  // landing DB-TX; latent barrel reach only, and the landing store names no submit factory.
  // Nothing on this path can submit: it observes the source head and lands by proof (No-blind-retry).
  "money-workers/send-completion-lander.ts":
    "@zucoins/node-core:1 (SEND landing observe + commit; no submit write call site)",
  "money-workers/sql-candidate-intake-ports.ts":
    "@zucoins/node-core:1 (locate/persist/sender-preflight SQL ports; no submit write call site)",
  "money-workers/sql-code-formation-store.ts": "@zucoins/node-core:1 (receive code formation store; no submit write call site)",
  "money-workers/sql-fresh-head-reader.ts":
    "@zucoins/node-core:1 (confirm-read + observation-ledger append; no submit write call site)",
  "money-workers/sql-landing-store.ts":
    "@zucoins/node-core:1 (landing DB-TX; no submit write call site)",
  "money-workers/sql-observation-persistence.ts":
    "@zucoins/node-core:1 (observation ledger persistence; no submit write call site)",
  "money-workers/start-money-workers.ts":
    "@zucoins/node-core:1 (pool scale/assign/form + candidate intake + settle + SEND + MOVE; no submit write call site)",
  // the Web Push slices — channel-1 Web Push. push/sql-store.ts is deliberately ABSENT:
  // it imports only types from node-core, which tsc erases, so it has no value edge.
  // All three below reach only via the node-core
  // barrel; none names the submit write-path factory or the submit ledger. The inbound
  // push leg hands a decoded transfer code to the candidate-intake inbox and stops there:
  // forming, co-signing and submitting stay entirely in the money workers.
  "push/compose.ts":
    "@zucoins/node-core (push composition; hands codes to candidate intake — no submit write call site)",
  "push/ece-decryptor.ts":
    "@zucoins/node-core:1 (RFC 8291 decrypt adapter; no submit write call site)",
  "push/gateway-actions.ts":
    "@zucoins/node-core:1 (push-API form-body codec reuse; no submit write call site)",
  "operations/arm-commit.ts": "@zucoins/node-core:15",
  "operations/arm-live.ts":
    "@zucoins/node-core:34 (live ARM composition; SQL arm stores + wallet gate — no submit write call site)",
  "operations/arm-route.ts": "@zucoins/node-core:15",
  "operations/arm-wallet-gate.ts": "@zucoins/node-core:18",
  "operations/index.ts": "-> operations/verification-material-route.ts (./verification-material-route.js:1)",
  "operations/recovery-actions.ts": "@zucoins/node-core:5",
  "operations/recovery-inspection.ts": "@zucoins/node-core:5",
  "operations/sql-recovery-store.ts": "@zucoins/node-core:22",
  "operations/sql-attention-retraction-store.ts":
    "@zucoins/node-core:1 (attention retraction CAS + audit insert; no submit write call site)",
  "operations/sql-operator-park-store.ts":
    "@zucoins/node-core:1 (operator park CAS + audit insert; no submit write call site)",
  "operations/rotate-master-key.cli.ts": "@zucoins/node-core:20",
  // Strict-JSON intake gate: parseStrictJson + VerificationCompleteBody.
  // Latent barrel reach only (types + parseStrictJson/apiErrorResponse) — no submit
  // factory/ledger call site. Pre-existing gap since the route module landed; declared
  // here as this census's own remediation for structural-reach-only modules.
  "operations/verification-complete-route.ts": "@zucoins/node-core:1 (strict-JSON intake gate; no submit write call site)",
  "operations/verification-complete-store.ts": "@zucoins/node-core:27",
  "operations/verification-material-route.ts": "@zucoins/node-core:13",
  "ops/ed25519-ops.ts": "@zucoins/node-core:1 (operator recovery signing helpers; no submit write call site)",
  "ops/export-live-backup-archive.ts": "@zucoins/node-core:1 (backup export for ceremony; no submit write call site)",
  "ops/restored-instance.ts": "@zucoins/node-core:1 (throwaway restore instance; no submit write call site)",
  "ops/sql-restored-instance.ts": "@zucoins/node-core:1 (SQL restored instance; no submit write call site)",
  "ops/run-recovery-ceremony.ts": "@zucoins/node-core:1 (ceremony composition; no submit write call site)",
  "ops/admin-recovery-ceremony.ts": "@zucoins/node-core:1 (Mode A in-process ceremony; no submit write call site)",
  // The single vault root-KDF salt resolver every derivation path calls (ZTR-1159). Reaches
  // the barrel for deriveRootKey / openWalletSecret only; it chooses a salt and proves the
  // derived key opens an envelope — no submit write call site.
  "vault/boot-canary.ts":
    "@zucoins/node-core:1 (vault unlock canary seal/unseal; no submit write call site)",
  "vault/root-kdf-salt.ts": "@zucoins/node-core:1 (root-KDF salt resolution; no submit write call site)",
  // admin-SPA reporting credential surface. Value-imports
  // bootstrap/reporting-key-enrol.ts (issueReportingCredential), which reaches the barrel;
  // it names no submit factory or ledger — reporting credential issue/list only.
  "reporting-credential-service.ts":
    "-> bootstrap/reporting-key-enrol.ts (issue/list; no submit write call site)",
  // in-memory front-leg import for the two-leg durable rate limiter.
  // Deny-only pre-filter composed inside SqlReportingRateLimiter; no submit factory or
  // ledger call site.
  "reporting/durable-security-ports.ts":
    "@zucoins/node-core:1 (InMemoryReportingRateLimiter deny-only front leg; no submit write call site)",
  "reporting/durable-store.ts": "@zucoins/node-core:13",
  "reporting/live-reporting-reads.ts":
    "@zucoins/node-core:1 (reporting list/stream/snapshot + durable subscription handles; no submit write call site)",
  "full-http-mount.ts": "@zucoins/node-core:1 (ROUTE_POLICIES composition; value import of reporting+admin factories — no submit write call site)",
  "runtime-listener.ts": "@zucoins/node-core:16",
  "stage1-main.ts":
    "@zucoins/node-core:1 (stage1 composition root; no submit write call site)",
  "storage-pressure.ts": "@zucoins/node-core:17",
};

describe("app-tree submit write-path reach census (apps/generic-node/src)", () => {
  const graph = crossPackageImportGraph();
  const appReachers = submitReachers(graph, WRITE_PATH_MODULE)
    .filter((module) => module.startsWith(APP_PREFIX))
    .map((module) => module.slice(APP_PREFIX.length));

  it("every app module reaching the submit write path is declared (census)", () => {
    // The load-bearing assertion. Exact-set, universally quantified over the app tree: a
    // new reacher enters the computed side and reddens, and an analyser that stops
    // resolving the cross-package edge empties the computed side and reddens too.
    expect(appReachers, `undeclared app module reaches ${WRITE_PATH_MODULE}`).toEqual(
      Object.keys(APP_SUBMIT_WRITE_PATH_REACHERS).sort(),
    );
  });

  it("the census is not vacuous: both trees, the cross-package edge and the sink are present", () => {
    // Belt and braces. The exact-set assertion above already fails closed on an empty
    // computed set, but an analyser that stops seeing a tree at all should say so in one
    // line rather than through a 26-element diff.
    const files = productionSourceFiles();
    // 53 app production modules when this was measured; a floor, not an equality, so an
    // unrelated new module does not redden a money-path guard for no reason — a new
    // REACHER is already caught by the exact-set assertion above.
    expect(files.filter((f) => f.startsWith(APP_PREFIX)).length).toBeGreaterThan(40);
    expect(files.filter((f) => f.startsWith("packages/node-core/src/")).length).toBeGreaterThan(300);
    expect([...graph.values()].reduce((total, edges) => total + edges.length, 0)).toBeGreaterThan(500);
    expect(existsSync(resolve(repoRoot, WRITE_PATH_MODULE))).toBe(true);
    // If the barrel ever stops reaching the write path, every app reacher disappears at
    // once and the diff above would be unreadable. Say which link broke.
    expect(submitReachers(graph, WRITE_PATH_MODULE)).toContain(CORE_BARREL);
  });

  it("only the declared RECEIVE settle step names a write-path factory or submit ledger", () => {
    // Until the settle step landed, no app module named either factory, and this asserted the empty set. The
    // property being protected is about SEND_EXTERNAL, not about the submit ledger being
    // untouchable: the flow contract gives RECEIVE_EXTERNAL a node submit, and submit_decisions
    // is the ledger that arbitrates it. So the assertion is now an exact-set census of
    // WHICH app modules name them, rather than a claim that none do — an undeclared second
    // caller still reddens, and the "no SEND surface at all" test below carries the rest.
    const namers = productionSourceFiles()
      .filter((f) => f.startsWith(APP_PREFIX))
      .filter((rel) =>
        WRITE_PATH_MARKERS.some((marker) =>
          readFileSync(resolve(repoRoot, rel), "utf8").includes(marker),
        ),
      )
      .map((rel) => rel.slice(APP_PREFIX.length));
    expect(namers, "an undeclared app module names a submit write-path factory or ledger").toEqual(
      [...RECEIVE_WRITE_PATH_CALLERS, ...MOVE_WRITE_PATH_CALLERS, ...RECOVERY_READ_CALLERS].sort(),
    );
  });

  it("the declared RECEIVE caller reaches the submit-once service, and calls it once", () => {
    // core/receive-submit-once.ts had zero production importers while the guards
    // already catalogued it as the RECEIVE No-blind-retry submit entry. This is the reach half of that
    // finding, measured the same way as the write-path census above: if the settle step or its
    // node-core module stops reaching the submit-once service, the app set empties and reddens.
    const receiveReachers = submitReachers(graph, RECEIVE_SUBMIT_ONCE_MODULE);
    expect(receiveReachers).toContain(RECEIVE_SETTLE_MODULE);
    expect(
      receiveReachers.filter((module) => module.startsWith(APP_PREFIX)),
      "no app module reaches receive-submit-once — it is test-only again",
    ).toContain(`${APP_PREFIX}money-workers/receive-settle-step.ts`);
    // Entry point, not just any module: the process main must reach it.
    expect(receiveReachers).toContain(`${APP_PREFIX}main.ts`);

    // The never-blind-retry rule in the shape a census can check: exactly one call site, in one module.
    const settleText = readFileSync(resolve(repoRoot, RECEIVE_SETTLE_MODULE), "utf8");
    expect(settleText.match(/receiveSubmitOnce\(/g)).toHaveLength(1);
    const callers = productionSourceFiles().filter(
      (rel) => rel !== RECEIVE_SUBMIT_ONCE_MODULE && /\breceiveSubmitOnce\(/.test(readFileSync(resolve(repoRoot, rel), "utf8")),
    );
    expect(callers, "receiveSubmitOnce has more than one production call site").toEqual([
      RECEIVE_SETTLE_MODULE,
    ]);
  });

  it("candidate intake is production-mounted under money workers (not test-only)", () => {
    const intakeReachers = submitReachers(graph, CANDIDATE_INTAKE_MODULE);
    expect(intakeReachers).toContain(CANDIDATE_INTAKE_APP_MODULE);
    expect(intakeReachers).toContain(`${APP_PREFIX}money-workers/start-money-workers.ts`);
    expect(intakeReachers).toContain(`${APP_PREFIX}main.ts`);
    const namers = productionSourceFiles().filter((rel) =>
      /\bcreateCandidateIntakeService\b/.test(readFileSync(resolve(repoRoot, rel), "utf8")),
    );
    expect(namers, "createCandidateIntakeService missing from production graph").toContain(
      CANDIDATE_INTAKE_APP_MODULE,
    );
    expect(namers.filter((rel) => rel.startsWith(APP_PREFIX)).length).toBeGreaterThan(0);
    // Review fix: production enqueue producer under src/ (real feed, not drain-only).
    const enqueueProducers = productionSourceFiles()
      .filter((rel) => rel.startsWith(APP_PREFIX))
      .filter((rel) => {
        const text = readFileSync(resolve(repoRoot, rel), "utf8");
        return (
          text.includes("inbox.enqueue(") ||
          text.includes("candidateIntake.enqueue(") ||
          text.includes("enqueueReceiverChannelDeposit")
        );
      });
    expect(
      enqueueProducers,
      "no production enqueue path for candidate intake",
    ).toEqual(
      expect.arrayContaining([
        `${APP_PREFIX}money-workers/receiver-channel-producer.ts`,
        `${APP_PREFIX}main.ts`,
      ]),
    );
    const mainText = readFileSync(resolve(repoRoot, `${APP_PREFIX}main.ts`), "utf8");
    expect(mainText).toMatch(/candidateIntakeInbox:\s*candidateIntake/);
    expect(mainText).toMatch(/moneyWorkers/);
    expect(mainText).toMatch(/onReceiverChannelDeposit/);
  });

  it("SEND_EXTERNAL surfaces exist only as post-approve/formation (never submit)", () => {
    // SEND formation is required; submit remains forbidden.
    // RECEIVE + MOVE write-path callers may name claim/attempt factories
    // (the RECEIVE settle and MOVE submit grants); they are asserted by their respective censuses above,
    // not by this SEND never-submit screen. recovery read callers query
    // gateway_submit_attempts read-only for reconciliation, same exemption logic.
    const writePathCallerSet = new Set<string>(
      [...RECEIVE_WRITE_PATH_CALLERS, ...MOVE_WRITE_PATH_CALLERS, ...RECOVERY_READ_CALLERS].map(
        (rel) => `${APP_PREFIX}${rel}`,
      ),
    );
    const flaggedSubmit = productionSourceFiles()
      .filter((f) => f.startsWith(APP_PREFIX))
      .filter((rel) => !writePathCallerSet.has(rel))
      .filter((rel) => {
        const text = readFileSync(resolve(repoRoot, rel), "utf8");
        return WRITE_PATH_MARKERS.some((m) => text.includes(m)) || text.includes("submit_transaction");
      });
    expect(flaggedSubmit, "submit markers in apps/generic-node/src (non-RECEIVE)").toEqual([]);
    const sendSurfaces = productionSourceFiles()
      .filter((f) => f.startsWith(APP_PREFIX))
      .filter((rel) => !writePathCallerSet.has(rel))
      .filter(
        (rel) =>
          /send/i.test(rel) ||
          readFileSync(resolve(repoRoot, rel), "utf8").includes("SEND_EXTERNAL") ||
          readFileSync(resolve(repoRoot, rel), "utf8").includes("runSendPostApproveFormation"),
      )
      .sort();
    expect(sendSurfaces.length).toBeGreaterThan(0);
    for (const rel of sendSurfaces) {
      const text = readFileSync(resolve(repoRoot, rel), "utf8");
      expect(text, rel).not.toContain("submit_transaction");
      expect(text, rel).not.toContain("makeSubmitDecisionClaimStore");
    }
  });

  it("predicate proof: the cross-package specifier resolves, and unresolvable edges throw", () => {
    // The new rule this file adds over the node-core census. Unreachable on a healthy tree, so a
    // mutation turning either throw into `return null` would survive every assertion
    // above; proving them on synthetic input is what makes them live rules.
    const from = resolve(APP_SRC, "anything.ts");
    expect(resolveModule(from, "@zucoins/node-core")).toBe(resolve(CORE_SRC, "index.ts"));
    expect(resolveModule(from, "@zucoins/node-core/core")).toBe(resolve(CORE_SRC, "core/index.ts"));
    expect(() => resolveModule(from, "@zucoins/node-core/no-such-subpath")).toThrow(
      /unresolvable node-core subpath/,
    );
    expect(() => resolveModule(from, "./no-such-module.js")).toThrow(/unresolvable import/);
    expect(resolveModule(from, "node:fs")).toBeNull();
    expect(resolveModule(from, "pg")).toBeNull();
  });

  it("predicate proof: type-only edges are elided, value and dynamic edges are not", () => {
    expect(valueImportEdges('import type { ReportingRegistration } from "@zucoins/node-core";')).toEqual([]);
    expect(valueImportEdges('import { type A, type B } from "@zucoins/node-core";')).toEqual([]);
    expect(valueImportEdges('import { type A, makeThing } from "@zucoins/node-core";')).toEqual([
      "@zucoins/node-core",
    ]);
    expect(valueImportEdges('import * as core from "@zucoins/node-core";')).toEqual(["@zucoins/node-core"]);
    expect(valueImportEdges('export * from "@zucoins/node-core";')).toEqual(["@zucoins/node-core"]);
    expect(valueImportEdges('import "@zucoins/node-core";')).toEqual(["@zucoins/node-core"]);
    expect(valueImportEdges('/* wiring */ import { a } from "@zucoins/node-core";')).toEqual([
      "@zucoins/node-core",
    ]);
    expect(valueImportEdges('const m = await import("@zucoins/node-core");')).toEqual(["@zucoins/node-core"]);
    // A string that merely looks like a specifier is not an edge.
    expect(valueImportEdges('export const PKG = "@zucoins/node-core";')).toEqual([]);
    // Not statically resolvable, so it fails closed rather than being dropped.
    expect(() => valueImportEdges('await import("@zucoins/" + "node-core");')).toThrow(
      /computed dynamic import/,
    );
    expect(() => valueImportEdges("const rq = createRequire(import.meta.url);")).toThrow(
      /unresolvable require/,
    );
  });

  it("predicate proof: every require()-minting form throws, however it is spelled", () => {
    // The round-4 escape, closed on the specifier rather than on the callee name.
    // Each of these binds a working `require` under a name the extractor cannot know, so a
    // spelling-keyed check lets the resulting edge vanish without a word.
    expect(() => valueImportEdges('import { createRequire } from "node:module";')).toThrow(/node:module/);
    expect(() => valueImportEdges('import { createRequire as cr } from "node:module";')).toThrow(
      /node:module/,
    );
    expect(() => valueImportEdges('import * as nodeModule from "node:module";')).toThrow(/node:module/);
    expect(() => valueImportEdges('const { createRequire: cr } = await import("node:module");')).toThrow(
      /node:module/,
    );
    expect(() => valueImportEdges('const m = require("node:module");')).toThrow(/node:module/);
    // Bare "module" is the CJS spelling of the same builtin.
    expect(() => valueImportEdges('import { createRequire } from "module";')).toThrow(/node:module/);
    // And the un-aliased call itself, for the file that acquired it some other way.
    expect(() => valueImportEdges("const rq = createRequire(import.meta.url);")).toThrow(
      /unresolvable require/,
    );
    // Adversarial review: req via eval, and createRequire via getBuiltinModule without
    // any node:module import, both left GREEN before these arms. Fail closed.
    expect(() => valueImportEdges('const req = eval("require");')).toThrow(/eval is not statically/);
    expect(() =>
      valueImportEdges('const f = new Function("return require");'),
    ).toThrow(/new Function is not statically/);
    expect(() =>
      valueImportEdges('const { createRequire: mint } = process.getBuiltinModule("node:module");'),
    ).toThrow(/getBuiltinModule mints builtins/);
    expect(() =>
      valueImportEdges('const m = process.getBuiltinModule("node:module").createRequire(import.meta.url);'),
    ).toThrow(/getBuiltinModule mints builtins|unresolvable require/);
  });

  it("predicate proof: `import x = require(...)` is an edge, not a silent drop", () => {
    // Its module reference is an ExternalModuleReference, so nothing in a CallExpression-keyed
    // walk ever visits it — the edge was pruned in silence before this arm existed.
    expect(valueImportEdges('import legacy = require("./legacy.js");')).toEqual(["./legacy.js"]);
    expect(valueImportEdges('import core = require("@zucoins/node-core");')).toEqual([
      "@zucoins/node-core",
    ]);
    expect(valueImportEdges('import type legacy = require("./legacy.js");')).toEqual([]);
    // An alias to an entity name is not a module edge at all.
    expect(valueImportEdges('import ns = require("./x.js");\nimport alias = ns.inner;')).toEqual([
      "./x.js",
    ]);
  });

  it("predicate proof: a NEW app reacher lands in the computed set, at any depth", () => {
    // The mutation this census exists to catch, driven on an in-memory graph so it proves
    // the walk rather than the current state of the tree. Each shape is a different way of
    // acquiring the edge; all three land for the same single reason.
    const withEdges = (edges: Readonly<Record<string, readonly string[]>>): readonly string[] =>
      submitReachers(new Map(Object.entries(edges)), WRITE_PATH_MODULE);
    const sinkChain = {
      [CORE_BARREL]: ["packages/node-core/src/core/index.ts"],
      "packages/node-core/src/core/index.ts": [WRITE_PATH_MODULE],
    };
    // Direct barrel import.
    expect(withEdges({ ...sinkChain, [`${APP_PREFIX}send/dispatch.ts`]: [CORE_BARREL] })).toContain(
      `${APP_PREFIX}send/dispatch.ts`,
    );
    // Two hops through an existing app module — invisible to any downward walk from a
    // derived SEND entry set, which is why the walk runs backwards from the sink.
    expect(
      withEdges({
        ...sinkChain,
        [`${APP_PREFIX}send/dispatch.ts`]: [`${APP_PREFIX}http-adapter.ts`],
        [`${APP_PREFIX}http-adapter.ts`]: [CORE_BARREL],
      }),
    ).toContain(`${APP_PREFIX}send/dispatch.ts`);
    // A subpath import, bypassing the root barrel entirely.
    expect(
      withEdges({
        "packages/node-core/src/core/index.ts": [WRITE_PATH_MODULE],
        [`${APP_PREFIX}send/dispatch.ts`]: ["packages/node-core/src/core/index.ts"],
      }),
    ).toContain(`${APP_PREFIX}send/dispatch.ts`);
    // And it is a real measurement, not "every module, always": no path, no membership.
    expect(withEdges({ ...sinkChain, [`${APP_PREFIX}db/client.ts`]: ["pg"] })).not.toContain(
      `${APP_PREFIX}db/client.ts`,
    );
  });
});
