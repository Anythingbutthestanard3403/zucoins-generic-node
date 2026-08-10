// structural proof that SEND_EXTERNAL cannot reach either submit-decision write path
// (submit_decisions / gateway_submit_attempts, the data model). Governing:
// operation flows step 9 (the claim-and-submit-once path belongs to MOVE_INTERNAL);
// operations recovery axiom 1 ("A submit call is single-shot for one exact authorized
// attempt"); the never-blind-retry rule (never blind-retry a submit).
//
// This is a literal call-site TEXT search, not an import-specifier search:
// packages/node-core/src/core/index.ts re-exports both factories via
// `export * from "./submit-decision-claim-store.js"`, so a caller reaching them through that
// barrel would carry a specifier like "../core/index.js" or "@zucoins/node-core", not
// "./submit-decision-claim-store.js" — an import-path scan would miss it. Scanning for the
// actual invocation text (`makeSubmitDecisionClaimStore(` / `makeSubmitAttemptRecorder(`)
// cannot be evaded that way, mirroring the census pattern in boundaries.test.ts.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const here = fileURLToPath(new URL(".", import.meta.url));
const srcRoot = resolve(here, "../src");
const testRoot = here;

const WRITE_PATH_CALLS = ["makeSubmitDecisionClaimStore(", "makeSubmitAttemptRecorder("] as const;

// Every text marker that means "this file touches a submit write path": the two factories, the
// module that defines them, and the two ledgers themselves.
const SUBMIT_WRITE_PATH_MARKERS = [
  "submit-decision-claim-store",
  "makeSubmitDecisionClaimStore",
  "makeSubmitAttemptRecorder",
  "gateway_submit_attempts",
  "submit_decisions",
] as const;

// A SEND-named core/ module that also names submit or claim would be the forbidden thing:
// SEND_EXTERNAL's own submit-claim orchestrator (e.g. core/send-submit-claim.ts).
function isSendSubmitClaimModule(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  return lower.includes("send") && (lower.includes("submit") || lower.includes("claim"));
}

interface SourceEntry {
  readonly file: string;
  readonly text: string;
}

// The module that DEFINES both factories necessarily contains their names as
// `export function makeX(` text, which the same literal search matches — that is a
// declaration, not a call site, and is excluded from both scans below rather than listed as
// an allowed call site.
const DEFINITION_FILE = "core/submit-decision-claim-store.ts";

// The only production call site permitted today: none. The app has not yet wired either
// factory into a real entry point (that wiring lands separately); this stays empty so the
// assertion fails closed the moment any production file — MOVE_INTERNAL's included — calls
// either factory without this list being updated in the same change, forcing the author to
// see the new call site named explicitly.
const ALLOWED_PRODUCTION_CALL_SITES: readonly string[] = [];

// Test call sites permitted to invoke the two factories: the original real-Postgres proof
// (229) and submit-ambiguity-authority half. Both drive the factories
// directly against a live database / MOVE_INTERNAL's executeMoveSubmitClaim. This guard test
// itself is excluded from its own scan below — it necessarily contains the two literal factory
// names as scan-target/fixture text, which is not a call site either.
// The chaos/invariant harnesses joined the list. Each drives the factories against a
// live database to prove the at-most-once property survives crash/overlap, exactly as the two
// original proofs do — none of them is production wiring, and all four are MOVE_INTERNAL-driven.
const ALLOWED_TEST_CALL_SITES: readonly string[] = [
  "submit-decision-claim-store.pg.test.ts",
  "submit-ambiguity-authority.pg.test.ts",
  "chaos/node-instance-harness.ts",
  "chaos/overlap-crash-handoff.pg.test.ts",
  "invariant-chaos-harness.ts",
  "invariant-chaos.pg.test.ts",
];
const SELF_FILE = "submit-write-path.guard.test.ts";

function listTsFiles(dir: string): string[] {
  return (readdirSync(dir, { recursive: true }) as string[])
    .map((entry) => join(dir, entry))
    .filter((file) => extname(file) === ".ts" && statSync(file).isFile());
}

function readEntries(files: readonly string[]): SourceEntry[] {
  return files.map((file) => ({ file, text: readFileSync(file, "utf8") }));
}

// The scan predicate under test. Kept pure (no fs) so the mutation-negative test below proves
// its behavior directly, without depending on the current state of the repo.
function findWritePathCallSites(entries: readonly SourceEntry[]): string[] {
  return entries
    .filter((entry) => WRITE_PATH_CALLS.some((call) => entry.text.includes(call)))
    .map((entry) => entry.file);
}

describe("submit write-path structural guard (SEND_EXTERNAL cannot reach either write path)", () => {
  it("production source calls neither write-path factory outside the allow-list", () => {
    const files = listTsFiles(srcRoot)
      .filter((file) => !file.endsWith(".test.ts"))
      .filter((file) => relative(srcRoot, file) !== DEFINITION_FILE);
    const found = findWritePathCallSites(readEntries(files))
      .map((file) => relative(srcRoot, file))
      .sort();
    expect(found).toEqual([...ALLOWED_PRODUCTION_CALL_SITES].sort());
  });

  it("test source calls neither write-path factory outside the real-Postgres proofs", () => {
    const files = listTsFiles(testRoot).filter((file) => relative(testRoot, file) !== SELF_FILE);
    const found = findWritePathCallSites(readEntries(files))
      .map((file) => relative(testRoot, file))
      .sort();
    expect(found).toEqual([...ALLOWED_TEST_CALL_SITES].sort());
  });

  it("the SEND_EXTERNAL reconcile module never mentions either write-path factory or module", () => {
    const sendSource = readFileSync(resolve(srcRoot, "protocol/reconcile/send.ts"), "utf8");
    expect(sendSource).not.toContain("submit-decision-claim-store");
    expect(sendSource).not.toContain("makeSubmitDecisionClaimStore");
    expect(sendSource).not.toContain("makeSubmitAttemptRecorder");
  });

  it("core/ has no SEND_EXTERNAL submit-claim module (only MOVE_INTERNAL's and RECEIVE's exist)", () => {
    const coreFiles = readdirSync(resolve(srcRoot, "core")).filter((entry) => entry.endsWith(".ts"));
    expect(coreFiles).toContain("move-submit-claim.ts");
    expect(coreFiles).toContain("receive-submit-once.ts");
    // The bar is signing custody — "SEND_EXTERNAL has no node submit function
    // in its type graph" — not "no core/ filename says send". SEND_EXTERNAL legitimately owns
    // core/send-form-and-sign.ts (crash-safe first formation) and
    // core/send-crash-recovery.ts (exact redelivery); neither is a submit module. What
    // must stay unrepresentable is a SEND-named *submit/claim* module, so match on that pair.
    expect(coreFiles.filter((entry) => isSendSubmitClaimModule(entry))).toEqual([]);
    // Names are only a proxy; the substantive bound is that no SEND-named core module reaches a
    // submit write path or its ledgers, whatever it is called.
    for (const entry of coreFiles.filter((f) => f.toLowerCase().includes("send"))) {
      const text = readFileSync(resolve(srcRoot, "core", entry), "utf8");
      for (const marker of SUBMIT_WRITE_PATH_MARKERS) {
        expect(text, `core/${entry} must not contain ${marker}`).not.toContain(marker);
      }
    }
  });

  it("send/ package never references the submit-decision claim store or attempt recorder", () => {
    const sendRoot = resolve(srcRoot, "send");
    const files = listTsFiles(sendRoot);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const marker of SUBMIT_WRITE_PATH_MARKERS) {
        expect(text, `${relative(srcRoot, file)} must not contain ${marker}`).not.toContain(marker);
      }
    }
  });

  it("mutation negative: an injected call site outside the allow-list is caught (fixture proof)", () => {
    const fixture: SourceEntry[] = [
      { file: "send-external-handler.ts", text: "const store = makeSubmitDecisionClaimStore(query);" },
      { file: "unrelated.ts", text: "export const x = 1;" },
    ];
    expect(findWritePathCallSites(fixture)).toEqual(["send-external-handler.ts"]);
  });
});

// ---------------------------------------------------------------------------
// A universal sink-reacher census, not a derived entry set.
//
// The bar is signing custody: "SEND_EXTERNAL has no node submit
// function in its type graph." That is a property of the import graph, not of source
// spelling, and everything above is a text scan. Two evasions defeat a text match while
// leaving a real write path reachable:
//
//   M2  a point-free re-export — `export const mintClaimLedger =
//       makeSubmitDecisionClaimStore;` in a non-send core module, invoked as
//       `mintClaimLedger(q)` from core/send-form-and-sign.ts. No banned literal exists
//       anywhere, and no `(` ever follows the factory name.
//   M2c a table name assembled at runtime — `["submit","decisions"].join("_")` — so the
//       ledger is written without its literal spelling appearing.
//
// The three previous cuts of this section asked "which modules are SEND, and what do
// they reach?": a negative existential over a DERIVED set. Every assertion of that shape
// passes when the derivation under-approximates, so each round closed the demonstrated
// derivation hole and handed the next reader an adjacent one out of the same unbounded
// family (every syntactic form that can carry a value, times every walk direction). The
// corroborating measurement: neuter the edge extractor and all 28 per-entry
// `not.toContain` assertions went GREEN. The load-bearing half was vacuous under its own
// degradation.
//
// This section inverts the quantifier. It asks the one question that needs no membership
// derivation at all —
//
//   which production modules have core/submit-decision-claim-store.ts in their
//   value-import closure?
//
// — and asserts that set, exactly, against a declared list. Aliasing, re-export depth,
// encoding, path naming, kind-declaration style and walk direction are not inputs to it,
// so none of them can evade it; the only way to leave the set is to not import the
// module. A new reacher enters the computed set and reddens unconditionally, and a
// DEGRADED analyser reddens too — an empty computed set fails an exact-set assertion
// against a non-empty declared one, where the old shape passed vacuously. That
// relocation of membership judgement, out of the fail-open position (deciding what to
// examine) into the fail-closed one (annotating an already-bounded set), is the whole
// design change.
//
// Half 2 (the ledger TABLE names) is inverted the same way. A table is not a module, so
// there is no import edge to walk and the scan stays textual — but it runs over EVERY
// production module rather than over a derived closure, so it inherits no membership bug.
//
// Type-only edges are elided, matching the emitted JS. established that
// `import type { SqlQueryFn }` is erased by tsc and leaves no import in the compiled
// output; following such an edge would flag a module the runtime never loads and would
// re-break exactly what fixed.
//
// Declared ceilings. This section does NOT prove:
//   * anything about apps/generic-node/src. 53 production modules there, 21 importing the
//     @zucoins/node-core root barrel directly, are undeclared cross-package reachers.
//     Latent, not a live breach — there is no *send* module in that tree today..
//   * completeness of half 2 under arbitrary encodings. decodeBase64Runs closes the one
//     encoding already demonstrated; hex, char-code arrays, template concatenation,
//     ROT13 and the rest stay open, and NO text scan can be closed under all of them —
//     that is a property of the approach, not a gap to fill, so no further decoder is
//     added here. The structural answer for a raw-SQL ledger write is a database grant, not
//     a test, and landed one: src/schema/privileges.sql subtracts INSERT/UPDATE on
//     both ledgers (and DELETE/TRUNCATE on every public table) from `node_core_send`,
//     PostgreSQL evaluates that against the table OID after parsing — every encoding is
//     already undone by then — assertPrivilegeReadiness verifies the subtraction fail-closed
//     at boot, and test/submit-ledger-grant-separation.pg.test.ts proves the 42501 refusals
//     against a real Postgres. Its own ceiling: the grant binds only a connection that has
//     assumed that role, and nothing assumes it yet — the SEND-path pool wiring is a later
//     landed, so today the grant is a guarantee about the role, not about a live session.
//     A module that IMPORTS the write path is caught by the census under any encoding,
//     because encoding a name does not remove an import edge.
//   * anything reached through eval / new Function / Module._load / process.getBuiltinModule.
//     Those are not import edges and are not thrown on. node:module IS an edge and is thrown
//     on (see valueImportEdges), which is why the createRequire family is closed and these
//     are not: there is no node to see.
//   * that a SECOND submit write path, in some new module, is unreachable. The census is
//     keyed to core/submit-decision-claim-store.ts; a new writer is caught only insofar
//     as it must name the ledgers, i.e. by half 2 and its ceiling above.

// the data model. Only the ledger TABLE names are scanned squash-normalized: the module
// and factory names are covered structurally by half 1, and squashing those would flag
// ordinary prose (core/transaction-material-store.ts names submit-decision-claim-store.ts in
// a comment about the SQL seam, which is not a reach).
const SUBMIT_LEDGER_TABLES = ["submit_decisions", "gateway_submit_attempts"] as const;
const WRITE_PATH_MODULE = "core/submit-decision-claim-store.ts";

// A base64 literal decodes to the same string at runtime, so any run long enough to carry a
// ledger name is decoded and appended before the squash. Only printable ASCII is kept, which
// drops the noise from ordinary identifiers that happen to be valid base64. This closes the
// encoding review B demonstrated. It does NOT make the text scan complete — hex, char-code
// arrays and every other encoding stay outside it, and no text scan can be closed under all of
// them. That is why half 1 above, the import-graph reach check, is the load-bearing property:
// it does not depend on spelling at all.
function decodeBase64Runs(text: string): string {
  return text.replace(/[A-Za-z0-9+/]{16,}={0,2}/g, (run) => {
    const decoded = Buffer.from(run, "base64").toString("utf8");
    return /^[\x20-\x7e]+$/.test(decoded) ? `${run} ${decoded}` : run;
  });
}

// Collapses every non-alphanumeric character, so a runtime-assembled identifier matches
// the same marker its literal spelling does. String escapes are decoded first: at runtime
// `"submit_decisions"` IS "submit_decisions", but left undecoded the escape contributes
// the literal characters `u005f`, which breaks the very adjacency this scan looks for.
function squash(text: string): string {
  return decodeBase64Runs(text)
    .toLowerCase()
    .replace(/\\u\{([0-9a-f]{1,6})\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})/g, (_match, braced, u, x) => {
      const code = Number.parseInt((braced ?? u ?? x) as string, 16);
      // An out-of-range escape is not a character; dropping it joins its neighbours, which
      // is the direction that keeps the scan detecting rather than excusing.
      return code <= 0x10ffff ? String.fromCodePoint(code) : "";
    })
    .replace(/[^a-z0-9]/g, "");
}

// Import/export specifiers that survive compilation, i.e. real runtime edges. PARSED,
// not matched. The regex this replaces could not skip a comment before the keyword — its
// `(?:^|[\n;])\s*` anchor meant `/* wiring */ import { a } from "./store.js";` was
// silently DROPPED rather than thrown on — and every other anchor in it had a sibling
// defect of the same kind: ASI, multi-line clauses, `export default`, class statics, the
// `[^;]*` clause truncation. A parser has no anchors, so that entire family closes
// structurally instead of case by case. `typescript` is already a test dependency of this
// package (protocol-source-safety.test.ts, protocol-transaction-source-safety.test.ts).
//
// `import type` / `export type` clauses, and brace lists whose every element is
// `type`-prefixed, are erased by tsc and are not edges.
function valueImportEdges(text: string, fileLabel = "<inline>"): string[] {
  const source = ts.createSourceFile(fileLabel, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const specifiers: string[] = [];
  const firstLine = (node: ts.Node): string => node.getText(source).split("\n")[0] as string;

  // A clause contributes a runtime edge unless tsc erases all of it.
  const clauseIsValue = (clause: ts.ImportClause): boolean => {
    if (clause.isTypeOnly) return false;
    if (clause.name !== undefined) return true; // default binding
    const bindings = clause.namedBindings;
    if (bindings === undefined) return false;
    if (ts.isNamespaceImport(bindings)) return true;
    // `import { type A, type B } from "…"` is fully erased; `import { type A, b }` is not.
    return bindings.elements.some((element) => !element.isTypeOnly);
  };

  // A module specifier that is not a string literal cannot be followed. Throwing rather
  // than dropping is the doctrine for every unresolvable edge in this file: a silently
  // pruned edge is exactly how a reach check goes vacuous.
  const specifierOf = (node: ts.ImportDeclaration | ts.ExportDeclaration): string => {
    const moduleSpecifier = node.moduleSpecifier;
    if (moduleSpecifier === undefined || !ts.isStringLiteralLike(moduleSpecifier)) {
      throw new Error(`non-literal module specifier: ${firstLine(node)}`);
    }
    return moduleSpecifier.text;
  };

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      // A side-effect import (`import "./x.js";`) carries no binding but does load the module.
      if (node.importClause === undefined || clauseIsValue(node.importClause)) {
        specifiers.push(specifierOf(node));
      }
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) {
      const clause = node.exportClause;
      if (
        !node.isTypeOnly &&
        (clause === undefined || // `export * from "./x.js"`
          ts.isNamespaceExport(clause) || // `export * as ns from "./x.js"`
          clause.elements.some((element) => !element.isTypeOnly))
      ) {
        specifiers.push(specifierOf(node));
      }
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const argument = node.arguments[0];
      const isLiteralArgument = argument !== undefined && ts.isStringLiteralLike(argument);
      if (callee.kind === ts.SyntaxKind.ImportKeyword) {
        // Dynamic `import("./x.js")` is a real runtime edge and loads the module exactly
        // as a static import does. A computed one — `import("./a" + "b")` — cannot be
        // resolved statically, so it throws rather than being dropped: dropping it lets a
        // module load the write path with every assertion green.
        if (!isLiteralArgument) {
          throw new Error(`computed dynamic import() is not statically resolvable: ${firstLine(node)}`);
        }
        specifiers.push(argument.text);
      } else {
        const name = ts.isIdentifier(callee)
          ? callee.text
          : ts.isPropertyAccessExpression(callee)
            ? callee.name.text
            : undefined;
        // CommonJS `require("./x.js")` loads a module exactly as `import()` does. The
        // `createRequire` arm below is keyed to the callee's SPELLING, so an alias defeats
        // it — `import { createRequire as cr }` calls `cr(…)` and `name` is "cr". It is
        // therefore not what closes that form, and is kept only because a bare
        // `createRequire(…)` should name itself in the error. What closes the form is the
        // edge to node:module, thrown on unconditionally after the walk: every route to a
        // minted require, under every alias, takes it first.
        if (name === "createRequire" || (name === "require" && !isLiteralArgument)) {
          throw new Error(`unresolvable require() edge: ${firstLine(node)}`);
        }
        if (name === "require" && isLiteralArgument) specifiers.push(argument.text);
      }
    } else if (ts.isImportEqualsDeclaration(node)) {
      // `import store = require("./x.js")` loads the module, and its require is an
      // ExternalModuleReference node rather than a CallExpression — the branch above never
      // sees it. An entity-name alias (`import A = B.C`) resolves an existing binding and
      // loads nothing, so it is not an edge; `import type x = require(…)` is erased.
      const reference = node.moduleReference;
      if (ts.isExternalModuleReference(reference)) {
        if (!ts.isStringLiteralLike(reference.expression)) {
          throw new Error(`unresolvable require() edge: ${firstLine(node)}`);
        }
        if (!node.isTypeOnly) specifiers.push(reference.expression.text);
      }
    }
    ts.forEachChild(node, visit);
  };

  ts.forEachChild(source, visit);
  // node:module hands out createRequire, which mints a require callable under ANY name.
  // Aliased at the import, destructured out of `await import("node:module")`, reached off a
  // namespace, or renamed again downstream — no callee-spelling check can see those, so the
  // edge to the builtin ITSELF is what is thrown on. It is present in every one of them, and
  // a module that loads node:module cannot be followed from here regardless. Nothing in src
  // imports it today, so this throws on nothing on a healthy tree.
  const moduleBuiltin = specifiers.find((specifier) => specifier === "node:module" || specifier === "module");
  if (moduleBuiltin !== undefined) {
    throw new Error(`unresolvable require() edge: "${moduleBuiltin}" mints require under any alias`);
  }
  return specifiers;
}

// Resolves a relative NodeNext specifier ("./x.js") back to the .ts source it compiles
// from. Anything unresolvable is a broken import and fails loudly rather than silently
// pruning the walk — a silently pruned edge is exactly how a reach check goes vacuous.
function resolveModule(fromFile: string, specifier: string): string | null {
  if (specifier.startsWith("@zucoins/node-core")) {
    // A self-package specifier would route through the core/ barrel, which re-exports both
    // factories, and leave this walk unable to follow it. None exists in src today; this
    // fails closed the day one is introduced instead of quietly pruning the edge.
    throw new Error(`self-package import "${specifier}" in ${relative(srcRoot, fromFile)}`);
  }
  if (!specifier.startsWith(".")) return null; // node: builtins and other packages
  const target = resolve(dirname(fromFile), specifier);
  for (const candidate of [target.replace(/\.js$/, ".ts"), `${target}.ts`, join(target, "index.ts")]) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  throw new Error(`unresolvable import "${specifier}" in ${relative(srcRoot, fromFile)}`);
}

function importClosure(entry: string): string[] {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const specifier of valueImportEdges(readFileSync(file, "utf8"))) {
      const resolved = resolveModule(file, specifier);
      if (resolved !== null) queue.push(resolved);
    }
  }
  return [...seen].map((file) => relative(srcRoot, file)).sort();
}
function productionSourceFiles(): string[] {
  return listTsFiles(srcRoot).filter((file) => !file.endsWith(".test.ts"));
}

// Every production module keyed to the modules it takes a runtime edge to. Built once —
// the censuses below are queries over this one graph, not a walk per entry.
function productionImportGraph(): Map<string, string[]> {
  const graph = new Map<string, string[]>();
  for (const file of productionSourceFiles()) {
    const rel = relative(srcRoot, file);
    const edges = valueImportEdges(readFileSync(file, "utf8"), rel)
      .map((specifier) => resolveModule(file, specifier))
      .filter((resolved): resolved is string => resolved !== null)
      .map((resolved) => relative(srcRoot, resolved));
    graph.set(rel, edges);
  }
  return graph;
}

// Which modules have `sink` in their value-import closure. Walked BACKWARDS over the
// reversed graph rather than forwards from a set of entries, because an entry set is a
// derivation and a derivation that under-approximates makes every downstream
// `not.toContain` pass vacuously. Reversing also makes the walk trivially cycle-safe,
// where a memoized forward `reaches()` is not.
//
// Pure, so the evasion battery below drives it on in-memory graphs without touching the
// tree — the same discipline findWritePathCallSites already follows.
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
  // A cycle through the sink must not declare the sink its own reacher.
  reachers.delete(sink);
  return [...reachers].sort();
}

// Half 2: every production module whose squash-normalized text names either ledger.
// Over the WHOLE tree, not over a closure — that is the inversion.
function submitLedgerNamingModules(): string[] {
  return productionSourceFiles()
    .filter((file) => {
      const squashed = squash(readFileSync(file, "utf8"));
      return SUBMIT_LEDGER_TABLES.some((table) => squashed.includes(squash(table)));
    })
    .map((file) => relative(srcRoot, file))
    .sort();
}

// Deliberately OVER-inclusive, and allowed to be wrong. It never decides WHAT to examine
// — the two censuses do that, over all 339 production modules — it only annotates sets a
// human has already read, of six and nine members. A miss here can no longer open a hole,
// because the census reddens FIRST on any new member. That relocation, out of the
// fail-open position and into the fail-closed one, is the design change.
function isSendExternalSurface(rel: string, text: string): boolean {
  return /send/i.test(rel) || text.includes("SEND_EXTERNAL");
}

// A justification per entry rather than a bare array, so adding a line forces the adder
// to write WHY and a reader sees it in the diff. Barrel churn is the expected failure
// mode: any module importing core/index.ts for an unrelated reason becomes a reacher and
// reddens this list, and a benign failure that gets rubber-stamped is how a list like this
// rots. Six members today, one direct importer.
const SUBMIT_WRITE_PATH_REACHERS: Readonly<Record<string, string>> = {
  "api/index.ts":
    "api barrel; re-exports ./verification-material.js and ./verification-material-source.js below",
  "api/verification-access.ts":
    "access gate; imports ../core/index.js (line 31) for the verification-material access resolver",
  "api/verification-material-source.ts":
    "imports ./verification-access.js (line 32), which reaches the core barrel",
  "api/verification-material.ts":
    "imports resolveVerificationMaterialAccess from ../core/index.js (line 22)",
  "core/index.ts":
    "the only DIRECT importer: `export * from \"./submit-decision-claim-store.js\"` (core/index.ts:26). This is MOVE_INTERNAL's submit machinery being re-exported by its own package barrel",
  "index.ts": "package barrel; `export * from \"./core/index.js\"` (index.ts:7)",
};

// Of the six reachers above, which the over-inclusive SEND predicate flags. Asserted as an
// EXACT set, so this is an exemption with a name attached, not a category: a SECOND
// SEND-naming reacher reddens instead of being absorbed. Empty would be better; it is not
// empty, and saying so is the point.
const SEND_NAMING_REACHERS: Readonly<Record<string, string>> = {
  "index.ts":
    "the package barrel re-exports SEND_EXTERNAL_CREATE_GN3_OBLIGATIONS / _INVARIANTS / _SCHEMA_FILE (index.ts:119-121), so the substring predicate matches an identifier PREFIX, not a kind literal. Its reach of the write path is core/index.ts:26 — MOVE_INTERNAL's submit machinery re-exported — not SEND reaching it",
};

// Half 2's declared set. Fourteen members; the two the over-inclusive SEND predicate flags are
// named in SEND_NAMING_LEDGER_MODULES below, on the same exact-set terms as half 1's.
const SUBMIT_LEDGER_NAMING_MODULES: Readonly<Record<string, string>> = {
  "core/backup/format.ts": "backup manifest names both ledgers as backed-up tables (06-backup)",
  "core/metrics.ts":
    "squash false positive, and a deliberate one: the counter help text \"Gateway submit attempts by outcome.\" (metrics.ts:422) squashes to the same run the table name does. Over-inclusion costs one declared line; under-inclusion is a hole",
  "core/move-submit-claim.ts":
    "MOVE_INTERNAL's own claim-and-submit-once path (operation flows step 9); names both ledgers in its header",
  "core/receive-submit-once.ts":
    "RECEIVE's own claim-and-submit-once path. Prose only: its header names submit_decisions to say that RECEIVE arbitrates on the same (operationId, transactionAttemptNo) pair MOVE does. It takes no import edge to the write path — half 1 does not list it — and is not a SEND surface",
  "core/submit-decision-claim-store.ts": "the write path itself — the module that owns both ledgers",
  "data/privilege-readiness.ts":
    "The boot half. SUBMIT_LEDGER_TABLES names both ledgers so the gate can ask has_table_privilege() whether node_core_send holds INSERT/UPDATE on them. It issues no write of its own — it reads pg_class/pg_roles — and takes no edge to the write path",
  "receive/expiry-release.ts":
    "queries gateway_submit_attempts to detect an in-flight submit at arm-time and at safe-terminal release (lines 237/286/316); produces a live-edge read of the submit ledgers",
  "schema/privileges.contract.ts":
    "The frozen invariant inventory. Names both ledgers inside the REVOKE anchors the census binds to privileges.sql; it is contract text, not a query",
  "gateway/records.ts": "gateway row mappers; names gateway_submit_attempts",
  "gateway/submit.ts": "the gateway submit seam; names both ledgers describing the at-most-once row",
  "move/sql-store.ts":
    "MOVE_INTERNAL live GET projection reads gateway_submit_attempts to derive execution phase; it does not write the submit ledger",
  "protocol/reconcile/move-ambiguity.ts":
    "MOVE reconcile; names both ledgers stating what it must never invent a second row of",
  "schema/submit-attempts.contract.ts": "the frozen DDL contract for gateway_submit_attempts",
  "testkit/gateway-fake.ts": "in-memory gateway double for the real-PG proofs; names gateway_submit_attempts",
  "workers/move-internal-money-worker.ts":
    "MOVE_INTERNAL pipeline compose — names both ledgers describing the at-most-once settle path it drives via core/move-submit-claim",
};

// Of the fourteen above, which the over-inclusive SEND predicate flags. Exact set, same terms as
// SEND_NAMING_REACHERS: a THIRD SEND-naming ledger module reddens rather than being absorbed.
// Both entries name SEND_EXTERNAL in prose because they describe the defence AGAINST it — the
// grant that denies node_core_send the ledgers, and the frozen inventory of that grant. Neither
// executes anything on the SEND path; neither takes an import edge to the write path (half 1
// lists neither).
const SEND_NAMING_LEDGER_MODULES: Readonly<Record<string, string>> = {
  "data/privilege-readiness.ts":
    "boot gate. Names SEND_EXTERNAL stating what node_core_send must NOT be able to write; its only statements are reads of pg_roles / pg_class",
  "schema/privileges.contract.ts":
    "frozen invariant inventory. Names SEND_EXTERNAL quoting signing custody in the rule text for the two REVOKE anchors; it is contract prose, not a query",
};

describe("submit write-path reach guard (import graph, not literal text)", () => {
  const graph = productionImportGraph();

  it("every module reaching the submit write path is declared (half 1, census)", () => {
    // The load-bearing assertion. Exact-set, universally quantified over the tree: a new
    // reacher enters the computed side and reddens, and a DEGRADED analyser empties the
    // computed side and reddens too. The predecessor of this test was a per-entry
    // `not.toContain`, which passed both times.
    expect(
      submitReachers(graph, WRITE_PATH_MODULE),
      `undeclared module reaches ${WRITE_PATH_MODULE}`,
    ).toEqual(Object.keys(SUBMIT_WRITE_PATH_REACHERS).sort());
  });

  it("the SEND_EXTERNAL surfaces among the declared reachers are exactly the named exemptions", () => {
    const flagged = Object.keys(SUBMIT_WRITE_PATH_REACHERS)
      .filter((rel) => isSendExternalSurface(rel, readFileSync(resolve(srcRoot, rel), "utf8")))
      .sort();
    expect(flagged, `a SEND_EXTERNAL surface reaches ${WRITE_PATH_MODULE}`).toEqual(
      Object.keys(SEND_NAMING_REACHERS).sort(),
    );
  });

  it("every module naming a submit ledger is declared (half 2, census)", () => {
    expect(submitLedgerNamingModules(), "undeclared module names a submit ledger").toEqual(
      Object.keys(SUBMIT_LEDGER_NAMING_MODULES).sort(),
    );
  });

  it("the SEND_EXTERNAL surfaces naming a submit ledger are exactly the named exemptions", () => {
    const flagged = Object.keys(SUBMIT_LEDGER_NAMING_MODULES)
      .filter((rel) => isSendExternalSurface(rel, readFileSync(resolve(srcRoot, rel), "utf8")))
      .sort();
    expect(flagged, "a SEND_EXTERNAL surface names a submit ledger").toEqual(
      Object.keys(SEND_NAMING_LEDGER_MODULES).sort(),
    );
  });

  it("neither census is vacuous: the tree and its computed graph are non-empty", () => {
    // Belt and braces. Both censuses already fail closed on an empty computed set — the
    // declared lists are non-empty — but an analyser that stops seeing the tree at all
    // should say so in one line rather than through an exact-set diff.
    expect(productionSourceFiles().length).toBeGreaterThan(300);
    expect([...graph.values()].reduce((total, edges) => total + edges.length, 0)).toBeGreaterThan(
      500,
    );
  });

  // Every evasion demonstrated across the three previous review rounds, plus the four
  // still-open ones, as SOURCE fixtures. Each is a different syntactic form for carrying
  // the write path under another name, and every one of them passes for the SAME single
  // reason: the module takes an import edge to the sink, and the census counts edges, not
  // declarations. That is the thesis — a twelfth variant of the same kind passes for the
  // same reason, and this table is where to demonstrate it in thirty seconds.
  const SINK_SPECIFIER = "./submit-decision-claim-store.js";
  const EVASION_SOURCES: readonly (readonly [string, string])[] = [
    [
      "point-free re-export (E1 / M2)",
      `import { makeSubmitDecisionClaimStore } from "${SINK_SPECIFIER}";\n` +
        "export const mintClaimLedger = makeSubmitDecisionClaimStore;",
    ],
    [
      "carrier laundering, no kind literal and no contracts edge (E3)",
      'import { METRIC_OPERATION_KINDS } from "./metrics.js";\n' +
        `import { mintClaimLedger } from "${SINK_SPECIFIER}";\n` +
        "export const run = () => mintClaimLedger(METRIC_OPERATION_KINDS[2]);",
    ],
    [
      "function-shaped kind carrier (E6)",
      `import { store } from "${SINK_SPECIFIER}";\n` +
        "export function kinds() { return OPERATION_KINDS; }\n" +
        "export const wired = store;",
    ],
    [
      "let-declared carrier",
      `import { store } from "${SINK_SPECIFIER}";\nexport let KINDS = OPERATION_KINDS;`,
    ],
    [
      "var-declared carrier",
      `import { store } from "${SINK_SPECIFIER}";\nexport var KINDS = OPERATION_KINDS;`,
    ],
    [
      "truncated .map() initializer",
      `import { store } from "${SINK_SPECIFIER}";\n` +
        "export const KINDS = OPERATION_KINDS.map((k) => { return k; });",
    ],
    [
      "two-hop non-exported local",
      `import { store } from "${SINK_SPECIFIER}";\n` +
        "const K = OPERATION_KINDS;\nexport const KK = K;",
    ],
    [
      "same-line comment prefix (round-3 blocker)",
      `/* wiring */ import { store } from "${SINK_SPECIFIER}";`,
    ],
    [
      "class static carrier",
      `import { store } from "${SINK_SPECIFIER}";\n` +
        "export class Wiring { static readonly kinds = OPERATION_KINDS; static readonly s = store; }",
    ],
    [
      "export default carrier",
      `import { store } from "${SINK_SPECIFIER}";\nexport default store;`,
    ],
    ["re-export without a local binding", `export * from "${SINK_SPECIFIER}";`],
    ["side-effect import only", `import "${SINK_SPECIFIER}";`],
    ["dynamic import", `export const load = async () => import("${SINK_SPECIFIER}");`],
    ["require()", `export const load = () => require("${SINK_SPECIFIER}");`],
    [
      "import-equals require (E9)",
      `import store = require("${SINK_SPECIFIER}");\nexport const wired = store;`,
    ],
  ];

  it.each(EVASION_SOURCES)("evasion battery (source): %s still leaves the edge", (_name, source) => {
    expect(valueImportEdges(source)).toContain(SINK_SPECIFIER);
  });

  // Sibling table for the forms whose honest outcome is a THROW rather than an edge: the
  // specifier such a module ends up loading is not statically knowable, so the census fails
  // closed instead of resolving it. Kept separate from EVASION_SOURCES rather than folded in,
  // so that table's `toContain` stays the strong claim it reads as — "the edge is still
  // there" — instead of quietly degrading to "an edge, or some error".
  //
  // E7 was runtime-proven: an aliased createRequire really does load the target, and every
  // one of these typechecks clean. Before all of them returned [] — no throw, no
  // edge, silently pruned, which is the one outcome this file forbids in three places.
  const FAIL_CLOSED_SOURCES: readonly (readonly [string, string])[] = [
    [
      "aliased createRequire (E7)",
      'import { createRequire as cr } from "node:module";\n' +
        `export const s = cr(import.meta.url)("${SINK_SPECIFIER}");`,
    ],
    [
      "createRequire destructured out of a dynamic import (E8)",
      'const { createRequire: mk } = await import("node:module");\n' +
        `export const s = mk(import.meta.url)("${SINK_SPECIFIER}");`,
    ],
    [
      "node:module reached as a namespace",
      'import * as mod from "node:module";\n' +
        `export const s = mod.createRequire(import.meta.url)("${SINK_SPECIFIER}");`,
    ],
    [
      "the un-prefixed builtin specifier",
      'import { createRequire as cr } from "module";\nexport const s = cr(import.meta.url);',
    ],
    [
      "side-effect import of the builtin, binding taken later",
      'import "node:module";\nexport const s = globalThis.mk(import.meta.url);',
    ],
    [
      "import-equals require with a non-literal specifier",
      "import store = require(specifier);\nexport const wired = store;",
    ],
  ];

  it.each(FAIL_CLOSED_SOURCES)(
    "fail-closed battery: %s throws rather than pruning the edge",
    (_name, source) => {
      expect(() => valueImportEdges(source)).toThrow(/unresolvable require/);
    },
  );

  // The same battery at the graph level: shapes where the edge is one or more hops away,
  // or where the evader is upstream of a SEND module and therefore invisible to any
  // downward walk from a derived entry set.
  const EVASION_GRAPHS: readonly (readonly [
    string,
    Readonly<Record<string, readonly string[]>>,
    string,
  ])[] = [
    [
      "one alias hop (E1 / M2)",
      {
        "core/send-form-and-sign.ts": ["core/ledger-alias.ts"],
        "core/ledger-alias.ts": [WRITE_PATH_MODULE],
      },
      "core/send-form-and-sign.ts",
    ],
    [
      "N-hop re-export chain (E8)",
      {
        "send/index.ts": ["core/a.ts"],
        "core/a.ts": ["core/b.ts"],
        "core/b.ts": ["core/c.ts"],
        "core/c.ts": [WRITE_PATH_MODULE],
      },
      "send/index.ts",
    ],
    [
      "upstream orchestrator imported by nobody",
      {
        "workers/dispatch-monitor.ts": ["send/index.ts", WRITE_PATH_MODULE],
        "send/index.ts": [],
      },
      "workers/dispatch-monitor.ts",
    ],
    [
      "orphan module, no path names send (E5 generalised)",
      { "workers/completion-tracker.ts": [WRITE_PATH_MODULE] },
      "workers/completion-tracker.ts",
    ],
    [
      "cycle among the reachers",
      { "core/a.ts": ["core/b.ts"], "core/b.ts": ["core/a.ts", WRITE_PATH_MODULE] },
      "core/a.ts",
    ],
  ];

  it.each(EVASION_GRAPHS)(
    "evasion battery (graph): %s lands in the reacher set",
    (_name, edges, evader) => {
      expect(submitReachers(new Map(Object.entries(edges)), WRITE_PATH_MODULE)).toContain(evader);
    },
  );

  it("the reacher set excludes non-reachers, and a cycle through the sink excludes the sink", () => {
    // Not over-inclusive: a module with no path to the sink is not a reacher, so the
    // census is a real measurement rather than "every module, always".
    expect(
      submitReachers(
        new Map(
          Object.entries({
            "core/unrelated.ts": ["core/other.ts"],
            "core/other.ts": [],
            [WRITE_PATH_MODULE]: ["core/other.ts"],
          }),
        ),
        WRITE_PATH_MODULE,
      ),
    ).toEqual([]);
    expect(
      submitReachers(
        new Map(
          Object.entries({
            [WRITE_PATH_MODULE]: ["core/x.ts"],
            "core/x.ts": [WRITE_PATH_MODULE],
          }),
        ),
        WRITE_PATH_MODULE,
      ),
    ).toEqual(["core/x.ts"]);
  });

  it("the closure resolves a real transitive graph, not just each entry in isolation", () => {
    const reached = importClosure(resolve(srcRoot, "send/index.ts"));
    // send/index.ts -> send/create.ts -> ... -> protocol/, i.e. edges are followed past
    // the first hop. If this collapses to the entry alone the reach checks are vacuous.
    expect(reached).toContain("send/index.ts");
    expect(reached).toContain("protocol/send-inner.ts");
    expect(reached.length).toBeGreaterThan(20);
  });

  it("the definition module exists where the reach checks expect it", () => {
    expect(existsSync(resolve(srcRoot, WRITE_PATH_MODULE))).toBe(true);
  });

  it("predicate proof: resolveModule fails closed on the two edges it cannot follow", () => {
    // Both throws are unreachable on a healthy tree — src has zero unresolvable
    // specifiers and zero self-package imports — so a mutation that turns either into
    // `return null` survives every tree-level assertion. Proving them on synthetic input
    // is what makes them live rules rather than commentary.
    const from = resolve(srcRoot, "core/anything.ts");
    expect(() => resolveModule(from, "./no-such-module.js")).toThrow(/unresolvable import/);
    expect(() => resolveModule(from, "@zucoins/node-core")).toThrow(/self-package import/);
    expect(() => resolveModule(from, "@zucoins/node-core/core")).toThrow(/self-package import/);
    // node: builtins and other packages are not edges inside this tree.
    expect(resolveModule(from, "node:fs")).toBeNull();
    expect(resolveModule(from, "@zucoins/generic-node-contracts/operations")).toBeNull();
    // A real relative specifier resolves back to the .ts it compiles from.
    expect(
      resolveModule(resolve(srcRoot, "core/index.ts"), "./submit-decision-claim-store.js"),
    ).toBe(resolve(srcRoot, WRITE_PATH_MODULE));
  });

  it("predicate proof: type-only edges are elided and value edges are not", () => {
    // The case — this must produce no edge, or that fix is re-broken.
    expect(valueImportEdges('import type { SqlQueryFn } from "./store.js";')).toEqual([]);
    expect(valueImportEdges('export type { A } from "./store.js";')).toEqual([]);
    expect(valueImportEdges('import { type A, type B } from "./store.js";')).toEqual([]);
    // Value edges, including a mixed list where only one binding survives compilation.
    expect(valueImportEdges('import { type A, makeThing } from "./store.js";')).toEqual([
      "./store.js",
    ]);
    expect(valueImportEdges('import { makeThing } from "./store.js";')).toEqual(["./store.js"]);
    expect(valueImportEdges('import Store from "./store.js";')).toEqual(["./store.js"]);
    expect(valueImportEdges('import * as store from "./store.js";')).toEqual(["./store.js"]);
    expect(valueImportEdges('export * from "./store.js";')).toEqual(["./store.js"]);
    expect(valueImportEdges('import "./store.js";')).toEqual(["./store.js"]);
    expect(valueImportEdges('import {\n  a,\n  b,\n} from "./store.js";')).toEqual([
      "./store.js",
    ]);
    // A preceding statement must not be swallowed into the clause, losing the real edge.
    expect(
      valueImportEdges('export type Foo = string;\nexport { bar } from "./store.js";'),
    ).toEqual(["./store.js"]);
    // A string that merely looks like a specifier is not an edge.
    expect(valueImportEdges('export const DEFINITION = "core/store.ts";')).toEqual([]);
    // The four the regex never covered. The first three are review-A's round-3 blocker:
    // its `(?:^|[\n;])\s*` anchor could not skip a comment, so these edges were silently
    // DROPPED — the exact failure mode that makes a reach check go vacuous. The last is
    // the `export { type … }` elision the brace-list rule only handled on the import side.
    expect(valueImportEdges('/* c */ import { a } from "./store.js";')).toEqual(["./store.js"]);
    expect(valueImportEdges('/* c */ import "./store.js";')).toEqual(["./store.js"]);
    expect(valueImportEdges('/* c */ export * from "./store.js";')).toEqual(["./store.js"]);
    expect(valueImportEdges('export { type A } from "./store.js";')).toEqual([]);
    expect(valueImportEdges('export { type A, b } from "./store.js";')).toEqual(["./store.js"]);
  });

  it("predicate proof: dynamic import() is an edge, and a computed one fails closed", () => {
    expect(valueImportEdges('const m = await import("./store.js");')).toEqual(["./store.js"]);
    expect(valueImportEdges("const m = await import('./store.js');")).toEqual(["./store.js"]);
    // A computed specifier cannot be resolved statically. Dropping it would let a SEND
    // module load the write path with every assertion green, so it throws instead.
    expect(() => valueImportEdges('await import("./submit" + "-store.js");')).toThrow(
      /computed dynamic import/,
    );
    expect(() => valueImportEdges("await import(specifier);")).toThrow(
      /computed dynamic import/,
    );
    // The static forms are unaffected by the dynamic scan.
    expect(valueImportEdges('import { a } from "./store.js";')).toEqual(["./store.js"]);
  });

  it("predicate proof: squash-normalization matches an assembled ledger name (M2c)", () => {
    for (const table of SUBMIT_LEDGER_TABLES) {
      expect(squash(`const t = "${table}";`)).toContain(squash(table));
    }
    expect(squash('const t = ["submit","decisions"].join("_");')).toContain(squash("submit_decisions"));
    expect(squash('const t = "gateway" + "_submit_" + "attempts";')).toContain(
      squash("gateway_submit_attempts"),
    );
    expect(squash('const t = `submit${"_"}decisions`;')).toContain(squash("submit_decisions"));
    expect(squash('const t = "send_landing_observations";')).not.toContain(squash("submit_decisions"));
    // A string escape is the same string at runtime; undecoded, `u005f` would break the
    // adjacency and the ledger name would slip past.
    expect(squash('const t = "submit\\u005Fdecisions";')).toContain(squash("submit_decisions"));
    expect(squash('const t = "submit\\x5Fdecisions";')).toContain(squash("submit_decisions"));
    expect(squash('const t = "submit\\u{5F}decisions";')).toContain(squash("submit_decisions"));
    expect(squash('const t = "gateway\\u005Fsubmit\\u005Fattempts";')).toContain(
      squash("gateway_submit_attempts"),
    );
    // Decoding must not manufacture a match out of an unrelated name.
    expect(squash('const t = "send\\u005Flanding\\u005Fobservations";')).not.toContain(
      squash("submit_decisions"),
    );
    // A base64 literal is the same string at runtime (review B's residual).
    for (const table of SUBMIT_LEDGER_TABLES) {
      const encoded = Buffer.from(table, "utf8").toString("base64");
      expect(encoded).not.toContain(table);
      expect(squash(`const t = atob("${encoded}");`)).toContain(squash(table));
    }
    // An unrelated base64 literal must not manufacture a match, and a base64-shaped run that
    // decodes to bytes rather than text is left alone rather than injecting noise.
    expect(
      squash(`const t = atob("${Buffer.from("send_landing_observations").toString("base64")}");`),
    ).not.toContain(squash("submit_decisions"));
    expect(squash("const f = makeSubmitAttemptRecorderFactory;")).not.toContain(
      squash("submit_decisions"),
    );
  });

  it("predicate proof: require() is an edge, and createRequire fails closed", () => {
    // Evasion 2 (review D1): createRequire + require("./alias.js") from a SEND entry.
    expect(valueImportEdges('const m = require("./alias.js");')).toEqual(["./alias.js"]);
    expect(valueImportEdges("const m = require('./alias.js');")).toEqual(["./alias.js"]);
    // createRequire mints a require function callable under any name, so it is not
    // statically resolvable and throws rather than pruning the edge — matching how a
    // computed dynamic import() already fails closed.
    expect(() => valueImportEdges("const rq = createRequire(import.meta.url);")).toThrow(
      /unresolvable require/,
    );
    expect(() => valueImportEdges("require(specifier);")).toThrow(/unresolvable require/);
    expect(() => valueImportEdges('require("./submit" + "-store.js");')).toThrow(
      /unresolvable require/,
    );
    // Prose must not be mistaken for a call.
    expect(valueImportEdges("// this step is required")).toEqual([]);
    // `import x = require("./y.js")` is an ExternalModuleReference, not a call, so
    // the CallExpression branch never sees it; it is a real edge and must be followed.
    expect(valueImportEdges('import store = require("./alias.js");')).toEqual(["./alias.js"]);
    // `import type x = require(…)` is erased, and an entity-name alias resolves an existing
    // binding rather than loading a module — neither is an edge, and neither should throw.
    expect(valueImportEdges('import type store = require("./alias.js");')).toEqual([]);
    expect(valueImportEdges("import Alias = Namespace.Member;")).toEqual([]);
    // The alias hole itself: keyed on the callee's spelling, `cr(…)` is not "createRequire",
    // so before this returned [] — no throw, no edge, silently pruned. The edge to
    // node:module is what closes it, so the throw does not depend on the local name at all.
    expect(() =>
      valueImportEdges('import { createRequire as cr } from "node:module";\nconst m = cr(import.meta.url)("./alias.js");'),
    ).toThrow(/unresolvable require/);
    // A node:module edge is thrown on even when nothing is called at all.
    expect(() => valueImportEdges('import { createRequire } from "node:module";')).toThrow(
      /unresolvable require/,
    );
    // Ordinary builtins stay edge-free rather than being caught by the node:module rule.
    expect(valueImportEdges('import { readFileSync } from "node:fs";')).toEqual(["node:fs"]);
  });

  it("predicate proof: an aliased re-export still leaves the structural edge (M2)", () => {
    // M2 hides the call site, not the import. The alias must be defined somewhere, and
    // defining it requires an edge to the module that exports the factory.
    const aliasModule = 'export const mintClaimLedger = makeSubmitDecisionClaimStore;';
    expect(aliasModule).not.toContain("makeSubmitDecisionClaimStore(");
    expect(findWritePathCallSites([{ file: "alias.ts", text: aliasModule }])).toEqual([]);
    expect(
      valueImportEdges(
        'import { makeSubmitDecisionClaimStore } from "./submit-decision-claim-store.js";',
      ),
    ).toEqual(["./submit-decision-claim-store.js"]);
  });
});
