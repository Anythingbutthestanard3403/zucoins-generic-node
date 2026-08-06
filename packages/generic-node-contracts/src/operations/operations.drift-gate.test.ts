import {
  existsSync,
  globSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

import { EXECUTION_TIMEOUTS } from "../testkit/executionPolicy.ts";
import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { OPERATION_KINDS, type OperationKind } from "./operations.contract.ts";

/** Compile-time canary: a `never` default only type-checks while the switch is exhaustive. */
const assertNever = (value: never): never => {
  throw new Error(`unhandled operation kind: ${JSON.stringify(value)}`);
};

const describeOperationKind = (kind: OperationKind): string => {
  switch (kind) {
    case "RECEIVE_EXTERNAL":
      return "an external sender pays into one leased receiver wallet";
    case "MOVE_INTERNAL":
      return "this node moves ZKZ between two wallets it controls";
    case "SEND_EXTERNAL":
      return "this node forms a partial for an external recipient to co-sign";
    default:
      return assertNever(kind);
  }
};

/**
 * Exact files that legitimately co-locate the three frozen `OperationKind` literals — the
 * source of truth, its own census/drift-gate self-tests, and the Appendix B transcription
 * check. Nothing else is exempt: `packages/node-core`, `apps/generic-node`, and `apps/node`
 * (the expected Downstream consumer surface) are deliberately NOT on this list — they may only
 * import/switch on the frozen `OperationKind` union, never redeclare an equivalent one, and
 * the census scans them via `KNOWN_CONSUMER_SCAN_PATHS` to enforce that. The contracts
 * package IS inside the scan roots, so this list is an ACTIVE filter, not a defensive one:
 * `operations.contract.ts` (the source of truth itself) and `operations.census.test.ts` both
 * match the detector on the real tree and are suppressed by exactly these entries.
 * File-exact (not directory-prefix) so adding an unrelated file under
 * `packages/generic-node-contracts` does not silently inherit the exemption.
 */
const SELF_REFERENCE_EXEMPT_FILES = [
  "packages/generic-node-contracts/src/operations/operations.contract.ts",
  "packages/generic-node-contracts/src/operations/operations.census.test.ts",
  "packages/generic-node-contracts/src/operations/operations.drift-gate.test.ts",
  "packages/generic-node-contracts/src/operations/states.contract.ts",
  "packages/generic-node-contracts/src/operations/states.census.test.ts",
  "packages/generic-node-contracts/src/operations/index.ts",
  "packages/generic-node-contracts/src/api-schema/index.ts",
  "packages/generic-node-contracts/src/api-schema/pg-enums.ts",
  "packages/generic-node-contracts/src/api-schema/api-schema.census.test.ts",
] as const;

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

/**
 * Repo-relative `src` directory of every workspace package that has one, read out of
 * `pnpm-workspace.yaml` — the file that DEFINES what a workspace package is. Sorted so the
 * scan sequence is deterministic. Deliberately a small regex parse of the `packages:` block
 * rather than a YAML dependency: the block is a flat list of quoted globs, and a parse that
 * returned nothing is caught by the coverage tests below, not shipped green.
 */
function deriveWorkspaceSourceRoots(root: string): readonly string[] {
  const workspaceYaml = readFileSync(join(root, "pnpm-workspace.yaml"), "utf8");
  const packagesBlock = /^packages:\n((?:[ \t]+-.*\n)+)/m.exec(workspaceYaml)?.[1] ?? "";
  const globs = [...packagesBlock.matchAll(/^[ \t]+-\s*["']?([^"'\n]+?)["']?\s*$/gm)].map(
    (match) => match[1],
  );
  const roots = globs.flatMap((glob) =>
    globSync(join(root, glob, "src")).map((directory) =>
      relative(root, directory).split(sep).join("/"),
    ),
  );
  return [...new Set(roots)].sort();
}

/**
 * Known consumer scan paths: EVERY workspace package's source tree, derived above rather than
 * hand-listed (F2). The hand-maintained list this replaces named six of the repo's
 * thirteen `src` roots, and `packages/consumer-example/src` — a real workspace package that
 * carried the exact canonical union in production source — sat outside the gate entirely. A
 * hand list makes "never scanned" and "deliberately exempt" indistinguishable; deriving it
 * means a new workspace package is inside the gate the moment `pnpm-workspace.yaml` knows
 * about it, with no second list to remember. The NESTED admin workspace
 * (`apps/generic-node/admin`) is a workspace entry in its own right, so
 * derivation picks it up along with everything else; its surface is overwhelmingly
 * `.tsx`, which is why the extension list carries `.tsx`/`.mts` beside `.ts` (AC1).
 *
 * The contracts package itself is included: a hand-rolled redeclaration inside the contracts
 * package is the most dangerous drift vector, and the `SELF_REFERENCE_EXEMPT_FILES` entries
 * keep the legitimate co-located literals from false-positiving. The fixture test below proves
 * the self-scan catches a synthetic redeclaration placed under the contracts path.
 *
 * SCOPE BOUNDARY, stated so it cannot be mistaken for an oversight: each package's `src` tree
 * is scanned and its `test` tree is NOT. Test trees legitimately model the union to drive
 * fixtures and fault injection (`packages/node-core/test/crash-injection-model.ts` declares its
 * own `OperationKind` for exactly that reason), so scanning them would flag deliberate doubles
 * as production drift. The price is that a test-tree fork is unpoliced by this gate; that is a
 * live boundary to revisit, not an omission.
 *
 * Growth stays bounded by `MAX_SCANNED_FILES`, and the "every scanned root contributes real
 * files" test below fails loudly if a derived root is renamed or emptied instead of silently
 * scanning nothing.
 */
const SCAN_ROOTS: readonly string[] = deriveWorkspaceSourceRoots(repoRoot);

/** Every extension the scanned roots can carry TypeScript in. */
const SCAN_EXTENSIONS = ["ts", "mts", "tsx"] as const;

const KNOWN_CONSUMER_SCAN_PATHS: readonly string[] = SCAN_ROOTS.flatMap((root) =>
  SCAN_EXTENSIONS.map((extension) => `${root}/**/*.${extension}`),
);

/**
 * Ceiling on the files the production scan may open in one run. HEAD opens 2,123 across the
 * thirteen derived `SCAN_ROOTS` (1,776 before widened the roots to the whole workspace);
 * 4,000 leaves ~1.9x headroom for ordinary growth while still failing loudly if a widened
 * extension list or a new top-level tree turns the census into a whole-repo walk — the growth
 * this gate is meant to notice.
 */
const MAX_SCANNED_FILES = 4_000;

const [firstKind, secondKind, thirdKind] = OPERATION_KINDS;

/**
 * The gate asks a LEXICAL question — does this file declare or re-fork the operation-kind
 * vocabulary? — so it PARSES rather than pattern-matches. Two rounds of this gate answered it with
 * regex surgery on raw source and went blind twice, each time on a different arm: a block-comment
 * opener inside the route string `"/admin/v1/*"` ran the comment stripper 25,755 bytes past the
 * declaration it existed to expose, and a `//` inside a URL string blanked the rest of a real line
 * of code (278 files over-stripped that way). A regular expression cannot know whether the bytes
 * under it are code, a comment, or the inside of a string, because in TypeScript those are mutually
 * recursive lexical states only a scanner resolves — so bounding one pattern just moved the hole to
 * the next, and two of the four strippers were ALREADY bounded when they went blind. The whole
 * class is retired here: the text is handed to `ts.createSourceFile` once and both questions are
 * asked of the syntax tree, where a comment and a string's contents are already classified and an
 * import specifier is structurally not a declaration. There is nothing left to strip.
 *
 * POST-CHANGE INVARIANT, checkable in one grep: no regular expression in this file is applied to
 * TypeScript source text. The only two survivors read `pnpm-workspace.yaml`.
 */
const FROZEN_KINDS_LOWERCASE: ReadonlySet<string> = new Set(
  OPERATION_KINDS.map((kind) => kind.toLowerCase()),
);

/**
 * Lower-cased text of a node that IS one of the frozen kind literals, else `undefined`. Accepts a
 * `LiteralTypeNode` wrapper so a type-position literal and an expression-position one read the
 * same, and `isStringLiteralLike` covers the backtick form (`NoSubstitutionTemplateLiteral`).
 * Lower-casing keeps the AC1 case-varied-twin catch the retired `i` flag gave: a lowercase
 * or mixed-case twin re-forks the same closed set even though its bytes are not the frozen ones.
 */
const frozenKindLiteral = (node: ts.Node | undefined): string | undefined => {
  if (node === undefined) {
    return undefined;
  }
  const literal = ts.isLiteralTypeNode(node) ? node.literal : node;
  if (!ts.isStringLiteralLike(literal)) {
    return undefined;
  }
  const text = literal.text.toLowerCase();
  return FROZEN_KINDS_LOWERCASE.has(text) ? text : undefined;
};

const distinctFrozenKinds = (nodes: readonly (ts.Node | undefined)[]): number =>
  new Set(nodes.map(frozenKindLiteral).filter((kind) => kind !== undefined)).size;

/**
 * NAME arm (F1). A node that BINDS the identifier `OperationKind` is a re-declaration
 * whatever its members happen to say — which is the point, because members drifting apart IS the
 * failure the three-generic-operation rule exists to catch: `packages/node-core/src/workers/boot-recovery.ts:80` declared
 * `export type OperationKind = "RECEIVE" | "MOVE_INTERNAL" | "SEND_EXTERNAL"` inside a scanned root
 * and read CLEAN to a members-exact detector, going visible again only if someone repaired it.
 *
 * The legitimate consumer forms bind nothing and are structurally excluded, with no stripping:
 * `import { type OperationKind } from "…"` puts the name on an `ImportSpecifier`,
 * `export { type OperationKind }` on an `ExportSpecifier`, and neither is in this list. Annotations
 * and switches on the imported type carry no declaration node at all.
 *
 * Wider than the keyword list it replaces — `FunctionDeclaration` and `ModuleDeclaration` are new,
 * and `VariableDeclaration` covers `const`/`let`/`var` uniformly INCLUDING declarations nested in a
 * block or a namespace body, which the old top-level-ish text match could miss. Verified: zero
 * additional hits over the real tree.
 */
const bindsOperationKindName = (node: ts.Node): boolean =>
  (ts.isTypeAliasDeclaration(node) ||
    ts.isInterfaceDeclaration(node) ||
    ts.isEnumDeclaration(node) ||
    ts.isClassDeclaration(node) ||
    ts.isVariableDeclaration(node) ||
    ts.isFunctionDeclaration(node) ||
    ts.isModuleDeclaration(node)) &&
  node.name !== undefined &&
  ts.isIdentifier(node.name) &&
  node.name.text === "OperationKind";

/**
 * SHAPE arm. A re-fork co-locates three DISTINCT frozen kinds inside ONE node: a type union, an
 * array literal (`as const` arrays and `z.enum([…])`), a tuple type, a string enum's member
 * initialisers, an object literal's property VALUES (the `{ K: "K", … } as const` runtime twin), or
 * a call's arguments (`makeEnum("A", "B", "C")`).
 *
 * The negatives fall out of the structure rather than out of a hand-tuned gap: object KEYS are
 * never read, so `{ RECEIVE_EXTERNAL: a, … }` and its quoted-key twin `{ "RECEIVE_EXTERNAL": a, … }`
 * both stay green; `getPolicy("…")` call sites, `it("…")` titles, and per-object
 * `operationType: "KIND"` policies each put their one literal in a SEPARATE node. Distinctness is
 * required so a node repeating one kind three times is not a re-fork. Members may sit arbitrarily
 * far apart or in any sequence (AC1) — the tree does not care about layout, and a comment
 * or a string between them is a different node, not a gap to be bridged.
 *
 * (the scan/dependency-boundary gate/the three-generic-operation rule intent: import/switch on the frozen union is allowed; redeclaring an equivalent
 * set — union, array, enum, OR object twin — is not.)
 */
const forksFrozenKindSet = (node: ts.Node): boolean => {
  if (ts.isUnionTypeNode(node)) {
    return distinctFrozenKinds(node.types) >= 3;
  }
  if (ts.isTupleTypeNode(node)) {
    return distinctFrozenKinds(node.elements) >= 3;
  }
  if (ts.isArrayLiteralExpression(node)) {
    return distinctFrozenKinds(node.elements) >= 3;
  }
  if (ts.isCallExpression(node)) {
    return distinctFrozenKinds(node.arguments) >= 3;
  }
  if (ts.isEnumDeclaration(node)) {
    return distinctFrozenKinds(node.members.map((member) => member.initializer)) >= 3;
  }
  if (ts.isObjectLiteralExpression(node)) {
    return (
      distinctFrozenKinds(
        node.properties.map((property) =>
          ts.isPropertyAssignment(property) ? property.initializer : undefined,
        ),
      ) >= 3
    );
  }
  return false;
};

/**
 * Parses `text` once. `.tsx` picks `ScriptKind.TSX` because two of the scanned roots are
 * JSX-dominated and a `.ts` parse mis-reads JSX text; `setParentNodes` stays false because no
 * predicate walks upward.
 */
const parseSource = (text: string, fileName: string): ts.SourceFile =>
  ts.createSourceFile(
    fileName,
    text,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ false,
    fileName.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );

/**
 * Syntax errors this parse recorded. `createSourceFile` populates `parseDiagnostics` but does not
 * put it on the public `SourceFile` type, hence the narrow cast — the only public alternative is
 * building a whole `ts.Program`, which this gate has no reason to pay for.
 */
const parseDiagnosticCount = (source: ts.SourceFile): number =>
  (source as unknown as { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics?.length ??
  0;

/** Walks `source` depth-first, short-circuiting on the first node `predicate` accepts. */
const someNode = (source: ts.SourceFile, predicate: (node: ts.Node) => boolean): boolean => {
  const visit = (node: ts.Node): boolean =>
    predicate(node) || ts.forEachChild(node, visit) === true;
  return ts.forEachChild(source, visit) === true;
};

/**
 * The SHAPE arm alone. Exists so a test can PIN that a given drifted sample is invisible to it —
 * which is what makes "the NAME arm is what sees this" an assertion rather than a claim.
 */
const hasFrozenKindFork = (text: string, fileName = "fixture.ts"): boolean =>
  someNode(parseSource(text, fileName), forksFrozenKindSet);

/**
 * Both arms, plus the one fail-open surface a text match did not have: a file the PARSER cannot
 * read is a hit, not a pass. Error recovery does NOT reliably re-emit the declaration. Three
 * characters of a botched conflict resolution at the top of a file (`<<<`) produce three parse
 * diagnostics and relocate every statement start outside the recovery region, so a
 * `export type OperationKind = "RECEIVE" | …` below it is invisible to BOTH arms, invisible to the
 * plant census, and the gate reads CLEAN — the exact declaration F1 exists to catch, hidden by a
 * typo. Two sibling shapes (an unterminated block comment, an unterminated template) go invisible
 * in place the same way. Failing closed on `parseDiagnostics` costs nothing today — zero parse
 * diagnostics across all 2,123 scanned files, pinned in the plant census below — and turns an
 * unreadable file into a loud one instead of a silent pass.
 */
const isOperationKindRedeclaration = (text: string, fileName = "fixture.ts"): boolean => {
  const source = parseSource(text, fileName);
  return (
    parseDiagnosticCount(source) > 0 ||
    someNode(source, (node) => bindsOperationKindName(node) || forksFrozenKindSet(node))
  );
};

const isUnderAllowedPath = (file: string, root: string = repoRoot): boolean =>
  SELF_REFERENCE_EXEMPT_FILES.some((allowed) => file === join(root, allowed));

/**
 * Runs the scan rooted at `root` (the real repo by default). `root` exists so the fixture tests
 * below can exercise the SAME production `KNOWN_CONSUMER_SCAN_PATHS` array against a throwaway
 * temp tree instead of writing into the shared working tree (AC6).
 *
 * `filesScanned` counts the files actually opened (post-exemption). uses it as the
 * scheduling-independent replacement for the wall-clock growth guard this gate used to carry: the
 * cost of the scan is the read pass, so bounding the read count bounds the scan without measuring
 * a machine under unknown parallel load.
 */
const findOperationKindRedeclarations = (
  globPatterns: readonly string[],
  root: string = repoRoot,
): { hits: string[]; filesScanned: number } => {
  const hits: string[] = [];
  let filesScanned = 0;
  for (const pattern of globPatterns) {
    const files = globSync(join(root, pattern));
    for (const file of files) {
      if (isUnderAllowedPath(file, root)) {
        continue;
      }
      filesScanned += 1;
      const text = readFileSync(file, "utf8");
      if (isOperationKindRedeclaration(text, file)) {
        hits.push(file);
      }
    }
  }
  return { hits, filesScanned };
};

/**
 *  AC6. Materialises `files` (repo-relative paths) under a fresh `mkdtemp` root, runs
 * `body`, then removes the whole tree. Crash-safe in the way the previous real-tree fixtures were
 * not: a killed process leaves the fixture in the OS temp dir, never under a scanned repo root,
 * so a concurrent session's scan can never transiently observe it and a crash
 * cannot contaminate the shared working tree. Cleanup is still `finally`-guarded for tidiness,
 * but correctness no longer depends on it.
 */
const withSyntheticTree = <T>(files: Readonly<Record<string, string>>, body: (root: string) => T): T => {
  const root = mkdtempSync(join(tmpdir(), "fixture-drift-gate-"));
  try {
    for (const [relativePath, contents] of Object.entries(files)) {
      const absolute = join(root, relativePath);
      mkdirSync(dirname(absolute), { recursive: true });
      writeFileSync(absolute, contents, "utf8");
    }
    return body(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

const redeclarationFixtureBody = `export const FAKE_KINDS = ["${firstKind}", "${secondKind}", "${thirdKind}"] as const;\n`;

// Real-tree globs over every workspace source root plus twenty-four synthetic-tree fixture runs
// (thirteen scan-coverage rows, ten adversarial-wrapper rows, one exemption run): the realTree
// class in ../testkit/executionPolicy.ts.
describe("operations drift gate (the scan/dependency-boundary gate, the three-generic-operation rule)", { timeout: EXECUTION_TIMEOUTS.realTree }, () => {
  it("exhaustive-switch compile fixture covers every operation kind", () => {
    for (const kind of OPERATION_KINDS) {
      expect(() => describeOperationKind(kind)).not.toThrow();
    }
  });

  it("a runtime 4th operation kind fails the census (negative path)", () => {
    const fourthOperationKind = "REFUND_LIKE_THING"; // synthetic, not a real product term
    expectRejects(
      () => [...OPERATION_KINDS, fourthOperationKind],
      (mutated) => assertFieldOrder(mutated, OPERATION_KINDS),
    );
  });

  // The census scans only the known consumer paths (KNOWN_CONSUMER_SCAN_PATHS) instead of the
  // entire repo, keeping the synchronous globSync+readFileSync cost bounded. That bound used to be
  // asserted as elapsed wall-clock (< 5 s), which measured the MACHINE, not the gate: the same
  // scan is fast alone and slow beside ten sibling forks, so the guard fired on load rather than
  // on growth. MAX_SCANNED_FILES asserts the same property deterministically — the read
  // pass is the cost, so a bounded read count is a bounded scan on any hardware, at any
  // concurrency. The lower bound keeps a glob that resolves to nothing from passing vacuously.
  it("anti-self-reference: no OperationKind-equivalent union is declared outside the contracts package", () => {
    const { hits, filesScanned } = findOperationKindRedeclarations(KNOWN_CONSUMER_SCAN_PATHS);
    expect(hits).toEqual([]);
    expect(filesScanned).toBeGreaterThan(0);
    expect(filesScanned).toBeLessThanOrEqual(MAX_SCANNED_FILES);
  });

  it("anti-self-reference detector mechanism: catches a synthetic const-array redeclaration fixture", () => {
    const syntheticRedeclaration = `export const FAKE_KINDS = ["${firstKind}", "${secondKind}", "${thirdKind}"] as const;`;
    expect(isOperationKindRedeclaration(syntheticRedeclaration)).toBe(true);
  });

  it("anti-self-reference detector mechanism: flags a type-alias union redeclaration", () => {
    const union = `export type Fake = "${firstKind}" | "${secondKind}" | "${thirdKind}";`;
    expect(isOperationKindRedeclaration(union)).toBe(true);
  });

  it("anti-self-reference detector mechanism: flags a z.enum tuple redeclaration", () => {
    const zenum = `const Schema = z.enum(["${firstKind}", "${secondKind}", "${thirdKind}"]);`;
    expect(isOperationKindRedeclaration(zenum)).toBe(true);
  });

  //  coverage: shapes the pre-fix delimiter-adjacency detector MISSED. Each is a genuine
  // re-fork of the frozen union a node-core / apps consumer could plausibly write, and each must
  // now CATCH (these assertions are RED against the narrowed pre-fix `:84-85` regex).
  it("anti-self-reference detector mechanism: flags a TS string-enum redeclaration (wire-value-equivalent)", () => {
    const stringEnum = `export enum Op { ${firstKind} = "${firstKind}", ${secondKind} = "${secondKind}", ${thirdKind} = "${thirdKind}" }`;
    expect(isOperationKindRedeclaration(stringEnum)).toBe(true);
  });

  it("anti-self-reference detector mechanism: flags a comment-laden leading-pipe union redeclaration", () => {
    const commentedUnion = `export type Fake =\n  | "${firstKind}" // receive\n  | "${secondKind}" /* move */\n  | "${thirdKind}";`;
    expect(isOperationKindRedeclaration(commentedUnion)).toBe(true);
  });

  it("anti-self-reference detector mechanism: flags a backtick/template-literal union redeclaration", () => {
    const backtickUnion = `export type Fake = \`${firstKind}\` | \`${secondKind}\` | \`${thirdKind}\`;`;
    expect(isOperationKindRedeclaration(backtickUnion)).toBe(true);
  });

  it("anti-self-reference detector mechanism: flags a literal array with inline block comments", () => {
    const commentedArray = `const FAKE = ["${firstKind}" /*a*/, "${secondKind}" /*b*/, "${thirdKind}"];`;
    expect(isOperationKindRedeclaration(commentedArray)).toBe(true);
  });

  //  object-enum blind spot: a runtime object twin (`const {…} as const`) that re-declares
  // the frozen kinds as `KEY: "VALUE"` entries — the value-set re-fork the scan/dependency-boundary gate exists to catch. RED
  // against the pre-fix `IDENT =`-only gap (comma-then-`:` was excluded), CAUGHT by the `IDENT [=:]`
  // gap. The paired quoted-key map below (`"KIND": value`, colon-first) must stay UNFLAGGED.
  it("anti-self-reference detector mechanism: flags a `const` object-enum re-fork (value twin of the frozen kinds)", () => {
    const objectEnum = `const OPERATION_KINDS = { ${firstKind}: "${firstKind}", ${secondKind}: "${secondKind}", ${thirdKind}: "${thirdKind}" } as const;`;
    expect(isOperationKindRedeclaration(objectEnum)).toBe(true);
  });

  //  F1. The regression the shape detector cannot see: a re-declaration whose members have
  // ALREADY drifted. The first assertion pins the blindness (the frozen-triple pattern is false on
  // this text — repair one literal and it would flag), the second is the fix. RED before the
  // name-based arm: `isOperationKindRedeclaration` returned the first assertion's value.
  it("anti-self-reference detector mechanism: flags a DRIFTED re-declaration named OperationKind (the case the shape detector goes blind on)", () => {
    const driftedRedeclaration = `export type OperationKind = "RECEIVE" | "${secondKind}" | "${thirdKind}";`;
    expect(hasFrozenKindFork(driftedRedeclaration)).toBe(false);
    expect(isOperationKindRedeclaration(driftedRedeclaration)).toBe(true);
  });

  //  rework. The name arm was once re-blinded by its own specifier stripper: a
  // side-effect-only import (`import "./x.js";` — no `from` of its own) let a lazy text match run
  // forward to the next `from "…"` it could find, typically a re-export barrel further down the
  // file, and erase everything between the two — including the drifted declaration the arm exists
  // to catch. So the exact defect F1 names survived inside an otherwise ordinary file. Retained
  // after the parser rewrite because it is a realistic file shape (37 real scanned files open with
  // a side-effect-only import), not because the mechanism it once defeated still exists. The
  // `hasFrozenKindFork` line pins that this is the SHAPE arm's blind spot, so the NAME arm is what
  // has to see it.
  it("anti-self-reference detector mechanism: a side-effect-only import and a re-export barrel cannot erase a DRIFTED re-declaration between them", () => {
    const barrel = [
      `import "./instrumentation.js";`,
      ``,
      `export type OperationKind = "RECEIVE" | "${secondKind}" | "${thirdKind}";`,
      ``,
      `export { helper } from "./helper.js";`,
    ].join("\n");
    expect(hasFrozenKindFork(barrel)).toBe(false);
    expect(isOperationKindRedeclaration(barrel)).toBe(true);
    // Each wrapper on its own, so neither stripper arm can be the one that goes blind: a
    // side-effect import with a plain later import, and a barrel with no import above it at all.
    const sideEffectThenImport = `import "./boot.js";\nexport type OperationKind = string;\nimport { z } from "zod";`;
    const barrelOnly = `export enum OperationKind { A = "A" }\nexport { helper } from "./helper.js";`;
    expect(isOperationKindRedeclaration(sideEffectThenImport)).toBe(true);
    expect(isOperationKindRedeclaration(barrelOnly)).toBe(true);
  });

  it("anti-self-reference detector mechanism: flags every declaration form that binds the name OperationKind", () => {
    expect(isOperationKindRedeclaration(`type OperationKind = string;`)).toBe(true);
    expect(isOperationKindRedeclaration(`interface OperationKind { kind: string }`)).toBe(true);
    expect(isOperationKindRedeclaration(`enum OperationKind { A = "A" }`)).toBe(true);
    expect(isOperationKindRedeclaration(`const OperationKind = ["A"] as const;`)).toBe(true);
  });

  //  B1. The fail-open surface the parser rewrite introduced and the previous round wrongly
  // dismissed as a ratchet: a file the parser cannot READ. Three characters of a botched conflict
  // resolution defeat error recovery — every statement start is relocated outside the recovery
  // region, so the drifted declaration below produces no declaration node at all, both arms go
  // blind IN PLACE, and the plant census cannot see it either. The two sibling shapes below go
  // invisible the same way. RED before the detector failed closed on `parseDiagnostics`.
  it("anti-self-reference detector mechanism: a file the parser cannot read is a hit, not a pass", () => {
    const drifted = `export type OperationKind = "RECEIVE" | "${secondKind}" | "${thirdKind}";`;
    const bothArms = (text: string): boolean =>
      someNode(
        parseSource(text, "fixture.ts"),
        (node) => bindsOperationKindName(node) || forksFrozenKindSet(node),
      );
    for (const unreadable of [
      `<<<\n${drifted}\n`, // conflict-marker remnant
      `/* unterminated\n${drifted}\n`, // unterminated block comment
      `const banner = \`unterminated\n${drifted}\n`, // unterminated template
    ]) {
      expect(parseDiagnosticCount(parseSource(unreadable, "fixture.ts"))).toBeGreaterThan(0);
      expect(bothArms(unreadable)).toBe(false); // pins WHY: neither arm can see the declaration
      expect(isOperationKindRedeclaration(unreadable)).toBe(true);
    }
    // The paired direction: a file that parses clean is judged on its nodes, not waved through or
    // flagged for the sake of it.
    expect(parseDiagnosticCount(parseSource(drifted, "fixture.ts"))).toBe(0);
    expect(isOperationKindRedeclaration(`export const ok = 1;\n`)).toBe(false);
  });

  // The paired direction, per the standing mutation rule: a legitimate CONSUMER of the canonical
  // type must stay green, or the name arm just relocates the false-positive problem.
  it("anti-self-reference detector mechanism: does NOT flag importing, annotating with, or re-exporting the canonical OperationKind", () => {
    const importer = [
      `import { OPERATION_KINDS, type OperationKind } from "@zucoins/generic-node-contracts/operations";`,
      `export { type OperationKind };`,
      `const kind: OperationKind = "${firstKind}";`,
      `function describe(kind: OperationKind): string { return kind; }`,
      `export const ALL: readonly OperationKind[] = OPERATION_KINDS;`,
    ].join("\n");
    const typeOnlyReexport = `export type { OperationKind } from "@zucoins/generic-node-contracts/operations";`;
    const defaultStyleImport = `import type { OperationKind } from "../operations/operations.contract.ts";\nlet current: OperationKind | null = null;`;
    expect(isOperationKindRedeclaration(importer)).toBe(false);
    expect(isOperationKindRedeclaration(typeOnlyReexport)).toBe(false);
    expect(isOperationKindRedeclaration(defaultStyleImport)).toBe(false);
  });

  it("anti-self-reference detector mechanism: does NOT flag legitimate consumer usage (object keys, quoted keys, call args, test titles, per-object operationType)", () => {
    const objectKeys = `const map = { ${firstKind}: a, ${secondKind}: b, ${thirdKind}: c };`;
    const quotedKeys = `const map = { "${firstKind}": a, "${secondKind}": b, "${thirdKind}": c };`;
    const callArgs = `getPolicy("${firstKind}");\n  getPolicy("${secondKind}");\n  getPolicy("${thirdKind}");`;
    const titles = `it("${firstKind} works");\n  it("${secondKind} works");\n  it("${thirdKind} works");`;
    const perObjectPolicy = `const A = { operationType: "${firstKind}", steps: [1] };\nconst B = { operationType: "${secondKind}", steps: [1] };\nconst C = { operationType: "${thirdKind}" };`;
    expect(isOperationKindRedeclaration(objectKeys)).toBe(false);
    expect(isOperationKindRedeclaration(quotedKeys)).toBe(false);
    expect(isOperationKindRedeclaration(callArgs)).toBe(false);
    expect(isOperationKindRedeclaration(titles)).toBe(false);
    expect(isOperationKindRedeclaration(perObjectPolicy)).toBe(false);
  });

  it("anti-self-reference detector mechanism: skips only the exact contracts-package files that legitimately co-locate the literals", () => {
    for (const allowed of SELF_REFERENCE_EXEMPT_FILES) {
      expect(isUnderAllowedPath(join(repoRoot, allowed))).toBe(true);
    }
    const unrelatedContractsFile = join(
      repoRoot,
      "packages/generic-node-contracts/src/operations/routes.contract.ts",
    );
    expect(isUnderAllowedPath(unrelatedContractsFile)).toBe(false);
  });

  it("anti-self-reference detector mechanism: does NOT skip node-core/generic-node — they are scanned, not exempted", () => {
    const nodeCoreFile = join(repoRoot, "packages/node-core/src/index.ts");
    const genericNodeFile = join(repoRoot, "apps/generic-node/src/index.ts");
    expect(isUnderAllowedPath(nodeCoreFile)).toBe(false);
    expect(isUnderAllowedPath(genericNodeFile)).toBe(false);
  });

  //  AC1 — the PRODUCTION path list, not a synthetic twin. A widened glob that resolves to
  // nothing is the failure mode this gate has already shipped once: a green fixture test named for
  // a root the running scan never opened. Each root must resolve to real files on the real tree,
  // and the two nested product workspaces must contribute the `.tsx` surface that a `.ts`-only
  // glob missed entirely.
  it("production scan paths actually resolve: every scanned root contributes real files to the running gate", () => {
    const filesPerRoot = Object.fromEntries(
      SCAN_ROOTS.map((root) => [
        root,
        SCAN_EXTENSIONS.flatMap((extension) =>
          globSync(join(repoRoot, `${root}/**/*.${extension}`)),
        ),
      ]),
    );
    for (const root of SCAN_ROOTS) {
      expect(filesPerRoot[root].length, `no files resolved under scanned root ${root}`).toBeGreaterThan(0);
    }
    // The nested admin workspace was previously scanned by nothing at all; assert its real
    // `.tsx` surface (not merely "some file") is inside the gate now.
    for (const nestedWorkspaceRoot of ["apps/generic-node/admin/src"]) {
      const tsxFiles = globSync(join(repoRoot, `${nestedWorkspaceRoot}/**/*.tsx`));
      expect(tsxFiles.length, `no .tsx resolved under ${nestedWorkspaceRoot}`).toBeGreaterThan(0);
    }
  });

  //  F2 — coverage of the FULL target class, derived from a source the scan itself does not
  // read. `SCAN_ROOTS` comes from `pnpm-workspace.yaml`; this walks the FILESYSTEM for package
  // manifests instead, so the two disagree if a package exists on disk but is missing from the
  // workspace file, if the YAML parse silently degrades to nothing, or if a new nested product
  // workspace lands. Any of those is a scope hole of exactly the kind that hid
  // `packages/consumer-example/src` — the assertion fails rather than the gate quietly shrinking.
  it("scan coverage: every workspace package source tree on disk is inside the gate", () => {
    const manifestPatterns = ["packages/*/package.json", "apps/*/package.json", "apps/*/*/package.json"];
    const sourceRootsOnDisk = [
      ...new Set(
        manifestPatterns
          .flatMap((pattern) => globSync(join(repoRoot, pattern)))
          .filter((manifest) => !manifest.includes(`${sep}node_modules${sep}`))
          .map((manifest) => join(dirname(manifest), "src"))
          .filter((directory) => existsSync(directory))
          .map((directory) => relative(repoRoot, directory).split(sep).join("/")),
      ),
    ].sort();
    expect(sourceRootsOnDisk.length).toBeGreaterThan(0);
    expect([...SCAN_ROOTS]).toEqual(sourceRootsOnDisk);
    // The same coverage hole one level up, and the reason the equality above is not enough on its
    // own: `deriveWorkspaceSourceRoots` hardcodes `src`, so a workspace package whose sources live
    // in `lib/` is outside the gate AND filtered off BOTH sides of that comparison, which then
    // holds vacuously. Pin the currently-empty set of `src`-less workspace packages so such a
    // package turns this red instead of disappearing.
    const packagesWithoutSourceRoot = [
      ...new Set(
        manifestPatterns
          .flatMap((pattern) => globSync(join(repoRoot, pattern)))
          .filter((manifest) => !manifest.includes(`${sep}node_modules${sep}`))
          .filter((manifest) => !existsSync(join(dirname(manifest), "src")))
          .map((manifest) => relative(repoRoot, dirname(manifest)).split(sep).join("/")),
      ),
    ].sort();
    expect(packagesWithoutSourceRoot).toEqual([]);
  });

  //  AC1+AC6. One table drives every fixture: each entry is a repo-relative path under a
  // DIFFERENT scanned root/extension, and every case runs the production KNOWN_CONSUMER_SCAN_PATHS
  // array against a temp tree. A root or extension dropped from the production list turns the
  // matching row red — the fixture cannot pass on a glob the real gate does not run.
  const scanCoverageFixtures = [
    ["packages/node-core/src/__census-fixture-redeclaration.ts", redeclarationFixtureBody],
    [
      "packages/node-core/src/__census-fixture-string-enum.ts",
      `export enum Op { ${firstKind} = "${firstKind}", ${secondKind} = "${secondKind}", ${thirdKind} = "${thirdKind}" }\n`,
    ],
    ["apps/generic-node/src/__census-fixture-redeclaration.ts", redeclarationFixtureBody],
    ["packages/generic-node-consumer/src/__census-fixture-redeclaration.ts", redeclarationFixtureBody],
    [
      "packages/generic-node-contracts/src/operations/__census-fixture-redeclaration.ts",
      redeclarationFixtureBody,
    ],
    ["apps/generic-node/admin/src/components/__census-fixture-redeclaration.tsx", redeclarationFixtureBody],
    [
      "apps/generic-node/admin/src/pages/__census-fixture-redeclaration.tsx",
      redeclarationFixtureBody,
    ],
    ["packages/generic-node-consumer/src/__census-fixture-redeclaration.mts", redeclarationFixtureBody],
    [
      // Case-varied twin under a nested workspace: not the frozen bytes, still the same closed set.
      "apps/generic-node/admin/src/__census-fixture-case-varied.tsx",
      `export type Fake = "${firstKind.toLowerCase()}" | "${secondKind.toLowerCase()}" | "${thirdKind.toLowerCase()}";\n`,
    ],
    [
      // Reordered + wide-spread twin: the two evasions the pre- proximity regex allowed.
      "apps/generic-node/admin/src/__census-fixture-reordered.tsx",
      `export type Fake =\n  | "${thirdKind}"${" ".repeat(400)}\n  | "${firstKind}"${" ".repeat(400)}\n  | "${secondKind}";\n`,
    ],
    [
      //  F1 through the PRODUCTION scan, not just the unit detector: the already-drifted
      // re-declaration the frozen-triple pattern cannot see.
      "packages/node-core/src/workers/__census-fixture-drifted-name.ts",
      `export type OperationKind = "RECEIVE" | "${secondKind}" | "${thirdKind}";\n`,
    ],
    [
      //  rework: the same drifted re-declaration WRAPPED in the two specifier shapes that
      // used to erase it — a side-effect-only import above, a re-export barrel below — driven
      // through the production scan rather than the unit detector alone. This is the realistic
      // file, not the bare line: 37 real scanned files open exactly like this. RED against the
      // unbounded strippers.
      "packages/node-core/src/workers/__census-fixture-drifted-barrel.ts",
      `import "./instrumentation.js";\n\nexport type OperationKind = "RECEIVE" | "${secondKind}" | "${thirdKind}";\n\nexport { helper } from "./helper.js";\n`,
    ],
    [
      //  F2: a root the pre-fix hand-maintained SCAN_ROOTS list did not contain at all.
      // RED until `packages/consumer-example/src` is inside the derived roots.
      "packages/consumer-example/src/__census-fixture-redeclaration.ts",
      redeclarationFixtureBody,
    ],
  ] as const;

  for (const [relativePath, contents] of scanCoverageFixtures) {
    it(`anti-self-reference: the production scan catches a redeclaration at ${relativePath}`, () => {
      withSyntheticTree({ [relativePath]: contents }, (root) => {
        const { hits } = findOperationKindRedeclarations(KNOWN_CONSUMER_SCAN_PATHS, root);
        expect(hits).toContain(join(root, relativePath));
      });
    });
  }

  //  rework 2 — the adversarial table. Every row wraps the SAME already-drifted declaration
  // in a context that defeated a text-scanning detector, and drives it through the PRODUCTION scan
  // rather than the unit detector alone. Five of these are RED against the regex pipeline this
  // change deletes (rows 1-5); they stay so a future lane that reaches for `String.replace` on
  // TypeScript source turns them red instead of shipping a third instance of the same defect. The
  // declaration binds `OperationKind` but spells only TWO frozen kinds, so only the NAME arm can
  // see it — every row is therefore a test of the name arm surviving its surroundings.
  const driftedDeclaration = `export type OperationKind = "RECEIVE" | "${secondKind}" | "${thirdKind}";`;
  const adversarialWrappers = [
    [
      // A block-comment OPENER inside a route string, with a doc-comment terminator below it. On
      // the deleted pipeline this blanked 25,755 bytes of `apps/node/src/index.ts`.
      "packages/node-core/src/__census-fixture-hostile-comment-open.ts",
      `const routes = { admin: "/admin/v1/*" };\n${driftedDeclaration}\n/** trailing doc. */\nexport const ok = 1;\n`,
    ],
    [
      // A `//` sequence inside a string on the declaration's own line. The line-comment arm was
      // BOUNDED to one line and still blanked real code in 278 scanned files this way. (A bare
      // `//` rather than a scheme-qualified locator, so the egress census stays green.)
      "packages/node-core/src/__census-fixture-hostile-double-slash.ts",
      `const marker = "a//b"; ${driftedDeclaration}\n`,
    ],
    [
      // Semicolon-free (ASI) file: the delimiter bound the import stripper relied on never arrives.
      "apps/generic-node/src/__census-fixture-hostile-asi.ts",
      `import "./x.js"\nexport type OperationKind = "RECEIVE" | "${secondKind}" | "${thirdKind}"\nexport { helper } from "./helper.js"\n`,
    ],
    [
      // An `export {` sequence inside a string literal, which opened the export-specifier arm.
      "packages/generic-node-consumer/src/__census-fixture-hostile-export-string.ts",
      `const banner = "export { a } from './b'";\n${driftedDeclaration}\n`,
    ],
    [
      // A regular-expression literal containing a block-comment opener.
      "packages/consumer-example/src/__census-fixture-hostile-regex-literal.ts",
      `const pattern = /a\\/*b/;\n${driftedDeclaration}\n/** trailing doc. */\n`,
    ],
    [
      // The word `import` in ordinary prose above the declaration.
      "packages/generic-node-consumer/src/__census-fixture-hostile-prose.ts",
      `// this module must not import the barrel directly\n${driftedDeclaration}\n`,
    ],
    [
      // Nested inside a namespace body — a declaration a top-level text match can miss.
      "packages/consumer-example/src/__census-fixture-hostile-namespace.ts",
      `export namespace Fixture {\n  ${driftedDeclaration}\n}\n`,
    ],
    [
      // Nested inside a function body, binding the name as a `const` rather than a type.
      "packages/generic-node-consumer/src/__census-fixture-hostile-function-body.ts",
      `export function make() {\n  const OperationKind = ["${firstKind}"] as const;\n  return OperationKind;\n}\n`,
    ],
    [
      //  B1 through the PRODUCTION scan, not the unit detector alone: a conflict-marker
      // remnant the parser cannot read, which relocates every statement start outside the recovery
      // region so neither arm sees the declaration below it. Caught only because the detector fails
      // closed on a parse diagnostic — RED before that, on all three surfaces at once.
      "packages/node-core/src/__census-fixture-unreadable-conflict.ts",
      `<<<\n${driftedDeclaration}\n`,
    ],
    [
      // JSX text carrying a block-comment opener and an apostrophe: a raw scanner mis-tokenises
      // this as an unterminated string, which is why the parse is driven with `ScriptKind.TSX`.
      "apps/generic-node/admin/src/__census-fixture-hostile-jsx.tsx",
      `export const Note = () => <p>It's fine /* and 100% ok</p>;\n${driftedDeclaration}\n`,
    ],
  ] as const;

  for (const [relativePath, contents] of adversarialWrappers) {
    it(`anti-self-reference: the production scan catches a DRIFTED re-declaration wrapped at ${relativePath}`, () => {
      withSyntheticTree({ [relativePath]: contents }, (root) => {
        const { hits } = findOperationKindRedeclarations(KNOWN_CONSUMER_SCAN_PATHS, root);
        expect(hits).toContain(join(root, relativePath));
      });
    });
  }

  //  rework 2. The instrument that finds the instance nobody enumerated, and the reason a
  // third round of this defect cannot ship silently: plant the drifted declaration at EVERY
  // top-level statement boundary of EVERY scanned file (plus offset 0 and EOF) and require the
  // PRODUCTION detector to catch it at every position. Exhaustiveness is the power — measured on
  // the deleted pipeline, planting only at the first statement caught 20 of its 27 blind files, at
  // the last statement 2 of 27, and at EOF 0 of 27. Asserts BLINDNESS = 0, never elapsed time
  // : a wall-clock assertion measures the machine, not the gate.
  it(
    "plant census: no scanned file can hide a drifted re-declaration at any top-level position",
    // 22.9 s observed on a loaded box (2,123 files, 29,497 positions, ~29,497 parses); the ceiling
    // is generous on purpose because the assertion is blindness = 0, not elapsed time.
    { timeout: 120_000 },
    () => {
      const planted = `\n${driftedDeclaration}\n`;
      const blind: string[] = [];
      const zeroStatementFiles: string[] = [];
      const unparseableFiles: string[] = [];
      let filesPlanted = 0;
      let positions = 0;
      for (const pattern of KNOWN_CONSUMER_SCAN_PATHS) {
        for (const file of globSync(join(repoRoot, pattern))) {
          if (isUnderAllowedPath(file)) {
            continue;
          }
          const text = readFileSync(file, "utf8");
          const source = parseSource(text, file);
          const repoRelative = relative(repoRoot, file).split(sep).join("/");
          if (parseDiagnosticCount(source) > 0) {
            unparseableFiles.push(repoRelative);
          }
          if (source.statements.length === 0 && text.trim().length > 0) {
            zeroStatementFiles.push(repoRelative);
          }
          filesPlanted += 1;
          const offsets = [
            ...new Set([0, ...source.statements.map((s) => s.getStart(source)), text.length]),
          ];
          for (const offset of offsets) {
            positions += 1;
            const mutated = `${text.slice(0, offset)}${planted}${text.slice(offset)}`;
            if (!isOperationKindRedeclaration(mutated, file)) {
              blind.push(`${repoRelative}@${offset}`);
            }
          }
        }
      }
      expect(blind).toEqual([]);
      expect(filesPlanted).toBeGreaterThan(0);
      expect(positions).toBeGreaterThan(filesPlanted);
      // The parser is a trusted component now, so a file it cannot read is a surface a text match
      // did not have. It was a LIVE hole, not a ratchet: error recovery does not reliably re-emit
      // the declaration — a `<<<` conflict remnant relocates every statement start outside the
      // recovery region, which left both arms AND this census blind on the file. The detector
      // therefore fails closed on `parseDiagnostics`, and the currently-empty set is pinned here so
      // an unreadable file has to be looked at rather than trusted. `blind` above is measured with
      // that fail-closed behaviour in place, so a plant that makes a file unparseable is a hit
      // either way, never a silent pass.
      expect(unparseableFiles.sort()).toEqual([]);
      // No scanned file legitimately carries zero statements today; one appearing has to be
      // looked at, not silently trusted.
      expect(zeroStatementFiles.sort()).toEqual([]);
    },
  );

  it("anti-self-reference: the exempt contracts-package files stay exempt under the production scan", () => {
    withSyntheticTree(
      Object.fromEntries(
        SELF_REFERENCE_EXEMPT_FILES.map((allowed) => [allowed, redeclarationFixtureBody]),
      ),
      (root) => {
        expect(findOperationKindRedeclarations(KNOWN_CONSUMER_SCAN_PATHS, root).hits).toEqual([]);
      },
    );
  });

  it("anti-self-reference: fixtures never touch the real tree (no residual census fixture on disk)", () => {
    const residual = SCAN_ROOTS.flatMap((root) =>
      SCAN_EXTENSIONS.flatMap((extension) =>
        globSync(join(repoRoot, `${root}/**/__census-fixture-*.${extension}`)),
      ),
    );
    expect(residual).toEqual([]);
  });
});
