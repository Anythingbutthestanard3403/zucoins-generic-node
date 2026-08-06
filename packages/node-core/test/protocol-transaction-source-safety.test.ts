import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vitest";

import * as nodeCoreApi from "../src/index.js";
import * as protocolApi from "../src/protocol/index.js";

interface ProductionSource {
  readonly relativePath: string;
  readonly sourceFile: ts.SourceFile;
}

const protocolRoot = fileURLToPath(new URL("../src/protocol/", import.meta.url));
const TRANSACTION_FILE = "transactions.ts";
const INNER_DIGEST_FILE = "inner.ts";
const INNER_SHAPE_FILE = "inner-shape.ts";
const TRANSFER_CODE_FILE = "send-transfer-code.ts";
const RECONCILE_DIRECTORY = "reconcile";
const RECONCILE_PREFIX = `${RECONCILE_DIRECTORY}${sep}`;
const RECONCILE_UNREACHABLE_FILE = join(RECONCILE_DIRECTORY, "types.ts");
// Changing this digest authorizes a semantic transaction-construction change and therefore
// requires a fresh independent byte-path rereview; never update it as snapshot churn.
const REVIEWED_TRANSACTION_AST_SHA256_REQUIRES_INDEPENDENT_BYTE_PATH_REREVIEW =
  "4954e6237ab8568e896efc1d8369f6d1a04504d75305b93013ced749d563a018";
const REVIEWED_AST_FINGERPRINT_VIOLATION =
  `${TRANSACTION_FILE}: reviewed normalized AST fingerprint (independent byte-path rereview required)`;
const normalizedAstPrinter = ts.createPrinter({
  newLine: ts.NewLineKind.LineFeed,
  removeComments: true,
});

function normalizedAstSha256(sourceFile: ts.SourceFile): string {
  const normalizedAst = normalizedAstPrinter.printFile(sourceFile);
  return createHash("sha256").update(normalizedAst, "utf8").digest("hex");
}

function collectSources(directory: string): ProductionSource[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry): ProductionSource[] => {
      const absolutePath = join(directory, entry.name);
      if (entry.isDirectory()) return collectSources(absolutePath);
      if (!entry.isFile() || !entry.name.endsWith(".ts")) return [];
      // Colocated *.test.ts files under src/protocol/ (the wallet-role
      // and economic-predicate tests) legitimately use spread/String()/.replace() as
      // fast-check generators and fixtures. This gate scans production money-path sources
      // only; a narrow.test.ts suffix excludes them. Mirrors the precedent (commit
      // a43ed9d0); a non-vacuity guard below proves the exclusion never empties the scan.
      if (entry.name.endsWith(".test.ts")) return [];
      return [
        {
          relativePath: relative(protocolRoot, absolutePath),
          sourceFile: ts.createSourceFile(
            absolutePath,
            readFileSync(absolutePath, "utf8"),
            ts.ScriptTarget.Latest,
            true,
            ts.ScriptKind.TS,
          ),
        },
      ];
    })
    .sort((left, right) => left.relativePath.localeCompare(right.relativePath));
}

// construction scope.
//
// This is a TRANSACTION-CONSTRUCTION ratchet, and `src/protocol/reconcile/` is not transaction
// construction: it is the MOVE invariant-breach / landing classification and quarantine concern of
// operations recovery. It was swept into the walk purely by directory placement, and every
// one of the 33 surfaces it contributed was a symptom of that single mis-scoping, not of a
// construction defect. The gate already reasoned exactly this way once, in the `assertUnreachable`
// exemption below: "The reconcile concern is a pure classification vocabulary: protocol/
// transactions.ts does not import it, protocol/index.ts does not re-export it."
//
// This is NOT a path skip or a directory trust grant, which the preamble rightly disclaims.
// The exclusion rests on a property that is COMPUTED and asserted on every run by
// `reconcileImportEdges` — a single new import edge from any scanned construction file (including a
// re-export in protocol/index.ts) turns the gate red and forces the scope to be re-argued. The
// excluded set is separately pinned non-empty so the exclusion cannot be satisfied vacuously by a
// rename or a move.
//
// State the computed property exactly, because it is narrower than "reconcile/ cannot reach signed
// bytes" and must not be read as that claim (review B, D3):
//
//   COMPUTED — no direct module specifier in any scanned construction file under src/protocol/**
//   resolves into src/protocol/reconcile/, protocol/index.ts does not re-export it, and the runtime
//   protocol surface does not carry it.
//
//   NOT COMPUTED — that reconcile/ is unreachable from signing generally. It is live and imported
//   from OUTSIDE this walk (src/core/move-submit-claim.ts, src/core/receive-submit-once.ts,
//   src/verifier/landing-path-oracle.ts, src/workers/boot-recovery.ts, src/receive/landing-commit.ts)
//   and those layers do sign. What the exclusion buys is only that reconcile/ cannot inject a
//   construction defect THROUGH THIS DIRECTORY into the transaction-construction surface this
//   ratchet guards. Coercion coverage of reconcile/ is unaffected
//   (protocol-source-safety.test.ts) still scans the same root including reconcile/. What reconcile/
//   loses here is spread / Date / stringify / permissive-Record detectors.
function isReconcileConcern(relativePath: string): boolean {
  return relativePath.startsWith(RECONCILE_PREFIX);
}

// Every module specifier a source depends on: static imports, re-exports (`export ... from`),
// dynamic `import()`, and `import("...")` type nodes. Missing a form here would silently weaken the
// isolation guard, so all four are collected rather than just `ImportDeclaration`.
function moduleSpecifiers(sourceFile: ts.SourceFile): string[] {
  const specifiers: string[] = [];
  visitEveryNode(sourceFile, (node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier !== undefined &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      specifiers.push(node.moduleSpecifier.text);
      return;
    }
    if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length > 0 &&
      ts.isStringLiteral(node.arguments[0])
    ) {
      specifiers.push(node.arguments[0].text);
      return;
    }
    if (
      ts.isImportTypeNode(node) &&
      ts.isLiteralTypeNode(node.argument) &&
      ts.isStringLiteral(node.argument.literal)
    ) {
      specifiers.push(node.argument.literal.text);
    }
  });
  return specifiers;
}

// Path containment on normalised ABSOLUTE paths, never a prefix test on a raw relative string. Two
// specifiers naming the same file must be judged the same way: `./reconcile/types.js` and
// `../protocol/reconcile/types.js` resolve identically on disk, but the second normalises to a
// string that starts with `..` and slips past any prefix test on the relative form.
//
// The comparison is case-insensitive because macOS mounts are: `./Reconcile/types.js` resolves into
// the excluded directory on this repo's own filesystem while an exact-case prefix test misses it.
// Folding case can only ever flag MORE edges, so the guard stays fail-closed on case-sensitive
// filesystems rather than trading one platform's soundness for another's.
function isInsideDirectory(directoryWithSeparator: string, absolutePath: string): boolean {
  return `${absolutePath}${sep}`
    .toLowerCase()
    .startsWith(directoryWithSeparator.toLowerCase());
}

const RECONCILE_ROOT = `${join(protocolRoot, RECONCILE_DIRECTORY)}${sep}`;

// Fails closed in three ways. A bare specifier that merely looks like `reconcile/...` is resolved
// relatively too, so it trips rather than being waved through. A relative specifier that climbs out
// of the protocol root and back resolves to the same absolute file as the direct form and trips
// identically. A relative specifier that lands OUTSIDE the protocol root is reported as well: it
// leaves the scanned surface, so this gate cannot prove where it re-enters, and an unprovable edge
// must read as a finding rather than as silence.
function reconcileEdgeReason(relativePath: string, specifier: string): string | null {
  const resolved = resolve(dirname(join(protocolRoot, relativePath)), specifier);
  if (isInsideDirectory(RECONCILE_ROOT, resolved)) return `imports ${specifier}`;
  if (specifier.startsWith(".") && !isInsideDirectory(protocolRoot, resolved)) {
    return `imports ${specifier} (resolves outside the protocol root; reconcile isolation unprovable)`;
  }
  return null;
}

function reconcileImportEdges(sources: readonly ProductionSource[]): string[] {
  return sources.flatMap(({ relativePath, sourceFile }) =>
    moduleSpecifiers(sourceFile)
      .map((specifier) => reconcileEdgeReason(relativePath, specifier))
      .filter((reason): reason is string => reason !== null)
      .map((reason) => `${relativePath}: ${reason}`),
  );
}

function visitEveryNode(sourceFile: ts.SourceFile, assertion: (node: ts.Node) => void): void {
  const visit = (node: ts.Node): void => {
    assertion(node);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function constantStringValue(
  expression: ts.Expression,
  constStrings: ReadonlyMap<string, string>,
): string | undefined {
  const current = unwrapExpression(expression);
  if (ts.isStringLiteral(current) || ts.isNoSubstitutionTemplateLiteral(current)) {
    return current.text;
  }
  if (ts.isIdentifier(current)) return constStrings.get(current.text);
  if (
    ts.isBinaryExpression(current) &&
    current.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = constantStringValue(current.left, constStrings);
    const right = constantStringValue(current.right, constStrings);
    return left === undefined || right === undefined ? undefined : left + right;
  }
  return undefined;
}

function expressionPath(
  expression: ts.Expression,
  sourceFile: ts.SourceFile,
  aliases: ReadonlyMap<string, string>,
  constStrings: ReadonlyMap<string, string>,
): string | null {
  const current = unwrapExpression(expression);
  if (ts.isIdentifier(current)) return aliases.get(current.text) ?? current.text;
  if (ts.isPropertyAccessExpression(current)) {
    const receiver = expressionPath(current.expression, sourceFile, aliases, constStrings);
    return receiver === null ? null : `${receiver}.${current.name.text}`;
  }
  if (ts.isElementAccessExpression(current) && current.argumentExpression !== undefined) {
    const propertyName = constantStringValue(current.argumentExpression, constStrings);
    if (propertyName === undefined) return null;
    const receiver = expressionPath(current.expression, sourceFile, aliases, constStrings);
    return receiver === null ? null : `${receiver}.${propertyName}`;
  }
  // A call-expression receiver has to keep the chain resolvable, or every `x(...).y()` under
  // src/protocol/** is invisible to the method rules: `Buffer.from(v).toString(e).replace(r)`
  // yields `Buffer.from().toString().replace`, so `finalPathSegment` sees `replace` instead of the
  // whole call node short-circuiting on a null path. The `()` marker is load-bearing — it keeps a
  // called segment distinguishable from a property of the same name in the exact-path rules, and
  // stops `collectAliases` conflating `const s = getParser()` with the parser itself.
  if (ts.isCallExpression(current)) {
    const callee = expressionPath(current.expression, sourceFile, aliases, constStrings);
    return callee === null ? null : `${callee}()`;
  }
  void sourceFile;
  return null;
}

function collectConstStrings(sourceFile: ts.SourceFile): ReadonlyMap<string, string> {
  const constStrings = new Map<string, string>();
  for (let pass = 0; pass < 4; pass += 1) {
    visitEveryNode(sourceFile, (node) => {
      if (
        !ts.isVariableDeclaration(node) ||
        !ts.isIdentifier(node.name) ||
        node.initializer === undefined ||
        !ts.isVariableDeclarationList(node.parent) ||
        (node.parent.flags & ts.NodeFlags.Const) === 0
      ) {
        return;
      }
      const value = constantStringValue(node.initializer, constStrings);
      if (value !== undefined) constStrings.set(node.name.text, value);
    });
  }
  return constStrings;
}

function bindingPropertyName(
  propertyName: ts.PropertyName | undefined,
  fallback: string,
  constStrings: ReadonlyMap<string, string>,
): string | null {
  if (propertyName === undefined) return fallback;
  if (
    ts.isIdentifier(propertyName) ||
    ts.isStringLiteral(propertyName) ||
    ts.isNoSubstitutionTemplateLiteral(propertyName)
  ) {
    return propertyName.text;
  }
  if (ts.isComputedPropertyName(propertyName)) {
    return constantStringValue(propertyName.expression, constStrings) ?? null;
  }
  return null;
}

function callableExpressionPath(
  expression: ts.Expression,
  sourceFile: ts.SourceFile,
  aliases: ReadonlyMap<string, string>,
  constStrings: ReadonlyMap<string, string>,
): string | null {
  // The `.bind` unwrap has to run before the direct path, because `expressionPath` now resolves a
  // call expression too: `Object.assign.bind(null)(...)` must still report as `Object.assign`
  // rather than degrading to `Object.assign.bind()` and slipping past the exact-path mutator rules.
  const current = unwrapExpression(expression);
  if (ts.isCallExpression(current)) {
    const calledPath = expressionPath(current.expression, sourceFile, aliases, constStrings);
    if (calledPath?.endsWith(".bind") === true) return calledPath.slice(0, -".bind".length);
  }
  return expressionPath(expression, sourceFile, aliases, constStrings);
}

function collectAliases(
  sourceFile: ts.SourceFile,
  constStrings: ReadonlyMap<string, string>,
): ReadonlyMap<string, string> {
  const aliases = new Map<string, string>();
  for (let pass = 0; pass < 4; pass += 1) {
    visitEveryNode(sourceFile, (node) => {
      if (
        !ts.isVariableDeclaration(node) ||
        node.initializer === undefined ||
        !isConstDeclaration(node)
      ) {
        return;
      }
      // `expressionPath`, not `callableExpressionPath`: the `.bind` strip is a claim about what
      // *runs* when the value is called, and it sheds the `()` marker the guard below depends on.
      // `const inner = Object.create.bind(null)` resolved to `Object.create` and re-opened the exact
      // hole the guard closes. What a bound callable invokes lives in
      // `collectBoundCallables`, which only the call-path rule reads.
      const initializerPath = expressionPath(node.initializer, sourceFile, aliases, constStrings);
      if (initializerPath === null) return;
      // A call-derived path must never enter the alias map. `transactions.ts` declares the canonical
      // signing object as `const inner = Object.create(null) as MutableInner`, so aliasing it to
      // `Object.create()` would make `writeReceiverPath` return that instead of `inner` and silently
      // disarm the `canonical inner write` / `canonical inner update` rules on the one file they
      // guard. Resolving a call keeps the receiver chain intact for the method rules — it says
      // nothing about what the resulting value *is*, which is all an alias claims. This mirrors the
      // base behaviour exactly, because `expressionPath` used to return null for every call node.
      // (`obj["foo()"]` could forge the marker through `constantStringValue`; skipping that alias too
      // is the safe direction.)
      if (initializerPath.includes("()")) return;
      if (ts.isIdentifier(node.name)) {
        aliases.set(node.name.text, initializerPath);
        return;
      }
      if (!ts.isObjectBindingPattern(node.name)) return;
      for (const element of node.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        const propertyName = bindingPropertyName(
          element.propertyName,
          element.name.text,
          constStrings,
        );
        if (propertyName !== null) {
          aliases.set(element.name.text, `${initializerPath}.${propertyName}`);
        }
      }
    });
  }
  return aliases;
}

// `const bd = Object.assign.bind(null); bd({}, inner)` still has to report `Object.assign`. That is
// a claim about what the identifier *invokes*, not about what object it is — a bound function is a
// different object from the function it binds — so it is kept out of `aliases`, which
// `writeReceiverPath` reads. Separating the two views is what lets `collectAliases` drop every
// call-derived initializer unconditionally.
function collectBoundCallables(
  sourceFile: ts.SourceFile,
  aliases: ReadonlyMap<string, string>,
  constStrings: ReadonlyMap<string, string>,
): ReadonlyMap<string, string> {
  const bound = new Map<string, string>();
  for (let pass = 0; pass < 4; pass += 1) {
    // Chained binds (`const b = a.bind(null)` where `a` is itself bound) resolve through the map
    // built so far. This merged view never leaves this function.
    const callableView = new Map([...aliases, ...bound]);
    visitEveryNode(sourceFile, (node) => {
      if (
        !ts.isVariableDeclaration(node) ||
        !ts.isIdentifier(node.name) ||
        node.initializer === undefined ||
        !isConstDeclaration(node)
      ) {
        return;
      }
      const initializer = unwrapExpression(node.initializer);
      if (!ts.isCallExpression(initializer)) return;
      const calleePath = expressionPath(
        initializer.expression,
        sourceFile,
        callableView,
        constStrings,
      );
      if (calleePath?.endsWith(".bind") !== true) return;
      bound.set(node.name.text, calleePath.slice(0, -".bind".length));
    });
  }
  return bound;
}

function finalPathSegment(path: string): string {
  const segments = path.split(".");
  return segments[segments.length - 1] ?? path;
}

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

function writeReceiverPath(
  expression: ts.Expression,
  sourceFile: ts.SourceFile,
  aliases: ReadonlyMap<string, string>,
  constStrings: ReadonlyMap<string, string>,
): string | null {
  const target = unwrapExpression(expression);
  if (!ts.isPropertyAccessExpression(target) && !ts.isElementAccessExpression(target)) {
    return null;
  }
  return expressionPath(target.expression, sourceFile, aliases, constStrings);
}

const DANGEROUS_MUTATORS = [
  "Object.assign",
  "Object.defineProperties",
  "Object.defineProperty",
  "Object.preventExtensions",
  "Object.seal",
  "Object.setPrototypeOf",
  "Reflect.defineProperty",
  "Reflect.deleteProperty",
  "Reflect.preventExtensions",
  "Reflect.set",
  "Reflect.setPrototypeOf",
] as const;

function invokedDangerousMutator(path: string): (typeof DANGEROUS_MUTATORS)[number] | null {
  for (const mutator of DANGEROUS_MUTATORS) {
    if (
      path === mutator ||
      path === `${mutator}.bind` ||
      path === `${mutator}.call` ||
      path === `${mutator}.apply`
    ) {
      return mutator;
    }
  }
  return null;
}

function invokedJsonMethod(path: string): "parse" | "rawJSON" | "stringify" | null {
  for (const method of ["parse", "rawJSON", "stringify"] as const) {
    const methodPath = `JSON.${method}`;
    if (
      path === methodPath ||
      path === `${methodPath}.bind` ||
      path === `${methodPath}.call` ||
      path === `${methodPath}.apply`
    ) {
      return method;
    }
  }
  return null;
}

function isExported(node: ts.Node): boolean {
  return (
    ts.canHaveModifiers(node) &&
    (ts
      .getModifiers(node)
      ?.some(({ kind }) => kind === ts.SyntaxKind.ExportKeyword) ?? false)
  );
}

type CanonicalStringifyRole = "inner" | "step1Signature" | "step2Signature";

const CANONICAL_INNER_ASSIGNMENT_ORDER = [
  "type",
  "version",
  "unix_time_secs",
  "signer_steps",
  "step_1_signer",
  "step_2_signer",
  "step_1_key_public__base64urlsafe",
  "step_2_key_public__base64urlsafe",
  "step_1_state",
  "step_2_state",
  "previous_step_1_state_signature",
  "previous_step_2_state_signature",
  "expiry__unix_time_secs",
  "message",
] as const;

function isAllowedCanonicalInnerAssignment(node: ts.BinaryExpression): boolean {
  if (
    node.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
    !ts.isPropertyAccessExpression(node.left) ||
    !ts.isIdentifier(node.left.expression) ||
    node.left.expression.text !== "inner" ||
    !CANONICAL_INNER_ASSIGNMENT_ORDER.includes(
      node.left.name.text as (typeof CANONICAL_INNER_ASSIGNMENT_ORDER)[number],
    )
  ) {
    return false;
  }
  const functionNode = enclosingFunction(node);
  return (
    functionNode !== null &&
    ts.isFunctionDeclaration(functionNode) &&
    functionNode.name?.text === "buildSplitChainInnerV2"
  );
}

function enclosingFunction(node: ts.Node): ts.FunctionLikeDeclaration | null {
  let current: ts.Node | undefined = node.parent;
  while (current !== undefined) {
    if (ts.isFunctionLike(current)) return current;
    current = current.parent;
  }
  return null;
}

// Every grant below resolves a call-site identifier to the declaration it binds to, so this
// collector defines what "declared" means for all of them. A name is bound by more than a plain
// `const x = …`: a destructuring pattern binds through its binding ELEMENTS (`const { x } = …`, the
// `const { p: x } = …` rename, `const [x] = …`, and any nesting of those), a function, class or enum
// declaration binds its own name, and a namespace binds its own name. A binding form this collector
// cannot see is a form that can substitute an arbitrary value for a reviewed binding without
// withdrawing that value's grant — which is how an object's source-order keys reach hashed wire
// bytes.
type BoundDeclaration =
  | ts.VariableDeclaration
  | ts.BindingElement
  | ts.FunctionDeclaration
  | ts.ClassDeclaration
  | ts.EnumDeclaration
  | ts.ModuleDeclaration;

function declaresName(node: ts.Node, name: string): node is BoundDeclaration {
  if (ts.isVariableDeclaration(node) || ts.isBindingElement(node)) {
    // A pattern-named `VariableDeclaration` binds nothing itself — its `BindingElement`s do, and
    // `visitEveryNode` reaches them, including nested and renamed ones.
    return ts.isIdentifier(node.name) && node.name.text === name;
  }
  if (ts.isModuleDeclaration(node)) {
    return ts.isIdentifier(node.name) && node.name.text === name;
  }
  return (
    (ts.isFunctionDeclaration(node) ||
      ts.isClassDeclaration(node) ||
      ts.isEnumDeclaration(node)) &&
    node.name?.text === name
  );
}

// The list above is an ALLOW list over a grammar that keeps growing, and three rounds proved
// what that costs: a value-binding syntax `declaresName` does not enumerate is invisible, and an
// invisible declaration reads as "no shadow found, therefore safe" — the grant is issued. The census
// is therefore paired with this fail-closed backstop. Every value binding inside a function body is
// introduced by a STATEMENT, and the statement grammar is closed in a way the declaration grammar is
// not, so the pinned set below is enumerable: each kind either provably introduces no lexical
// binding, or is one `declaresName` resolves by name. Anything else appearing inside a reviewed
// function — a statement kind TypeScript adds later, or one nobody classified — is treated as
// binding every name, which withdraws the grant and turns the gate RED. The next unhandled binding
// form is a failing test, not a silent exemption.
const RECOGNISED_STATEMENT_KINDS: ReadonlySet<ts.SyntaxKind> = new Set([
  // Binds nothing.
  ts.SyntaxKind.Block,
  ts.SyntaxKind.EmptyStatement,
  ts.SyntaxKind.ExpressionStatement,
  ts.SyntaxKind.IfStatement,
  ts.SyntaxKind.DoStatement,
  ts.SyntaxKind.WhileStatement,
  ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement,
  ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.ContinueStatement,
  ts.SyntaxKind.BreakStatement,
  ts.SyntaxKind.ReturnStatement,
  ts.SyntaxKind.SwitchStatement,
  ts.SyntaxKind.LabeledStatement,
  ts.SyntaxKind.ThrowStatement,
  ts.SyntaxKind.TryStatement,
  ts.SyntaxKind.DebuggerStatement,
  // Type-only: erased before runtime, so neither can stand in for a value.
  ts.SyntaxKind.InterfaceDeclaration,
  ts.SyntaxKind.TypeAliasDeclaration,
  // Binds a value name, and `declaresName` resolves each one by name.
  ts.SyntaxKind.VariableStatement,
  ts.SyntaxKind.FunctionDeclaration,
  ts.SyntaxKind.ClassDeclaration,
  ts.SyntaxKind.EnumDeclaration,
  ts.SyntaxKind.ModuleDeclaration,
]);
// Deliberately absent, so each fails closed: `WithStatement` injects an object's own properties into
// scope (and is TS1101 under `strict` anyway), and the import/export statement kinds cannot appear in
// a function body at all — if one ever does, the grant should die rather than be re-reasoned.

function hasUnrecognisedStatement(functionNode: ts.FunctionLikeDeclaration): boolean {
  let unrecognised = false;
  visitEveryNode(functionNode.getSourceFile(), (node) => {
    if (unrecognised || enclosingFunction(node) !== functionNode) return;
    if (ts.isStatement(node) && !RECOGNISED_STATEMENT_KINDS.has(node.kind)) unrecognised = true;
  });
  return unrecognised;
}

/**
 * Declarations of `variableName` introduced inside `functionNode`'s own body, or `null` when the
 * body contains a construct this census cannot classify — in which case no caller may grant.
 *
 * `functionNode`'s own parameters are deliberately NOT counted: a parameter does not shadow itself,
 * and every grant that depends on one pins it explicitly by name and type at its own call site.
 */
function localDeclarations(
  functionNode: ts.FunctionLikeDeclaration,
  variableName: string,
): BoundDeclaration[] | null {
  if (hasUnrecognisedStatement(functionNode)) return null;
  const declarations: BoundDeclaration[] = [];
  visitEveryNode(functionNode.getSourceFile(), (node) => {
    if (declaresName(node, variableName) && enclosingFunction(node) === functionNode) {
      declarations.push(node);
    }
  });
  return declarations;
}

/** The `length === 0` form of the census, with the unclassifiable case folded in as "not proven". */
function hasNoLocalDeclaration(
  functionNode: ts.FunctionLikeDeclaration,
  variableName: string,
): boolean {
  const declarations = localDeclarations(functionNode, variableName);
  return declarations !== null && declarations.length === 0;
}

function isConstDeclaration(declaration: ts.VariableDeclaration): boolean {
  return (
    ts.isVariableDeclarationList(declaration.parent) &&
    (declaration.parent.flags & ts.NodeFlags.Const) !== 0
  );
}

function isExactParserDeclaration(
  declaration: ts.VariableDeclaration,
  parserArgumentName: string,
): boolean {
  if (!isConstDeclaration(declaration) || declaration.initializer === undefined) return false;
  const initializer = unwrapExpression(declaration.initializer);
  if (!ts.isCallExpression(initializer) || initializer.arguments.length !== 1) return false;
  const parserPath = expressionPath(
    initializer.expression,
    declaration.getSourceFile(),
    new Map(),
    new Map(),
  );
  const parserArgument = unwrapExpression(initializer.arguments[0]);
  return (
    parserPath === "parseEd25519Signature" &&
    ts.isIdentifier(parserArgument) &&
    parserArgument.text === parserArgumentName
  );
}

function hasMutableInnerAssertion(initializer: ts.Expression): boolean {
  let current = initializer;
  while (ts.isParenthesizedExpression(current)) current = current.expression;
  return ts.isAsExpression(current) && current.type.getText() === "MutableInner";
}

function isCanonicalInnerDeclaration(declaration: ts.VariableDeclaration): boolean {
  if (
    !isConstDeclaration(declaration) ||
    declaration.initializer === undefined ||
    !hasMutableInnerAssertion(declaration.initializer)
  ) {
    return false;
  }
  const initializer = unwrapExpression(declaration.initializer);
  if (!ts.isCallExpression(initializer) || initializer.arguments.length !== 1) return false;
  const constructorPath = expressionPath(
    initializer.expression,
    declaration.getSourceFile(),
    new Map(),
    new Map(),
  );
  return constructorPath === "Object.create" && initializer.arguments[0].kind === ts.SyntaxKind.NullKeyword;
}

function innerAssignments(
  functionNode: ts.FunctionLikeDeclaration,
): Array<{ readonly name: string; readonly position: number }> {
  const assignments: Array<{ readonly name: string; readonly position: number }> = [];
  visitEveryNode(functionNode.getSourceFile(), (node) => {
    if (
      !ts.isBinaryExpression(node) ||
      node.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
      enclosingFunction(node) !== functionNode ||
      !ts.isPropertyAccessExpression(node.left) ||
      !ts.isIdentifier(node.left.expression) ||
      node.left.expression.text !== "inner"
    ) {
      return;
    }
    assignments.push({ name: node.left.name.text, position: node.getStart() });
  });
  return assignments.sort((left, right) => left.position - right.position);
}

function preStringifyFreezePosition(
  functionNode: ts.FunctionLikeDeclaration,
  stringifyCall: ts.CallExpression,
): number | null {
  let position: number | null = null;
  visitEveryNode(functionNode.getSourceFile(), (node) => {
    if (
      position !== null ||
      !ts.isCallExpression(node) ||
      node.getStart() >= stringifyCall.getStart() ||
      enclosingFunction(node) !== functionNode ||
      node.arguments.length !== 1
    ) {
      return;
    }
    const path = expressionPath(
      node.expression,
      node.getSourceFile(),
      new Map(),
      new Map(),
    );
    const argument = unwrapExpression(node.arguments[0]);
    if (path === "Object.freeze" && ts.isIdentifier(argument) && argument.text === "inner") {
      position = node.getStart();
    }
  });
  return position;
}

function canonicalStringifyRole(
  stringifyCall: ts.CallExpression,
): CanonicalStringifyRole | null {
  if (stringifyCall.arguments.length !== 1) return null;
  const argument = unwrapExpression(stringifyCall.arguments[0]);
  if (!ts.isIdentifier(argument)) return null;
  const functionNode = enclosingFunction(stringifyCall);
  if (
    functionNode === null ||
    !ts.isFunctionDeclaration(functionNode) ||
    functionNode.name === undefined
  ) {
    return null;
  }
  const declarations = localDeclarations(functionNode, argument.text);
  if (
    declarations === null ||
    declarations.length !== 1 ||
    declarations[0].getStart() >= stringifyCall.getStart()
  ) {
    return null;
  }
  const declaration = declarations[0];
  // None of the three reviewed roles is a destructured, function, or class binding.
  if (!ts.isVariableDeclaration(declaration)) return null;

  if (
    argument.text === "inner" &&
    functionNode.name.text === "buildSplitChainInnerV2" &&
    isCanonicalInnerDeclaration(declaration)
  ) {
    const assignments = innerAssignments(functionNode);
    const freezePosition = preStringifyFreezePosition(functionNode, stringifyCall);
    if (
      assignments.map(({ name }) => name).join("\u0000") ===
        CANONICAL_INNER_ASSIGNMENT_ORDER.join("\u0000") &&
      assignments.length > 0 &&
      declaration.getStart() < assignments[0].position &&
      freezePosition !== null &&
      assignments.every(({ position }) => position < freezePosition) &&
      freezePosition < stringifyCall.getStart()
    ) {
      return "inner";
    }
  }
  if (
    argument.text === "step1Signature" &&
    functionNode.name.text === "buildSplitChainPartialV2" &&
    isExactParserDeclaration(declaration, "step1SignatureValue")
  ) {
    return "step1Signature";
  }
  if (
    argument.text === "step2Signature" &&
    functionNode.name.text === "buildSettledSplitChainTransactionV2" &&
    isExactParserDeclaration(declaration, "step2SignatureValue")
  ) {
    return "step2Signature";
  }
  return null;
}

// Reviewed byte-exact safety exemption for inner.ts's computeInnerDigest.
// The function computes I = SHA-256(JSON.stringify(inner)) — the observation digest defined
// verbatim in observation verification
// ("I — SHA-256 of the exact reconstructed JSON.stringify(inner) preimage"). It re-stringifies
// the SAME already-verified in-memory `inner` it is handed; it never parses, never mutates,
// and never constructs, so it can introduce no byte drift. observation verification makes exactly this the
// sanctioned reconstruction (`step_1_preimage_text = JSON.stringify(tx.inner)`) against which
// both Ed25519 signatures are verified upstream in — any key-order or formatting drift
// is rejected there before a SettledSplitChainTransaction can exist. It never re-derives the
// retained settled-ledger text, so it does not touch the JSON.stringify(JSON.parse(stored_text))
// surface that protocol foundation forbids. The exemption is deliberately narrow:
// the stringify argument must be computeInnerDigest's own untouched `inner` parameter, never a
// local re-parse or rebuild — which the always-on JSON.parse and canonical-inner-write checks
// would independently flag in any case.
function isReviewedInnerDigestStringify(stringifyCall: ts.CallExpression): boolean {
  if (stringifyCall.arguments.length !== 1) return false;
  const argument = unwrapExpression(stringifyCall.arguments[0]);
  if (!ts.isIdentifier(argument) || argument.text !== "inner") return false;
  const functionNode = enclosingFunction(stringifyCall);
  if (
    functionNode === null ||
    !ts.isFunctionDeclaration(functionNode) ||
    functionNode.name?.text !== "computeInnerDigest"
  ) {
    return false;
  }
  const innerIsParameter = functionNode.parameters.some(
    (parameter) => ts.isIdentifier(parameter.name) && parameter.name.text === "inner",
  );
  return innerIsParameter && hasNoLocalDeclaration(functionNode, "inner");
}

// ---------------------------------------------------------------------------
// suite-tuple serializer exemptions (186/187/188).
//
// The suite serializer (src/protocol/suite/) is the one canonical suite-tuple constructor
// signing custody mandates. A serializer legitimately spreads, stringifies, and parses, so this gate's
// always-on rules necessarily fire on it. Every exemption below was ruled per construct, is keyed
// to a specific file + symbol + argument shape, and is proven live by the exact-count non-vacuity
// guard plus the near-miss mutation suite. None is a path skip, a directory trust grant, or a
// file-wide grant: each names the enclosing function and the exact node shape, so a future author
// cannot widen the surface by adding an unrelated construct to an already-exempt file.
// ---------------------------------------------------------------------------

const SUITE_SERIALIZE_FILE = "suite/serialize.ts";
const SUITE_BUILDERS_FILE = "suite/builders.ts";
const SUITE_PARSERS_FILE = "suite/parsers.ts";
const SUITE_REGISTRY_FILE = "suite/registry.ts";
const SUITE_ENCODERS_FILE = "suite/encoders.ts";
const SUITE_MANIFEST_FILE = "suite/manifest.ts";
// Pinned to manifest.ts's SUITE_SERIALIZER_ENTRYPOINT datum by an assertion below, so renaming the
// canonical entrypoint without updating the manifest turns this gate red instead of silently
// un-exempting (or worse, silently re-exempting a different symbol).
const SUITE_SERIALIZER_ENTRYPOINT = "serializeSuiteTuple";
const SUITE_ORDERED_PAYLOAD_BUILDER = "buildOrderedPayload";

type SuiteExemption =
  | "builder values spread"
  | "parser result spread"
  | "registry field-sequence spread"
  | "label code-point spread"
  | "canonical serializer call"
  | "canonical serializer declaration"
  | "manifest census builder"
  | "boundary input Record"
  | "timestamp validation Date"
  | "signed-window Date.parse"
  | "wire JSON.parse"
  | "canonical suite preimage stringify"
  // additions outside suite/ — same discipline, same exact-count ledger and near-miss suite.
  | "transfer-code string escape"
  | "inner-shape boundary input Record"
  | "inner-shape key-sequence spread";

type SuiteExemptionLedger = Map<SuiteExemption, number>;

function enclosingFunctionName(node: ts.Node): string | null {
  const functionNode = enclosingFunction(node);
  if (functionNode === null) return null;
  if (
    (ts.isFunctionDeclaration(functionNode) || ts.isMethodDeclaration(functionNode)) &&
    functionNode.name !== undefined &&
    ts.isIdentifier(functionNode.name)
  ) {
    return functionNode.name.text;
  }
  // `export const encodeLabel: CanonicalEncoder = (value) => { ... }` — the arrow itself is
  // anonymous, so the binding name is the reviewable identity.
  if (
    (ts.isArrowFunction(functionNode) || ts.isFunctionExpression(functionNode)) &&
    ts.isVariableDeclaration(functionNode.parent) &&
    ts.isIdentifier(functionNode.parent.name)
  ) {
    return functionNode.parent.name.text;
  }
  return null;
}

function enclosingTypeAliasName(node: ts.Node): string | null {
  let current: ts.Node | undefined = node.parent;
  while (current !== undefined) {
    if (ts.isTypeAliasDeclaration(current)) return current.name.text;
    if (ts.isFunctionLike(current)) return null;
    current = current.parent;
  }
  return null;
}

function stringLiteralText(node: ts.Node | undefined): string | null {
  if (node === undefined) return null;
  const current = ts.isExpression(node) ? unwrapExpression(node) : node;
  return ts.isStringLiteral(current) || ts.isNoSubstitutionTemplateLiteral(current)
    ? current.text
    : null;
}

function calleeIdentifierName(call: ts.CallExpression): string | null {
  const callee = unwrapExpression(call.expression);
  return ts.isIdentifier(callee) ? callee.text : null;
}

// E1 — builders.ts: `serializeSuiteTuple(P, { purpose: P, canonical_version: 1, ...input })`.
//
// SAFE. The spread cannot influence emitted bytes: this object is a values BAG, not the payload.
// `buildOrderedPayload` (src/protocol/suite/serialize.ts:64-79) re-emits keys strictly in
// `specification.fields` sequence into a fresh object, and `rejectUnexpectedFields`
// (serialize.ts:81-86) rejects any own key absent from the schema. Even a caller smuggling a
// `purpose` through `...input` (possible at runtime, since TS excess-property checks do not survive
// a widened call site) cannot equivocate the domain prefix: registry.ts:87 types field 1 as
// `closedEnum("purpose", [purpose])` against the dispatch literal, so a mismatch throws
// `invalid_enum` — this is exactly the A.9 #2 prefix/payload mismatch check.
//
// Anti-stretch: the literal must have exactly three properties in exactly this order, the `purpose`
// literal must equal the dispatch literal, and the callee must be the pinned canonical entrypoint.
// A fourth property, a reorder, a computed key, or a spread into any other call all still trip.
function isSuiteBuilderValuesSpread(node: ts.SpreadAssignment, relativePath: string): boolean {
  if (relativePath !== SUITE_BUILDERS_FILE) return false;
  const literal = node.parent;
  if (!ts.isObjectLiteralExpression(literal)) return false;
  const call = literal.parent;
  if (
    !ts.isCallExpression(call) ||
    calleeIdentifierName(call) !== SUITE_SERIALIZER_ENTRYPOINT ||
    call.arguments.length !== 2 ||
    call.arguments[1] !== literal
  ) {
    return false;
  }
  const dispatchPurpose = stringLiteralText(call.arguments[0]);
  if (dispatchPurpose === null) return false;
  if (literal.properties.length !== 3) return false;
  const [purposeProperty, versionProperty, spreadProperty] = literal.properties;
  if (
    !ts.isPropertyAssignment(purposeProperty) ||
    !ts.isIdentifier(purposeProperty.name) ||
    purposeProperty.name.text !== "purpose" ||
    stringLiteralText(purposeProperty.initializer) !== dispatchPurpose
  ) {
    return false;
  }
  if (
    !ts.isPropertyAssignment(versionProperty) ||
    !ts.isIdentifier(versionProperty.name) ||
    versionProperty.name.text !== "canonical_version" ||
    !ts.isNumericLiteral(unwrapExpression(versionProperty.initializer)) ||
    (unwrapExpression(versionProperty.initializer) as ts.NumericLiteral).text !== "1"
  ) {
    return false;
  }
  return spreadProperty === node && ts.isIdentifier(unwrapExpression(node.expression));
}

// E2 — parsers.ts: `return { ...result, payload: result.payload as unknown as XPayload };`.
//
// SAFE. `result` is a `parseSuitePurpose` return value, so it has already cleared the byte-equality
// fence at parsers.ts:104. The spread copies `preimageText` / `preimageBytes` / `sha256` verbatim and
// the only override is `payload`, replaced by a type assertion — a compile-time no-op over the same
// runtime object. Nothing in the returned value is ever re-serialized.
//
// Anti-stretch: the operand must be a `const` bound exactly once to a `parseSuitePurpose(...)` call
// in the same function, so this can never be stretched to spread arbitrary or unfenced data.
function isSuiteParserResultSpread(node: ts.SpreadAssignment, relativePath: string): boolean {
  if (relativePath !== SUITE_PARSERS_FILE) return false;
  const literal = node.parent;
  if (!ts.isObjectLiteralExpression(literal) || literal.properties.length !== 2) return false;
  if (!ts.isReturnStatement(literal.parent)) return false;
  const [spreadProperty, payloadProperty] = literal.properties;
  if (spreadProperty !== node) return false;
  if (
    !ts.isPropertyAssignment(payloadProperty) ||
    !ts.isIdentifier(payloadProperty.name) ||
    payloadProperty.name.text !== "payload"
  ) {
    return false;
  }
  const operand = unwrapExpression(node.expression);
  if (!ts.isIdentifier(operand) || operand.text !== "result") return false;
  const functionNode = enclosingFunction(node);
  if (functionNode === null) return false;
  const declarations = localDeclarations(functionNode, "result");
  if (declarations === null || declarations.length !== 1) return false;
  const declaration = declarations[0];
  if (!ts.isVariableDeclaration(declaration)) return false;
  if (!isConstDeclaration(declaration) || declaration.initializer === undefined) return false;
  const initializer = unwrapExpression(declaration.initializer);
  return (
    ts.isCallExpression(initializer) && calleeIdentifierName(initializer) === "parseSuitePurpose"
  );
}

// E3 — registry.ts: `fields: [...header(purpose), ...rest]` inside `spec()`.
//
// SAFE. Array spread is order-preserving concatenation; it DEFINES the frozen field sequence rather
// than perturbing an existing one, and the sequence it defines is independently pinned outside this
// AST: test/protocol-suite-census.test.ts:59 asserts every purpose's `fieldOrder` equals the actual
// JSON key order of the committed golden preimage, and :60 pins the `["purpose","canonical_version"]`
// header. A reorder here therefore fails the census and golden tests loudly — the AST rule is not
// the control that protects this construct, so exempting it removes no real coverage.
//
// Anti-stretch: only a two-element array of exactly `header(...)` then `rest`, only as the `fields`
// initializer, only inside `spec`.
function isSuiteRegistryFieldSequenceSpread(node: ts.SpreadElement, relativePath: string): boolean {
  if (relativePath !== SUITE_REGISTRY_FILE) return false;
  if (enclosingFunctionName(node) !== "spec") return false;
  const array = node.parent;
  if (!ts.isArrayLiteralExpression(array) || array.elements.length !== 2) return false;
  const property = array.parent;
  if (
    !ts.isPropertyAssignment(property) ||
    !ts.isIdentifier(property.name) ||
    property.name.text !== "fields"
  ) {
    return false;
  }
  const [headerElement, restElement] = array.elements;
  if (!ts.isSpreadElement(headerElement) || !ts.isSpreadElement(restElement)) return false;
  const headerOperand = unwrapExpression(headerElement.expression);
  const restOperand = unwrapExpression(restElement.expression);
  return (
    ts.isCallExpression(headerOperand) &&
    calleeIdentifierName(headerOperand) === "header" &&
    ts.isIdentifier(restOperand) &&
    restOperand.text === "rest"
  );
}

// E4 — encoders.ts: `const scalars = [...text];` inside `encodeLabel`.
//
// SAFE, and shape-identical to the pre-existing `isExistingScalarCodePointCount` exemption this gate
// already grants scalars.ts: iterate code points to validate them. `encodeLabel` returns `text` — the
// original string — never `scalars.join("")`, so no iteration artifact can reach emitted bytes. That
// verbatim return is what satisfies A.9's NFC-admission gate (normalize-then-sign is forbidden).
//
// Anti-stretch: single-element array, operand must be the identifier `text`, only inside `encodeLabel`.
function isSuiteLabelCodePointSpread(node: ts.SpreadElement, relativePath: string): boolean {
  if (relativePath !== SUITE_ENCODERS_FILE) return false;
  if (enclosingFunctionName(node) !== "encodeLabel") return false;
  const array = node.parent;
  if (!ts.isArrayLiteralExpression(array) || array.elements.length !== 1) return false;
  const operand = unwrapExpression(node.expression);
  return ts.isIdentifier(operand) && operand.text === "text";
}

// E5 — calls to the canonical entrypoint itself (builders.ts x10, parsers.ts x1).
//
// SAFE by construction. The "generic public object serializer call" rule exists to ban AD-HOC
// serializers; signing custody requires exactly the opposite of a ban here — "The codebase MUST expose one
// canonical module ... Calling JSON.stringify for these tuples outside that module is forbidden".
// Routing every builder and the parser through `serializeSuiteTuple` IS the conformance the rule is
// meant to produce. Every other serializer-shaped name still trips, and the far stronger control —
// JSON.stringify anywhere outside a proven site — remains fully armed.
function isCanonicalSuiteSerializerCall(path: string, relativePath: string): boolean {
  return relativePath.startsWith("suite/") && path === SUITE_SERIALIZER_ENTRYPOINT;
}

// E6 — the canonical serializer's own declaration (serialize.ts x1).
//
// SAFE. This is the single sanctioned constructor. Its export shape is deliberately closed: it yields
// only `{preimageText, preimageBytes, sha256}` and never the assembled payload object, so no caller
// can obtain something to re-stringify. Guarded by an exact-count uniqueness assertion below — a
// SECOND canonical-serializer declaration anywhere in the scan trips the gate.
function isCanonicalSuiteSerializerDeclaration(
  node: ts.FunctionDeclaration,
  relativePath: string,
): boolean {
  return (
    relativePath === SUITE_SERIALIZE_FILE && node.name?.text === SUITE_SERIALIZER_ENTRYPOINT
  );
}

// E7 — manifest.ts `buildSuiteSerializerManifest`.
//
// SAFE — a name-substring false positive. The rule matches /serializ/i on the identifier, but this
// function builds a CENSUS OF the serializer (purpose list, key classes, field order) and returns a
// `SuiteSerializerManifest`. It never receives tuple values, never stringifies, and never touches a
// payload; it reads only the registry's own metadata.
function isSuiteManifestCensusBuilder(
  node: ts.FunctionDeclaration,
  relativePath: string,
): boolean {
  return (
    relativePath === SUITE_MANIFEST_FILE && node.name?.text === "buildSuiteSerializerManifest"
  );
}

// E8 — `Record<string, unknown>` at the trust boundary (encoders.ts x3, serialize.ts x1).
//
// SAFE. A permissive Record is dangerous when it types EMITTED data, because an unvalidated key could
// then reach signed bytes. Every occurrence here types INBOUND, not-yet-validated data:
// `requirePlainObject` / `requireExactKeys` (encoders.ts:199-222) narrow an untrusted composite before
// any field is encoded, and `SuiteTupleValues` (serialize.ts:54) is the serializer's untrusted input
// alias. The EMITTED types are the closed `JsonObject` / `CanonicalJson` union (encoders.ts:30-34), and
// `buildOrderedPayload` accumulates into `Record<string, CanonicalJson>` — not `unknown`. A value can
// only cross from the `unknown` side to the `CanonicalJson` side through a `CanonicalEncoder`.
//
// Anti-stretch: keyed to those three named symbols. A permissive Record introduced anywhere else in
// the suite — including elsewhere in these same two files — still trips.
function isSuiteBoundaryInputRecord(node: ts.TypeReferenceNode, relativePath: string): boolean {
  if (relativePath === SUITE_ENCODERS_FILE) {
    const owner = enclosingFunctionName(node);
    return owner === "requirePlainObject" || owner === "requireExactKeys";
  }
  if (relativePath === SUITE_SERIALIZE_FILE) {
    return enclosingTypeAliasName(node) === "SuiteTupleValues";
  }
  return false;
}

// E9 — encoders.ts `new Date(text)` inside `encodeCanonicalTimestamp`.
//
// SAFE, and specifically NOT the non-determinism the rule hunts. This is a calendar-validity oracle,
// not a clock read: `text` has already matched RFC3339_MS_PATTERN, and the Date is used only in
// `Number.isNaN(parsed.getTime()) || parsed.toISOString() !== text` to reject an in-pattern but
// out-of-range calendar value (e.g. month 13). The encoder returns `text`, so no Date-derived value
// can reach emitted bytes.
//
// Anti-stretch (the load-bearing guard): exactly one argument is required. `new Date()` — the
// zero-argument clock read, which IS the real non-determinism vector near a signed payload — still
// trips the gate, as does `new Date()` anywhere else in the suite.
function isSuiteTimestampValidationDate(node: ts.NewExpression, relativePath: string): boolean {
  return (
    relativePath === SUITE_ENCODERS_FILE &&
    enclosingFunctionName(node) === "encodeCanonicalTimestamp" &&
    node.arguments?.length === 1
  );
}

// E10 — serialize.ts `Date.parse(...)` x2 inside `enforceSignedWindow`.
//
// SAFE. Two independent reasons. (1) Determinism: `Date.parse` over an ECMA-262 Date Time String
// Format value is specified and locale-independent, and both operands were already validated as
// canonical RFC3339-ms by `encodeCanonicalTimestamp` in the encoding pass that ran immediately before,
// so it is total here. (2) Structural, and decisive: `enforceSignedWindow` returns `void` and its only
// effect is `throw`. It receives the already-built payload and never writes to it, so it is incapable
// of introducing byte drift — its worst case is rejecting a tuple, which is fail-closed.
//
// Anti-stretch: `Date.now()` and every other `Date.*` member still trip, and the call must sit inside
// `enforceSignedWindow`.
function isSuiteSignedWindowDateParse(
  node: ts.CallExpression,
  path: string,
  relativePath: string,
): boolean {
  return (
    relativePath === SUITE_SERIALIZE_FILE &&
    path === "Date.parse" &&
    node.arguments.length === 1 &&
    enclosingFunctionName(node) === "enforceSignedWindow"
  );
}

// E11 — parsers.ts `JSON.parse(...)` inside `parseSuitePurpose`.
//
// SAFE, but ONLY because of the fence, so the fence is made a structural precondition of the
// exemption. A parse -> re-stringify round trip is the classic byte-drift vector: the danger is
// trusting the REBUILT bytes in place of the source bytes. `parseSuitePurpose` never does that. It
// rebuilds through the canonical serializer and then compares the rebuild to the decoded source
// byte-for-byte (parsers.ts:102-106), throwing `non_canonical_bytes` on any difference. A source that
// was not already canonical cannot survive; a source that was canonical is byte-identical to the
// rebuild, so returning the rebuilt preimage is a no-op substitution. This is a VERIFYING round trip,
// not a reconstructing one. (Adjacent hardening that this check also covers: duplicate JSON keys and a
// `__proto__` own-property both change the rebuild and are rejected — the latter additionally by
// `rejectUnexpectedFields`, which is own-key based.)
//
// Anti-stretch (the load-bearing guard): the exemption requires the enclosing function to CONTAIN the
// fence — a `serializeSuiteTuple` rebuild after the parse, an `.equals(...)` byte comparison after
// that, and a `throw new SuiteParseError("non_canonical_bytes")`. Delete or weaken the fence and this
// exemption evaporates, turning the gate red rather than silently widening the surface.
function hasCanonicalRebuildFence(
  functionNode: ts.FunctionLikeDeclaration,
  parseCall: ts.CallExpression,
): boolean {
  let rebuildPosition: number | null = null;
  let equalsPosition: number | null = null;
  let throwPosition: number | null = null;

  visitEveryNode(functionNode.getSourceFile(), (node) => {
    if (enclosingFunction(node) !== functionNode) return;
    if (ts.isCallExpression(node)) {
      if (
        calleeIdentifierName(node) === SUITE_SERIALIZER_ENTRYPOINT &&
        node.getStart() > parseCall.getStart() &&
        (rebuildPosition === null || node.getStart() < rebuildPosition)
      ) {
        rebuildPosition = node.getStart();
      }
      const callee = unwrapExpression(node.expression);
      if (
        ts.isPropertyAccessExpression(callee) &&
        callee.name.text === "equals" &&
        (equalsPosition === null || node.getStart() < equalsPosition)
      ) {
        equalsPosition = node.getStart();
      }
    }
    if (ts.isThrowStatement(node)) {
      const thrown = unwrapExpression(node.expression);
      if (
        ts.isNewExpression(thrown) &&
        ts.isIdentifier(thrown.expression) &&
        thrown.expression.text === "SuiteParseError" &&
        thrown.arguments?.length === 1 &&
        stringLiteralText(thrown.arguments[0]) === "non_canonical_bytes" &&
        (throwPosition === null || node.getStart() < throwPosition)
      ) {
        throwPosition = node.getStart();
      }
    }
  });

  return (
    rebuildPosition !== null &&
    equalsPosition !== null &&
    throwPosition !== null &&
    rebuildPosition < equalsPosition &&
    equalsPosition < throwPosition
  );
}

function isSuiteWireJsonParse(node: ts.CallExpression, relativePath: string): boolean {
  if (relativePath !== SUITE_PARSERS_FILE) return false;
  if (node.arguments.length !== 1) return false;
  const functionNode = enclosingFunction(node);
  if (
    functionNode === null ||
    !ts.isFunctionDeclaration(functionNode) ||
    functionNode.name?.text !== "parseSuitePurpose"
  ) {
    return false;
  }
  return hasCanonicalRebuildFence(functionNode, node);
}

// E12 — serialize.ts `JSON.stringify(payload)` — THE canonical suite-tuple signing preimage.
//
// SAFE. Modelled node-for-node on this gate's existing `isReviewedInnerDigestStringify` precedent.
// The argument is a FRESHLY CONSTRUCTED object, serialized exactly once: `buildOrderedPayload`
// (serialize.ts:64-79) allocates a new `{}` and inserts keys strictly in `specification.fields`
// sequence — the frozen registry order — with every value produced by that field's `CanonicalEncoder`.
// Nothing is sorted, spread, normalized, or reconstructed from parsed text, and the result is consumed
// only by the `` `${purpose}\n${...}` `` domain-separated template. It CANNOT re-stringify previously
// signed bytes: the only object it can reach is the one `buildOrderedPayload` just built on this call.
//
// Anti-stretch: `payload` must have exactly one local declaration in `serializeSuiteTuple`, it must be
// a `const`, its initializer must be a direct `buildOrderedPayload(...)` call, and it must precede the
// stringify. Rebinding `payload`, sourcing it from a parse, or stringifying anything else all trip.
function isReviewedSuiteTupleStringify(
  stringifyCall: ts.CallExpression,
  relativePath: string,
): boolean {
  if (relativePath !== SUITE_SERIALIZE_FILE) return false;
  if (stringifyCall.arguments.length !== 1) return false;
  const argument = unwrapExpression(stringifyCall.arguments[0]);
  if (!ts.isIdentifier(argument) || argument.text !== "payload") return false;
  const functionNode = enclosingFunction(stringifyCall);
  if (
    functionNode === null ||
    !ts.isFunctionDeclaration(functionNode) ||
    functionNode.name?.text !== SUITE_SERIALIZER_ENTRYPOINT
  ) {
    return false;
  }
  const declarations = localDeclarations(functionNode, "payload");
  if (declarations === null || declarations.length !== 1) return false;
  const declaration = declarations[0];
  if (
    !ts.isVariableDeclaration(declaration) ||
    !isConstDeclaration(declaration) ||
    declaration.initializer === undefined ||
    declaration.getStart() >= stringifyCall.getStart()
  ) {
    return false;
  }
  const initializer = unwrapExpression(declaration.initializer);
  return (
    ts.isCallExpression(initializer) &&
    calleeIdentifierName(initializer) === SUITE_ORDERED_PAYLOAD_BUILDER
  );
}

// Reviewed byte-exact safety exemption for reconcile/types.ts's assertUnreachable.
// The function is the closed-union exhaustiveness helper described in
// operations recovery — its parameter is typed
// `never`, so every call site is statically unreachable and the stringify cannot execute at all
// unless a union member is added without updating a switch, which `tsc -b` rejects first. The
// exemption is not "this file is trusted": it is granted only when the produced text provably
// cannot escape as bytes. The parent chain is pinned exactly — the call must be a template-literal
// interpolation that is the sole argument of a `new Error(...)` which is itself the operand of a
// `throw`. Text on that path is consumed by the thrown Error and is never returned, stored,
// hashed, or signed, so it cannot reach a preimage. The reconcile concern is a pure classification
// vocabulary: protocol/transactions.ts does not import it, protocol/index.ts does not re-export
// it, and it contains no other JSON call, no object spread, and no hashing or signing surface.
//
// generalized that same reasoning into the construction-scope hold-out at the top of this
// file, so reconcile/types.ts is no longer in the scanned set and this predicate no longer fires on
// a real file. It is deliberately retained rather than deleted: it is the fail-safe for the day the
// hold-out is reversed or a reconcile file is moved back onto the construction surface, and it stays
// armed and exercised by the near-miss suite below, which proves it is file-keyed (the identical
// helper still trips inside transactions.ts).
function isThrownErrorTemplateOperand(call: ts.CallExpression): boolean {
  const span = call.parent;
  if (!ts.isTemplateSpan(span) || span.expression !== call) return false;
  const template = span.parent;
  if (!ts.isTemplateExpression(template)) return false;
  const errorConstruction = template.parent;
  if (
    !ts.isNewExpression(errorConstruction) ||
    !ts.isIdentifier(errorConstruction.expression) ||
    errorConstruction.expression.text !== "Error" ||
    errorConstruction.arguments?.length !== 1 ||
    errorConstruction.arguments[0] !== template
  ) {
    return false;
  }
  const throwStatement = errorConstruction.parent;
  return (
    ts.isThrowStatement(throwStatement) && throwStatement.expression === errorConstruction
  );
}

function isReviewedUnreachableDiagnosticStringify(stringifyCall: ts.CallExpression): boolean {
  if (stringifyCall.arguments.length !== 1) return false;
  const argument = unwrapExpression(stringifyCall.arguments[0]);
  if (!ts.isIdentifier(argument)) return false;
  const functionNode = enclosingFunction(stringifyCall);
  if (
    functionNode === null ||
    !ts.isFunctionDeclaration(functionNode) ||
    functionNode.name?.text !== "assertUnreachable"
  ) {
    return false;
  }
  // The stringified value must be the helper's own `never`-typed parameter — never a local
  // re-parse, rebuild, or any other in-scope value.
  const neverTypedParameter = functionNode.parameters.some(
    (parameter) =>
      ts.isIdentifier(parameter.name) &&
      parameter.name.text === argument.text &&
      parameter.type?.kind === ts.SyntaxKind.NeverKeyword,
  );
  return (
    neverTypedParameter &&
    hasNoLocalDeclaration(functionNode, argument.text) &&
    isThrownErrorTemplateOperand(stringifyCall)
  );
}

// E13 — send-transfer-code.ts: the ONE `JSON.stringify(<string>)` inside `jsonEscapeString`.
//
// SAFE. `JSON.stringify` is dangerous here because of KEY ORDERING: stringifying an object commits
// this gate's whole subject — the order in which fields are emitted — to V8's property order rather
// than to a reviewed sequence, and those bytes are exactly what `hashTransferCodeText` hashes. A
// string argument has no keys. `JSON.stringify(s)` over a `string` is RFC 8259 string escaping and
// nothing else: one deterministic, locale-independent quoted scalar. It is the correct way to splice
// a value into hand-assembled JSON, and the alternative — hand-rolling the quoting — is strictly
// worse.
//
// What makes it safe is a RUNTIME guard, not a static absence proof. Earlier rounds granted
// the escape at each of the three assembler call sites and tried to prove that no local binding
// shadowed the reviewed symbol. Every round enumerated more binding syntaxes and review found one
// more still invisible — the last was a nested `enum step1Signature { … }`, which compiles, keeps
// the gate green, and leaves the exemption ledger unchanged because it REPLACES a ruled site. Proving
// the absence of a construct over an open-ended grammar is unbounded, and each miss failed OPEN.
//
// The production file now routes all three splices through a single `jsonEscapeString(value: string)`
// whose first statement throws unless `typeof value === "string"`. Any binding form — a shadowed
// const, a destructuring pattern, an enum, an import, or a syntax TypeScript ships next year — that
// substitutes a non-string throws there instead of reaching `JSON.stringify`, so no object can be
// serialised into the hashed wire bytes at all. The guard is the enforcement; this predicate only has
// to RECOGNISE it.
//
// Recognition is structural and exact: the stringify must sit inside a function named
// `jsonEscapeString` in this file, that function must take exactly one parameter typed `string`, its
// body must be exactly the `typeof` guard that throws followed by
// `return JSON.stringify(<that same parameter>)`, and the stringified identifier must be that
// parameter. A two-statement body with no declarations leaves no room for a shadow to exist, so the
// predicate no longer proves a negative — it recognises four lines.
//
// Anti-stretch: a `JSON.stringify` anywhere else in the file still trips, including inside
// `buildSendTransferCodeText` itself, where `JSON.stringify(innerPreimageText)` would double-escape
// the persisted signed inner (the byte-exact signing rule/ SEND_CODE_INNER_KEPT_VERBATIM). So does dropping
// the guard, inverting it, widening the parameter type, adding a second parameter, adding a
// statement, returning anything other than the guarded parameter, or lifting the same helper shape
// into another production file. The near-miss suite proves each one.
const TRANSFER_CODE_ESCAPE_HELPER = "jsonEscapeString";

/** `if (typeof <parameterName> !== "string") { throw … }`, with no `else` and no other branch. */
function isStringTypeofThrowGuard(statement: ts.Statement, parameterName: string): boolean {
  if (!ts.isIfStatement(statement) || statement.elseStatement !== undefined) return false;
  const condition = unwrapExpression(statement.expression);
  if (
    !ts.isBinaryExpression(condition) ||
    condition.operatorToken.kind !== ts.SyntaxKind.ExclamationEqualsEqualsToken
  ) {
    return false;
  }
  const inspected = unwrapExpression(condition.left);
  const expected = unwrapExpression(condition.right);
  if (!ts.isTypeOfExpression(inspected)) return false;
  const operand = unwrapExpression(inspected.expression);
  if (!ts.isIdentifier(operand) || operand.text !== parameterName) return false;
  if (!ts.isStringLiteral(expected) || expected.text !== "string") return false;
  const branch = ts.isBlock(statement.thenStatement)
    ? statement.thenStatement.statements.length === 1
      ? statement.thenStatement.statements[0]
      : undefined
    : statement.thenStatement;
  return branch !== undefined && ts.isThrowStatement(branch);
}

function isTransferCodeStringEscape(
  stringifyCall: ts.CallExpression,
  relativePath: string,
): boolean {
  if (relativePath !== TRANSFER_CODE_FILE) return false;
  if (stringifyCall.arguments.length !== 1) return false;
  const argument = unwrapExpression(stringifyCall.arguments[0]);
  if (!ts.isIdentifier(argument)) return false;
  const functionNode = enclosingFunction(stringifyCall);
  if (
    functionNode === null ||
    !ts.isFunctionDeclaration(functionNode) ||
    functionNode.name?.text !== TRANSFER_CODE_ESCAPE_HELPER ||
    functionNode.parameters.length !== 1
  ) {
    return false;
  }
  const parameter = functionNode.parameters[0];
  if (
    parameter.dotDotDotToken !== undefined ||
    parameter.questionToken !== undefined ||
    parameter.initializer !== undefined ||
    parameter.type?.kind !== ts.SyntaxKind.StringKeyword ||
    !ts.isIdentifier(parameter.name) ||
    parameter.name.text !== argument.text
  ) {
    return false;
  }
  const body = functionNode.body;
  if (body === undefined || body.statements.length !== 2) return false;
  if (!isStringTypeofThrowGuard(body.statements[0], parameter.name.text)) return false;
  const returned = body.statements[1];
  return (
    ts.isReturnStatement(returned) &&
    returned.expression !== undefined &&
    unwrapExpression(returned.expression) === stringifyCall
  );
}

// E14 — inner-shape.ts `Record<string, unknown>` x3.
//
// SAFE, and the same call E8 already makes for the suite boundary. A permissive Record is
// dangerous when it types EMITTED data. All three occurrences type INBOUND, not-yet-validated
// `JSON.parse` output on its way INTO the narrowing gate: the `SplitChainInnerParseInput` alias, and
// the `isPlainRecord` / `hasExactKeySequence` shape probes that run before any field is read. The
// EMITTED type is the closed `SplitChainInnerV2`, reached only after the closed field-set, sequence,
// literal and branded-scalar checks all pass — and reached by returning the PARSED OBJECT ITSELF
// (`inner: parsed as unknown as SplitChainInnerV2`), never a rebuild, which is precisely why this
// module cannot rewrite signed bytes at all.
//
// Anti-stretch: keyed to those three named symbols. A permissive Record introduced anywhere else in
// inner-shape.ts still trips.
const INNER_SHAPE_BOUNDARY_INPUT_ALIAS = "SplitChainInnerParseInput";
const INNER_SHAPE_BOUNDARY_PROBES: readonly string[] = ["isPlainRecord", "hasExactKeySequence"];

function isInnerShapeBoundaryInputRecord(node: ts.TypeReferenceNode, relativePath: string): boolean {
  if (relativePath !== INNER_SHAPE_FILE) return false;
  if (enclosingTypeAliasName(node) === INNER_SHAPE_BOUNDARY_INPUT_ALIAS) return true;
  const owner = enclosingFunctionName(node);
  return owner !== null && INNER_SHAPE_BOUNDARY_PROBES.includes(owner);
}

// E15 — inner-shape.ts spread x3 building `PERMITTED_INNER_KEY_SEQUENCES`.
//
// SAFE, and shape-identical to E3's call for the registry field sequence. The spread rule exists
// because spreading rebuilds an object and can reorder or inject keys on the way to signed bytes.
// These three spreads build no payload: they widen the frozen `SPLIT_CHAIN_INNER_REQUIRED_FIELDS`
// tuple into the three longer protocol foundation key SEQUENCES that `hasExactKeySequence` compares an inbound
// object's `Object.keys()` against. The result is compared, never emitted, and the module returns the
// parsed object unmodified. The spread is what makes the required prefix impossible to restate by
// hand and therefore impossible to drift from positions 1–12.
//
// Anti-stretch: the operand must be exactly `SPLIT_CHAIN_INNER_REQUIRED_FIELDS`, it must be the FIRST
// element of its array (a trailing or middle spread would move the required prefix), and the array
// must be an element of the `PERMITTED_INNER_KEY_SEQUENCES` initializer. Any other spread in
// inner-shape.ts — including spreading the optional-field tuple, or spreading anywhere else in the
// same declaration — still trips.
const INNER_SHAPE_REQUIRED_FIELDS_CONST = "SPLIT_CHAIN_INNER_REQUIRED_FIELDS";
const INNER_SHAPE_PERMITTED_SEQUENCES_CONST = "PERMITTED_INNER_KEY_SEQUENCES";

function isInnerShapeKeySequenceSpread(node: ts.SpreadElement, relativePath: string): boolean {
  if (relativePath !== INNER_SHAPE_FILE) return false;
  const operand = unwrapExpression(node.expression);
  if (!ts.isIdentifier(operand) || operand.text !== INNER_SHAPE_REQUIRED_FIELDS_CONST) return false;
  const sequence = node.parent;
  if (!ts.isArrayLiteralExpression(sequence) || sequence.elements[0] !== node) return false;
  const sequenceSet = sequence.parent;
  if (!ts.isArrayLiteralExpression(sequenceSet)) return false;
  const declaration = sequenceSet.parent;
  return (
    ts.isVariableDeclaration(declaration) &&
    ts.isIdentifier(declaration.name) &&
    declaration.name.text === INNER_SHAPE_PERMITTED_SEQUENCES_CONST
  );
}

function analyzeTransactionSafety(
  relativePath: string,
  sourceFile: ts.SourceFile,
  requireExactProductionStringifyCalls = false,
  exemptionLedger?: SuiteExemptionLedger,
): string[] {
  const violations: string[] = [];
  const constStrings = collectConstStrings(sourceFile);
  const aliases = collectAliases(sourceFile, constStrings);
  // `aliases` answers "what object is this"; `callableAliases` also answers "what runs when this is
  // called". Only the call-path rule below reads the second, so a `.bind` result can never stand in
  // for its target on a write receiver.
  const callableAliases: ReadonlyMap<string, string> = new Map([
    ...aliases,
    ...collectBoundCallables(sourceFile, aliases, constStrings),
  ]);
  const stringifyRoles: CanonicalStringifyRole[] = [];
  const add = (rule: string): void => {
    violations.push(`${relativePath}: ${rule}`);
  };
  // Records that a reviewed exemption actually fired. The exact-count guard below turns every grant
  // into a pinned number, so a grant that silently stops matching (or starts matching more) fails.
  const exempt = (exemption: SuiteExemption): true => {
    exemptionLedger?.set(exemption, (exemptionLedger.get(exemption) ?? 0) + 1);
    return true;
  };

  visitEveryNode(sourceFile, (node) => {
    const isExistingScalarCodePointCount =
      relativePath === "scalars.ts" &&
      ts.isSpreadElement(node) &&
      ts.isArrayLiteralExpression(node.parent) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "text";
    if (
      (ts.isSpreadAssignment(node) || ts.isSpreadElement(node)) &&
      !isExistingScalarCodePointCount
    ) {
      const exemptedSpread =
        (ts.isSpreadAssignment(node) &&
          isSuiteBuilderValuesSpread(node, relativePath) &&
          exempt("builder values spread")) ||
        (ts.isSpreadAssignment(node) &&
          isSuiteParserResultSpread(node, relativePath) &&
          exempt("parser result spread")) ||
        (ts.isSpreadElement(node) &&
          isSuiteRegistryFieldSequenceSpread(node, relativePath) &&
          exempt("registry field-sequence spread")) ||
        (ts.isSpreadElement(node) &&
          isSuiteLabelCodePointSpread(node, relativePath) &&
          exempt("label code-point spread")) ||
        (ts.isSpreadElement(node) &&
          isInnerShapeKeySequenceSpread(node, relativePath) &&
          exempt("inner-shape key-sequence spread"));
      if (!exemptedSpread) add("spread syntax");
    }
    if (ts.isDeleteExpression(node)) add("delete expression");
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.PlusToken) {
      add("unary numeric coercion");
    }
    if (
      ts.isBinaryExpression(node) &&
      isAssignmentOperator(node.operatorToken.kind) &&
      !isAllowedCanonicalInnerAssignment(node) &&
      writeReceiverPath(node.left, sourceFile, aliases, constStrings) === "inner"
    ) {
      add("canonical inner write");
    }
    if (
      ((ts.isPrefixUnaryExpression(node) &&
        (node.operator === ts.SyntaxKind.PlusPlusToken ||
          node.operator === ts.SyntaxKind.MinusMinusToken)) ||
        ts.isPostfixUnaryExpression(node)) &&
      writeReceiverPath(node.operand, sourceFile, aliases, constStrings) === "inner"
    ) {
      add("canonical inner update");
    }

    if (
      ts.isTypeReferenceNode(node) &&
      node.typeName.getText(sourceFile) === "Record" &&
      node.typeArguments?.length === 2 &&
      node.typeArguments[0]?.kind === ts.SyntaxKind.StringKeyword &&
      node.typeArguments[1]?.kind === ts.SyntaxKind.UnknownKeyword
    ) {
      if (isSuiteBoundaryInputRecord(node, relativePath)) exempt("boundary input Record");
      else if (isInnerShapeBoundaryInputRecord(node, relativePath)) {
        exempt("inner-shape boundary input Record");
      } else add("permissive Record<string, unknown>");
    }

    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const moduleName = node.moduleSpecifier.text.toLowerCase();
      if (
        moduleName.includes("stable-stringify") ||
        moduleName.includes("canonical-json") ||
        moduleName.includes("canonicalize")
      ) {
        add("stable or canonical JSON library");
      }
      if (relativePath === TRANSACTION_FILE && moduleName === "bignumber.js") {
        add("direct BigNumber dependency");
      }
    }

    if (
      ts.isFunctionDeclaration(node) &&
      isExported(node) &&
      node.name !== undefined &&
      /serializ|stringif|canonicaliz/i.test(node.name.text)
    ) {
      if (isCanonicalSuiteSerializerDeclaration(node, relativePath)) {
        exempt("canonical serializer declaration");
      } else if (isSuiteManifestCensusBuilder(node, relativePath)) {
        exempt("manifest census builder");
      } else {
        add("generic public object serializer");
      }
    }

    if (ts.isNewExpression(node)) {
      const constructorPath = expressionPath(
        node.expression,
        sourceFile,
        aliases,
        constStrings,
      );
      if (constructorPath === "Date") {
        if (isSuiteTimestampValidationDate(node, relativePath)) {
          exempt("timestamp validation Date");
        } else {
          add("Date construction");
        }
      }
      if (relativePath === TRANSACTION_FILE && constructorPath?.endsWith("BigNumber")) {
        add("direct BigNumber construction");
      }
    }

    if (!ts.isCallExpression(node)) return;
    const path = callableExpressionPath(node.expression, sourceFile, callableAliases, constStrings);
    if (path === null) return;
    const method = finalPathSegment(path);

    // One decision per call node: `JSON.parse` and `Date.parse` each trip two always-on rules
    // (the method-specific one and the `.parse()` schema-transform one), so a construct ruled SAFE
    // must clear both from a single decision rather than being re-judged per rule.
    const exemptedWireJsonParse =
      path === "JSON.parse" &&
      isSuiteWireJsonParse(node, relativePath) &&
      exempt("wire JSON.parse");
    const exemptedSignedWindowDateParse =
      isSuiteSignedWindowDateParse(node, path, relativePath) &&
      exempt("signed-window Date.parse");
    const exemptedCanonicalSerializerCall =
      isCanonicalSuiteSerializerCall(path, relativePath) && exempt("canonical serializer call");

    const dangerousMutator = invokedDangerousMutator(path);
    if (dangerousMutator !== null) add(dangerousMutator);
    if (path === "Object.fromEntries") add(path);
    if (method === "sort") add("sort call");
    const jsonMethod = invokedJsonMethod(path);
    if (jsonMethod === "parse" && !exemptedWireJsonParse) add("JSON.parse");
    if (jsonMethod === "rawJSON") add("JSON.rawJSON");
    if (path === "structuredClone") add("structuredClone");
    if (["Number", "String", "parseFloat", "parseInt"].includes(path)) add(`${path}()`);
    if ((path === "Date" || path.startsWith("Date.")) && !exemptedSignedWindowDateParse) {
      add("Date call");
    }
    if (relativePath === TRANSACTION_FILE && path.endsWith("BigNumber")) {
      add("direct BigNumber call");
    }

    if (
      [
        "normalize",
        "trim",
        "trimStart",
        "trimEnd",
        "toLocaleLowerCase",
        "toLocaleUpperCase",
        "localeCompare",
        "replace",
        "replaceAll",
      ].includes(method)
    ) {
      add(`.${method}()`);
    }
    const isAllowedAmountFormatter =
      relativePath === "amounts.ts" &&
      method === "toFixed" &&
      node.arguments.length === 0;
    if (
      [
        "toFixed",
        "toExponential",
        "toPrecision",
        "toLocaleString",
        "toNumber",
        "toFormat",
        "valueOf",
      ].includes(method) &&
      !isAllowedAmountFormatter
    ) {
      add(`numeric formatter .${method}()`);
    }
    if (relativePath === TRANSACTION_FILE && method === "toString") {
      add("numeric formatter .toString()");
    }
    if (
      ["parse", "safeParse", "transform", "strip", "passthrough"].includes(method) &&
      !exemptedWireJsonParse &&
      !exemptedSignedWindowDateParse
    ) {
      add(`schema-transformed output .${method}()`);
    }

    if (jsonMethod === "stringify") {
      if (path !== "JSON.stringify") {
        add("unproven JSON.stringify call");
        return;
      }
      if (node.arguments.length !== 1) {
        add("JSON.stringify replacer or spacing");
        return;
      }
      if (relativePath === INNER_DIGEST_FILE && isReviewedInnerDigestStringify(node)) {
        return;
      }
      if (isReviewedSuiteTupleStringify(node, relativePath)) {
        exempt("canonical suite preimage stringify");
        return;
      }
      if (isTransferCodeStringEscape(node, relativePath)) {
        exempt("transfer-code string escape");
        return;
      }
      if (
        relativePath === RECONCILE_UNREACHABLE_FILE &&
        isReviewedUnreachableDiagnosticStringify(node)
      ) {
        return;
      }
      const role =
        relativePath === TRANSACTION_FILE ? canonicalStringifyRole(node) : null;
      if (role === null) add("unproven JSON.stringify call");
      else stringifyRoles.push(role);
      return;
    }

    if (
      /^(?:serialize|stringify|canonicalize|serializer)/i.test(method) &&
      !exemptedCanonicalSerializerCall
    ) {
      add("generic public object serializer call");
    }
  });

  if (requireExactProductionStringifyCalls && relativePath === TRANSACTION_FILE) {
    const counts = new Map<string, number>();
    for (const role of stringifyRoles) counts.set(role, (counts.get(role) ?? 0) + 1);
    if (
      stringifyRoles.length !== 3 ||
      counts.get("inner") !== 1 ||
      counts.get("step1Signature") !== 1 ||
      counts.get("step2Signature") !== 1
    ) {
      add("exact JSON.stringify call set");
    }
  }

  return violations;
}

function analyzeReviewedTransactionSafety(
  relativePath: string,
  sourceFile: ts.SourceFile,
  requireExactProductionStringifyCalls = false,
  exemptionLedger?: SuiteExemptionLedger,
): string[] {
  const violations = analyzeTransactionSafety(
    relativePath,
    sourceFile,
    requireExactProductionStringifyCalls,
    exemptionLedger,
  );
  if (
    relativePath === TRANSACTION_FILE &&
    normalizedAstSha256(sourceFile) !==
      REVIEWED_TRANSACTION_AST_SHA256_REQUIRES_INDEPENDENT_BYTE_PATH_REREVIEW
  ) {
    violations.push(
      REVIEWED_AST_FINGERPRINT_VIOLATION,
    );
  }
  return violations;
}

function mutationSource(source: string): ts.SourceFile {
  return ts.createSourceFile(
    "transactions.mutation.ts",
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
}

const scannedSources = collectSources(protocolRoot);
// The construction surface this ratchet was written for. `reconcile/` is held out (see the
// construction-scope note above) and is asserted non-empty and unreachable below.
const productionSources = scannedSources.filter(
  ({ relativePath }) => !isReconcileConcern(relativePath),
);
const reconcileSources = scannedSources.filter(({ relativePath }) =>
  isReconcileConcern(relativePath),
);
const reviewedTransactionSource = productionSources.find(
  ({ relativePath }) => relativePath === TRANSACTION_FILE,
);
if (reviewedTransactionSource === undefined) {
  throw new Error(`Missing reviewed production source: ${TRANSACTION_FILE}`);
}

const INNER_FREEZE_INSERTION_POINT =
  "  Object.freeze(inner);\n\n  const innerPreimageText";

function fullTransactionMutation(statements: string): ts.SourceFile {
  const source = reviewedTransactionSource.sourceFile.text;
  if (source.split(INNER_FREEZE_INSERTION_POINT).length !== 2) {
    throw new Error("transaction mutation insertion point is not unique");
  }
  const indentedStatements = statements
    .trim()
    .split("\n")
    .map((line) => `  ${line}`)
    .join("\n");
  return mutationSource(
    source.replace(
      INNER_FREEZE_INSERTION_POINT,
      `${indentedStatements}\n${INNER_FREEZE_INSERTION_POINT}`,
    ),
  );
}

describe("recursive transaction construction safety gate", () => {
  it("keeps every protocol production file free of unsafe construction surfaces", () => {
    const violations = productionSources.flatMap(({ relativePath, sourceFile }) =>
      analyzeReviewedTransactionSafety(relativePath, sourceFile, true),
    );
    expect(violations).toEqual([]);
  });

  it("scans a non-empty production source set that excludes colocated *.test.ts", () => {
    expect(productionSources.length).toBeGreaterThan(0);
    expect(
      productionSources.filter(({ relativePath }) => relativePath.endsWith(".test.ts")),
    ).toEqual([]);
    // The two byte-critical money-path files must remain in scope so the *.test.ts exclusion
    // can never pass this gate vacuously by dropping the sources it exists to protect.
    const scannedPaths = productionSources.map(({ relativePath }) => relativePath);
    expect(scannedPaths).toContain(TRANSACTION_FILE);
    expect(scannedPaths).toContain(INNER_DIGEST_FILE);
    // The suite serializer lives in a subdirectory, so the recursive walk — not just the top
    // level — must stay in scope; otherwise the E1–E12 exemptions below could be satisfied
    // vacuously by a scan that never reaches the files it exempts. (This anchor was previously
    // reconcile/types.ts; moved it to suite/ when reconcile/ left the construction scope.)
    expect(scannedPaths).toContain(SUITE_SERIALIZE_FILE);
    expect(
      scannedPaths.filter((path) => path.startsWith(`suite${sep}`)).length,
    ).toBeGreaterThan(1);
  });

  it("holds the reconcile concern out of scope only while it stays unreachable from construction", () => {
    // The scoping decision (option (b)) rests on exactly one computed property: no direct
    // module specifier in a scanned construction file resolves into reconcile/, so the excluded
    // directory cannot inject a construction defect into this ratchet's surface through an import
    // edge. It is NOT a claim that reconcile/ is unreachable from signing — see the scope note above.
    expect(reconcileImportEdges(productionSources)).toEqual([]);

    // Falsifiability: the same computation must flag the edge it exists to catch. A re-export in
    // protocol/index.ts is the same ExportDeclaration shape and is caught identically.
    expect(
      reconcileImportEdges([
        {
          relativePath: TRANSACTION_FILE,
          sourceFile: mutationSource(
            `import { classifyMove } from "./${RECONCILE_DIRECTORY}/index.js";`,
          ),
        },
      ]),
    ).toEqual([`${TRANSACTION_FILE}: imports ./${RECONCILE_DIRECTORY}/index.js`]);
    expect(
      reconcileImportEdges([
        {
          relativePath: join("suite", "serialize.ts"),
          sourceFile: mutationSource(
            `export type { MoveBreachRow } from "../${RECONCILE_DIRECTORY}/invariant-breach.js";`,
          ),
        },
      ]),
    ).toHaveLength(1);

    // M4c (review B, D2) — the same file reached by a specifier that climbs OUT of the
    // protocol root and back. It resolves to exactly the file M4 imports; a prefix test on the raw
    // relative form let it through silently, which is the opposite of failing closed.
    expect(
      reconcileImportEdges([
        {
          relativePath: "send-baseline.ts",
          sourceFile: mutationSource(
            `import { classifyMove } from "../protocol/${RECONCILE_DIRECTORY}/index.js";`,
          ),
        },
      ]),
    ).toEqual([`send-baseline.ts: imports ../protocol/${RECONCILE_DIRECTORY}/index.js`]);
    // Same climb from a subdirectory, where the escaping form is one level deeper.
    expect(
      reconcileImportEdges([
        {
          relativePath: join("suite", "serialize.ts"),
          sourceFile: mutationSource(
            `import { classifyMove } from "../../protocol/${RECONCILE_DIRECTORY}/index.js";`,
          ),
        },
      ]),
    ).toHaveLength(1);
    // A relative specifier that leaves the protocol root and does NOT come back is reported too:
    // this walk cannot see where it re-enters, so the isolation property is unprovable, not proven.
    expect(
      reconcileImportEdges([
        {
          relativePath: TRANSACTION_FILE,
          sourceFile: mutationSource(`import { classifyMove } from "../reconcile-barrel.js";`),
        },
      ]),
    ).toHaveLength(1);
    // Bare package specifiers are not paths and must not be swept up by that rule.
    expect(
      reconcileImportEdges([
        {
          relativePath: TRANSACTION_FILE,
          sourceFile: mutationSource(
            `import { createHash } from "node:crypto";\nimport { x } from "@zucoins/generic-node-contracts";`,
          ),
        },
      ]),
    ).toEqual([]);

    // Non-vacuity for the hold-out itself: the excluded set must actually be the reconcile concern
    // and must not be empty, so a rename or a move cannot turn "excluded" into "nothing was there".
    expect(reconcileSources.length).toBeGreaterThan(1);
    expect(reconcileSources.map(({ relativePath }) => relativePath)).toContain(
      RECONCILE_UNREACHABLE_FILE,
    );
    expect(
      productionSources.filter(({ relativePath }) => isReconcileConcern(relativePath)),
    ).toEqual([]);

    // Runtime twin of the static edge check: protocol/index.ts's public surface must not carry the
    // reconcile concern either.
    expect(protocolApi).not.toHaveProperty("InMemoryMoveInvariantBreachStore");
    expect(protocolApi).not.toHaveProperty("assertOutcomeIsInvariantBreach");
  });

  it("exempts the assertUnreachable diagnostic only in its exact throw-only form", () => {
    const reviewed = `
      export function assertUnreachable(value: never): never {
        throw new Error(\`unreachable reconcile classification member: \${JSON.stringify(value)}\`);
      }
    `;
    expect(
      analyzeTransactionSafety(RECONCILE_UNREACHABLE_FILE, mutationSource(reviewed)),
    ).toEqual([]);

    // The exemption is file-keyed: the identical helper cannot license a stringify inside the
    // byte-critical transaction constructor file.
    expect(analyzeTransactionSafety(TRANSACTION_FILE, mutationSource(reviewed))).toContain(
      `${TRANSACTION_FILE}: unproven JSON.stringify call`,
    );

    const nearMisses: ReadonlyArray<{ readonly name: string; readonly source: string }> = [
      {
        name: "text escapes through a local before the throw",
        source: `
          export function assertUnreachable(value: never): never {
            const text = \`member: \${JSON.stringify(value)}\`;
            throw new Error(text);
          }
        `,
      },
      {
        name: "text returned instead of thrown",
        source: `
          export function assertUnreachable(value: never): string {
            return \`member: \${JSON.stringify(value)}\`;
          }
        `,
      },
      {
        name: "thrown through a non-Error constructor",
        source: `
          export function assertUnreachable(value: never): never {
            throw new TypeError(\`member: \${JSON.stringify(value)}\`);
          }
        `,
      },
      {
        name: "parameter is not typed never",
        source: `
          export function assertUnreachable(value: unknown): never {
            throw new Error(\`member: \${JSON.stringify(value)}\`);
          }
        `,
      },
      {
        name: "helper renamed",
        source: `
          export function describeMember(value: never): never {
            throw new Error(\`member: \${JSON.stringify(value)}\`);
          }
        `,
      },
      {
        name: "stringifies a local shadow rather than the parameter",
        source: `
          export function assertUnreachable(value: never): never {
            const value = rebuildMember();
            throw new Error(\`member: \${JSON.stringify(value)}\`);
          }
        `,
      },
      {
        name: "stringifies an unrelated in-scope value",
        source: `
          export function assertUnreachable(value: never): never {
            const rebuilt = rebuildMember();
            throw new Error(\`member: \${JSON.stringify(rebuilt)}\`);
          }
        `,
      },
      {
        name: "Error carries a second argument beyond the message",
        source: `
          export function assertUnreachable(value: never): never {
            throw new Error(\`member: \${JSON.stringify(value)}\`, { cause: value });
          }
        `,
      },
    ];

    for (const nearMiss of nearMisses) {
      expect(
        analyzeTransactionSafety(RECONCILE_UNREACHABLE_FILE, mutationSource(nearMiss.source)),
        nearMiss.name,
      ).toContain(`${RECONCILE_UNREACHABLE_FILE}: unproven JSON.stringify call`);
    }
  });

  it("pins the independently reviewed AST while ignoring comments and whitespace", () => {
    const reviewedSource = reviewedTransactionSource.sourceFile;
    expect(normalizedAstSha256(reviewedSource)).toBe(
      REVIEWED_TRANSACTION_AST_SHA256_REQUIRES_INDEPENDENT_BYTE_PATH_REREVIEW,
    );
    expect(analyzeReviewedTransactionSafety(TRANSACTION_FILE, reviewedSource, true)).toEqual(
      [],
    );

    const commentOnly = mutationSource(
      `// comment-only control\n${reviewedSource.text}\n// trailing review note\n`,
    );
    const whitespaceOnly = mutationSource(`\n\n${reviewedSource.text}\n\n`);
    expect(normalizedAstSha256(commentOnly)).toBe(normalizedAstSha256(reviewedSource));
    expect(normalizedAstSha256(whitespaceOnly)).toBe(normalizedAstSha256(reviewedSource));
    expect(analyzeReviewedTransactionSafety(TRANSACTION_FILE, commentOnly, true)).toEqual(
      [],
    );
    expect(analyzeReviewedTransactionSafety(TRANSACTION_FILE, whitespaceOnly, true)).toEqual(
      [],
    );
  });

  it("fails closed on full-source mutations beyond semantic alias diagnostics", () => {
    const semanticFalseNegatives: ReadonlyArray<{
      readonly name: string;
      readonly statements: string;
    }> = [
      {
        name: "mutable alias",
        statements: 'let target = inner; target.message = "changed";',
      },
      {
        name: "reassigned alias",
        statements:
          'let target = Object.create(null) as MutableInner; target = inner; target.message = "changed";',
      },
      {
        name: "nested alias",
        statements:
          'const holder = { current: inner }; const target = holder.current; target.message = "changed";',
      },
      {
        name: "destructured alias",
        statements:
          'const holder = { current: inner }; const { current: target } = holder; target.message = "changed";',
      },
      {
        name: "array alias",
        statements:
          'const aliases = [inner]; const [target] = aliases; target.message = "changed";',
      },
      {
        name: "long nested alias chain",
        statements: `
          const aliasRoot = { value: inner };
          const alias1 = aliasRoot.value;
          const alias2 = alias1;
          const alias3 = alias2;
          const alias4 = alias3;
          const alias5 = alias4;
          const alias6 = alias5;
          alias6.message = "changed";
        `,
      },
      {
        name: "globalThis Object mutator",
        statements:
          'globalThis.Object.defineProperty(inner, "rogue", { value: true });',
      },
      {
        name: "globalThis Reflect mutator",
        statements: 'globalThis.Reflect.set(inner, "rogue", true);',
      },
      {
        name: "template-computed JSON parse",
        statements: 'const decode = JSON[`par${"se"}`]; void decode("{}");',
      },
    ];

    for (const mutation of semanticFalseNegatives) {
      const mutatedSource = fullTransactionMutation(mutation.statements);
      expect(
        analyzeTransactionSafety(TRANSACTION_FILE, mutatedSource, true),
        `${mutation.name}: semantic diagnostic precondition`,
      ).toEqual([]);
      expect(
        analyzeReviewedTransactionSafety(TRANSACTION_FILE, mutatedSource, true),
        `${mutation.name}: composite gate`,
      ).toEqual([REVIEWED_AST_FINGERPRINT_VIOLATION]);
    }
  });

  it("evaluates method rules through a call-expression receiver", () => {
    // `expressionPath` returned null for a call-expression receiver, so
    // `callableExpressionPath` yielded null and the whole call node short-circuited before a single
    // method rule ran. Every shape below was silently green in a production module.
    const chainedReceivers: ReadonlyArray<{
      readonly expected: string;
      readonly statements: string;
    }> = [
      {
        expected: ".replace()",
        statements: 'const stripped = encodeInner(inner).replace(/a/g, "b");',
      },
      {
        // The shape that discovered the false negative: send-transfer-code.ts:45.
        expected: ".replace()",
        statements:
          'const code = Buffer.from(uriEncoded, "utf8").toString("base64url").replace(/=/g, "");',
      },
      {
        // A called call — `factory()(value)` resolves through two call segments.
        expected: ".replaceAll()",
        statements: 'const flattened = codecFor(kind)(inner).replaceAll("a", "b");',
      },
      { expected: ".trim()", statements: "const text = readMessage(inner).trim();" },
      { expected: "sort call", statements: "const ordered = collectFields(inner).sort();" },
      {
        expected: "schema-transformed output .parse()",
        statements: "const parsed = schemaFor(kind).parse(payload);",
      },
      {
        expected: "numeric formatter .toFixed()",
        statements: "const shown = amountOf(inner).toFixed(8);",
      },
    ];

    for (const { expected, statements } of chainedReceivers) {
      expect(
        analyzeTransactionSafety(TRANSACTION_FILE, fullTransactionMutation(statements), true),
        statements,
      ).toContain(`${TRANSACTION_FILE}: ${expected}`);
    }

    // Anti-stretch: widening the receiver must not blanket-flag every chained call, and the
    // exact-path mutator rules must still see through a bound callee rather than degrading to
    // `Object.assign.bind()`.
    expect(
      analyzeTransactionSafety(
        TRANSACTION_FILE,
        fullTransactionMutation("const head = normalizeOnce(inner).slice(0, 2);"),
        true,
      ),
    ).toEqual([]);
    expect(
      analyzeTransactionSafety(
        TRANSACTION_FILE,
        fullTransactionMutation("Object.assign.bind(null)({}, inner);"),
        true,
      ),
    ).toContain(`${TRANSACTION_FILE}: Object.assign`);

    // ...and a comment-only edit to the same production module stays green on both the
    // construction rules and the reviewed-AST fingerprint.
    const commentOnly = mutationSource(
      `// comment-only control\n${reviewedTransactionSource.sourceFile.text}\n`,
    );
    expect(analyzeReviewedTransactionSafety(TRANSACTION_FILE, commentOnly, true)).toEqual([]);
  });

  it("keeps the canonical-inner rules armed against the real transaction module", () => {
    // regression. The `canonical inner write` / `canonical inner update` rules key on the
    // bare identifier `inner`, and the module under guard declares it as
    // `const inner = Object.create(null) as MutableInner`. Any change that lets a call-derived path
    // into the alias map makes `writeReceiverPath` report that path instead of `inner` and kills
    // both rules on the byte-exact `JSON.stringify(inner)` preimage — while every case in
    // "detects direct, computed, destructured, and aliased mutation forms" stays green, because
    // `mutationSource` snippets leave `inner` undeclared and therefore unaliased. These cases splice
    // into the real source through `fullTransactionMutation`, so only this fixture can see it.
    const constStrings = collectConstStrings(reviewedTransactionSource.sourceFile);
    const aliases = collectAliases(reviewedTransactionSource.sourceFile, constStrings);
    for (const [name, path] of aliases) {
      expect(path, `alias ${name} must not resolve through a call`).not.toContain("()");
    }
    expect(aliases.get("inner")).toBeUndefined();
    expect(aliases.get("capability")).toBeUndefined();

    const canonicalInnerMutations: ReadonlyArray<{
      readonly expected: string;
      readonly statements: string;
    }> = [
      { expected: "canonical inner write", statements: "inner.rogue = true;" },
      { expected: "canonical inner write", statements: 'inner["rogue"] = true;' },
      {
        expected: "canonical inner write",
        statements: 'const target = inner; target["rogue"] = true;',
      },
      {
        expected: "canonical inner write",
        statements: 'const field = "ro" + "gue"; inner[field] = true;',
      },
      { expected: "canonical inner update", statements: 'inner["signer_steps"]++;' },
      { expected: "canonical inner update", statements: "++inner.signer_steps;" },
      // A `.bind` initializer is the one shape whose path sheds the `` marker, so it
      // used to alias `inner` to the bound function and disarm both rules the same way.
      {
        expected: "canonical inner write",
        statements: "const inner = Object.create.bind(null); inner.rogue = true;",
      },
      {
        expected: "canonical inner update",
        statements: "const inner = wrap.bind(null); inner.signer_steps++;",
      },
    ];

    for (const { expected, statements } of canonicalInnerMutations) {
      expect(
        analyzeTransactionSafety(TRANSACTION_FILE, fullTransactionMutation(statements), true),
        statements,
      ).toContain(`${TRANSACTION_FILE}: ${expected}`);
    }

    // The fourteen whitelisted assignments in `buildSplitChainInnerV2` are the reason a dead rule is
    // invisible to the census: they resolve `inner` but are exempt, so the findings list never moves.
    // Pin the resolution itself, not the finding.
    let resolvedCanonicalWrites = 0;
    visitEveryNode(reviewedTransactionSource.sourceFile, (node) => {
      if (
        ts.isBinaryExpression(node) &&
        isAssignmentOperator(node.operatorToken.kind) &&
        writeReceiverPath(
          node.left,
          reviewedTransactionSource.sourceFile,
          aliases,
          constStrings,
        ) === "inner"
      ) {
        resolvedCanonicalWrites += 1;
        expect(isAllowedCanonicalInnerAssignment(node)).toBe(true);
      }
    });
    expect(resolvedCanonicalWrites).toBe(CANONICAL_INNER_ASSIGNMENT_ORDER.length);
  });

  it("resolves a bound callable to its target without aliasing the receiver", () => {
    // anti-stretch. Keeping `.bind` out of `aliases` must not cost the mutator rules the
    // `const bd = Object.assign.bind(null); bd(...)` shape: that claim moves to the callable view.
    const boundAssign = "const bd = Object.assign.bind(null); bd({}, inner);";
    const chainedBind =
      "const bd = Object.assign.bind(null); const bd2 = bd.bind(null); bd2({}, inner);";
    for (const statements of [boundAssign, chainedBind]) {
      expect(
        analyzeTransactionSafety(TRANSACTION_FILE, fullTransactionMutation(statements), true),
        statements,
      ).toContain(`${TRANSACTION_FILE}: Object.assign`);
    }

    const bound = fullTransactionMutation(boundAssign);
    const constStrings = collectConstStrings(bound);
    const aliases = collectAliases(bound, constStrings);
    expect(aliases.get("bd")).toBeUndefined();
    expect(collectBoundCallables(bound, aliases, constStrings).get("bd")).toBe("Object.assign");
  });

  it("detects direct, computed, destructured, and aliased mutation forms", () => {
    const mutations: ReadonlyArray<{ readonly expected: string; readonly source: string }> = [
      { expected: "spread syntax", source: "const output = { ...inner };" },
      { expected: "spread syntax", source: "const output = [...fields];" },
      { expected: "Object.assign", source: "const output = Object.assign({}, inner);" },
      { expected: "Object.assign", source: "const O = Object; O[\"assign\"]({}, inner);" },
      {
        expected: "Object.assign",
        source: 'const method = "assign"; Object[method]({}, inner);',
      },
      {
        expected: "canonical inner write",
        source: 'inner["rogue"] = true;',
      },
      {
        expected: "canonical inner write",
        source: 'const field = "ro" + "gue"; inner[field] = true;',
      },
      {
        expected: "canonical inner write",
        source: 'const target = inner; target["rogue"] = true;',
      },
      {
        expected: "canonical inner write",
        source: 'const target = inner; target.message = "changed";',
      },
      {
        expected: "canonical inner write",
        source: 'const first = inner; const target = first; target.message += "changed";',
      },
      {
        expected: "canonical inner update",
        source: 'inner["signer_steps"]++;',
      },
      {
        expected: "canonical inner update",
        source: '++inner["signer_steps"];',
      },
      {
        expected: "canonical inner update",
        source: 'const target = inner; --target.signer_steps;',
      },
      {
        expected: "Object.defineProperty",
        source: 'Object.defineProperty(inner, "rogue", { value: true });',
      },
      {
        expected: "Object.defineProperty",
        source:
          'const define = Object["define" + "Property"]; define(inner, "rogue", { value: true });',
      },
      {
        expected: "Object.defineProperty",
        source:
          'Object.defineProperty.call(Object, inner, "rogue", { value: true });',
      },
      {
        expected: "Object.defineProperty",
        source:
          'const define = Object.defineProperty.bind(Object); define(inner, "rogue", descriptor);',
      },
      {
        expected: "Object.defineProperties",
        source: 'Object.defineProperties(inner, { rogue: { value: true } });',
      },
      {
        expected: "Object.defineProperties",
        source: 'const { defineProperties } = Object; defineProperties(inner, descriptors);',
      },
      {
        expected: "Reflect.set",
        source: 'Reflect.set(inner, "rogue", true);',
      },
      {
        expected: "Reflect.set",
        source: 'Reflect["s" + "et"](inner, "rogue", true);',
      },
      {
        expected: "Reflect.set",
        source: 'const invoke = Reflect.set.call; invoke(Reflect, inner, "rogue", true);',
      },
      {
        expected: "Reflect.defineProperty",
        source: 'Reflect.defineProperty(inner, "rogue", descriptor);',
      },
      {
        expected: "Reflect.defineProperty",
        source:
          'const R = Reflect; const define = R.defineProperty; define(inner, "rogue", descriptor);',
      },
      {
        expected: "Reflect.deleteProperty",
        source: 'Reflect.deleteProperty(inner, "message");',
      },
      {
        expected: "Reflect.deleteProperty",
        source: 'const remove = Reflect["delete" + "Property"]; remove(inner, "message");',
      },
      {
        expected: "Reflect.setPrototypeOf",
        source: "Reflect.setPrototypeOf(inner, null);",
      },
      {
        expected: "Reflect.setPrototypeOf",
        source: "Reflect.setPrototypeOf.apply(Reflect, [inner, null]);",
      },
      {
        expected: "Object.preventExtensions",
        source: "Object.preventExtensions(inner);",
      },
      { expected: "Object.seal", source: "Object.seal(inner);" },
      {
        expected: "Reflect.preventExtensions",
        source: "Reflect.preventExtensions(inner);",
      },
      {
        expected: "Object.fromEntries",
        source: "const { fromEntries: build } = Object; build(entries);",
      },
      { expected: "Object.setPrototypeOf", source: "Object[\"setPrototypeOf\"](inner, null);" },
      { expected: "sort call", source: "fields.sort();" },
      { expected: "sort call", source: "const sorter = fields[\"sort\"]; sorter();" },
      {
        expected: "sort call",
        source: 'const method = "sort"; fields[method]();',
      },
      { expected: "JSON.parse", source: "const output = JSON.parse(text);" },
      {
        expected: "JSON.parse",
        source: 'const decode = JSON["pa" + "rse"]; decode(text);',
      },
      {
        expected: "JSON.parse",
        source: "const decode = JSON.parse.bind(JSON); decode(text);",
      },
      {
        expected: "JSON.parse",
        source: "JSON.parse.bind(JSON)(text);",
      },
      {
        expected: "JSON.parse",
        source: "const bind = JSON.parse.bind; const decode = bind(JSON); decode(text);",
      },
      {
        expected: "JSON.parse",
        source: "const invoke = JSON.parse.call; invoke(JSON, text);",
      },
      {
        expected: "JSON.parse",
        source: 'const invoke = JSON["parse"]["apply"]; invoke(JSON, [text]);',
      },
      { expected: "JSON.parse", source: "JSON.parse.call(JSON, text);" },
      { expected: "JSON.parse", source: "JSON.parse.apply(JSON, [text]);" },
      {
        expected: "JSON.parse",
        source: "const J = JSON; const decode = J[\"parse\"]; decode(text);",
      },
      {
        expected: "JSON.parse",
        source: 'const first = "parse"; const method = first; JSON[method](text);',
      },
      {
        expected: "JSON.parse",
        source: 'const method = "parse"; const { [method]: decode } = JSON; decode(text);',
      },
      { expected: "JSON.rawJSON", source: "const output = JSON[\"rawJSON\"](text);" },
      {
        expected: "JSON.rawJSON",
        source: "const invoke = JSON.rawJSON.call; invoke(JSON, text);",
      },
      { expected: "structuredClone", source: "const output = structuredClone(inner);" },
      { expected: "delete expression", source: "delete inner.message;" },
      { expected: "unary numeric coercion", source: "const output = +amount;" },
      { expected: "Number()", source: "const output = Number(amount);" },
      { expected: "String()", source: "const output = String(amount);" },
      { expected: "parseFloat()", source: "const output = parseFloat(amount);" },
      { expected: "parseInt()", source: "const output = parseInt(amount);" },
      { expected: "Date construction", source: "const output = new Date();" },
      { expected: "Date call", source: "const output = Date[\"now\"]();" },
      { expected: "direct BigNumber construction", source: "const output = new BigNumber(amount);" },
      { expected: ".normalize()", source: "const output = message.normalize();" },
      { expected: ".trim()", source: "const output = message[\"trim\"]();" },
      {
        expected: ".trim()",
        source: 'const method = "trim"; const output = message[method]();',
      },
      { expected: ".toLocaleLowerCase()", source: "message.toLocaleLowerCase();" },
      { expected: ".replace()", source: "message.replace(/a/g, \"b\");" },
      { expected: "numeric formatter .toFixed()", source: "amount.toFixed();" },
      { expected: "numeric formatter .toExponential()", source: "amount.toExponential();" },
      { expected: "numeric formatter .toPrecision()", source: "amount.toPrecision();" },
      { expected: "numeric formatter .toLocaleString()", source: "amount.toLocaleString();" },
      { expected: "numeric formatter .toString()", source: "amount.toString();" },
      { expected: "schema-transformed output .parse()", source: "schema.parse(input);" },
      { expected: "schema-transformed output .safeParse()", source: "schema.safeParse(input);" },
      { expected: "schema-transformed output .transform()", source: "schema.transform(mapper);" },
      {
        expected: "JSON.stringify replacer or spacing",
        source: "JSON.stringify(inner, null, 2);",
      },
      { expected: "unproven JSON.stringify call", source: "JSON.stringify(rebuiltInner);" },
      {
        expected: "unproven JSON.stringify call",
        source: "const encode = JSON[\"stringify\"]; encode(rebuiltInner);",
      },
      {
        expected: "unproven JSON.stringify call",
        source: "const encode = JSON.stringify.bind(JSON); encode(rebuiltInner);",
      },
      {
        expected: "unproven JSON.stringify call",
        source:
          "function buildSplitChainInnerV2() { const inner = rebuiltInner; JSON.stringify(inner); }",
      },
      {
        expected: "unproven JSON.stringify call",
        source:
          'const method = "stringify"; function buildSplitChainInnerV2() { const inner = rebuiltInner; JSON[method](inner); }',
      },
      { expected: "generic public object serializer call", source: "serializeInner(inner);" },
      {
        expected: "generic public object serializer",
        source: "export function serializeAnything(value: object) { return value; }",
      },
      {
        expected: "permissive Record<string, unknown>",
        source: "type ForeignInner = Record<string, unknown>;",
      },
    ];

    for (const mutation of mutations) {
      expect(
        analyzeTransactionSafety(TRANSACTION_FILE, mutationSource(mutation.source)),
        mutation.source,
      ).toContain(`${TRANSACTION_FILE}: ${mutation.expected}`);
    }
  });

  it("rejects stable/canonical JSON imports but ignores comments and string literals", () => {
    for (const moduleName of [
      "json-stable-stringify",
      "fast-json-stable-stringify",
      "canonical-json",
    ]) {
      const source = mutationSource(`import encode from "${moduleName}"; void encode;`);
      expect(analyzeTransactionSafety(TRANSACTION_FILE, source)).toContain(
        `${TRANSACTION_FILE}: stable or canonical JSON library`,
      );
    }

    const harmless = mutationSource(`
      // JSON.parse(inner); Object.assign({}, inner); message.trim();
      // inner["rogue"] = true; Object.defineProperty(inner, "rogue", descriptor);
      const documentation = "JSON.stringify(inner, null, 2), JSON[pa + rse], Reflect.set, and stable-json are forbidden";
      const harmlessMethod = "slice";
      const excerpt = documentation[harmlessMethod](0, 4);
      const safe = Object.create(null) as { message?: string; signer_steps: number };
      const safeAlias = safe;
      safeAlias.message = "changed";
      safeAlias["signer_steps"]++;
      void documentation;
      void excerpt;
      void safe;
    `);
    expect(analyzeTransactionSafety(TRANSACTION_FILE, harmless)).toEqual([]);
  });

  it("exposes constructors only and no parser, rehydrator, signer, or generic serializer", () => {
    expect(protocolApi).toHaveProperty("buildSplitChainInnerV2", expect.any(Function));
    expect(protocolApi).toHaveProperty("buildSplitChainPartialV2", expect.any(Function));
    expect(protocolApi).toHaveProperty(
      "buildSettledSplitChainTransactionV2",
      expect.any(Function),
    );
    for (const forbidden of [
      "issueCoherentWalletBaselineV2ForVerifiedHead",
      "parseSplitChainInnerV2",
      "rehydrateSplitChainInnerV2",
      "signSplitChainTransactionV2",
      "serializeSplitChainObject",
    ]) {
      expect(protocolApi).not.toHaveProperty(forbidden);
      expect(nodeCoreApi).not.toHaveProperty(forbidden);
    }
  });
});

// ---------------------------------------------------------------------------
// suite serializer — exemption integrity.
//
// Each ruled exemption above removes always-on coverage from a money-path file, so each one has to
// pay for itself here: it must be proven to fire exactly as often as it was ruled to (so a grant
// cannot quietly widen or die), and near-miss sources that differ only in the property that made the
// construct safe must still be flagged (so the grant cannot be stretched by a future author).
// ---------------------------------------------------------------------------

const SUITE_PREFIX = "suite/";

function suiteSource(source: string): ts.SourceFile {
  return ts.createSourceFile(
    "suite-exemption.mutation.ts",
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
}

describe("suite-tuple serializer exemption integrity", () => {
  it("leaves the suite serializer free of unruled construction surfaces", () => {
    // Scoped twin of the whole-tree gate, retained as a localized failure signal: when this fails,
    // the defect is provably own rather than some unrelated protocol file's. The three
    // reconcile/ violations that originally motivated the scoping (reconcile/move.ts spread x2,
    // reconcile/types.ts JSON.stringify) no longer exist — move.ts was rewritten to push-based
    // construction and types.ts's assertUnreachable earned a ruled exemption, both on main. The
    // whole-tree assertion above therefore now holds at zero violations, and this twin is a strict
    // subset of it: it masks nothing.
    const suiteViolations = productionSources
      .filter(({ relativePath }) => relativePath.startsWith(SUITE_PREFIX))
      .flatMap(({ relativePath, sourceFile }) =>
        analyzeReviewedTransactionSafety(relativePath, sourceFile, true),
      );
    expect(suiteViolations).toEqual([]);
  });

  it("keeps the whole suite serializer inside the scanned production set", () => {
    // Non-vacuity for the exemptions themselves: they can only be judged safe if the files carrying
    // them are actually being scanned. A rename or a move that dropped one out of the scan would
    // otherwise read as a clean pass.
    const scannedPaths = productionSources.map(({ relativePath }) => relativePath);
    for (const suiteFile of [
      SUITE_SERIALIZE_FILE,
      SUITE_BUILDERS_FILE,
      SUITE_PARSERS_FILE,
      SUITE_REGISTRY_FILE,
      SUITE_ENCODERS_FILE,
      SUITE_MANIFEST_FILE,
    ]) {
      expect(scannedPaths).toContain(suiteFile);
    }
  });

  it("pins the canonical entrypoint name to the manifest datum", () => {
    // The `canonical serializer call` and `canonical serializer declaration` exemptions are keyed to
    // this identifier. Renaming the entrypoint without updating manifest.ts's datum — or pointing the
    // datum at some other symbol — must break the gate, never silently re-key the exemption.
    expect(protocolApi).toHaveProperty(
      "SUITE_SERIALIZER_ENTRYPOINT",
      SUITE_SERIALIZER_ENTRYPOINT,
    );
    expect(protocolApi).toHaveProperty("EXTERNAL_SUITE_SERIALIZATION_PROHIBITED", true);
    expect(protocolApi).toHaveProperty(SUITE_SERIALIZER_ENTRYPOINT, expect.any(Function));
  });

  it("fires every ruled exemption exactly the number of times it was ruled for", () => {
    const ledger: SuiteExemptionLedger = new Map();
    for (const { relativePath, sourceFile } of productionSources) {
      analyzeReviewedTransactionSafety(relativePath, sourceFile, true, ledger);
    }

    // Exact counts, not lower bounds. A new builder, a new parser, or a new permissive Record in an
    // already-exempt file changes a count and forces a reviewed edit here — which is the point: the
    // surface cannot grow silently under cover of an existing grant.
    expect(Object.fromEntries([...ledger].sort())).toEqual({
      "boundary input Record": 4,
      "builder values spread": 10,
      "canonical serializer call": 11,
      "canonical serializer declaration": 1,
      "canonical suite preimage stringify": 1,
      "inner-shape boundary input Record": 3,
      "inner-shape key-sequence spread": 3,
      "label code-point spread": 1,
      "manifest census builder": 1,
      "parser result spread": 10,
      "registry field-sequence spread": 2,
      "signed-window Date.parse": 2,
      "timestamp validation Date": 1,
      // One, not three: routed all three envelope splices through the single guarded
      // `jsonEscapeString` helper, so the file now holds exactly one `JSON.stringify` call.
      "transfer-code string escape": 1,
      "wire JSON.parse": 1,
    });

    // The canonical serializer is singular by contract. A second declaration anywhere in
    // the scan would take the same exemption, so the count is pinned at one.
    expect(ledger.get("canonical serializer declaration")).toBe(1);
    expect(ledger.get("canonical suite preimage stringify")).toBe(1);
  });

  it("still flags near-miss constructs that differ only in what made the original safe", () => {
    const nearMisses: ReadonlyArray<{
      readonly name: string;
      readonly relativePath: string;
      readonly source: string;
      readonly expected: readonly string[];
    }> = [
      // --- E1 builder values spread ------------------------------------------------------------
      {
        name: "builder literal carrying a fourth property",
        relativePath: SUITE_BUILDERS_FILE,
        source:
          'serializeSuiteTuple("zp-x-v1", { purpose: "zp-x-v1", canonical_version: 1, ...input, extra: 1 });',
        expected: ["spread syntax"],
      },
      {
        name: "builder purpose literal disagreeing with the dispatch literal",
        relativePath: SUITE_BUILDERS_FILE,
        source:
          'serializeSuiteTuple("zp-x-v1", { purpose: "zp-other-v1", canonical_version: 1, ...input });',
        expected: ["spread syntax"],
      },
      {
        name: "builder literal with header keys reordered",
        relativePath: SUITE_BUILDERS_FILE,
        source:
          'serializeSuiteTuple("zp-x-v1", { canonical_version: 1, purpose: "zp-x-v1", ...input });',
        expected: ["spread syntax"],
      },
      {
        name: "builder spread routed through a non-canonical serializer",
        relativePath: SUITE_BUILDERS_FILE,
        source:
          'serializeTupleFast("zp-x-v1", { purpose: "zp-x-v1", canonical_version: 1, ...input });',
        expected: ["generic public object serializer call", "spread syntax"],
      },
      {
        name: "builder declaring a non-1 canonical_version",
        relativePath: SUITE_BUILDERS_FILE,
        source:
          'serializeSuiteTuple("zp-x-v1", { purpose: "zp-x-v1", canonical_version: 2, ...input });',
        expected: ["spread syntax"],
      },
      // --- E2 parser result spread -------------------------------------------------------------
      {
        name: "parser spreading a value that never cleared the fence",
        relativePath: SUITE_PARSERS_FILE,
        source:
          "function parseX(s: string) { const result = untrusted(s); return { ...result, payload: result.payload as unknown as P }; }",
        expected: ["spread syntax"],
      },
      {
        name: "parser return literal carrying an extra property",
        relativePath: SUITE_PARSERS_FILE,
        source:
          "function parseX(s: string) { const result = parseSuitePurpose('p', s); return { ...result, payload: result.payload as unknown as P, extra: 1 }; }",
        expected: ["spread syntax"],
      },
      // --- E3 registry field-sequence spread ----------------------------------------------------
      {
        name: "registry field sequence gaining a third segment",
        relativePath: SUITE_REGISTRY_FILE,
        source:
          "function spec(purpose: string, rest: readonly F[]) { return { fields: [...header(purpose), ...rest, ...extra] }; }",
        expected: ["spread syntax", "spread syntax", "spread syntax"],
      },
      {
        name: "registry spread outside the fields sequence",
        relativePath: SUITE_REGISTRY_FILE,
        source:
          "function spec(purpose: string, rest: readonly F[]) { return { other: [...header(purpose), ...rest] }; }",
        expected: ["spread syntax", "spread syntax"],
      },
      // --- E4 label code-point spread -----------------------------------------------------------
      {
        name: "code-point spread outside encodeLabel",
        relativePath: SUITE_ENCODERS_FILE,
        source: "export const encodeAnchor = (value) => { const scalars = [...text]; };",
        expected: ["spread syntax"],
      },
      // --- E9 timestamp validation Date ---------------------------------------------------------
      {
        name: "zero-argument clock read inside encodeCanonicalTimestamp",
        relativePath: SUITE_ENCODERS_FILE,
        source: "export const encodeCanonicalTimestamp = (value) => { const now = new Date(); };",
        expected: ["Date construction"],
      },
      {
        name: "Date construction in a sibling encoder",
        relativePath: SUITE_ENCODERS_FILE,
        source: "export const encodeAnchor = (value) => { const parsed = new Date(text); };",
        expected: ["Date construction"],
      },
      // --- E10 signed-window Date.parse ---------------------------------------------------------
      {
        name: "clock read inside enforceSignedWindow",
        relativePath: SUITE_SERIALIZE_FILE,
        source: "function enforceSignedWindow(s, payload) { const now = Date.now(); }",
        expected: ["Date call"],
      },
      {
        name: "Date.parse outside enforceSignedWindow",
        relativePath: SUITE_SERIALIZE_FILE,
        source: "function other(payload) { const at = Date.parse(payload.issued_at); }",
        expected: ["Date call", "schema-transformed output .parse()"],
      },
      // --- E11 wire JSON.parse ------------------------------------------------------------------
      {
        name: "parseSuitePurpose with the byte-equality fence removed",
        relativePath: SUITE_PARSERS_FILE,
        source:
          "function parseSuitePurpose(purpose: string, source: string) { const parsed = JSON.parse(source); const rebuilt = serializeSuiteTuple(purpose, parsed); return rebuilt; }",
        expected: ["JSON.parse", "schema-transformed output .parse()"],
      },
      {
        name: "parseSuitePurpose that compares bytes but never throws",
        relativePath: SUITE_PARSERS_FILE,
        source:
          "function parseSuitePurpose(purpose: string, source: string) { const parsed = JSON.parse(source); const rebuilt = serializeSuiteTuple(purpose, parsed); const ok = Buffer.from(rebuilt.preimageBytes).equals(Buffer.from(source)); return ok ? rebuilt : rebuilt; }",
        expected: ["JSON.parse", "schema-transformed output .parse()"],
      },
      {
        name: "JSON.parse in a sibling parser function",
        relativePath: SUITE_PARSERS_FILE,
        source: "function decodeOther(source: string) { const parsed = JSON.parse(source); }",
        expected: ["JSON.parse", "schema-transformed output .parse()"],
      },
      // --- E12 canonical suite preimage stringify -----------------------------------------------
      {
        name: "canonical stringify fed from a parse instead of buildOrderedPayload",
        relativePath: SUITE_SERIALIZE_FILE,
        source:
          "export function serializeSuiteTuple(purpose: string, values) { const payload = JSON.parse(values); return `${purpose}\\n${JSON.stringify(payload)}`; }",
        expected: [
          "JSON.parse",
          "schema-transformed output .parse()",
          "unproven JSON.stringify call",
        ],
      },
      {
        name: "canonical stringify fed from a rebound payload",
        relativePath: SUITE_SERIALIZE_FILE,
        source:
          "export function serializeSuiteTuple(purpose: string, values) { const payload = buildOrderedPayload(s, values); const payload2 = payload; return `${purpose}\\n${JSON.stringify(payload2)}`; }",
        expected: ["unproven JSON.stringify call"],
      },
      {
        name: "canonical stringify moved outside serializeSuiteTuple",
        relativePath: SUITE_SERIALIZE_FILE,
        source:
          "function helper(purpose: string, values) { const payload = buildOrderedPayload(s, values); return `${purpose}\\n${JSON.stringify(payload)}`; }",
        expected: ["unproven JSON.stringify call"],
      },
      {
        name: "stringify with a replacer inside the canonical serializer",
        relativePath: SUITE_SERIALIZE_FILE,
        source:
          "export function serializeSuiteTuple(purpose: string, values) { const payload = buildOrderedPayload(s, values); return JSON.stringify(payload, null, 2); }",
        expected: ["JSON.stringify replacer or spacing"],
      },
      // --- E5/E6/E7 serializer identity ----------------------------------------------------------
      {
        name: "a second serializer-shaped export in the canonical module",
        relativePath: SUITE_SERIALIZE_FILE,
        source: "export function serializeSuiteTupleFast(purpose: string, values) { return ''; }",
        expected: ["generic public object serializer"],
      },
      {
        name: "a serializer-shaped export in the manifest module",
        relativePath: SUITE_MANIFEST_FILE,
        source: "export function serializeCensus() { return ''; }",
        expected: ["generic public object serializer"],
      },
      {
        name: "an ad-hoc serializer call inside the suite",
        relativePath: SUITE_BUILDERS_FILE,
        source: "const bytes = canonicalizeTuple(values);",
        expected: ["generic public object serializer call"],
      },
      {
        name: "the canonical entrypoint called from outside the suite",
        relativePath: "reconcile/move.ts",
        source: "const preimage = serializeSuiteTuple('zp-x-v1', values);",
        expected: ["generic public object serializer call"],
      },
      // --- E8 boundary input Record ---------------------------------------------------------------
      {
        name: "permissive Record in a non-boundary encoder helper",
        relativePath: SUITE_ENCODERS_FILE,
        source: "function emit(object: Record<string, unknown>) { return object; }",
        expected: ["permissive Record<string, unknown>"],
      },
      {
        name: "permissive Record outside the SuiteTupleValues alias",
        relativePath: SUITE_SERIALIZE_FILE,
        source: "export type SuitePayload = Readonly<Record<string, unknown>>;",
        expected: ["permissive Record<string, unknown>"],
      },
      // --- inner-digest stringify: the declaration census that guards it --------------------------
      //
      // `isReviewedInnerDigestStringify` grants only while `inner` is `computeInnerDigest`'s own
      // parameter AND nothing inside the body binds that name. That grant records nothing in the
      // exemption ledger, so a shadow which REPLACES the ruled site is invisible to the exact-count
      // guard — `localDeclarations` is the only thing standing between a substituted object and a
      // hashed preimage. Every value-binding form must therefore withdraw it, and the last entry
      // proves the fail-closed default for forms nobody enumerated. The control comes first so the
      // list cannot pass vacuously.
      {
        name: "the unmutated inner-digest helper (control — must stay granted)",
        relativePath: INNER_DIGEST_FILE,
        source: [
          "export function computeInnerDigest(inner: SplitChainInnerV2): string {",
          "  return JSON.stringify(inner);",
          "}",
        ].join("\n"),
        expected: [],
      },
      ...(
        [
          ["a plain const", 'const inner = { zeta: "z", alpha: "a" };'],
          ["an object-pattern", 'const { inner } = { inner: { zeta: "z" } };'],
          ["a renamed object-pattern", 'const { held: inner } = { held: { zeta: "z" } };'],
          ["an array-pattern", 'const [inner] = [{ zeta: "z", alpha: "a" }];'],
          ["a nested object-pattern", 'const { outer: { inner } } = { outer: { inner: {} } };'],
          ["a defaulted object-pattern", 'const { inner = { zeta: "z" } } = {};'],
          ["an object rest-pattern", 'const { ...inner } = { zeta: "z", alpha: "a" };'],
          ["a function declaration", 'function inner() { return { zeta: "z" }; }'],
          ["a class declaration", "class inner {}"],
          // The form round 3 of missed: it compiles, and on this grant there is no ledger
          // entry to betray it because it replaces the ruled site rather than adding one.
          ["an enum declaration", 'enum inner { zulu = "z", alpha = "a" }'],
          ["a namespace declaration", 'namespace inner { export const zulu = "z"; }'],
          ["a for-of binding", 'for (const inner of [{ zeta: "z" }]) { void inner; }'],
          ["a catch binding", "try { void 0; } catch (inner) { void inner; }"],
          // Fail-closed backstop. `with` binds an object's own properties into scope under no
          // declaration the census could resolve, so it is absent from RECOGNISED_STATEMENT_KINDS
          // and withdraws the grant wholesale. Every statement kind TypeScript adds after this file
          // was written lands in the same branch: an unhandled binding form is a red test, never a
          // silent grant.
          ["an unclassifiable `with` scope", 'with ({ inner: { zeta: "z" } }) { void 0; }'],
        ] as const
      ).map(([label, declaration]) => ({
        name: `${label} shadowing the reviewed inner-digest parameter`,
        relativePath: INNER_DIGEST_FILE,
        source: [
          "export function computeInnerDigest(inner: SplitChainInnerV2): string {",
          "  {",
          `    ${declaration}`,
          "  }",
          "  return JSON.stringify(inner);",
          "}",
        ].join("\n"),
        expected: ["unproven JSON.stringify call"],
      })),
      // --- E13 transfer-code string escape --------------------------------------------------------
      //
      // The grant is now keyed to the guarded `jsonEscapeString` helper, so the control that proves
      // it is non-vacuous is the live file scan plus the exact-count ledger (one site). These prove
      // the two ways it could be stretched: escaping something the helper was not reviewed for, and
      // mutating the helper into a shape whose runtime guard no longer holds.
      {
        // The byte-exact-signing hazard: the persisted inner preimage is spliced verbatim and must never
        // be re-escaped. It is a `string` parameter of the assembler, but the assembler is not the
        // guarded helper, so no grant reaches it.
        name: "stringifying the verbatim persisted inner preimage",
        relativePath: TRANSFER_CODE_FILE,
        source:
          "export function buildSendTransferCodeText(innerPreimageText: string, step1Signature: string) { return JSON.stringify(innerPreimageText); }",
        expected: ["unproven JSON.stringify call"],
      },
      {
        name: "stringifying an object that merely carries the escaped value",
        relativePath: TRANSFER_CODE_FILE,
        source:
          "export function buildSendTransferCodeText(step1Signature: string) { return JSON.stringify({ step1Signature }); }",
        expected: ["unproven JSON.stringify call"],
      },
      {
        name: "the escaped value stringified outside the guarded helper",
        relativePath: TRANSFER_CODE_FILE,
        source:
          "export function reEncode(step1Signature: string) { return JSON.stringify(step1Signature); }",
        expected: ["unproven JSON.stringify call"],
      },
      // The shadow family that defeated rounds 1–3. Each REPLACES the ruled site rather than adding
      // a fourth, so the exact-count ledger cannot see it, and each substitutes an object whose
      // source-order keys would be spliced into the `step_1_signature` position of the wire JSON
      // that `hashTransferCodeText` hashes (Byte-exact). They no longer depend on a shadow census
      // seeing the binding form: the stringify is not inside `jsonEscapeString`, so it trips
      // whatever declared the name — including `enum`, which round 3 missed.
      ...(
        [
          ["a block-scoped const", 'const step1Signature = { zeta: "z", alpha: "a" };'],
          ["an object-pattern", 'const { step1Signature } = { step1Signature: { zeta: "z" } };'],
          ["a renamed object-pattern", 'const { sig: step1Signature } = { sig: { zeta: "z" } };'],
          ["an array-pattern", 'const [step1Signature] = [{ zeta: "z", alpha: "a" }];'],
          [
            "a nested object-pattern",
            'const { outer: { step1Signature } } = { outer: { step1Signature: {} } };',
          ],
          ["a defaulted object-pattern", 'const { step1Signature = { zeta: "z" } } = {};'],
          ["an object rest-pattern", 'const { ...step1Signature } = { zeta: "z", alpha: "a" };'],
          ["a function declaration", 'function step1Signature() { return "z"; }'],
          ["a class declaration", "class step1Signature {}"],
          ["an enum declaration", 'enum step1Signature { zulu = "z", alpha = "a" }'],
        ] as const
      ).map(([label, declaration]) => ({
        name: `${label} substituted for the reviewed string parameter`,
        relativePath: TRANSFER_CODE_FILE,
        source: [
          "export function buildSendTransferCodeText(innerPreimageText: string, step1Signature: string) {",
          "  let partialJson: string;",
          "  {",
          `    ${declaration}`,
          "    partialJson =",
          "      '{\"inner\":' + innerPreimageText + ',\"step_1_signature\":' +",
          '      JSON.stringify(step1Signature) + "}";',
          "  }",
          "  return partialJson;",
          "}",
        ].join("\n"),
        expected: ["unproven JSON.stringify call"],
      })),
      // One mutation per clause of the guarded-helper shape. Anything that lets a non-string reach
      // `JSON.stringify`, or lets the helper escape a value other than its own guarded parameter,
      // must withdraw the grant — the runtime guard is the whole reason the grant exists.
      ...(
        [
          ["the guard removed", "function jsonEscapeString(value: string): string {", "  return JSON.stringify(value);"],
          [
            "the guard inverted to reject only strings",
            "function jsonEscapeString(value: string): string {",
            '  if (typeof value === "string") { throw new TypeError("no"); }\n  return JSON.stringify(value);',
          ],
          [
            "the guard testing a type other than string",
            "function jsonEscapeString(value: string): string {",
            '  if (typeof value !== "object") { throw new TypeError("no"); }\n  return JSON.stringify(value);',
          ],
          [
            "a guard that recovers instead of throwing",
            "function jsonEscapeString(value: string): string {",
            '  if (typeof value !== "string") { value = ""; }\n  return JSON.stringify(value);',
          ],
          [
            "the guard inspecting a different binding",
            "function jsonEscapeString(value: string): string {",
            '  if (typeof SEND_TRANSFER_CODE_TYPE !== "string") { throw new TypeError("no"); }\n  return JSON.stringify(value);',
          ],
          [
            "a parameter type widened past string",
            "function jsonEscapeString(value: unknown): string {",
            '  if (typeof value !== "string") { throw new TypeError("no"); }\n  return JSON.stringify(value);',
          ],
          [
            "an optional parameter",
            "function jsonEscapeString(value?: string): string {",
            '  if (typeof value !== "string") { throw new TypeError("no"); }\n  return JSON.stringify(value);',
          ],
          [
            "a second parameter",
            "function jsonEscapeString(value: string, replacer: unknown): string {",
            '  if (typeof value !== "string") { throw new TypeError("no"); }\n  return JSON.stringify(value);',
          ],
          [
            "a statement inserted between the guard and the return",
            "function jsonEscapeString(value: string): string {",
            '  if (typeof value !== "string") { throw new TypeError("no"); }\n  const escaped = JSON.stringify(value);\n  return escaped;',
          ],
          [
            "the helper escaping something other than its guarded parameter",
            "function jsonEscapeString(value: string): string {",
            '  if (typeof value !== "string") { throw new TypeError("no"); }\n  return JSON.stringify(SEND_TRANSFER_CODE_TYPE);',
          ],
          [
            "the helper renamed",
            "function escapeJsonString(value: string): string {",
            '  if (typeof value !== "string") { throw new TypeError("no"); }\n  return JSON.stringify(value);',
          ],
        ] as const
      ).map(([label, signature, body]) => ({
        name: `${label} in the transfer-code escape helper`,
        relativePath: TRANSFER_CODE_FILE,
        source: [signature, body, "}"].join("\n"),
        expected: ["unproven JSON.stringify call"],
      })),
      {
        name: "the guarded helper shape lifted into another production file",
        relativePath: "send-baseline.ts",
        source: [
          "function jsonEscapeString(value: string): string {",
          '  if (typeof value !== "string") { throw new TypeError("no"); }',
          "  return JSON.stringify(value);",
          "}",
        ].join("\n"),
        expected: ["unproven JSON.stringify call"],
      },
      // --- E14 inner-shape boundary input Record --------------------------------------------------
      {
        name: "permissive Record in a non-boundary inner-shape helper",
        relativePath: INNER_SHAPE_FILE,
        source: "function emit(object: Record<string, unknown>) { return object; }",
        expected: ["permissive Record<string, unknown>"],
      },
      {
        name: "permissive Record outside the SplitChainInnerParseInput alias",
        relativePath: INNER_SHAPE_FILE,
        source: "export type SplitChainInnerOutput = Readonly<Record<string, unknown>>;",
        expected: ["permissive Record<string, unknown>"],
      },
      // --- E15 inner-shape key-sequence spread ----------------------------------------------------
      {
        // A non-leading spread moves the protocol foundation required prefix, which is exactly the drift the
        // spread rule exists to catch.
        name: "required-field tuple spread at a non-leading position",
        relativePath: INNER_SHAPE_FILE,
        source:
          'const PERMITTED_INNER_KEY_SEQUENCES = [["message", ...SPLIT_CHAIN_INNER_REQUIRED_FIELDS]];',
        expected: ["spread syntax"],
      },
      {
        name: "a different tuple spread into the permitted sequences",
        relativePath: INNER_SHAPE_FILE,
        source:
          'const PERMITTED_INNER_KEY_SEQUENCES = [[...SPLIT_CHAIN_INNER_OPTIONAL_FIELDS, "message"]];',
        expected: ["spread syntax"],
      },
      {
        name: "the required-field tuple spread into some other declaration",
        relativePath: INNER_SHAPE_FILE,
        source: 'const OTHER_SEQUENCES = [[...SPLIT_CHAIN_INNER_REQUIRED_FIELDS, "message"]];',
        expected: ["spread syntax"],
      },
      {
        name: "the permitted-sequence shape lifted into another production file",
        relativePath: "send-baseline.ts",
        source:
          'const PERMITTED_INNER_KEY_SEQUENCES = [[...SPLIT_CHAIN_INNER_REQUIRED_FIELDS, "message"]];',
        expected: ["spread syntax"],
      },
    ];

    for (const nearMiss of nearMisses) {
      expect(
        analyzeTransactionSafety(nearMiss.relativePath, suiteSource(nearMiss.source)),
        nearMiss.name,
      ).toEqual(nearMiss.expected.map((rule) => `${nearMiss.relativePath}: ${rule}`));
    }
  });

  it("grants no exemption to a near-miss construct", () => {
    // The near-miss suite above proves the violations still surface; this proves the exemption
    // ledger stays empty for them, so a near miss can never be recorded as a reviewed grant.
    const ledger: SuiteExemptionLedger = new Map();
    analyzeTransactionSafety(
      SUITE_SERIALIZE_FILE,
      suiteSource(
        "export function serializeSuiteTuple(purpose: string, values) { const payload = JSON.parse(values); return JSON.stringify(payload); }",
      ),
      false,
      ledger,
    );
    expect(ledger.get("canonical suite preimage stringify")).toBeUndefined();
    expect(ledger.get("wire JSON.parse")).toBeUndefined();

    // Same proof for the grants: a near miss must surface as a violation AND leave the
    // ledger untouched, so it can never be laundered into a reviewed grant.
    const protocol_transactionLedger: SuiteExemptionLedger = new Map();
    analyzeTransactionSafety(
      TRANSFER_CODE_FILE,
      suiteSource(
        "export function buildSendTransferCodeText(innerPreimageText: string) { return JSON.stringify(innerPreimageText); }",
      ),
      false,
      protocol_transactionLedger,
    );
    analyzeTransactionSafety(
      INNER_SHAPE_FILE,
      suiteSource(
        'export type SplitChainInnerOutput = Readonly<Record<string, unknown>>;\nconst OTHER_SEQUENCES = [[...SPLIT_CHAIN_INNER_REQUIRED_FIELDS, "message"]];',
      ),
      false,
      protocol_transactionLedger,
    );
    expect(protocol_transactionLedger.get("transfer-code string escape")).toBeUndefined();
    expect(protocol_transactionLedger.get("inner-shape boundary input Record")).toBeUndefined();
    expect(protocol_transactionLedger.get("inner-shape key-sequence spread")).toBeUndefined();
  });
});
