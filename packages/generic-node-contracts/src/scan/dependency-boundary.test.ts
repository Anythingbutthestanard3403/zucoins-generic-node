import {
  existsSync,
  globSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

import { EXECUTION_TIMEOUTS } from "../testkit/executionPolicy.ts";
import { readIfPresent, readPresentFiles } from "../testkit/realTreeScan.ts";
import {
  isIdentifierNamed,
  moduleSpecifierText,
  parseTsSource,
  stringLiteralText,
  unwrapExpression,
  visitEveryNode,
} from "./ast-source.ts";

/**
 * CONTRACT_FREEZE line (../../CONTRACT.md "Import and dependency boundary (CONTRACT_FREEZE)"):
 * legal artifacts are const manifests, pure stateless verifier fns, tests/fixtures, scanners,
 * and type decls. Forbidden: network/DB/durable-state/workers/private keys/main() seams. This
 * test enforces the import side of that boundary for every module in this package.
 */
const FORBIDDEN_IMPORT_SPECIFIERS = [
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:worker_threads",
  "worker_threads",
  "node:child_process",
  "child_process",
  "undici",
  "pg",
  "postgres",
] as const;

/**
 *  — laundering seams that hand a runtime module loader without a static
 * network/DB import. `node:module`/`module` enable `createRequire`; `node:vm`/`vm`
 * are code-execution seams. Allowed only under tier-two dirs (testkit uses
 * createRequire to load libsodium-wrappers; scan/scripts are harnesses).
 * Kept OFF the unconditional FORBIDDEN list so testkit stays legal.
 */
const LAUNDERING_SEAM_SPECIFIERS = ["node:module", "module", "node:vm", "vm"] as const;

const CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS = ["node:crypto", "crypto", "node:fs", "fs"] as const;

const TIER_TWO_PERMITTED_DIR_SEGMENTS = ["testkit", "scan", "scripts"] as const;

/** Packages that must never appear in this package's dependency manifest (any section). */
const DENYLISTED_MANIFEST_PACKAGES = ["pg", "postgres", "undici"] as const;

const isUnderTierTwoPermittedDir = (file: string): boolean =>
  TIER_TWO_PERMITTED_DIR_SEGMENTS.some((segment) => file.includes(`${join("src", segment)}/`));

const isContractOrManifestModule = (file: string): boolean =>
  (basename(file) === "manifest.ts" || file.endsWith(".contract.ts")) &&
  !file.endsWith(".test.ts") &&
  !isUnderTierTwoPermittedDir(file);

const FORBIDDEN_ENV_NAMES = [
  "SPLITCHAIN_GATEWAY_URLS",
  "VAULT_MASTER_KEY",
  "DATABASE_URL",
  "PGHOST",
  "PGPORT",
  "PGUSER",
  "PGPASSWORD",
  "PGDATABASE",
] as const;

/**
 *  — the gate asks a lexical boundary question of TypeScript source, so it PARSES.
 * Pre-change detectors ran regular expressions over raw source text and therefore could not
 * tell code from a comment or a string literal (the same defect class named on the
 * OperationKind drift gate). POST-CHANGE INVARIANT: no regular expression in this file is
 * applied to TypeScript source text. JSON package manifests stay byte-matched as before.
 */

/** True when `node` is the identifier `process` after unwrapping parens/assertions. */
const isProcessExpr = (node: ts.Expression): boolean =>
  isIdentifierNamed(unwrapExpression(node), "process");

const isModuleIdentExpr = (node: ts.Expression): boolean =>
  isIdentifierNamed(unwrapExpression(node), "Module");

const memberName = (node: ts.Expression): string | undefined => {
  const expr = unwrapExpression(node);
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text;
  }
  if (ts.isElementAccessExpression(expr)) {
    return stringLiteralText(expr.argumentExpression);
  }
  return undefined;
};

const memberRoot = (node: ts.Expression): ts.Expression | undefined => {
  const expr = unwrapExpression(node);
  if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
    return unwrapExpression(expr.expression);
  }
  return undefined;
};

/** True when an object binding pattern names `name` (plain or string-named element). */
const bindingPatternNames = (pattern: ts.ObjectBindingPattern, name: string): boolean =>
  pattern.elements.some((element) => {
    if (element.dotDotDotToken !== undefined) return false;
    if (element.propertyName !== undefined) {
      if (ts.isIdentifier(element.propertyName)) return element.propertyName.text === name;
      if (ts.isStringLiteral(element.propertyName) || ts.isNoSubstitutionTemplateLiteral(element.propertyName)) {
        return element.propertyName.text === name;
      }
      return false;
    }
    return ts.isIdentifier(element.name) && element.name.text === name;
  });

/**
 * Static/dynamic/require/getBuiltinModule acquisition of `specifier` as a controlled module
 * edge — ImportDeclaration / ExportDeclaration / ImportEquals / import()/require()/getBuiltinModule
 * call sites. Prose mentions and string contents that are not module edges stay green.
 */
const importsSpecifierStructurally = (sourceFile: ts.SourceFile, specifier: string): boolean => {
  let found = false;
  visitEveryNode(sourceFile, (node) => {
    if (found) return;
    if (moduleSpecifierText(node) === specifier) {
      found = true;
    }
  });
  return found;
};

/**
 * Whether `text` acquires `specifier` at all: by a structural module edge, or — the fail-closed
 * half — by naming it as a quoted string in a file that also carries a runtime-loader binding in
 * code, however many statements apart. Deliberately broad in the second case: a frozen contract
 * package has no legitimate reason to hold both a loader and a builtin's name.
 *
 *  also treats a call-argument of the forbidden specifier (`load("node:net")`) as
 * acquisition: that is the aliased createRequire form after the loader was renamed off
 * `createRequire`/`import`/`require` tokens. Call site is an Identifier callee so
 * fixture prose methods do not fire.
 */
/** One AST pass: module edges, loader presence, quoted strings, call-arg specs. */
const analyzeAcquisitions = (
  sourceFile: ts.SourceFile,
): {
  readonly imported: ReadonlySet<string>;
  readonly hasLoader: boolean;
  readonly quoted: ReadonlySet<string>;
  readonly callArgs: ReadonlySet<string>;
} => {
  const imported = new Set<string>();
  const quoted = new Set<string>();
  const callArgs = new Set<string>();
  let hasLoader = false;

  visitEveryNode(sourceFile, (node) => {
    const edge = moduleSpecifierText(node);
    if (edge !== undefined) {
      imported.add(edge);
    }

    if (ts.isIdentifier(node) && (node.text === "createRequire" || node.text === "getBuiltinModule")) {
      hasLoader = true;
    }
    if (ts.isCallExpression(node)) {
      const callee = unwrapExpression(node.expression);
      if (
        callee.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(callee) && callee.text === "require")
      ) {
        hasLoader = true;
      }
      if (node.arguments.length >= 1) {
        const arg = stringLiteralText(node.arguments[0]);
        if (arg !== undefined) {
          if (
            ts.isIdentifier(callee) ||
            callee.kind === ts.SyntaxKind.ImportKeyword ||
            (ts.isPropertyAccessExpression(callee) &&
              (callee.name.text === "getBuiltinModule" || callee.name.text === "require"))
          ) {
            callArgs.add(arg);
          }
        }
      }
    }
    const lit = stringLiteralText(node);
    if (lit !== undefined) {
      quoted.add(lit);
    }
  });

  return { imported, hasLoader, quoted, callArgs };
};

const analysisCache = new WeakMap<ts.SourceFile, ReturnType<typeof analyzeAcquisitions>>();

const acquisitionsOf = (
  sourceFile: ts.SourceFile,
): ReturnType<typeof analyzeAcquisitions> => {
  const cached = analysisCache.get(sourceFile);
  if (cached !== undefined) {
    return cached;
  }
  const analysis = analyzeAcquisitions(sourceFile);
  analysisCache.set(sourceFile, analysis);
  return analysis;
};

const acquiresSpecifierFrom = (sourceFile: ts.SourceFile, specifier: string): boolean => {
  const analysis = acquisitionsOf(sourceFile);
  if (analysis.imported.has(specifier)) {
    return true;
  }
  if (analysis.hasLoader && analysis.quoted.has(specifier)) {
    return true;
  }
  return analysis.callArgs.has(specifier);
};

const acquiresSpecifier = (text: string, specifier: string): boolean =>
  acquiresSpecifierFrom(parseTsSource(text), specifier);

/** Static/dynamic import form only — used for laundering-seam list walks that ignore prose. */
const importRegexFor = (specifier: string): { test: (text: string) => boolean } => ({
  test: (text: string): boolean => importsSpecifierStructurally(parseTsSource(text), specifier),
});

const hasCreateRequireCall = (text: string): boolean => {
  let found = false;
  visitEveryNode(parseTsSource(text), (node) => {
    if (found) return;
    if (!ts.isCallExpression(node)) return;
    const callee = unwrapExpression(node.expression);
    if (ts.isIdentifier(callee) && callee.text === "createRequire") {
      found = true;
    }
  });
  return found;
};

const hasInternalLoaderSeam = (text: string): boolean => {
  let found = false;
  visitEveryNode(parseTsSource(text), (node) => {
    if (found) return;
    if (!ts.isPropertyAccessExpression(node) && !ts.isElementAccessExpression(node)) return;
    const name = memberName(node);
    const root = memberRoot(node);
    if (root === undefined) return;
    if (name === "binding" && isProcessExpr(root)) {
      found = true;
      return;
    }
    if (name === "_load" && isModuleIdentExpr(root)) {
      found = true;
    }
  });
  return found;
};

/**
 *  — dynamic `import` / `require` whose argument is not a single string literal.
 * Catches `import(s)`, `import("node:" + "net")`, `import(\`x${y}\`)`. Empty `import()` is ignored.
 */
const hasNonliteralRuntimeLoad = (text: string): boolean => {
  let found = false;
  visitEveryNode(parseTsSource(text), (node) => {
    if (found) return;
    if (!ts.isCallExpression(node)) return;
    const callee = unwrapExpression(node.expression);
    const isImportCall = callee.kind === ts.SyntaxKind.ImportKeyword;
    const isRequire = ts.isIdentifier(callee) && callee.text === "require";
    if (!isImportCall && !isRequire) return;
    if (node.arguments.length === 0) return;
    if (stringLiteralText(node.arguments[0]) === undefined) {
      found = true;
    }
  });
  return found;
};

type LoaderSeamHit = { readonly label: string };

const isModulePackageSpecifier = (spec: string | undefined): boolean =>
  spec === "module" || spec === "node:module";

const isProcessPackageSpecifier = (spec: string | undefined): boolean =>
  spec === "process" || spec === "node:process";

/**
 * Internal loader seams via the syntax tree rather than spanning regexes. Alias forms
 * are resolved by collecting binders first, then testing member access against the alias set —
 * a regex `[\s\S]*?` span cannot do this without going blind on comments/strings in the gap.
 */
const findBannedLoaderSeams = (text: string): LoaderSeamHit[] => {
  const sourceFile = parseTsSource(text);
  const hits: LoaderSeamHit[] = [];
  const processAliases = new Set<string>();
  const processFromImport = new Set<string>();
  const processFromNamespace = new Set<string>();
  const moduleFromImport = new Set<string>();
  const moduleFromNamespace = new Set<string>();
  const moduleFromRequire = new Set<string>();

  visitEveryNode(sourceFile, (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer !== undefined) {
      const init = unwrapExpression(node.initializer);
      if (isProcessExpr(init)) {
        processAliases.add(node.name.text);
      }
      if (ts.isCallExpression(init)) {
        const callee = unwrapExpression(init.expression);
        if (ts.isIdentifier(callee) && callee.text === "require") {
          const spec = stringLiteralText(init.arguments[0]);
          if (isModulePackageSpecifier(spec)) {
            moduleFromRequire.add(node.name.text);
          }
        }
      }
    }
    if (ts.isImportDeclaration(node) && node.importClause !== undefined) {
      const spec = stringLiteralText(node.moduleSpecifier);
      if (isProcessPackageSpecifier(spec)) {
        if (node.importClause.name !== undefined) {
          processFromImport.add(node.importClause.name.text);
        }
        if (
          node.importClause.namedBindings !== undefined &&
          ts.isNamespaceImport(node.importClause.namedBindings)
        ) {
          processFromNamespace.add(node.importClause.namedBindings.name.text);
        }
      }
      if (isModulePackageSpecifier(spec)) {
        if (node.importClause.name !== undefined) {
          moduleFromImport.add(node.importClause.name.text);
        }
        if (
          node.importClause.namedBindings !== undefined &&
          ts.isNamespaceImport(node.importClause.namedBindings)
        ) {
          moduleFromNamespace.add(node.importClause.namedBindings.name.text);
        }
      }
    }
  });

  visitEveryNode(sourceFile, (node) => {
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const name = memberName(node);
      const root = memberRoot(node);
      if (root === undefined || name === undefined) return;
      if (name === "binding") {
        if (isProcessExpr(root)) {
          hits.push({ label: "process.binding" });
        } else if (ts.isIdentifier(root) && processAliases.has(root.text)) {
          hits.push({ label: "process-alias .binding" });
        } else if (ts.isIdentifier(root) && processFromImport.has(root.text)) {
          hits.push({ label: "process-import-alias .binding" });
        } else if (ts.isIdentifier(root) && processFromNamespace.has(root.text)) {
          hits.push({ label: "process-namespace-alias .binding" });
        }
      }
      if (name === "_load") {
        if (isModuleIdentExpr(root)) {
          hits.push({ label: "Module._load" });
        } else if (ts.isIdentifier(root) && moduleFromImport.has(root.text)) {
          hits.push({ label: "module-import-alias ._load" });
        } else if (ts.isIdentifier(root) && moduleFromNamespace.has(root.text)) {
          hits.push({ label: "module-namespace-alias ._load" });
        } else if (ts.isIdentifier(root) && moduleFromRequire.has(root.text)) {
          hits.push({ label: "module-require-alias ._load" });
        }
      }
    }
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer !== undefined
    ) {
      const init = unwrapExpression(node.initializer);
      if (bindingPatternNames(node.name, "binding") && isProcessExpr(init)) {
        hits.push({ label: "process.binding destructure" });
      }
      if (bindingPatternNames(node.name, "_load")) {
        if (isModuleIdentExpr(init)) {
          hits.push({ label: "Module._load destructure" });
        }
        if (ts.isCallExpression(init)) {
          const callee = unwrapExpression(init.expression);
          if (ts.isIdentifier(callee) && callee.text === "require") {
            const spec = stringLiteralText(init.arguments[0]);
            if (isModulePackageSpecifier(spec)) {
              hits.push({ label: "require(module)._load destructure" });
            }
          }
        }
      }
    }
  });

  return hits;
};

/** Every module specifier `text` names via real module edges, in source order. */
const specifiersOfSource = (sourceFile: ts.SourceFile): string[] => {
  const specs: string[] = [];
  visitEveryNode(sourceFile, (node) => {
    const spec = moduleSpecifierText(node);
    if (spec !== undefined) {
      specs.push(spec);
    }
  });
  return specs;
};

const FORBIDDEN_ENV_SET = new Set<string>(FORBIDDEN_ENV_NAMES);

/** process.env.NAME / process.env["NAME"] via the syntax tree. */
const readsForbiddenEnv = (text: string): string[] => {
  const found = new Set<string>();
  visitEveryNode(parseTsSource(text), (node) => {
    if (!ts.isPropertyAccessExpression(node) && !ts.isElementAccessExpression(node)) return;
    const name = ts.isPropertyAccessExpression(node)
      ? node.name.text
      : stringLiteralText(node.argumentExpression);
    if (name === undefined || !FORBIDDEN_ENV_SET.has(name)) return;
    const root = unwrapExpression(node.expression);
    if (!ts.isPropertyAccessExpression(root) && !ts.isElementAccessExpression(root)) return;
    const envName = memberName(root);
    const processRoot = memberRoot(root);
    if (envName === "env" && processRoot !== undefined && isProcessExpr(processRoot)) {
      found.add(name);
    }
  });
  return [...found];
};

/**
 * Resolves a RELATIVE specifier to a file on disk. The package writes imports with an explicit
 * `.ts` extension and, for a handful of generated modules, `.js` — both denote the `.ts` source.
 * A non-relative specifier resolves to `undefined`: it is a package/builtin edge, matched by
 * `importRegexFor` at the node that names it, not walked.
 */
const resolveRelative = (fromFile: string, specifier: string): string | undefined => {
  if (!specifier.startsWith(".")) {
    return undefined;
  }
  const base = join(dirname(fromFile), specifier);
  const candidates = [
    base,
    base.endsWith(".js") ? `${base.slice(0, -3)}.ts` : `${base}.ts`,
    join(base, "index.ts"),
  ];
  return candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
};

// One read and one parse per file for the whole suite: the walk starts at every module, so the
// graph is traversed hundreds of times and uncached I/O dominates (it blew the 5 s default).
const textCache = new Map<string, string>();
const sourceFileCache = new Map<string, ts.SourceFile>();
const specifierCache = new Map<string, string[]>();
const acquiresCache = new Map<string, boolean>();

const textOf = (file: string): string => {
  const cached = textCache.get(file);
  if (cached !== undefined) {
    return cached;
  }
  // : a walked file can already be gone (the tree is live). It then has no imports and no
  // edges, which is exactly what an empty text yields.
  const text = readIfPresent(file) ?? "";
  textCache.set(file, text);
  return text;
};

const sourceFileOf = (file: string, text: string): ts.SourceFile => {
  const cached = sourceFileCache.get(file);
  if (cached !== undefined) {
    return cached;
  }
  const sourceFile = parseTsSource(text, file);
  sourceFileCache.set(file, sourceFile);
  return sourceFile;
};

const specifiersOfCached = (file: string, text: string): string[] => {
  const cached = specifierCache.get(file);
  if (cached !== undefined) {
    return cached;
  }
  const specifiers = specifiersOfSource(sourceFileOf(file, text));
  specifierCache.set(file, specifiers);
  return specifiers;
};

const acquiresCached = (file: string, text: string, specifier: string): boolean => {
  const key = `${file} ${specifier}`;
  const cached = acquiresCache.get(key);
  if (cached !== undefined) {
    return cached;
  }
  const acquires = acquiresSpecifierFrom(sourceFileOf(file, text), specifier);
  acquiresCache.set(key, acquires);
  return acquires;
};

/**
 *  AC4 — transitive laundering. `isContractOrManifestModule` reads each file's OWN text, so
 * a frozen contract could inherit a forbidden seam one hop away: import a tier-two module
 * (`testkit`/`scan`/`scripts`), which CONTRACT.md permits to touch crypto/fs "because they are the
 * emitters and test harness", and the contract silently acquires what it is forbidden to hold.
 *
 * Walks the relative-import graph from `root` and returns one entry per reachable forbidden edge,
 * carrying the chain that reaches it. `requireTierTwoHop` restricts the result to chains that pass
 * through a tier-two permitted directory — the shape of the crypto/fs grant. It is left off for
 * `FORBIDDEN_IMPORT_SPECIFIERS`, which no tier may hold, so ANY chain to them is a violation.
 *
 * Scope, stated rather than implied: this catches inheritance THROUGH the tier-two grant. A
 * contract importing a NON-tier-two peer module that holds `node:crypto` is a different question,
 * settled by (`instruction-origin/identity-key-hash.ts` — pure SHA-256 preimage helpers
 * deliberately split out of the testkit oracle so the contract stops loading the libsodium
 * `createRequire` seam), and the negative fixture below pins that rule so a later lane cannot
 * quietly reinterpret it.
 */
const reachableForbiddenEdges = (
  root: string,
  forbiddenSpecifiers: readonly string[],
  requireTierTwoHop: boolean,
): Array<{ readonly root: string; readonly specifier: string; readonly chain: string[] }> => {
  const found: Array<{ root: string; specifier: string; chain: string[] }> = [];
  // Keyed on the (file, sawTierTwo) PAIR, not the file. A plain per-root `visited` launders: reach
  // a module first by a clean path and its forbidden edge is memoised as "seen and permitted", so
  // the same module reached later THROUGH tier-two returns early and never flags. That is the
  // path-insensitive memo hole this gate exists to close.
  const visited = new Set<string>();
  const walk = (file: string, chain: string[], sawTierTwo: boolean): void => {
    const key = `${file} ${String(sawTierTwo)}`;
    if (visited.has(key)) {
      return;
    }
    visited.add(key);
    const text = textOf(file);
    for (const specifier of forbiddenSpecifiers) {
      if (acquiresCached(file, text, specifier) && (!requireTierTwoHop || sawTierTwo)) {
        found.push({ root, specifier, chain });
      }
    }
    for (const specifier of specifiersOfCached(file, text)) {
      const resolved = resolveRelative(file, specifier);
      if (resolved !== undefined) {
        walk(resolved, [...chain, resolved], sawTierTwo || isUnderTierTwoPermittedDir(resolved));
      }
    }
  };
  walk(root, [root], isUnderTierTwoPermittedDir(root));
  return found;
};

/**
 * `src/scan/**` is excluded from its own dependency-boundary check for the same reason it's
 * excluded from the forbidden-terms gate: this module's own specifier/env-name lists and
 * self-test fixtures necessarily contain the literal forbidden strings.
 *
 * `zz-*` directories are excluded (sub-claim 3): drift-audit tests previously planted
 * real `src/zz-*` fixtures that this module's globSync could observe at load time. If the
 * fixture was cleaned up before a test's readFileSync ran, ENOENT crashed the scan.
 * No `zz-*` directory is a production concern -- this is a reserved test-fixture namespace.
 *
 *  generalised that mitigation twice over: the walk now happens at test time rather
 * than at collect time, and reads go through readPresentFiles. A name-shaped filter only ever
 * covers the fixture names someone already thought of — it did not cover the
 * `__census-fixture-*.ts` files operations.drift-gate.test.ts once wrote into the scanned roots,
 * and it covers nothing an editor or a checkout removes mid-walk.
 */
const srcDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const walkFiles = (): string[] =>
  globSync(join(srcDir, "**", "*.ts")).filter(
    (f) => !f.includes(`${join("src", "scan")}/`) && !basename(dirname(f)).startsWith("zz-"),
  );

// The real-tree walk classes: see ../testkit/executionPolicy.ts for the measured budgets.
describe("dependency-boundary (the scan/dependency-boundary gate)", { timeout: EXECUTION_TIMEOUTS.realTree }, () => {
  it("has files to check (guards against an empty/broken glob)", () => {
    expect(walkFiles().length).toBeGreaterThan(0);
  });

  it("imports none of the forbidden network/DB/worker/process module specifiers (all modules)", () => {
    const violations: { file: string; specifier: string }[] = [];
    for (const { file, text } of readPresentFiles(walkFiles())) {
      const sourceFile = sourceFileOf(file, text);
      for (const specifier of FORBIDDEN_IMPORT_SPECIFIERS) {
        if (acquiresSpecifierFrom(sourceFile, specifier)) {
          violations.push({ file, specifier });
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("imports none of the laundering-seam specifiers outside tier-two permitted dirs", () => {
    const violations: { file: string; specifier: string }[] = [];
    for (const { file, text } of readPresentFiles(
      walkFiles().filter((f) => !isUnderTierTwoPermittedDir(f)),
    )) {
      for (const specifier of LAUNDERING_SEAM_SPECIFIERS) {
        // Static/dynamic import form only — not the broad acquires path — so JSDoc that
        // mentions `node:module` as prose does not fail the tree.
        if (importRegexFor(specifier).test(text)) {
          violations.push({ file, specifier });
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("uses no createRequire call outside tier-two, and no process.binding/Module._load anywhere", () => {
    const violations: { file: string; kind: string }[] = [];
    for (const { file, text } of readPresentFiles(walkFiles())) {
      if (hasInternalLoaderSeam(text)) {
        violations.push({ file, kind: "process.binding|Module._load" });
      }
      if (!isUnderTierTwoPermittedDir(file) && hasCreateRequireCall(text)) {
        violations.push({ file, kind: "createRequire(" });
      }
    }
    expect(violations).toEqual([]);
  });

  it("uses no non-literal import/require outside tier-two and test files", () => {
    const violations: { file: string }[] = [];
    for (const { file, text } of readPresentFiles(
      walkFiles().filter((f) => !isUnderTierTwoPermittedDir(f) && !f.endsWith(".test.ts")),
    )) {
      if (hasNonliteralRuntimeLoad(text)) {
        violations.push({ file });
      }
    }
    expect(violations).toEqual([]);
  });

  it("declares none of the denylisted packages in any package.json dependency section", () => {
    const packageJsonPath = join(dirname(srcDir), "package.json");
    // Manifest is not a live-tree walk path; ENOENT here means a broken package layout.
    const raw = readIfPresent(packageJsonPath);
    expect(raw).toBeDefined();
    if (raw === undefined) return;
    const packageJson = JSON.parse(raw) as Readonly<{
      dependencies?: Readonly<Record<string, string>>;
      devDependencies?: Readonly<Record<string, string>>;
      optionalDependencies?: Readonly<Record<string, string>>;
      peerDependencies?: Readonly<Record<string, string>>;
    }>;
    const sections = [
      packageJson.dependencies,
      packageJson.devDependencies,
      packageJson.optionalDependencies,
      packageJson.peerDependencies,
    ];
    const declared = sections.flatMap((section) =>
      section === undefined
        ? []
        : DENYLISTED_MANIFEST_PACKAGES.filter((name) => Object.hasOwn(section, name)),
    );
    expect(declared).toEqual([]);
  });

  it("has at least one contract/manifest module to check (guards against an empty/broken filter)", () => {
    expect(walkFiles().filter(isContractOrManifestModule).length).toBeGreaterThan(0);
  });

  it("imports none of the crypto/fs module specifiers in contract or manifest modules", () => {
    const violations: { file: string; specifier: string }[] = [];
    for (const { file, text } of readPresentFiles(
      walkFiles().filter(isContractOrManifestModule),
    )) {
      const sourceFile = sourceFileOf(file, text);
      for (const specifier of CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS) {
        if (acquiresSpecifierFrom(sourceFile, specifier)) {
          violations.push({ file, specifier });
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("reads none of the forbidden gateway/key environment variable names", () => {
    const violations: { file: string; envName: string }[] = [];
    for (const { file, text } of readPresentFiles(walkFiles())) {
      for (const envName of readsForbiddenEnv(text)) {
        violations.push({ file, envName });
      }
    }
    expect(violations).toEqual([]);
  });

  it("uses none of the banned internal loader seams (process.binding / Module._load family)", () => {
    const violations: { file: string; label: string }[] = [];
    for (const { file, text } of readPresentFiles(walkFiles())) {
      for (const hit of findBannedLoaderSeams(text)) {
        violations.push({ file, label: hit.label });
      }
    }
    expect(violations).toEqual([]);
  });

  it("detector mechanism: catches a synthetic forbidden import fixture", () => {
    const fixture = 'import { Socket } from "node:net";';
    expect(importRegexFor("node:net").test(fixture)).toBe(true);
  });

  it("detector mechanism: catches a synthetic forbidden worker/process import fixture", () => {
    expect(importRegexFor("node:worker_threads").test('import { Worker } from "node:worker_threads";')).toBe(
      true,
    );
    expect(importRegexFor("node:child_process").test('import { exec } from "node:child_process";')).toBe(
      true,
    );
  });

  it("detector mechanism: catches a synthetic contract-module fs import fixture", () => {
    const fixture = 'import { readFileSync } from "node:fs";\nexport const FAKE_CONTRACT = "x" as const;';
    expect(importRegexFor("node:fs").test(fixture)).toBe(true);
  });

  it("detector mechanism: classifies contract/manifest modules correctly for the tier-two boundary", () => {
    expect(
      isContractOrManifestModule(join(srcDir, "operations", "operations.contract.ts")),
    ).toBe(true);
    expect(isContractOrManifestModule(join(srcDir, "operations", "manifest.ts"))).toBe(true);
    expect(
      isContractOrManifestModule(join(srcDir, "operations", "operations.census.test.ts")),
    ).toBe(false);
    expect(isContractOrManifestModule(join(srcDir, "testkit", "freeze.ts"))).toBe(false);
    expect(
      isContractOrManifestModule(join(srcDir, "scan", "dependency-boundary.test.ts")),
    ).toBe(false);
  });

  it("detector mechanism: catches a synthetic forbidden env-read fixture", () => {
    const fixture = "const url = process.env.SPLITCHAIN_GATEWAY_URLS;";
    expect(readsForbiddenEnv(fixture)).toEqual(["SPLITCHAIN_GATEWAY_URLS"]);
  });

  it("detector mechanism: catches the runtime-loader bypasses that name a forbidden specifier", () => {
    // Neither expression is a static import; both hand the module back at runtime.
    expect(
      acquiresSpecifier(
        'const load = createRequire(import.meta.url);\nconst c = load("node:crypto");',
        "node:crypto",
      ),
    ).toBe(true);
    expect(
      acquiresSpecifier('const { getBuiltinModule } = process;\nconst f = getBuiltinModule("node:fs");', "node:fs"),
    ).toBe(true);
    expect(acquiresSpecifier('process.getBuiltinModule("node:crypto");', "node:crypto")).toBe(true);
    // A file that names the specifier but carries NO loader token and no call-arg form is not a violation.
    expect(acquiresSpecifier('export const DOC = "node:crypto is forbidden here";', "node:crypto")).toBe(false);
  });

  // ---- corrected repros (fail-first against pre-change head, green under the new rules).

  it("repro #1: flags import { createRequire } from \"node:module\" as a laundering seam", () => {
    const fixture = 'import { createRequire } from "node:module";';
    expect(importRegexFor("node:module").test(fixture)).toBe(true);
    expect(LAUNDERING_SEAM_SPECIFIERS).toContain("node:module");
  });

  it("repro #2: catches aliased createRequire two-line load(\"node:net\")", () => {
    // Loader renamed off createRequire/import/require tokens — still a call-arg acquisition.
    const fixture = 'const load = cr(import.meta.url);\nconst net = load("node:net");';
    expect(acquiresSpecifier(fixture, "node:net")).toBe(true);
    // Full enabling form also trips the seam + createRequire call bans.
    const full =
      'import { createRequire as cr } from "node:module";\nconst load = cr(import.meta.url);\nconst net = load("node:net");';
    expect(importRegexFor("node:module").test(full)).toBe(true);
    expect(acquiresSpecifier(full, "node:net")).toBe(true);
  });

  it("repro #3: catches computed-specifier dynamic import (literal-var and concat)", () => {
    // Variable indirection still names the forbidden specifier as a quoted string next to import(.
    expect(acquiresSpecifier('const s = "node:net"; await import(s);', "node:net")).toBe(true);
    // Concat/interpolated form has no complete "node:net" token — nonliteral load catches it.
    expect(hasNonliteralRuntimeLoad('const s = "node:" + "net"; await import(s);')).toBe(true);
    expect(hasNonliteralRuntimeLoad('await import("node:" + "net");')).toBe(true);
    // Pure string-literal dynamic import is fine for this detector (still subject to specifier bans).
    expect(hasNonliteralRuntimeLoad('await import("node:net");')).toBe(false);
  });

  it("residual: flags node:vm/vm, process.binding, Module._load", () => {
    expect(importRegexFor("node:vm").test('import "node:vm";')).toBe(true);
    expect(importRegexFor("vm").test('import "vm";')).toBe(true);
    expect(hasInternalLoaderSeam('process.binding("net");')).toBe(true);
    expect(hasInternalLoaderSeam('process["binding"]("fs");')).toBe(true);
    expect(hasInternalLoaderSeam('const load = process.binding; load("net");')).toBe(true);
    expect(hasInternalLoaderSeam('Module._load("pg");')).toBe(true);
    expect(hasInternalLoaderSeam('const load = Module._load; load("pg");')).toBe(true);
    expect(hasCreateRequireCall("const r = createRequire(import.meta.url);")).toBe(true);
    // Prose must not trip call-form token bans.
    expect(
      hasCreateRequireCall(
        '"dependency-boundary scan covers createRequire, require.resolve, and dynamic import()"',
      ),
    ).toBe(false);
  });
});

// ---- AC4: transitive (not merely direct) dependency-boundary enforcement.

/** Materialises `tree` (relative path -> contents) under a fresh temp root for one assertion. */
const withModuleTree = <T>(tree: Readonly<Record<string, string>>, body: (root: string) => T): T => {
  const root = mkdtempSync(join(tmpdir(), "fixture-dep-boundary-"));
  try {
    for (const [relativePath, contents] of Object.entries(tree)) {
      const absolute = join(root, relativePath);
      mkdirSync(dirname(absolute), { recursive: true });
      writeFileSync(absolute, contents, "utf8");
    }
    return body(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

// : the per-test `{ timeout: 30_000 }` this file used to carry existed only because the
// root project's 30s budget did not reach the package command. The whole real-tree class now
// shares one measured budget from ../testkit/executionPolicy.ts.
describe("dependency-boundary transitive reachability (the scan/dependency-boundary gate, AC4)", { timeout: EXECUTION_TIMEOUTS.realTree }, () => {
  it("no module REACHES a network/DB/worker/process specifier, however many hops away", () => {
    const violations = walkFiles().flatMap((file) =>
      reachableForbiddenEdges(file, FORBIDDEN_IMPORT_SPECIFIERS, false).map(
        ({ specifier, chain }) => ({ file, specifier, chain }),
      ),
    );
    expect(violations).toEqual([]);
  });

  it("no contract or manifest module REACHES crypto/fs through a tier-two permitted directory", () => {
    const violations = walkFiles()
      .filter(isContractOrManifestModule)
      .flatMap((file) =>
        reachableForbiddenEdges(file, CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS, true).map(
          ({ specifier, chain }) => ({ file, specifier, chain }),
        ),
      );
    expect(violations).toEqual([]);
  });

  it("catches a contract module that launders crypto through a tier-two module (one hop)", () => {
    withModuleTree(
      {
        "src/thing/thing.contract.ts": 'import { hash } from "../testkit/oracle.ts";\nexport const T = hash;',
        "src/testkit/oracle.ts": 'import { createHash } from "node:crypto";\nexport const hash = createHash;',
      },
      (root) => {
        const found = reachableForbiddenEdges(
          join(root, "src/thing/thing.contract.ts"),
          CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS,
          true,
        );
        expect(found.map((edge) => edge.specifier)).toEqual(["node:crypto"]);
        expect(found[0]?.chain.at(-1)).toBe(join(root, "src/testkit/oracle.ts"));
      },
    );
  });

  it("catches a two-hop launder through a tier-two re-export barrel", () => {
    withModuleTree(
      {
        "src/thing/manifest.ts": 'import { hash } from "../testkit/index.ts";\nexport const M = hash;',
        "src/testkit/index.ts": 'export { hash } from "./oracle.ts";',
        "src/testkit/oracle.ts": 'import { readFileSync } from "node:fs";\nexport const hash = readFileSync;',
      },
      (root) => {
        const found = reachableForbiddenEdges(
          join(root, "src/thing/manifest.ts"),
          CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS,
          true,
        );
        expect(found.map((edge) => edge.specifier)).toEqual(["node:fs"]);
      },
    );
  });

  it("catches a tier-two launder that uses createRequire instead of a static import", () => {
    withModuleTree(
      {
        "src/thing/thing.contract.ts": 'import { load } from "../testkit/loader.ts";\nexport const T = load;',
        "src/testkit/loader.ts":
          'import { createRequire } from "node:module";\nexport const load = createRequire(import.meta.url)("node:crypto");',
      },
      (root) => {
        const found = reachableForbiddenEdges(
          join(root, "src/thing/thing.contract.ts"),
          CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS,
          true,
        );
        expect(found.map((edge) => edge.specifier)).toEqual(["node:crypto"]);
      },
    );
  });

  it("catches a tier-two launder that destructures getBuiltinModule off process", () => {
    withModuleTree(
      {
        "src/thing/thing.contract.ts": 'import { fsp } from "../testkit/loader.ts";\nexport const T = fsp;',
        "src/testkit/loader.ts":
          'const { getBuiltinModule } = process;\nexport const fsp = getBuiltinModule("node:fs");',
      },
      (root) => {
        const found = reachableForbiddenEdges(
          join(root, "src/thing/thing.contract.ts"),
          CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS,
          true,
        );
        expect(found.map((edge) => edge.specifier)).toEqual(["node:fs"]);
      },
    );
  });

  // The memo hole in its own fixture: the SAME seam module is reachable by a clean path AND by a
  // tier-two path. A per-file `visited` set memoises the clean visit and returns early on the
  // laundering one, reporting zero violations. Keying on (file, sawTierTwo) is what makes this red.
  it("catches the laundering path even when a clean path reaches the same seam module first", () => {
    withModuleTree(
      {
        "src/thing/thing.contract.ts":
          'import { a } from "./clean.ts";\nimport { b } from "../testkit/bridge.ts";\nexport const T = [a, b];',
        "src/thing/clean.ts": 'export { hash as a } from "../shared/seam.ts";',
        "src/testkit/bridge.ts": 'export { hash as b } from "../shared/seam.ts";',
        "src/shared/seam.ts": 'import { createHash } from "node:crypto";\nexport const hash = createHash;',
      },
      (root) => {
        const found = reachableForbiddenEdges(
          join(root, "src/thing/thing.contract.ts"),
          CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS,
          true,
        );
        expect(found.map((edge) => edge.specifier)).toEqual(["node:crypto"]);
      },
    );
  });

  it("a network specifier is caught with NO tier-two hop — no tier may hold it", () => {
    withModuleTree(
      {
        "src/thing/thing.contract.ts": 'import { send } from "./peer.ts";\nexport const T = send;',
        "src/thing/peer.ts": 'import { Socket } from "node:net";\nexport const send = Socket;',
      },
      (root) => {
        const found = reachableForbiddenEdges(
          join(root, "src/thing/thing.contract.ts"),
          FORBIDDEN_IMPORT_SPECIFIERS,
          false,
        );
        expect(found.map((edge) => edge.specifier)).toEqual(["node:net"]);
      },
    );
  });

  // Pins the boundary in the OTHER direction so the scope above is a stated rule, not an
  // accident: deliberately moved the SHA-256 preimage helpers into a non-tier-two peer
  // module so a frozen contract stops loading the testkit's libsodium `createRequire` seam. That
  // peer edge is permitted; only the tier-two grant is non-inheritable.
  it("does NOT flag a contract reaching crypto through a non-tier-two peer module (split)", () => {
    withModuleTree(
      {
        "src/thing/thing.contract.ts": 'import { sha256Hex } from "./key-hash.ts";\nexport const T = sha256Hex;',
        "src/thing/key-hash.ts": 'import { createHash } from "node:crypto";\nexport const sha256Hex = createHash;',
      },
      (root) => {
        expect(
          reachableForbiddenEdges(
            join(root, "src/thing/thing.contract.ts"),
            CONTRACT_MODULE_ONLY_FORBIDDEN_IMPORT_SPECIFIERS,
            true,
          ),
        ).toEqual([]);
      },
    );
  });
});

// ----: process.binding / Module._load seam class (direct + destructure + alias).
// Fixtures are fed through `findBannedLoaderSeams` — the same function the production scan uses —
// so a pattern that never runs in the live gate cannot green these tests.

describe("dependency-boundary banned loader seams", () => {
  const labelsOf = (text: string): string[] => findBannedLoaderSeams(text).map((hit) => hit.label);

  it("flags direct process.binding (dot, bracket, acquisition)", () => {
    expect(labelsOf('process.binding("fs");')).toContain("process.binding");
    expect(labelsOf('process["binding"]("fs");')).toContain("process.binding");
    expect(labelsOf("const load = process.binding; load(\"net\");")).toContain("process.binding");
  });

  it("flags direct Module._load (dot, bracket, acquisition)", () => {
    expect(labelsOf('Module._load("pg");')).toContain("Module._load");
    expect(labelsOf('Module["_load"]("net");')).toContain("Module._load");
    expect(labelsOf("const load = Module._load; load(\"pg\");")).toContain("Module._load");
  });

  it("flags destructure-extraction of binding / _load", () => {
    expect(labelsOf('const { binding } = process; binding("fs");')).toContain(
      "process.binding destructure",
    );
    expect(labelsOf('const { _load } = Module; _load("net");')).toContain("Module._load destructure");
    expect(labelsOf('const { binding: load } = process; load("fs");')).toContain(
      "process.binding destructure",
    );
    expect(labelsOf('const { _load } = require("module"); _load("net");')).toContain(
      "require(module)._load destructure",
    );
    expect(labelsOf('const { _load } = require("node:module"); _load("pg");')).toContain(
      "require(module)._load destructure",
    );
  });

  it("flags process aliases that reach .binding (assignment, default import, namespace import)", () => {
    expect(labelsOf('const p = process; p.binding("fs");')).toContain("process-alias .binding");
    expect(labelsOf('import p from "node:process"; p.binding("fs");')).toContain(
      "process-import-alias .binding",
    );
    expect(labelsOf('import p from "process"; p["binding"]("fs");')).toContain(
      "process-import-alias .binding",
    );
    expect(labelsOf('import * as p from "node:process"; p.binding("fs");')).toContain(
      "process-namespace-alias .binding",
    );
  });

  it("flags module aliases that reach ._load", () => {
    expect(labelsOf('import M from "module"; M._load("pg");')).toContain("module-import-alias ._load");
    expect(labelsOf('import * as M from "node:module"; M._load("net");')).toContain(
      "module-namespace-alias ._load",
    );
    expect(labelsOf('const M = require("module"); M._load("pg");')).toContain(
      "module-require-alias ._load",
    );
  });

  it("does not false-positive on unrelated destructures, imports, or getBuiltinModule", () => {
    expect(labelsOf("const { binding } = someOther;")).toEqual([]);
    expect(labelsOf("const { _load } = someOther;")).toEqual([]);
    expect(labelsOf('import p from "node:path"; p.join("a");')).toEqual([]);
    expect(labelsOf('const p = process; p.env.HOME;')).toEqual([]);
    expect(labelsOf('const { getBuiltinModule } = process; getBuiltinModule("node:fs");')).toEqual(
      [],
    );
    expect(labelsOf('process.getBuiltinModule("node:crypto");')).toEqual([]);
  });
});

// ----: mutual-blindness plants — AST red / legacy regex green on the same bytes.

/** Legacy regex detector retained ONLY for the mutual-blindness proof. Do not call in production. */
const legacyHasInternalLoaderSeam = (text: string): boolean =>
  /process\s*(?:\.\s*binding|\s*\[\s*["'`]binding["'`]\s*\])/.test(text) ||
  /\bModule\s*(?:\.\s*_load|\s*\[\s*["'`]_load["'`]\s*\])/.test(text);

const legacyImportOf = (specifier: string, text: string): boolean =>
  new RegExp(
    `\\b(?:import|require|getBuiltinModule)\\b\\s*\\(?[^;\\n]*["'\`]${specifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'\`]`,
  ).test(text);

describe("dependency-boundary AST vs legacy regex", () => {
  it("flags (0, process).binding where the spanning regex cannot see past the comma wrapper", () => {
    const plant = '(0, process).binding("fs");';
    expect(findBannedLoaderSeams(plant).map((h) => h.label)).toContain("process.binding");
    expect(hasInternalLoaderSeam(plant)).toBe(true);
    expect(legacyHasInternalLoaderSeam(plant)).toBe(false);
  });

  it("prose string that looks like an import no longer false-positives; a real import still flags", () => {
    // Source bytes that contain import … "node:net" only inside a string literal.
    const proseOnly = "const note = 'import { Socket } from \"node:net\";';";
    const withImport = `${proseOnly}\nimport { Socket } from "node:net";`;
    expect(importRegexFor("node:net").test(proseOnly)).toBe(false);
    expect(legacyImportOf("node:net", proseOnly)).toBe(true);
    expect(importRegexFor("node:net").test(withImport)).toBe(true);
  });
});
