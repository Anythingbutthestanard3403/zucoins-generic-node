import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vitest";

import * as rootApi from "../src/index.js";
import * as protocolApi from "../src/protocol/index.js";

interface ProductionSource {
  readonly relativePath: string;
  readonly sourceFile: ts.SourceFile;
}

const protocolRoot = fileURLToPath(new URL("../src/protocol/", import.meta.url));
const packageManifest = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as {
  dependencies?: Record<string, string>;
  exports?: Record<string, string>;
};

function collectProtocolSources(directory: string): ProductionSource[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry): ProductionSource[] => {
      const absolutePath = join(directory, entry.name);
      if (entry.isDirectory()) return collectProtocolSources(absolutePath);
      if (!entry.isFile() || !entry.name.endsWith(".ts")) return [];
      // Colocated *.test.ts files under src/protocol/ (e.g. the/ property
      // tests) legitimately use Math.floor/String as fast-check generators. This gate
      // scans production money-path sources only; a narrow .test.ts suffix excludes them.
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

function visitEveryNode(sourceFile: ts.SourceFile, assertion: (node: ts.Node) => void): void {
  const visit = (node: ts.Node): void => {
    assertion(node);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
}

function calledMember(
  expression: ts.LeftHandSideExpression,
  sourceFile: ts.SourceFile,
): { readonly receiver: string; readonly method: string } | null {
  if (ts.isPropertyAccessExpression(expression)) {
    return {
      receiver: expression.expression.getText(sourceFile),
      method: expression.name.text,
    };
  }
  if (
    ts.isElementAccessExpression(expression) &&
    expression.argumentExpression !== undefined &&
    ts.isStringLiteral(expression.argumentExpression)
  ) {
    return {
      receiver: expression.expression.getText(sourceFile),
      method: expression.argumentExpression.text,
    };
  }
  return null;
}

function isZeroLiteral(expression: ts.Expression): boolean {
  if (ts.isParenthesizedExpression(expression)) {
    return isZeroLiteral(expression.expression);
  }
  return ts.isNumericLiteral(expression) && Number(expression.text) === 0;
}

// Compound-assignment forms (`a op= b`) parse as a BinaryExpression whose operatorToken is the
// COMPOUND SyntaxKind — distinct from the plain arithmetic/bitwise tokens gated below — so they
// silently bypassed every numeric-coercion gate. `a >>>= 0` truncates a money amount to int32
// exactly like the banned `a >>> 0`; `a += b` / `a -= b` etc. mutate an amount in place. Golden
// rule 3 (coercion-class closure): gate the whole compound-assignment family, each token
// individually load-bearing, in the amounts.ts scope.
const COMPOUND_ASSIGNMENT_COERCION_TOKENS: readonly ts.SyntaxKind[] = [
  ts.SyntaxKind.PlusEqualsToken,
  ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AsteriskEqualsToken,
  ts.SyntaxKind.AsteriskAsteriskEqualsToken,
  ts.SyntaxKind.SlashEqualsToken,
  ts.SyntaxKind.PercentEqualsToken,
  ts.SyntaxKind.LessThanLessThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.AmpersandEqualsToken,
  ts.SyntaxKind.BarEqualsToken,
  ts.SyntaxKind.CaretEqualsToken,
];

function collectUnsafeNumericUses(
  relativePath: string,
  sourceFile: ts.SourceFile,
): string[] {
  const violations: string[] = [];

  visitEveryNode(sourceFile, (node) => {
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.PlusToken) {
      violations.push(`${relativePath}: unary numeric coercion`);
    }

    if (ts.isTypeReferenceNode(node) && node.typeName.getText(sourceFile) === "BigNumber.Value") {
      violations.push(`${relativePath}: BigNumber.Value`);
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      node.expression.getText(sourceFile) === "BigNumber" &&
      node.name.text === "Value"
    ) {
      violations.push(`${relativePath}: BigNumber.Value`);
    }

    if (relativePath === "amounts.ts") {
      if (
        ts.isBinaryExpression(node) &&
        (node.operatorToken.kind === ts.SyntaxKind.MinusToken ||
          node.operatorToken.kind === ts.SyntaxKind.AsteriskToken ||
          node.operatorToken.kind === ts.SyntaxKind.SlashToken ||
          node.operatorToken.kind === ts.SyntaxKind.PercentToken ||
          node.operatorToken.kind === ts.SyntaxKind.AsteriskAsteriskToken)
      ) {
        violations.push(`${relativePath}: binary arithmetic (-|*|/|%|**)`);
      }
      // Binary `+` (PlusToken) is the one arithmetic token the group above omits; only unary +x is
      // caught elsewhere (PrefixUnaryExpression). This closes numeric-addition / string-concat
      // coercion of an amount. amounts.ts does all arithmetic via BigNumber methods (the sole `+`
      // in the file is inside a regex literal, not a BinaryExpression), so this is inert on real code.
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        violations.push(`${relativePath}: unsafe binary +`);
      }
      if (
        ts.isBinaryExpression(node) &&
        (node.operatorToken.kind === ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken ||
          node.operatorToken.kind === ts.SyntaxKind.LessThanLessThanToken ||
          node.operatorToken.kind === ts.SyntaxKind.GreaterThanGreaterThanToken ||
          node.operatorToken.kind === ts.SyntaxKind.AmpersandToken ||
          node.operatorToken.kind === ts.SyntaxKind.CaretToken)
      ) {
        violations.push(`${relativePath}: bitwise operator (>>>|<<|>>|&|^)`);
      }
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.BarToken &&
        (isZeroLiteral(node.left) || isZeroLiteral(node.right))
      ) {
        violations.push(`${relativePath}: bitwise |0 truncation`);
      }
      if (
        ts.isBinaryExpression(node) &&
        COMPOUND_ASSIGNMENT_COERCION_TOKENS.includes(node.operatorToken.kind)
      ) {
        violations.push(`${relativePath}: compound-assignment numeric coercion (op=)`);
      }
      if (
        ts.isPrefixUnaryExpression(node) &&
        node.operator === ts.SyntaxKind.MinusToken &&
        !ts.isNumericLiteral(node.operand)
      ) {
        violations.push(`${relativePath}: unary numeric coercion`);
      }
      if (
        ts.isPrefixUnaryExpression(node) &&
        node.operator === ts.SyntaxKind.TildeToken &&
        ts.isPrefixUnaryExpression(node.operand) &&
        node.operand.operator === ts.SyntaxKind.TildeToken
      ) {
        violations.push(`${relativePath}: double bitwise NOT (~~)`);
      }
      // Single unary bitwise-NOT `~x` is itself a ToInt32 coercion (`~x` === `-(x+1)` under
      // ToInt32 semantics) — the same class as `|0` and `~~`, and the remaining unbanned bitwise
      // coercion after. amounts.ts performs no bitwise math, so this is inert on real code.
      if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.TildeToken) {
        violations.push(`${relativePath}: bitwise NOT (~)`);
      }
      if (ts.isTemplateExpression(node)) {
        violations.push(`${relativePath}: template literal coercion`);
      }
    }

    if (!ts.isCallExpression(node)) return;
    const expression = node.expression;
    if (ts.isIdentifier(expression)) {
      if (["Number", "String", "parseFloat", "parseInt"].includes(expression.text)) {
        violations.push(`${relativePath}: ${expression.text}()`);
      }
      return;
    }

    const member = calledMember(expression, sourceFile);
    if (member === null) return;
    const { receiver, method } = member;
    if (receiver === "BigNumber" && ["config", "set"].includes(method)) {
      violations.push(`${relativePath}: BigNumber.${method}()`);
    }
    if (receiver === "Number" && ["parseFloat", "parseInt"].includes(method)) {
      violations.push(`${relativePath}: Number.${method}()`);
    }
    if (receiver === "Math" && ["round", "floor", "ceil", "trunc"].includes(method)) {
      violations.push(`${relativePath}: Math.${method}()`);
    }
    if (
      [
        "toNumber",
        "toLocaleString",
        "toExponential",
        "toPrecision",
        "toFormat",
        "toJSON",
        "valueOf",
      ].includes(method)
    ) {
      violations.push(`${relativePath}: .${method}()`);
    }
    if (method === "toFixed" && node.arguments.length !== 0) {
      violations.push(`${relativePath}: .toFixed() with arguments`);
    }
    if (relativePath === "amounts.ts" && method === "toString") {
      violations.push(`${relativePath}: amount .toString()`);
    }
  });

  return violations;
}

function parseMutationSource(source: string): ts.SourceFile {
  return ts.createSourceFile(
    "amounts.mutation.ts",
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
}

const productionSources = collectProtocolSources(protocolRoot);

describe("recursive production money-path gates", () => {
  it("keeps the production money path free of any direct bignumber.js import", () => {
    // The amount arithmetic is consumed from the frozen contracts package; the manifest still
    // pins bignumber.js because this package's test suite uses it as an independent oracle.
    expect(packageManifest.dependencies?.["bignumber.js"]).toBe("9.1.0");

    const moduleReferences: Array<{ relativePath: string; text: string }> = [];
    for (const { relativePath, sourceFile } of productionSources) {
      for (const statement of sourceFile.statements) {
        if (
          (ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) &&
          statement.moduleSpecifier !== undefined &&
          ts.isStringLiteral(statement.moduleSpecifier) &&
          statement.moduleSpecifier.text === "bignumber.js"
        ) {
          moduleReferences.push({ relativePath, text: statement.getText(sourceFile) });
        }
      }
    }

    expect(moduleReferences).toEqual([]);
  });

  it("scans a non-empty set of production sources and excludes colocated *.test.ts", () => {
    expect(productionSources.length).toBeGreaterThan(0);
    expect(productionSources.filter(({ relativePath }) => relativePath.endsWith(".test.ts"))).toEqual([]);
  });

  it("rejects unsafe numeric coercion and formatting APIs throughout protocol production", () => {
    const violations = productionSources.flatMap(({ relativePath, sourceFile }) =>
      collectUnsafeNumericUses(relativePath, sourceFile),
    );

    expect(violations).toEqual([]);
  });

  it("walks a production-shaped file but excludes a colocated .test.ts with the same content", () => {
    const scratchDir = mkdtempSync(join(tmpdir(), "protocol-source-safety-teeth-"));
    try {
      const violatingSource = "export const output = Math.floor(amount);\n";
      writeFileSync(join(scratchDir, "zz-gate-check.ts"), violatingSource);
      writeFileSync(join(scratchDir, "zz-gate-check.test.ts"), violatingSource);
      writeFileSync(join(scratchDir, "zz-gate-check.property.test.ts"), violatingSource);

      const walked = collectProtocolSources(scratchDir);
      expect(walked.map((source) => basename(source.relativePath))).toEqual(["zz-gate-check.ts"]);

      const violations = walked.flatMap(({ relativePath, sourceFile }) =>
        collectUnsafeNumericUses(relativePath, sourceFile),
      );
      expect(violations).toHaveLength(1);
      expect(violations[0]?.endsWith("Math.floor()")).toBe(true);
    } finally {
      rmSync(scratchDir, { recursive: true, force: true });
    }
  });

  it("detects mutations for every banned numeric surface and permits zero-argument toFixed", () => {
    const mutations: ReadonlyArray<{
      readonly expected: string;
      readonly source: string;
    }> = [
      { expected: "unary numeric coercion", source: "const output = +amount;" },
      { expected: "BigNumber.Value", source: "type Input = BigNumber.Value;" },
      { expected: "Number()", source: "const output = Number(amount);" },
      { expected: "String()", source: "const output = String(amount);" },
      { expected: "parseFloat()", source: "const output = parseFloat(amount);" },
      { expected: "parseInt()", source: "const output = parseInt(amount);" },
      { expected: "BigNumber.config()", source: "BigNumber.config({});" },
      { expected: "BigNumber.set()", source: "BigNumber.set({});" },
      { expected: "Number.parseFloat()", source: "const output = Number.parseFloat(amount);" },
      { expected: "Number.parseInt()", source: "const output = Number.parseInt(amount);" },
      { expected: "Math.round()", source: "const output = Math.round(amount);" },
      { expected: "Math.floor()", source: "const output = Math.floor(amount);" },
      { expected: "Math.ceil()", source: "const output = Math.ceil(amount);" },
      { expected: "Math.trunc()", source: "const output = Math.trunc(amount);" },
      { expected: ".toNumber()", source: "const output = amount.toNumber();" },
      { expected: ".toLocaleString()", source: "const output = amount.toLocaleString();" },
      { expected: ".toExponential()", source: "const output = amount.toExponential();" },
      { expected: ".toPrecision()", source: "const output = amount.toPrecision();" },
      { expected: ".toFormat()", source: "const output = amount.toFormat();" },
      { expected: ".toJSON()", source: "const output = amount.toJSON();" },
      { expected: ".valueOf()", source: "const output = amount.valueOf();" },
      { expected: "amount .toString()", source: "const output = amount.toString();" },
      {
        expected: ".toFixed() with arguments",
        source: "const output = amount.toFixed(32);",
      },
      {
        expected: ".toFixed() with arguments",
        source: "const output = amount[\"toFixed\"](undefined);",
      },
      { expected: "binary arithmetic (-|*|/|%|**)", source: "const output = a - b;" },
      { expected: "binary arithmetic (-|*|/|%|**)", source: "const output = a * b;" },
      { expected: "binary arithmetic (-|*|/|%|**)", source: "const output = a / b;" },
      { expected: "binary arithmetic (-|*|/|%|**)", source: "const output = a % b;" },
      { expected: "binary arithmetic (-|*|/|%|**)", source: "const output = a ** b;" },
      { expected: "bitwise operator (>>>|<<|>>|&|^)", source: "const output = a >>> b;" },
      { expected: "bitwise operator (>>>|<<|>>|&|^)", source: "const output = a << b;" },
      { expected: "bitwise operator (>>>|<<|>>|&|^)", source: "const output = a >> b;" },
      { expected: "bitwise operator (>>>|<<|>>|&|^)", source: "const output = a & b;" },
      { expected: "bitwise operator (>>>|<<|>>|&|^)", source: "const output = a ^ b;" },
      { expected: "bitwise |0 truncation", source: "const output = a | 0;" },
      { expected: "bitwise |0 truncation", source: "const output = 0 | a;" },
      { expected: "bitwise |0 truncation", source: "const output = a | 0x0;" },
      { expected: "bitwise |0 truncation", source: "const output = a | (0);" },
      { expected: "unary numeric coercion", source: "const output = -amount;" },
      { expected: "double bitwise NOT (~~)", source: "const output = ~~a;" },
      { expected: "bitwise NOT (~)", source: "const output = ~amount;" },
      { expected: "template literal coercion", source: "const output = `${a}`;" },
      // Binary + (PlusToken) — the arithmetic token the plain-operator group omits.
      { expected: "unsafe binary +", source: "const output = a + b;" },
      // Compound-assignment family (`a op= b`): each token individually load-bearing via the
      // COMPOUND_ASSIGNMENT_COERCION_TOKENS membership check. `+=` closes the binary-+ analogue.
      { expected: "compound-assignment numeric coercion (op=)", source: "a += b;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a -= b;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a *= b;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a **= b;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a /= b;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a %= b;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a <<= b;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a >>= b;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a >>>= 0;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a &= mask;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a |= 0;" },
      { expected: "compound-assignment numeric coercion (op=)", source: "a ^= 0;" },
    ];

    for (const mutation of mutations) {
      expect(
        collectUnsafeNumericUses("amounts.ts", parseMutationSource(mutation.source)),
        mutation.source,
      ).toContain(`amounts.ts: ${mutation.expected}`);
    }

    expect(
      collectUnsafeNumericUses(
        "amounts.ts",
        parseMutationSource("const output = amount.toFixed();"),
      ),
    ).toEqual([]);
  });

  it("does not export the Decimal implementation from any protocol production module", () => {
    const violations: string[] = [];
    for (const { relativePath, sourceFile } of productionSources) {
      for (const statement of sourceFile.statements) {
        if (ts.isExportDeclaration(statement) && statement.exportClause !== undefined) {
          if (ts.isNamedExports(statement.exportClause)) {
            for (const element of statement.exportClause.elements) {
              if (["BigNumber", "Decimal"].includes(element.name.text)) {
                violations.push(`${relativePath}: ${element.name.text}`);
              }
            }
          } else if (["BigNumber", "Decimal"].includes(statement.exportClause.name.text)) {
            violations.push(`${relativePath}: ${statement.exportClause.name.text}`);
          }
          continue;
        }

        if (!statement.modifiers?.some(({ kind }) => kind === ts.SyntaxKind.ExportKeyword)) {
          continue;
        }
        if (
          (ts.isVariableStatement(statement) &&
            statement.declarationList.declarations.some(
              ({ name }) => ts.isIdentifier(name) && ["BigNumber", "Decimal"].includes(name.text),
            )) ||
          ((ts.isClassDeclaration(statement) ||
            ts.isFunctionDeclaration(statement) ||
            ts.isInterfaceDeclaration(statement) ||
            ts.isTypeAliasDeclaration(statement) ||
            ts.isEnumDeclaration(statement)) &&
            statement.name !== undefined &&
            ["BigNumber", "Decimal"].includes(statement.name.text))
        ) {
          violations.push(relativePath);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("omits construction quantization from protocol and root runtime APIs", () => {
    expect(protocolApi).not.toHaveProperty("roundDownComputedZkz");
    expect(rootApi).not.toHaveProperty("roundDownComputedZkz");
    expect(protocolApi).toHaveProperty("parseZkzBalance", expect.any(Function));
    expect(rootApi).toHaveProperty("parseZkzBalance", expect.any(Function));
    expect(packageManifest.exports).not.toHaveProperty("./protocol/amounts");
  });
});
