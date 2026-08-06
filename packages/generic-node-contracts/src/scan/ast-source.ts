/**
 * Shared TypeScript AST helpers for source gates.
 *
 * A regex cannot tell code from a comment or a string literal. Every detector that used to
 * strip/match TypeScript source text goes through `parseTsSource` + a tree walk instead.
 * `src/scan/**` is excluded from the forbidden-terms walk, so this module may name patterns.
 */
import ts from "typescript";

export function parseTsSource(
  text: string,
  fileName = "anonymous.ts",
  scriptKind: ts.ScriptKind = ts.ScriptKind.TS,
): ts.SourceFile {
  return ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, scriptKind);
}

export function visitEveryNode(sourceFile: ts.SourceFile, visit: (node: ts.Node) => void): void {
  const walk = (node: ts.Node): void => {
    visit(node);
    ts.forEachChild(node, walk);
  };
  walk(sourceFile);
}

export function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  for (;;) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isTypeAssertionExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isSatisfiesExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    // `(0, process).binding` — the comma expression's right-hand side is the receiver.
    if (
      ts.isBinaryExpression(current) &&
      current.operatorToken.kind === ts.SyntaxKind.CommaToken
    ) {
      current = current.right;
      continue;
    }
    return current;
  }
}

/** String contents of a string/no-sub template literal, or undefined. */
export function stringLiteralText(node: ts.Node | undefined): string | undefined {
  if (node === undefined) return undefined;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  return undefined;
}

export function isIdentifierNamed(node: ts.Node | undefined, name: string): boolean {
  return node !== undefined && ts.isIdentifier(node) && node.text === name;
}

/** Module specifier text from import/export/"require"/dynamic-import style nodes. */
export function moduleSpecifierText(node: ts.Node): string | undefined {
  if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
    return stringLiteralText(node.moduleSpecifier);
  }
  if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
    return stringLiteralText(node.moduleReference.expression);
  }
  if (ts.isCallExpression(node)) {
    const callee = unwrapExpression(node.expression);
    const isImportCall = callee.kind === ts.SyntaxKind.ImportKeyword;
    const isRequireIdent =
      ts.isIdentifier(callee) && (callee.text === "require" || callee.text === "getBuiltinModule");
    const isGetBuiltinMember =
      ts.isPropertyAccessExpression(callee) && callee.name.text === "getBuiltinModule";
    if ((isImportCall || isRequireIdent || isGetBuiltinMember) && node.arguments.length >= 1) {
      return stringLiteralText(node.arguments[0]);
    }
  }
  return undefined;
}
