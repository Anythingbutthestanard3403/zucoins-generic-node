// Flat ESLint config — typescript-eslint `recommended` (non-type-aware: no
// parserOptions.project / projectService, so it stays fast and needs no
// per-package tsconfig wiring).
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

// Bare-amount float ban. Any module that imports the `ZkzDecimalString` brand
// is handling wire amounts, and in such a module every road from a decimal
// string to a JavaScript number is a defect: amounts are decimal strings end
// to end, and display precision loss at 32 fractional digits is a money-path
// bug. Import-gated — files that never touch the brand are left alone — so it
// applies tree-wide, tests included.
const noFloatAmount = {
  meta: {
    type: "problem",
    docs: {
      description:
        "in modules importing ZkzDecimalString, ban parseFloat / Number() / toFixed / toLocaleString / Intl.NumberFormat",
    },
    schema: [],
  },
  create(context) {
    let importsBrand = false;
    const hits = [];
    return {
      ImportDeclaration(node) {
        for (const spec of node.specifiers) {
          if (spec.type === "ImportSpecifier" && spec.imported.name === "ZkzDecimalString") {
            importsBrand = true;
          }
        }
      },
      CallExpression(node) {
        if (
          node.callee.type === "Identifier" &&
          (node.callee.name === "parseFloat" || node.callee.name === "Number")
        ) {
          hits.push({ node, road: `${node.callee.name}(` });
        }
      },
      MemberExpression(node) {
        if (node.property.type !== "Identifier") return;
        const name = node.property.name;
        if (name === "toFixed" || name === "toLocaleString" || name === "parseFloat") {
          hits.push({ node, road: name });
        }
        if (name === "NumberFormat" && node.object.type === "Identifier" && node.object.name === "Intl") {
          hits.push({ node, road: "Intl.NumberFormat" });
        }
      },
      "Program:exit"() {
        if (!importsBrand) return;
        for (const { node, road } of hits) {
          context.report({
            node,
            message: `${road} in a module that imports ZkzDecimalString — amount_zkz is a decimal string end to end. Render by string slicing; a JavaScript number must be unreachable.`,
          });
        }
      },
    };
  },
};


// SPA-wide bare-amount float ban (ZTR-1168 interim). The import-gated rule above
// never fires in admin/src because the SPA does not import ZkzDecimalString yet.
// Apply the same roads unconditionally under the operator console tree.
const noFloatAmountAdmin = {
  meta: {
    type: "problem",
    docs: {
      description:
        "in the operator SPA, ban parseFloat / Number() / toFixed / toLocaleString / Intl.NumberFormat on amount paths",
    },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        if (
          node.callee.type === "Identifier" &&
          (node.callee.name === "parseFloat" || node.callee.name === "Number")
        ) {
          context.report({
            node,
            message: `${node.callee.name}( in operator SPA — amount_zkz is a decimal string end to end. Render by string slicing; a JavaScript number must be unreachable.`,
          });
        }
      },
      MemberExpression(node) {
        if (node.property.type !== "Identifier") return;
        const name = node.property.name;
        if (name === "toFixed" || name === "toLocaleString" || name === "parseFloat") {
          context.report({
            node,
            message: `${name} in operator SPA — amount_zkz is a decimal string end to end. Render by string slicing; a JavaScript number must be unreachable.`,
          });
        }
        if (name === "NumberFormat" && node.object.type === "Identifier" && node.object.name === "Intl") {
          context.report({
            node,
            message: `Intl.NumberFormat in operator SPA — amount_zkz is a decimal string end to end. Render by string slicing; a JavaScript number must be unreachable.`,
          });
        }
      },
    };
  },
};

// Operator-console dead-control ban. A `<button>` with no onClick,
// type="submit", or disabled compiles and renders as clickable but does
// nothing — a control must be wired or explicitly inert.
const buttonMustBeInteractiveOrInert = {
  meta: {
    type: "problem",
    docs: {
      description:
        'every <button> must have onClick, type="submit", or disabled — a control that is none of these renders as clickable but does nothing.',
    },
    schema: [],
  },
  create(context) {
    return {
      JSXOpeningElement(node) {
        if (node.name.type !== "JSXIdentifier" || node.name.name !== "button") return;
        if (node.attributes.some((a) => a.type === "JSXSpreadAttribute")) return;
        const names = new Set(
          node.attributes
            .filter((a) => a.type === "JSXAttribute" && a.name.type === "JSXIdentifier")
            .map((a) => a.name.name),
        );
        const typeAttr = node.attributes.find(
          (a) => a.type === "JSXAttribute" && a.name.name === "type",
        );
        const isSubmit =
          typeAttr?.value?.type === "Literal" && typeAttr.value.value === "submit";
        if (!names.has("onClick") && !names.has("disabled") && !isSubmit) {
          context.report({
            node,
            message:
              '<button> has no onClick, type="submit", or disabled — wire it or make it explicitly inert.',
          });
        }
      },
    };
  },
};

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/coverage/**",
      "**/*.d.ts",
      // Raw byte golden artifacts, digest-pinned and never reformatted.
      "packages/generic-node-contracts/goldens/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // Kept at "warn" deliberately — legitimate `any` use exists at trust
      // boundaries. Ratchet to "error" only after measuring the count.
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          // Intentionally-unused params/vars/catch bindings (e.g. mock
          // signatures like `(_url, _init)`).
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          // `const { droppedField, ...rest } = obj;` destructure-to-omit
          // intentionally leaves `droppedField` unused — that IS the point.
          ignoreRestSiblings: true,
        },
      ],
    },
  },
  {
    // Plain Node.js scripts (build/test-fixture/CLI helpers) — not part of the
    // tsc project graph, so they need their globals declared explicitly.
    files: ["**/*.mjs"],
    languageOptions: {
      globals: globals.node,
    },
  },
  {
    // The operator SPA's service worker runs in a ServiceWorkerGlobalScope, not
    // a window or Node: self/caches/fetch/Response come from that scope.
    files: ["apps/generic-node/admin/public/**/*.js"],
    languageOptions: {
      globals: globals.serviceworker,
    },
  },
  {
    files: ["**/*.{ts,tsx}"],
    plugins: {
      amounts: { rules: { "no-float-amount": noFloatAmount } },
    },
    rules: { "amounts/no-float-amount": "error" },
  },
  {
    files: ["apps/generic-node/admin/src/**/*.tsx"],
    plugins: {
      "admin-ui": {
        rules: { "button-must-be-interactive-or-inert": buttonMustBeInteractiveOrInert },
      },
    },
    rules: { "admin-ui/button-must-be-interactive-or-inert": "error" },
  },
  {
    files: ["apps/generic-node/admin/src/**/*.{ts,tsx}"],
    ignores: ["apps/generic-node/admin/src/**/*.{test,spec}.{ts,tsx}", "apps/generic-node/admin/src/e2e/**"],
    plugins: {
      "amounts-admin": { rules: { "no-float-amount": noFloatAmountAdmin } },
    },
    rules: { "amounts-admin/no-float-amount": "error" },
  },
);
