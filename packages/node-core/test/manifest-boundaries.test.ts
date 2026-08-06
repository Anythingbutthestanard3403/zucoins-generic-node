import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { FORBIDDEN_DEPENDENCY_FRAGMENTS, FORBIDDEN_PACKAGE_NAMES } from "./boundary-rules.js";

// The nine product projections /(3) forbid the generic core from coupling to.
// Hard-coded here as an independent drift tripwire: if the canonical FORBIDDEN_TERMS or the
// derivation in boundary-rules.ts ever narrows below this set, the manifest gate fails
// loudly instead of passing green over its own gap (the -FAIL mode).
const D91_FORBIDDEN_PROJECTIONS = [
  "checkout",
  "payment",
  "sweep",
  "treasury",
  "refund",
  "payout",
  "withdrawal",
  "reservation",
  "order",
] as const;

type JsonObject = Record<string, unknown>;

interface ManifestDependency {
  readonly name: string;
  readonly target: string;
}

function parseJsonObject(file: string): JsonObject {
  const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`expected JSON object in ${file}`);
  }
  return parsed as JsonObject;
}

function manifestDependencies(manifest: JsonObject): ManifestDependency[] {
  const sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
  return sections.flatMap((section) => {
    const value = manifest[section];
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return [];
    }
    return Object.entries(value).map(([name, target]) => ({ name, target: String(target) }));
  });
}

function packageLeafName(name: string): string {
  if (!name.startsWith("@")) {
    return name;
  }
  const slash = name.indexOf("/");
  if (slash === -1 || slash === name.length - 1) {
    return name;
  }
  return name.slice(slash + 1);
}

function npmAliasPackageName(target: string): string | undefined {
  if (!target.startsWith("npm:")) {
    return undefined;
  }
  const alias = target.slice("npm:".length);
  if (alias === "") {
    return undefined;
  }
  if (!alias.startsWith("@")) {
    const versionStart = alias.indexOf("@");
    return versionStart === -1 ? alias : alias.slice(0, versionStart);
  }
  const slash = alias.indexOf("/");
  if (slash === -1) {
    return alias;
  }
  const versionStart = alias.indexOf("@", slash + 1);
  return versionStart === -1 ? alias : alias.slice(0, versionStart);
}

function isForbiddenPackageName(name: string): boolean {
  const leaf = packageLeafName(name).toLowerCase();
  return FORBIDDEN_PACKAGE_NAMES.some((forbidden) => leaf === forbidden);
}

function forbiddenManifestDependencies(
  dependencies: readonly ManifestDependency[],
): ManifestDependency[] {
  return dependencies.filter(({ name, target }) => {
    const fullSpecifier = `${name}:${target}`.toLowerCase();
    if (isForbiddenPackageName(name)) {
      return true;
    }
    const aliasPackage = npmAliasPackageName(target);
    if (aliasPackage !== undefined) {
      if (isForbiddenPackageName(aliasPackage)) {
        return true;
      }
      const lowerAliasPackage = aliasPackage.toLowerCase();
      return FORBIDDEN_DEPENDENCY_FRAGMENTS.some(
        (fragment) =>
          fragment.startsWith("@") && lowerAliasPackage === fragment.toLowerCase(),
      );
    }
    return FORBIDDEN_DEPENDENCY_FRAGMENTS.some((fragment) =>
      fullSpecifier.includes(fragment.toLowerCase()),
    );
  });
}

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const nodeCoreManifest = resolve(repoRoot, "packages/node-core/package.json");
const appManifest = resolve(repoRoot, "apps/generic-node/package.json");

describe("package manifest boundaries", () => {
  it("contains no forbidden dependency name, path, or target", () => {
    const dependencies = [nodeCoreManifest, appManifest].flatMap((file) =>
      manifestDependencies(parseJsonObject(file)),
    );
    expect(forbiddenManifestDependencies(dependencies)).toEqual([]);
  });

  it("contains no forbidden fragment elsewhere in either manifest", () => {
    const violations = [nodeCoreManifest, appManifest].flatMap((file) => {
      const text = readFileSync(file, "utf8").toLowerCase();
      return FORBIDDEN_DEPENDENCY_FRAGMENTS.filter((fragment) =>
        text.includes(fragment.toLowerCase()),
      ).map((fragment) => ({ file, fragment }));
    });
    expect(violations).toEqual([]);
  });

  it("does not export the offline testkit as a production package path", () => {
    const manifest = parseJsonObject(nodeCoreManifest);
    const packageExports = manifest.exports;
    expect(packageExports).toBeTypeOf("object");
    expect(packageExports).not.toBeNull();
    expect((packageExports as JsonObject)["./testkit"]).toBeUndefined();
  });

  it("detects a forbidden target hidden behind a neutral dependency name", () => {
    const fixture = {
      dependencies: { "neutral-name": "file:../../apps/platform" },
    } satisfies JsonObject;
    const dependencies = manifestDependencies(fixture);
    expect(forbiddenManifestDependencies(dependencies)).toEqual(dependencies);
  });

  it("keeps the denylist a superset of the nine forbidden product projections", () => {
    const missing = D91_FORBIDDEN_PROJECTIONS.filter(
      (term) => !FORBIDDEN_PACKAGE_NAMES.includes(term),
    );
    expect(missing).toEqual([]);
  });

  it("rejects a bare product dependency the prior 6-term denylist missed (treasury)", () => {
    const fixture = { dependencies: { treasury: "1.0.0" } } satisfies JsonObject;
    const dependencies = manifestDependencies(fixture);
    expect(forbiddenManifestDependencies(dependencies)).toEqual(dependencies);
  });

  it("rejects an npm alias to a product package behind a neutral name (sweep)", () => {
    const fixture = { dependencies: { helper: "npm:sweep@1.0.0" } } satisfies JsonObject;
    const dependencies = manifestDependencies(fixture);
    expect(forbiddenManifestDependencies(dependencies)).toEqual(dependencies);
  });

  it("rejects a file: target to a product package path behind a neutral name (withdrawal)", () => {
    const fixture = {
      dependencies: { helper: "file:../../packages/withdrawal-svc" },
    } satisfies JsonObject;
    const dependencies = manifestDependencies(fixture);
    expect(forbiddenManifestDependencies(dependencies)).toEqual(dependencies);
  });

  it.each(FORBIDDEN_PACKAGE_NAMES)("detects the bare forbidden package name %s", (name) => {
    const fixture = {
      dependencies: { [name]: "1.0.0" },
    } satisfies JsonObject;
    const dependencies = manifestDependencies(fixture);
    expect(forbiddenManifestDependencies(dependencies)).toEqual(dependencies);
  });

  it.each(FORBIDDEN_PACKAGE_NAMES)("detects npm alias targets for %s", (name) => {
    const targets = [
      `npm:${name}@1.0.0`,
      `npm:${name}@>=1.0.0 <2.0.0`,
      `npm:@neutral-scope/${name}@^1.0.0`,
    ];
    for (const target of targets) {
      const fixture = {
        dependencies: { "neutral-name": target },
      } satisfies JsonObject;
      const dependencies = manifestDependencies(fixture);
      expect(forbiddenManifestDependencies(dependencies)).toEqual(dependencies);
    }
  });

  it("allows neutral npm alias targets that only contain a forbidden word as a prefix", () => {
    const fixture = {
      dependencies: {
        "neutral-one": "npm:payment-tools@1.0.0",
        "neutral-two": "npm:@neutral-scope/checkout-tools@^2.0.0",
      },
    } satisfies JsonObject;
    expect(forbiddenManifestDependencies(manifestDependencies(fixture))).toEqual([]);
  });
});
