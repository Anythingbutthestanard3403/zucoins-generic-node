import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export interface SourceAlias {
  find: string;
  replacement: string;
}

type ExportConditions = {
  import?: unknown;
  default?: unknown;
  types?: unknown;
};

type ExportTarget = string | ExportConditions;

interface PackageManifest {
  name: string;
  exports: Record<string, ExportTarget>;
}

/** String path from a package `exports` value: a string, or `import` / `default` / `types`. */
export function resolveExportTarget(target: ExportTarget): string {
  if (typeof target === "string") return target;
  for (const key of ["import", "default", "types"] as const) {
    const value = target[key];
    if (typeof value === "string") return value;
  }
  throw new TypeError(
    "package export target is not a string or conditions object with import/default/types",
  );
}

/**
 * Ordered vitest `resolve.alias` entries mapping every export subpath of a workspace package to
 * its `src/` entry point, derived from that package's own `exports` map.
 *
 * Derived rather than hand-listed for two reasons. A subpath added to `exports` later would
 * otherwise keep resolving to `dist/`, which is the stale-build hazard this exists to close: the
 * consumer suites prove the trust boundary, and `pnpm build` and `pnpm test` are separate commands
 * with no ordering guarantee between them. And alias entries match by PREFIX with the first match
 * winning (see CLAUDE.md, "Vitest aliases are duplicated and order-sensitive"), so the list is
 * sorted longest-`find`-first: every subpath necessarily sits above the package-root entry, which
 * can therefore never swallow `@zucoins/node-core/verifier/consumer` into
 * `.../src/index.ts/verifier/consumer`.
 *
 * `packageDirUrl` must carry its trailing slash — it is resolved against, not replaced.
 */
export function packageSourceAliases(packageDirUrl: URL): SourceAlias[] {
  const manifest = JSON.parse(
    readFileSync(new URL("package.json", packageDirUrl), "utf8"),
  ) as PackageManifest;

  return Object.entries(manifest.exports)
    .map(([subpath, target]) => {
      const resolved = resolveExportTarget(target);
      return {
        find: subpath === "." ? manifest.name : `${manifest.name}/${subpath.slice("./".length)}`,
        replacement: fileURLToPath(
          new URL(resolved.replace(/^\.\/dist\//, "src/").replace(/\.js$/, ".ts"), packageDirUrl),
        ),
      };
    })
    .sort((left, right) => right.find.length - left.find.length);
}
