import { globSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { expectRejects } from "../testkit/freeze.ts";
import { EXECUTION_TIMEOUTS } from "../testkit/executionPolicy.ts";
import { readIfPresent } from "../testkit/realTreeScan.ts";
import { countExemptionMarkers, EXEMPTION_MARKER_PREFIX, SCAN_SCOPE } from "../scan/forbidden-terms.ts";
import { RETIRED_ROUTES_NON_PATH_CATEGORY } from "../operations/routes.contract.ts";
import { CUSTODY_BINDING_OBLIGATIONS } from "../custody/predicates.contract.ts";
import { CUTOVER_GATE, FORBIDDEN_LAUNCH_CAPABILITY_VERBS } from "./deferral.contract.ts";
import {
  ABSENCE_LINE_ALLOWLIST,
  ABSENCE_SURFACE_CLASSES,
  DEPLOY_FILE_EXTENSIONS,
  DEPLOY_SCAN_SCOPE,
  IDENTIFIER_EXEMPT_FILES,
  IMPORTED_KEY_ORIGIN,
  SCOPE_FILE_EXTENSIONS,
  scanFileForAbsenceSurfaces,
  type AbsenceScanInput,
  type AbsenceSurfaceClass,
} from "./absence-census.ts";

/**
 * The walk: every TypeScript/SQL file under the scan-scope freeze frozen three-dir scope, plus the
 * tolerate-absent deployment-script scope (today both deploy globs resolve empty — the walk
 * itself proves tolerance). Same globSync-over-SCAN_SCOPE idiom as
 * ../scan/generic-core.scan-gate.test.ts.
 */
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const here = dirname(fileURLToPath(import.meta.url));

/**
 * Never its own scan target: this module pair (the scanner's fixtures necessarily contain
 * the signatures it hunts) and the src/scan/** scanner directory itself (its files cite the
 * forbidden vocabulary in comments and history by design) — the same self-reference
 * exclusion every sibling gate (generic-core.scan-gate, forbidden-terms, network-egress)
 * already carries.
 */
const SELF_EXCLUDED_BASENAMES = ["absence-census.ts", "absence.census.test.ts"] as const;
const SCANNER_DIR_SEGMENT = `${join("src", "scan")}/`;

/**
 * Computed lazily at test time, not at collect time: the walked node-core/apps roots are a live
 * working tree, so a collect-time glob can capture a path that no longer exists when the test
 * reads it (the cross-file-flake class — operations.drift-gate.test.ts produced it directly until
 * its positive controls moved to `mkdtemp`). A late glob shrinks the window; readIfPresent
 * (../testkit/realTreeScan.ts, shared with every sibling gate since) closes it — a file
 * vanishing mid-run was never committed tree content.
 */
const walkScopeFiles = (): string[] => {
  const scopeFiles = SCAN_SCOPE.flatMap((scopePath) =>
    SCOPE_FILE_EXTENSIONS.flatMap((extension) =>
      globSync(join(repoRoot, scopePath, "**", `*.${extension}`)),
    ),
  );
  const deployFiles = DEPLOY_SCAN_SCOPE.flatMap((scopePath) =>
    DEPLOY_FILE_EXTENSIONS.flatMap((extension) =>
      globSync(join(repoRoot, scopePath, "**", `*.${extension}`)),
    ),
  );
  return [...scopeFiles, ...deployFiles].filter(
    (file) =>
      !SELF_EXCLUDED_BASENAMES.some((selfName) => file.endsWith(selfName)) &&
      !file.includes(SCANNER_DIR_SEGMENT),
  );
};

const REMOVAL_VERB = FORBIDDEN_LAUNCH_CAPABILITY_VERBS[1];

const assertNoAbsenceViolations = (inputs: readonly AbsenceScanInput[]): void => {
  const violations = inputs.flatMap((input) => scanFileForAbsenceSurfaces(input));
  if (violations.length > 0) {
    const first = violations[0];
    throw new Error(
      `absence census found ${violations.length} surface violation(s); first: ${first?.surfaceClass} at ${first?.file}:${first?.line}`,
    );
  }
};

/** Plants a synthetic fixture tree in a TEMP dir — the real tree is never mutated. */
const withTempTree = (
  files: Readonly<Record<string, string>>,
  run: (paths: readonly string[]) => void,
): void => {
  const tmp = mkdtempSync(join(tmpdir(), "absence-census-absence-census-"));
  try {
    const paths = Object.entries(files).map(([name, contents]) => {
      const filePath = join(tmp, name);
      mkdirSync(dirname(filePath), { recursive: true });
      writeFileSync(filePath, contents);
      return filePath;
    });
    run(paths);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
};

const classesFor = (filePath: string, text: string): AbsenceSurfaceClass[] =>
  scanFileForAbsenceSurfaces({ filePath, text }).map((violation) => violation.surfaceClass);

// Every case below walks and reads the real tree (~1,200 files, synchronous) — the realTree
// class in ../testkit/executionPolicy.ts, whose budget is set from the measured worst case.
describe("import/removal absence census (the launch-deferral absence census, the launch-deferral/route-policy rule, R-04)", { timeout: EXECUTION_TIMEOUTS.realTree }, () => {
  it("walks the frozen three-dir scope plus tolerate-absent deploy scope (guards against an empty/broken glob)", () => {
    const walkedFiles = walkScopeFiles();
    expect(walkedFiles.length).toBeGreaterThan(0);
    const contractsPrefix = join(repoRoot, "packages", "generic-node-contracts", "src");
    expect(walkedFiles.some((file) => file.startsWith(contractsPrefix))).toBe(true);
  });

  it("walks only the frozen v2 scope — never the frozen rule-frozen apps/node v1 tree", () => {
    const allowedRoots = [...SCAN_SCOPE, ...DEPLOY_SCAN_SCOPE].map((scope) =>
      join(repoRoot, scope),
    );
    const v1TreeSegment = `${join("apps", "node")}/`;
    for (const file of walkScopeFiles()) {
      expect(allowedRoots.some((root) => file.startsWith(root))).toBe(true);
      expect(file.includes(v1TreeSegment)).toBe(false);
    }
  });

  it("the current tree carries zero import/removal surface violations across the frozen scope", () => {
    const violations = walkScopeFiles().flatMap((file) => {
      const text = readIfPresent(file);
      if (text === undefined) {
        return [];
      }
      return scanFileForAbsenceSurfaces({ filePath: file, text });
    });
    expect(violations).toEqual([]);
  });

  it("gives RETIRED_ROUTES_NON_PATH_CATEGORY ('any import endpoint') an executable check", () => {
    expect(RETIRED_ROUTES_NON_PATH_CATEGORY).toBe("any import endpoint");
    expect(RETIRED_ROUTES_NON_PATH_CATEGORY).toContain(FORBIDDEN_LAUNCH_CAPABILITY_VERBS[0]);
    const probes = [
      "/v1/wallets/import",
      "/v1/import",
      "/v1/imports",
      "/v1/walletImport",
      "/v1/wallets/import-wallet",
    ];
    for (const probe of probes) {
      expect(classesFor("probe.ts", `{ method: "POST", path: "${probe}" }`)).toContain(
        "route_path",
      );
    }
  });

  it("cross-references the launch-deferral concern.2 schema guard — asserted exercised, never re-implemented", () => {
    const custodySqlPath = join(
      repoRoot,
      "packages",
      "node-core",
      "src",
      "schema",
      "custody-eligibility.sql",
    );
    const custodySql = readFileSync(custodySqlPath, "utf8");
    expect(custodySql).toContain("destinations_custody_insert_guard");
    expect(custodySql).toContain("custody_reject_destination_insert");
    expect(custodySql).toContain("CUSTODY_DESTINATION_ORIGIN_REJECTED");
    expect(custodySql).toContain("IS DISTINCT FROM 'node_generated'");
    expect(CUSTODY_BINDING_OBLIGATIONS.importedDestinationInsert).toBe("REJECT");
    expect(IMPORTED_KEY_ORIGIN).toBe(CUTOVER_GATE.reserved_enum_value);
    expect(walkScopeFiles()).toContain(custodySqlPath);
    expect(scanFileForAbsenceSurfaces({ filePath: custodySqlPath, text: custodySql })).toEqual([]);
  });

  it("every IDENTIFIER_EXEMPT_FILES entry still resolves to a walked file (staleness guard)", () => {
    for (const suffix of IDENTIFIER_EXEMPT_FILES) {
      expect(
        walkScopeFiles().some((file) => file.endsWith(suffix)),
        `identifier-exempt freeze file not found in scan scope: ${suffix}`,
      ).toBe(true);
    }
  });

  it("every ABSENCE_LINE_ALLOWLIST entry is still present verbatim (staleness guard)", () => {
    for (const entry of ABSENCE_LINE_ALLOWLIST) {
      const file = walkScopeFiles().find((candidate) => candidate.endsWith(entry.relativePath));
      expect(file, `allowlisted file not found in scan scope: ${entry.relativePath}`).toBeDefined();
      const lines = readFileSync(file as string, "utf8")
        .split("\n")
        .map((line) => line.trim());
      expect(lines, `allowlist entry no longer present verbatim: ${entry.relativePath}`).toContain(
        entry.content,
      );
    }
  });

  it("adds no contract-allow markers of its own — the scan/dependency-boundary gate's FROZEN_EXEMPTION_COUNT stays untouched", () => {
    const selfFiles = [
      join(here, "absence-census.ts"),
      join(here, "absence.census.test.ts"),
    ];
    const markers = selfFiles.reduce(
      (total, file) => total + countExemptionMarkers(readFileSync(file, "utf8")),
      0,
    );
    expect(markers).toBe(0);
  });

  it("exposes exactly the five surface signature classes", () => {
    expect(ABSENCE_SURFACE_CLASSES).toEqual([
      "route_path",
      "command_name",
      "capability_identifier",
      "origin_write",
      "surface_file_name",
    ]);
  });
});

describe("absence census: false-positive guards", () => {
  it("never fires on ordinary ES-module vocabulary or read-side origin checks", () => {
    const text = [
      'import { createNodeCore } from "@zucoins/node-core";',
      'import type { RouteEntry } from "./routes.contract.ts";',
      'const origins = ["node_generated", "imported"];',
      'const importedWallet = { keyOrigin: "node_generated" };',
      "if (wallet.key_origin === 'imported') reject(wallet);",
      "CREATE TYPE wallet_key_origin AS ENUM ('node_generated', 'imported');",
      'expect(route.path.toLowerCase().includes("import")).toBe(false);',
      "// an import endpoint must never exist; the imported enum stays inert",
    ].join("\n");
    expect(scanFileForAbsenceSurfaces({ filePath: "fixture.ts", text })).toEqual([]);
  });

  it("skips content classes in test modules (the package's synthetic-citation home) but not file names", () => {
    expect(classesFor("thing.test.ts", 'const x = "wallet-import";')).toEqual([]);
    expect(classesFor("wallet-import.test.ts", "")).toEqual(["surface_file_name"]);
  });

  it("exempts capability identifiers only inside the existing freeze files", () => {
    const text = "const pair = WALLET_IMPORT;";
    expect(classesFor(join("operations", "capabilities.contract.ts"), text)).toEqual([]);
    expect(classesFor(join("launch-deferral", "deferral.contract.ts"), text)).toEqual([]);
    expect(classesFor(join("anywhere", "new-surface.ts"), text)).toEqual([
      "capability_identifier",
    ]);
  });

  it("the line allowlist exempts only the exact pinned line", () => {
    expect(ABSENCE_LINE_ALLOWLIST.length).toBeGreaterThan(0);
    for (const entry of ABSENCE_LINE_ALLOWLIST) {
      expect(classesFor(entry.relativePath, entry.content)).toEqual([]);
      expect(classesFor(entry.relativePath, `${entry.content} // drifted`).length).toBeGreaterThan(0);
    }
  });
});

describe("absence census: planted-surface fixtures (negative path)", () => {
  it("rejects a planted import route present in a fixture tree (negative path)", () => {
    withTempTree(
      { "routes.ts": 'export const routes = [{ method: "POST", path: "/v1/wallets/import" }];\n' },
      (paths) => {
        expectRejects(
          () =>
            paths.map((filePath) => ({ filePath, text: readFileSync(filePath, "utf8") })),
          (inputs) => assertNoAbsenceViolations(inputs),
        );
      },
    );
  });

  it("catches every checklist surface shape: route, command, migration, seed, signer, generated client", () => {
    const fixtures: Readonly<Record<string, string>> = {
      [join("src", "routes.ts")]: '{ method: "POST", path: "/v1/wallets/import" }',
      [join("src", "cli.ts")]: 'program.command("wallet-import");',
      [join("migrations", "003_wallet_import.sql")]:
        "INSERT INTO wallets (wallet_id, node_id, public_key, key_origin) VALUES ('a', 'b', 'c', 'imported');",
      [join("seeds", "import-wallet-seed.ts")]: 'await seed({ keyOrigin: "imported" });',
      [join("src", "signer.ts")]: "export function importWallet() {}",
      [join("gen", "client.ts")]: 'post("/v1/wallets/import");',
    };
    withTempTree(fixtures, (paths) => {
      const classesByPath = new Map(
        paths.map((filePath) => [
          filePath,
          classesFor(filePath, readFileSync(filePath, "utf8")),
        ]),
      );
      const expectClasses = (name: string, expected: AbsenceSurfaceClass[]): void => {
        const filePath = paths.find((candidate) => candidate.endsWith(name));
        expect(filePath, `fixture not planted: ${name}`).toBeDefined();
        for (const surfaceClass of expected) {
          expect(classesByPath.get(filePath as string)).toContain(surfaceClass);
        }
      };
      expectClasses("routes.ts", ["route_path"]);
      expectClasses("cli.ts", ["command_name"]);
      expectClasses("003_wallet_import.sql", ["surface_file_name", "origin_write"]);
      expectClasses("import-wallet-seed.ts", ["surface_file_name", "origin_write"]);
      expectClasses("signer.ts", ["capability_identifier"]);
      expectClasses("client.ts", ["route_path"]);
      expectRejects(
        () => paths.map((filePath) => ({ filePath, text: readFileSync(filePath, "utf8") })),
        (inputs) => assertNoAbsenceViolations(inputs),
      );
    });
  });

  it("catches removal-side surfaces derived from the frozen verb pair", () => {
    const text = [
      `{ method: "POST", path: "/admin/v1/${REMOVAL_VERB}s" }`,
      `program.command("wallet-${REMOVAL_VERB}");`,
      `export function ${REMOVAL_VERB}Wallet() {}`,
      `export const ${REMOVAL_VERB}Imported = 1;`,
    ].join("\n");
    const classes = classesFor("fixture.ts", text);
    expect(classes).toContain("route_path");
    expect(classes).toContain("command_name");
    expect(classes).toContain("capability_identifier");
  });

  it("catches camelCase evasions across classes", () => {
    const text = [
      "export const walletImport = async () => {};",
      "export function importWallet() {}",
      'const client = { path: "/v1/walletImport" };',
      'program.command("importWallet");',
    ].join("\n");
    const classes = classesFor("fixture.ts", text);
    expect(classes).toContain("capability_identifier");
    expect(classes).toContain("route_path");
    expect(classes).toContain("command_name");
  });

  it("catches a deployment-script surface once one exists (tolerate-absent scope arms it)", () => {
    const classes = classesFor(
      join("apps", "generic-node", "deploy", "import-wallet.sh"),
      'run("wallet-import", "--key", "./key.json");',
    );
    expect(classes).toContain("surface_file_name");
    expect(classes).toContain("command_name");
  });

  it("honors the exemption-marker idiom (frozen citations carry zero authority)", () => {
    const text = `const RETIRED = "/admin/v1/${REMOVAL_VERB}s*"; // ${EXEMPTION_MARKER_PREFIX}fixture-citation`;
    expect(scanFileForAbsenceSurfaces({ filePath: "fixture.ts", text })).toEqual([]);
  });
});
