import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { FORBIDDEN_DEPENDENCY_FRAGMENTS } from "./boundary-rules.js";

const PRODUCTION_MODULES = [
  "protocol",
  "data",
  "event-log",
  "gateway",
  "observation",
  "verifier",
  "core",
  "api",
  "operator",
  "push",
  "reporting",
  "proof-body",
  "proof",
  "receive",
  "device",
  "cosign-persist",
  "schema",
  "signing-keys",
  "send",
  "move",
  "leases",
  "workers",
  "http",
  "net",
  "observability",
  "credential",
  "implementer",
  "integration-request",
  "vault",
  "verification",
  "totp",
] as const;
const MODULES = [...PRODUCTION_MODULES, "testkit"] as const;
type ModuleName = (typeof MODULES)[number] | "root";

const ALLOWED_INTERNAL_IMPORTS: Readonly<Record<ModuleName, readonly ModuleName[]>> = {
  root: PRODUCTION_MODULES,
  protocol: [],
  data: ["schema"],
  // Event log is a leaf over protocol event vocabulary only (no reporting/api cycle).
  "event-log": ["protocol"],
  gateway: ["protocol"],
  // Observation capture may surface through api routes and data ports.
  observation: ["protocol"],
  verifier: ["protocol"],
  core: ["protocol", "data", "gateway", "verifier"],
  // GET /v1/events binds the reporting credential pipeline to the
  // implementer-scoped read-service; api may import reporting for that binder only.
  // api/routes/operation-routes maps MoveAdmissionError for MOVE_INTERNAL.
  // Admin recovery inspection/actions live under operator/ and surface via api/.
  // api/routes/operation-routes maps PushSubscriptionRequiredError from push.
  // GET /v1/implementer/identity resolves effective funding pin via implementer/
  // (ZTR-1288); implementer imports only core — no cycle.
  api: ["protocol", "core", "reporting", "move", "operator", "push", "implementer"],
  operator: ["protocol"],
  // Reporting wraps protocol/ed25519-verify for UTF-8 preimage convenience.
  reporting: ["protocol"],
  "proof-body": [],
  // Proof policies compose protocol economic predicates + verifier transaction checks.
  proof: ["protocol", "verifier"],
  // admission uses protocol amount validators. POST /v1/receives transport is
  // api/routes handleCreateReceive (operation-router) — receive/ no longer owns HTTP.
  // receive landing commit runs the oracle and re-verifies each
  // persisted path body (verifier) and derives proof-access expiry (data) — the same two
  // edges the SEND_EXTERNAL landing twin already carries.
  // expiry release delegates proof mint/consume and exact-tuple
  // wallet unpin exclusively to the canonical guarded lease repository. Expiry release
  // reuses verification's canonical durable group-fact reader and release verdict.
  // Receive still needs api for arm-preopen / arm-binding route-schema types.
  // The landing store appends the signed node_events + implementer_events pair
  // inside the landing transaction, so it depends on the event-log leaf. event-log
  // imports only protocol, so this adds no cycle.
  // ZTR-1301: admitReceiveExternal gates NODE_VERIFIED via verification policy port.
  receive: ["protocol", "api", "verifier", "data", "leases", "verification", "event-log"],
  // device enrolment: protocol suite parsers + reporting ed25519 verify.
  device: ["protocol", "reporting"],
  "cosign-persist": [],
  schema: ["data"],
  // signing-key registry + NODE_SIGNING_KEYS seal/open (reuses vault
  // hygiene / root envelope primitives; private seed material never leaves this module).
  "signing-keys": ["vault"],
  // external-send create: builds and signs the frozen zp-send-external-expected-v1
  // tuple via protocol. approval optionally verifies a device signature against the
  // enrolled-device store (type + store ports only — no key material).
  // Send create/approve/landing touches protocol builders, device approval, observation
  // baselines, proof surfaces, and worker handoff ports as landed on main.
  // Landing store adds "event-log": the landing store appends the signed dual-chain terminal
  // event inside the landing transaction. event-log imports only protocol — no cycle.
  // ZTR-1301: createExternalSend gates NODE_VERIFIED via verification policy port.
  send: ["protocol", "device", "verifier", "reporting", "observation", "workers", "data", "proof", "core", "totp", "event-log", "verification"],
  // MOVE_INTERNAL admission: amount/UUID parsers live in protocol.
  // dual-lease acquisition drives the one canonical lease repository rather than
  // re-sorting or re-inserting wallet_active_leases itself. The live point-read reuses
  // core's canonical execution-phase derivation and transaction-material fact reader;
  // move remains read-only across that edge.
  // dual-chain internal_move.created (ZTR-1146) adds event-log — leaf over protocol only.
  // ZTR-1301: createInternalMove gates NODE_VERIFIED via verification policy port.
  move: ["protocol", "leases", "core", "event-log", "verification"],
  // persisted lease foundation: reads frozen schema version/file constants only.
  leases: ["schema"],
  workers: ["protocol", "core", "gateway"],
  // Admin TOTP chain consumes the shared matcher leaf. The login volume throttle
  // (login-rate-limit.ts) reuses reporting's InMemoryReportingRateLimiter rather than
  // minting a second limiter shape, so "am I throttled" has one answer node-wide;
  // reporting imports only protocol, so this adds no cycle.
  http: ["totp", "reporting"],
  net: [],
  observability: [],
  credential: ["proof-body"],
  // Named integration identity registry (create/list/retire + audit). Imports core only
  // for the AuditLogRow shape used by the in-memory adapter; SQL store is leaf-over-SQL.
  implementer: ["core"],
  // Route 2 public handshake store + handlers. Imports api (error envelope,
  // pipeline) + credential (issue shapes) + protocol (amount grammar) +
  // reporting (rate limiter) + schema (status contract). api does not import
  // this module — composition root wires the router.
  "integration-request": ["api", "credential", "protocol", "reporting", "schema"],
  vault: [],
  // verification-complete acknowledgement: reuses the reporting SHA-256 helper for
  // the evidence-set digest and declares its own SqlExecutor port, like every other
  // persist module here. It never imports `leases` — the release decision travels back to the
  // composition root, which drives the proof-backed release itself (the one-in-flight-per-wallet rule).
  // allow-node-verified policy (ZTR-1301) uses protocol UUID parse only.
  verification: ["reporting", "protocol"],
  // Canonical HOTP/window TOTP matcher + TOTP_SECRET seal/rewrap (vault root DEK).
  // Leaf shared by send approval + http chain; seal site mirrors push/signing-keys.
  totp: ["vault"],
  // Web Push declares its own transport ports. Rotation may reuse only vault key-ring
  // primitives for sealed receive material; it cannot reach into the money path.
  push: ["vault"],
  testkit: ["protocol", "data", "gateway", "verifier", "operator"],
};

/** Explicit bipartite cycle the architecture accepts today (ZTR-1167).
 * `data` loads schema pack metadata; `schema` loads migration helpers from `data`.
 * Whole-graph acyclicity treats only this pair as allowed; any other cycle fails the gate.
 */
const ACCEPTED_INTERNAL_CYCLES: ReadonlyArray<readonly [ModuleName, ModuleName]> = [
  ["data", "schema"],
] as const;

interface SourceImport {
  readonly file: string;
  readonly specifier: string;
}

function listTsFiles(dir: string): string[] {
  return (readdirSync(dir, { recursive: true }) as string[])
    .map((entry) => join(dir, entry))
    .filter((file) => extname(file) === ".ts" && statSync(file).isFile());
}

function extractSpecifiers(text: string): string[] {
  const specifiers: string[] = [];
  const staticPattern = /(?:import|export)\s+(?:type\s+)?(?:[^"'`]*?\s+from\s+)?["'`]([^"'`]+)["'`]/g;
  const dynamicPattern = /import\(\s*["'`]([^"'`]+)["'`]\s*\)/g;
  const requirePattern = /\brequire\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g;

  for (const match of text.matchAll(staticPattern)) {
    if (match[1] !== undefined) {
      specifiers.push(match[1]);
    }
  }
  for (const match of text.matchAll(dynamicPattern)) {
    if (match[1] !== undefined) {
      specifiers.push(match[1]);
    }
  }
  for (const match of text.matchAll(requirePattern)) {
    if (match[1] !== undefined) {
      specifiers.push(match[1]);
    }
  }
  return specifiers;
}

function extractImports(file: string): SourceImport[] {
  return extractSpecifiers(readFileSync(file, "utf8")).map((specifier) => ({
    file,
    specifier,
  }));
}

function hasCreateRequire(text: string): boolean {
  return /\bcreateRequire\s*\(/.test(text);
}

function forbiddenFileReferences(files: readonly string[]): Array<{ file: string; fragment: string }> {
  return files.flatMap((file) => {
    const text = readFileSync(file, "utf8");
    return FORBIDDEN_DEPENDENCY_FRAGMENTS.filter((fragment) =>
      text.toLowerCase().includes(fragment.toLowerCase()),
    ).map((fragment) => ({ file, fragment }));
  });
}

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const srcRoot = resolve(repoRoot, "packages/node-core/src");
const appSrcRoot = resolve(repoRoot, "apps/generic-node/src");
const architectureConfigFiles = [
  resolve(repoRoot, "packages/node-core/tsconfig.json"),
  resolve(repoRoot, "apps/generic-node/tsconfig.json"),
];
const sourceFiles = [...listTsFiles(srcRoot), ...listTsFiles(appSrcRoot)];
const sourceImports = sourceFiles.flatMap(extractImports);

function moduleForFile(file: string): ModuleName | undefined {
  const pathFromRoot = relative(srcRoot, file);
  if (!pathFromRoot.includes(sep)) {
    return "root";
  }
  const segment = pathFromRoot.split(sep)[0];
  if (segment !== undefined && MODULES.includes(segment as (typeof MODULES)[number])) {
    return segment as (typeof MODULES)[number];
  }
  // Unregistered src/<dir>/ is a violation entry, not a throw — throwing aborts the
  // import walk inside flatMap and suppresses every direction violation behind it.
  return undefined;
}

function targetModule(source: SourceImport): ModuleName | undefined {
  if (!source.specifier.startsWith(".")) {
    return undefined;
  }
  const absoluteTarget = resolve(dirname(source.file), source.specifier);
  const pathFromRoot = relative(srcRoot, absoluteTarget);
  if (pathFromRoot.startsWith("..")) {
    return undefined;
  }
  const segment = pathFromRoot.split(sep)[0];
  if (segment === "index.js" || segment === "index.ts") {
    return "root";
  }
  if (segment !== undefined && MODULES.includes(segment as (typeof MODULES)[number])) {
    return segment as (typeof MODULES)[number];
  }
  return undefined;
}

interface DirectionViolation {
  readonly source: ModuleName | "<unregistered>";
  readonly target?: ModuleName;
  readonly file: string;
  readonly specifier: string;
}

function directionViolations(imports: readonly SourceImport[]): DirectionViolation[] {
  return imports.flatMap((sourceImport) => {
    if (!sourceImport.file.startsWith(srcRoot)) {
      return [];
    }
    // Colocated *.test.ts under src/ is not a production dependency surface.
    if (sourceImport.file.endsWith(".test.ts")) {
      return [];
    }
    const source = moduleForFile(sourceImport.file);
    if (source === undefined) {
      return [
        {
          source: "<unregistered>",
          file: sourceImport.file,
          specifier: sourceImport.specifier,
        },
      ];
    }
    const target = targetModule(sourceImport);
    if (target === undefined || target === source) {
      return [];
    }
    if (ALLOWED_INTERNAL_IMPORTS[source].includes(target)) {
      return [];
    }
    return [{ source, target, file: sourceImport.file, specifier: sourceImport.specifier }];
  });
}

function forbiddenDependencies(imports: readonly SourceImport[]): SourceImport[] {
  return imports.filter(({ specifier }) =>
    FORBIDDEN_DEPENDENCY_FRAGMENTS.some((fragment) =>
      specifier.toLowerCase().includes(fragment.toLowerCase()),
    ),
  );
}

describe("node-core dependency boundaries", () => {
  it("registers every production source module", () => {
    const sourceModules = readdirSync(srcRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && entry.name !== "testkit")
      .map((entry) => entry.name)
      .sort();
    expect(sourceModules).toEqual([...PRODUCTION_MODULES].sort());
  });

  it.each(MODULES)("has an explicit %s module", (moduleName) => {
    expect(listTsFiles(resolve(srcRoot, moduleName)).length).toBeGreaterThan(0);
  });

  it("classifies schema sources and root-to-schema exports", () => {
    const schemaFile = resolve(srcRoot, "schema/custody-eligibility.contract.ts");
    expect(moduleForFile(schemaFile)).toBe("schema");
    expect(
      targetModule({
        file: resolve(srcRoot, "index.ts"),
        specifier: "./schema/custody-eligibility.contract.js",
      }),
    ).toBe("schema");
  });

  it("treats a schema dependency as a normal leaf-boundary violation", () => {
    const sourceImport = {
      file: resolve(srcRoot, "schema/fixture.ts"),
      specifier: "../protocol/index.js",
    };
    const source = moduleForFile(sourceImport.file);
    const target = targetModule(sourceImport);
    expect(source).toBeDefined();
    expect({ source, target, allowed: ALLOWED_INTERNAL_IMPORTS[source!].includes(target!) }).toEqual({
      source: "schema",
      target: "protocol",
      allowed: false,
    });
  });

  it("reports an unregistered source directory without aborting the direction walk", () => {
    const unregisteredFile = resolve(srcRoot, "not-a-registered-module/create.ts");
    const schemaViolation = {
      file: resolve(srcRoot, "schema/fixture.ts"),
      specifier: "../protocol/index.js",
    };
    const unregisteredImport = {
      file: unregisteredFile,
      specifier: "../protocol/index.js",
    };
    // Direction violation listed after the unregistered import proves the walk continues.
    const violations = directionViolations([unregisteredImport, schemaViolation]);
    expect(moduleForFile(unregisteredFile)).toBeUndefined();
    expect(violations).toEqual([
      {
        source: "<unregistered>",
        file: unregisteredFile,
        specifier: "../protocol/index.js",
      },
      {
        source: "schema",
        target: "protocol",
        file: schemaViolation.file,
        specifier: "../protocol/index.js",
      },
    ]);
  });

  it("keeps every internal import within the allowed direction", () => {
    expect(directionViolations(sourceImports)).toEqual([]);
  });

  it("ALLOWED_INTERNAL_IMPORTS is acyclic except for named accepted cycles", () => {
    const allowedPairs = new Set<string>();
    for (const [from, targets] of Object.entries(ALLOWED_INTERNAL_IMPORTS) as Array<
      [ModuleName, readonly ModuleName[]]
    >) {
      for (const to of targets) {
        allowedPairs.add(`${from}->${to}`);
      }
    }
    for (const [a, b] of ACCEPTED_INTERNAL_CYCLES) {
      expect(allowedPairs.has(`${a}->${b}`)).toBe(true);
      expect(allowedPairs.has(`${b}->${a}`)).toBe(true);
    }
    const acceptedUndirected = new Set(
      ACCEPTED_INTERNAL_CYCLES.map(([a, b]) => [a, b].sort().join("|")),
    );

    // Tarjan-style: any strongly connected component larger than 1, or a 1-node self-loop,
    // is a cycle. Self-loops are never accepted.
    const nodes = Object.keys(ALLOWED_INTERNAL_IMPORTS) as ModuleName[];
    const index = new Map<ModuleName, number>();
    const lowlink = new Map<ModuleName, number>();
    const onStack = new Set<ModuleName>();
    const stack: ModuleName[] = [];
    let next = 0;
    const sccs: ModuleName[][] = [];

    const strongConnect = (v: ModuleName): void => {
      index.set(v, next);
      lowlink.set(v, next);
      next += 1;
      stack.push(v);
      onStack.add(v);
      for (const w of ALLOWED_INTERNAL_IMPORTS[v]) {
        if (!index.has(w)) {
          strongConnect(w);
          lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!));
        } else if (onStack.has(w)) {
          lowlink.set(v, Math.min(lowlink.get(v)!, index.get(w)!));
        }
      }
      if (lowlink.get(v) === index.get(v)) {
        const comp: ModuleName[] = [];
        for (;;) {
          const w = stack.pop()!;
          onStack.delete(w);
          comp.push(w);
          if (w === v) break;
        }
        sccs.push(comp);
      }
    };

    for (const n of nodes) {
      if (!index.has(n)) strongConnect(n);
    }

    const unexpected = sccs.filter((comp) => {
      if (comp.length === 1) {
        const only = comp[0]!;
        return ALLOWED_INTERNAL_IMPORTS[only].includes(only);
      }
      if (comp.length === 2) {
        const key = [...comp].sort().join("|");
        return !acceptedUndirected.has(key);
      }
      return true;
    });
    expect(unexpected).toEqual([]);
  });

  it("contains no product-surface dependency", () => {
    expect(forbiddenDependencies(sourceImports)).toEqual([]);
  });

  it("contains no product-surface alias or project reference in TypeScript configuration", () => {
    expect(forbiddenFileReferences(architectureConfigFiles)).toEqual([]);
  });

  it("prohibits createRequire loaders in production source", () => {
    const violations = sourceFiles.filter((file) =>
      hasCreateRequire(readFileSync(file, "utf8")),
    );
    expect(violations).toEqual([]);
  });

  it("prohibits production source from importing the testkit module", () => {
    const violations = sourceImports.filter((sourceImport) => {
      if (!sourceImport.file.startsWith(srcRoot)) {
        return false;
      }
      return targetModule(sourceImport) === "testkit" && moduleForFile(sourceImport.file) !== "testkit";
    });
    expect(violations).toEqual([]);
  });

  it.each(FORBIDDEN_DEPENDENCY_FRAGMENTS)(
    "detects the forbidden dependency fragment %s",
    (fragment) => {
      const fixture = [{ file: "fixture.ts", specifier: `../../${fragment}/entry.js` }];
      expect(forbiddenDependencies(fixture)).toEqual(fixture);
    },
  );

  it("does not reject the shared protocol library by package scope alone", () => {
    const fixture = [
      { file: "fixture.ts", specifier: "@zupayments/splitchain" },
      { file: "fixture.ts", specifier: "@zupayments/shared" },
    ];
    expect(forbiddenDependencies(fixture)).toEqual([]);
  });

  it("extracts static, dynamic, and CommonJS dependency forms", () => {
    const fixture = [
      'import "alpha";',
      'export { value } from "beta";',
      'const dynamicValue = import("gamma");',
      'const commonValue = require("delta");',
    ].join("\n");
    expect(extractSpecifiers(fixture)).toEqual(["alpha", "beta", "gamma", "delta"]);
  });

  it("detects a createRequire alias fixture", () => {
    expect(
      hasCreateRequire(
        'const localRequire = createRequire(import.meta.url); localRequire("apps/platform");',
      ),
    ).toBe(true);
  });

  it("detects a forbidden TypeScript alias fixture", () => {
    const fixture = JSON.stringify({
      compilerOptions: { paths: { "@core/*": ["../../apps/platform/src/*"] } },
    });
    expect(
      FORBIDDEN_DEPENDENCY_FRAGMENTS.some((fragment) =>
        fixture.toLowerCase().includes(fragment.toLowerCase()),
      ),
    ).toBe(true);
  });

  it("limits the application shell to the core package and its sanctioned drivers", () => {
    const appImports = sourceImports
      .filter(({ file }) => file.startsWith(appSrcRoot))
      // Production-source gate only: colocated *.test.ts under src/ (if any) is not a
      // production dependency surface.
      .filter(({ file }) => !file.endsWith(".test.ts"))
      .filter(({ specifier }) => !specifier.startsWith("node:"))
      .filter(({ specifier }) => !specifier.startsWith("."));
    // Unique-specifier set equality over EXTERNAL imports (node: builtins and app-internal
    // relative imports are out of scope for this gate). sanctions the Postgres
    // driver + drizzle migrator in apps/generic-node only (node-core stays zero-DB); the
    // shell may import those three subpaths in addition to the core package.
    expect([...new Set(appImports.map(({ specifier }) => specifier))].sort()).toEqual(
      [
        "@libpg-query/parser",
        // Recovery-pack export passphrase hardening (argon2id) — app-shell-only,
        // declared in apps/generic-node/package.json.
        "@noble/hashes/argon2.js",
        // Frozen contracts vocabulary consumed by the lab receive surface.
        "@zucoins/generic-node-contracts",
        // Operator-console operations list/detail wire shapes. The app projects rows into
        // the same declaration the SPA renders from, so neither side can invent a field
        // (ZTR-1202: destination_address was read off a summary row nothing populated).
        "@zucoins/generic-node-contracts/admin-inventory",
        "@zucoins/generic-node-contracts/admin-auth-errors",
        // Frozen observation wire vocabulary for SQL anomaly/stream persistence (ZTR-1127).
        "@zucoins/generic-node-contracts/observation",
        "@zucoins/generic-node-contracts/operations",
        "@zucoins/generic-node-contracts/operations/events",
        "@zucoins/generic-node-contracts/operator-halt",
        // Wallet money-capability preset validation (ZTR-1269 admin PATCH).
        "@zucoins/generic-node-contracts/wallet-state",
        "@zucoins/node-core",
        "@zucoins/node-core/data",
        // scrubErrorDetails for the process-level fatal net, and the redacting
        // console adapter both entry points log through (boot/safe-logger.ts).
        // The subpath, not the barrel: both modules are imported by the
        // zero-custody stage1-main.ts, which must not reach a vault/signing/
        // submit surface.
        "@zucoins/node-core/observability",
        "@zucoins/node-core/verifier/consumer",
        "drizzle-orm/node-postgres",
        "drizzle-orm/node-postgres/migrator",
        // aes128gcm decrypt lives in node-core (`decryptWebPushPayload` over
        // http_ece). The app shell no longer imports the ECE library; it only binds the
        // WebPushPayloadDecryptor port. DB drivers remain app-shell-only.
        "pg",
      ].sort(),
    );
  });

  // Follow-up : the allowlist above says which external specifiers the app MAY
  // import; this says they must actually be installable. apps/generic-node is built into a
  // prod-slim image (`pnpm install --prod`), where only DECLARED dependencies are linked.
  // A specifier that resolves locally through pnpm's hoisted store but is absent from
  // package.json passes tsc, passes vitest, and then dies at runtime with
  // ERR_MODULE_NOT_FOUND — caught only after deploy. Adding a specifier to the allowlist
  // without adding the dependency is exactly that mistake, so the two are bound here.
  it("every external specifier the app imports is a declared dependency", () => {
    const pkg = JSON.parse(
      readFileSync(resolve(appSrcRoot, "../package.json"), "utf8"),
    ) as { dependencies?: Record<string, string> };
    const declared = new Set(Object.keys(pkg.dependencies ?? {}));

    const appImports = sourceImports
      .filter(({ file }) => file.startsWith(appSrcRoot))
      .filter(({ file }) => !file.endsWith(".test.ts"))
      .filter(({ specifier }) => !specifier.startsWith("node:"))
      .filter(({ specifier }) => !specifier.startsWith("."));

    // Subpath imports resolve against their package root (`@scope/pkg/sub` → `@scope/pkg`).
    const packageOf = (specifier: string): string => {
      const parts = specifier.split("/");
      return specifier.startsWith("@") ? `${parts[0]}/${parts[1]}` : (parts[0] ?? specifier);
    };

    const undeclared = [
      ...new Set(
        appImports
          .map(({ specifier }) => packageOf(specifier))
          .filter((name) => !declared.has(name)),
      ),
    ].sort();

    expect(
      undeclared,
      "app imports a package absent from apps/generic-node/package.json dependencies — " +
        "it will fail at runtime in the prod-slim image even though tsc and vitest pass",
    ).toEqual([]);
  });
});
