import type { AddressInfo } from "node:net";
import { execFile } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { afterEach, describe, expect, it, vi } from "vitest";

import { loadStage1Config } from "../src/stage1-config.js";
import {
  startStage1Service,
  type Stage1Service,
} from "../src/stage1-main.js";
import type { BackupSchedulerHandle } from "../src/dr/index.js";

const VALID_BACKUP_KEY = "a".repeat(32);

function productionBackupEnv(
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return {
    NODE_ENV: "production",
    BIND_HOST: "127.0.0.1",
    DATABASE_URL: "postgresql://stage1.invalid/zunode",
    BACKUP_SCHEDULE_ENABLED: "true",
    BACKUP_MASTER_KEY: VALID_BACKUP_KEY,
    BACKUP_OUTPUT_DIR: "/var/lib/generic-node/backups",
    ...overrides,
  };
}

async function call(port: number, path: string, method = "GET"): Promise<{
  readonly body: unknown;
  readonly status: number;
}> {
  const script = `
    const http = require("node:http");
    const request = http.request(
      { host: "127.0.0.1", port: ${port}, path: ${JSON.stringify(path)}, method: ${JSON.stringify(method)} },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => process.stdout.write(JSON.stringify({
          status: response.statusCode,
          body: JSON.parse(Buffer.concat(chunks).toString("utf8"))
        })));
      }
    );
    request.on("error", (error) => { console.error(error); process.exit(1); });
    request.end();
  `;
  const { stdout } = await promisify(execFile)(process.execPath, ["-e", script]);
  return JSON.parse(stdout) as { readonly body: unknown; readonly status: number };
}

// AC#4 / Key-custody — Stage-1 custody census by TypeScript-AST forward module-walk.
//
// The Stage-1 entrypoint (src/stage1-main.ts) is the zero-custody composition
// root and must not be able to reach any Stage-2 signing/vault surface. A fixed
// list of files cannot prove that: stage1-main pulls ./db/client and
// ./db/migrate through *dynamic* import() (see its main()), so a readFileSync
// scan of named files silently prunes those edges and everything they reach.
// This walk starts at the entrypoint and follows every static import /
// export-from AND dynamic import()/require with a string-literal specifier,
// resolving each first-party ".js" specifier to its ".ts" source, so no
// reachable module is pruned. A dynamic import whose specifier is not a string
// literal is unresolvable and fails the census CLOSED rather than hiding a
// possible custody-reaching edge. Custody tokens are matched against AST code
// symbols (identifiers + string literals), never comment trivia — a doc comment
// naming a scrubbed secret (e.g. FUNDED_NODE_SIGNING_KEY in the migration
// classifier's isolation notes) is not a custody reach.
const CUSTODY_TOKENS = [
  "VAULT_MASTER_KEY",
  "PRIVATE_KEY",
  "SIGNING_KEY",
  "GatewaySubmitCapability",
  "enableGatewaySubmit",
] as const;

function resolveFirstPartyModule(fromFile: string, spec: string): string | undefined {
  if (!spec.startsWith(".")) return undefined; // external package / node builtin — boundary leaf
  const base = resolve(dirname(fromFile), spec);
  const candidates = [
    base.replace(/\.js$/, ".ts"),
    base.replace(/\.js$/, ".tsx"),
    base,
    `${base}.ts`,
    join(base, "index.ts"),
  ];
  return candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
}

interface ModuleEdges {
  readonly specifiers: readonly string[];
  readonly computedImports: readonly string[];
}

function moduleEdges(sf: ts.SourceFile): ModuleEdges {
  const specifiers: string[] = [];
  const computedImports: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const ms = node.moduleSpecifier;
      if (ms !== undefined && ts.isStringLiteral(ms)) specifiers.push(ms.text);
    } else if (ts.isImportEqualsDeclaration(node)) {
      const ref = node.moduleReference;
      if (ts.isExternalModuleReference(ref) && ref.expression && ts.isStringLiteral(ref.expression)) {
        specifiers.push(ref.expression.text);
      }
    } else if (ts.isCallExpression(node)) {
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === "require";
      if (isDynamicImport || isRequire) {
        const arg = node.arguments[0];
        if (arg !== undefined && ts.isStringLiteral(arg)) specifiers.push(arg.text);
        else if (isDynamicImport) computedImports.push(node.getText(sf).slice(0, 80));
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return { specifiers, computedImports };
}

function codeSymbols(sf: ts.SourceFile): string[] {
  const symbols: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) || ts.isPrivateIdentifier(node) || ts.isStringLiteralLike(node)) {
      symbols.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return symbols;
}

interface Census {
  readonly reached: readonly string[];
  readonly computedImports: readonly string[];
  readonly unresolvedRelative: readonly string[];
  readonly offenders: readonly string[];
}

function stage1CustodyCensus(entry: string, root: string): Census {
  const visited = new Set<string>();
  const queue = [entry];
  const reached: string[] = [];
  const computedImports: string[] = [];
  const unresolvedRelative: string[] = [];
  const offenders: string[] = [];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (visited.has(file)) continue;
    visited.add(file);
    reached.push(file);
    const sf = ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.ESNext, true);
    const edges = moduleEdges(sf);
    for (const spec of edges.specifiers) {
      if (!spec.startsWith(".")) continue; // boundary leaf
      const resolved = resolveFirstPartyModule(file, spec);
      if (resolved === undefined) unresolvedRelative.push(`${relative(root, file)} -> ${spec}`);
      else queue.push(resolved);
    }
    for (const computed of edges.computedImports) {
      computedImports.push(`${relative(root, file)} :: ${computed}`);
    }
    const symbols = codeSymbols(sf);
    for (const token of CUSTODY_TOKENS) {
      if (symbols.some((symbol) => symbol.includes(token))) {
        offenders.push(`${relative(root, file)} :: ${token}`);
      }
    }
  }
  return { reached, computedImports, unresolvedRelative, offenders };
}

describe("Stage-1 production composition", () => {
  let service: Stage1Service | undefined;

  afterEach(async () => {
    await service?.stop();
    service = undefined;
  });

  it("reaches ready=200 after migrations and constructs the backup scheduler", async () => {
    const config = loadStage1Config(productionBackupEnv());
    expect(config.backup?.enabled).toBe(true);
    expect(config.backup?.outputDir).toBe("/var/lib/generic-node/backups");

    const started = vi.fn();
    const stopped = vi.fn();
    const fakeScheduler: BackupSchedulerHandle = {
      start: started,
      stop: stopped,
      runOnce: async () => {
        throw new Error("not used");
      },
      status: () => ({
        enabled: true,
        running: false,
        lastSuccessAtMs: null,
        lastFailureAtMs: null,
        lastError: null,
        newestArtifactAtMs: null,
        rpoBreached: true,
        consecutiveFailures: 0,
      }),
    };

    const events: string[] = [];
    service = await startStage1Service(
      { ...config, port: 0 },
      {
        runMigrations: async () => {
          events.push("migrated");
        },
        pingDatabase: async () => {
          events.push("db");
        },
        closeDatabase: async () => {
          events.push("closed");
        },
        createScheduler: () => fakeScheduler,
        // Composition test — the real pg_dump/psql probe is host-dependent
        // and covered by test/dr/client-probe.test.ts.
        probeBackupClient: async () => ({ ok: true }),
      },
    );

    expect(started).toHaveBeenCalledTimes(1);
    expect(service.backupScheduler).toBe(fakeScheduler);

    const address = service.server.address() as AddressInfo;
    const ready = await call(address.port, "/health/ready");
    expect(ready.status).toBe(200);
    expect(ready.body).toEqual({
      status: "ready",
      stage: "zero-custody",
      checks: { migrations: true, database: true },
    });
    expect(events).toEqual(["migrated", "db"]);

    await service.stop();
    expect(stopped).toHaveBeenCalledTimes(1);
    service = undefined;
    events.push("—");
    expect(events).toContain("closed");
  });

  it("keeps readiness false when the live DB probe fails and mounts no operations", async () => {
    const config = loadStage1Config(productionBackupEnv());
    service = await startStage1Service(
      { ...config, port: 0 },
      {
        runMigrations: async () => {},
        pingDatabase: async () => {
          throw new Error("offline");
        },
        closeDatabase: async () => {},
        createScheduler: () => undefined,
        probeBackupClient: async () => ({ ok: true }),
      },
    );

    const address = service.server.address() as AddressInfo;
    expect((await call(address.port, "/health/ready")).status).toBe(503);
    expect((await call(address.port, "/v1/operations/receive", "POST")).status).toBe(503);
  });

  it("refuses to start with the backup schedule enabled when the client probe fails closed", async () => {
    const config = loadStage1Config(productionBackupEnv());
    await expect(
      startStage1Service(
        { ...config, port: 0 },
        {
          runMigrations: async () => {},
          pingDatabase: async () => {},
          closeDatabase: async () => {},
          createScheduler: () => undefined,
          probeBackupClient: async () => ({ ok: false, reason: "pg_dump not found" }),
        },
      ),
    ).rejects.toThrow(/postgresql-client probe failed.*pg_dump not found/);
  });

  it("dev may omit backup; production refuses spam BACKUP_SCHEDULE_ENABLED=false and /tmp sinks", () => {
    const dev = loadStage1Config({
      NODE_ENV: "development",
      DATABASE_URL: "postgresql://stage1.invalid/zunode",
    });
    expect(dev.backup).toBeUndefined();

    expect(() =>
      loadStage1Config({
        NODE_ENV: "production",
        DATABASE_URL: "postgresql://stage1.invalid/zunode",
        BACKUP_SCHEDULE_ENABLED: "false",
      }),
    ).toThrow(/BACKUP_SCHEDULE_ENABLED=false is forbidden/);

    expect(() =>
      loadStage1Config({
        NODE_ENV: "production",
        DATABASE_URL: "postgresql://stage1.invalid/zunode",
      }),
    ).toThrow(/BACKUP_MASTER_KEY/);

    expect(() =>
      loadStage1Config(
        productionBackupEnv({
          BACKUP_OUTPUT_DIR: "/tmp/backups",
        }),
      ),
    ).toThrow(/must not be under \/tmp/);
  });

  it("Stage-1 entrypoint reaches no Stage-2 custody surface via any static or dynamic import (AC#4/Key-custody)", () => {
    const root = fileURLToPath(new URL("../", import.meta.url));
    const census = stage1CustodyCensus(join(root, "src/stage1-main.ts"), root);
    const reachedRel = census.reached.map((file) => relative(root, file));

    // The walk followed the DYNAMIC ./db/client + ./db/migrate edges (stage1-main
    // main() imports them at runtime) that a fixed-file scan prunes — proof the
    // module-resolver walk is genuinely forward-reaching, not a stub over a few
    // hand-named files.
    expect(reachedRel, "dynamic import ./db/client.js must be walked").toContain("src/db/client.ts");
    expect(reachedRel, "dynamic import ./db/migrate.js must be walked").toContain("src/db/migrate.ts");
    expect(census.reached.length).toBeGreaterThan(4);

    // Fail-closed: an unresolvable dynamic or relative edge must not silently
    // prune a possibly PRIVATE_KEY-reaching module.
    expect(census.computedImports, "computed dynamic import — census cannot prove custody-free").toEqual([]);
    expect(census.unresolvedRelative, "unresolvable relative import").toEqual([]);

    // No reachable first-party module NAMES a Stage-2 custody surface.
    expect(census.offenders).toEqual([]);

    // The dedicated backup KEK is intentionally reachable (not vault material),
    // and the Stage-1/Stage-2 split holds: a named zero-custody binary plus a
    // Stage-2-custody default deploy.
    const reachedText = census.reached.map((file) => readFileSync(file, "utf8")).join("\n");
    expect(reachedText).toContain("BACKUP_MASTER_KEY");
    expect(readFileSync(`${root}package.json`, "utf8")).toContain("start:stage1");
    expect(readFileSync(`${root}deploy/deployment.yaml`, "utf8")).toContain("VAULT_MASTER_KEY");
  });

  it("reference deployment pins durable backup PVC + schedule", () => {
    const root = fileURLToPath(new URL("../", import.meta.url));
    const manifest = readFileSync(`${root}deploy/deployment.yaml`, "utf8");
    expect(manifest).toContain("kind: PersistentVolumeClaim");
    expect(manifest).toContain("name: zunode-backups");
    expect(manifest).toContain("BACKUP_SCHEDULE_ENABLED");
    expect(manifest).toContain('value: "true"');
    expect(manifest).toContain("BACKUP_OUTPUT_DIR");
    expect(manifest).toContain("/var/lib/generic-node/backups");
    expect(manifest).toContain("backup-master-key");
    expect(manifest).toContain("claimName: zunode-backups");
    expect(manifest).toContain("mountPath: /var/lib/generic-node/backups");
    // emptyDir remains allowed for /tmp scratch only — not the backup sink.
    expect(manifest).toMatch(/name: tmp[\s\S]*emptyDir:/);
    expect(manifest).not.toMatch(
      /name: backups[\s\S]{0,80}emptyDir/,
    );
    // RWO + Recreate — RollingUpdate maxSurge sticks multi-attach (rework).
    const live = manifest
      .split("\n")
      .filter((line) => !/^\s*#/.test(line))
      .join("\n");
    expect(live).toContain("ReadWriteOnce");
    expect(live).toMatch(/strategy:\s*\n\s*type:\s*Recreate/);
    expect(live).not.toMatch(/type:\s*RollingUpdate/);
    expect(live).not.toMatch(/rollingUpdate:/);
  });
});
