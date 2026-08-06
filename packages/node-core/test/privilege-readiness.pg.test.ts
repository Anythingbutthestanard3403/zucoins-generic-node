// real-PostgreSQL proof of the fail-closed privilege readiness gate.
// Gated on TEST_DATABASE_URL (provisioned by vitest.global-setup.ts). psql runs as a
// child process so the in-process network-containment guard stays intact.
//
// Roles are cluster-wide: tests never DROP node_core_app (other databases may hold grants
// to it). The role-absent path uses a never-created probe name. When the connecting role
// lacks CREATEROLE, privileges.sql degrades to NOTICE and tests that need the role skip
// rather than false-fail — the unit suite still covers the refuse-when-absent branch.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  assertPrivilegeReadiness,
  PrivilegeReadinessError,
  type PrivilegeSqlExecutor,
} from "../src/data/privilege-readiness.ts";
import { PRIVILEGES_SCHEMA_FILE } from "../src/schema/privileges.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const privilegesSqlPath = resolve(here, "../src/schema", PRIVILEGES_SCHEMA_FILE);
const registrySqlPath = resolve(here, "../src/schema/node-implementer-registry.sql");
const databaseUrl = process.env.TEST_DATABASE_URL;

const pgEnv = (): Record<string, string> => {
  const url = new URL(databaseUrl as string);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  env.PGHOST = url.hostname;
  env.PGPORT = url.port || "5432";
  env.PGUSER = decodeURIComponent(url.username);
  env.PGPASSWORD = decodeURIComponent(url.password);
  env.PGDATABASE = url.pathname.replace(/^\//, "");
  return env;
};

interface PsqlResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

const psql = (args: readonly string[]): PsqlResult => {
  try {
    const stdout = execFileSync("psql", ["-v", "ON_ERROR_STOP=1", "-q", ...args], {
      env: pgEnv(),
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 15_000,
    });
    return { status: 0, stdout: stdout.toString(), stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: err.status ?? 1,
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? String(error),
    };
  }
};

/** psql -t -A single-value query via the TEST_DATABASE_URL connection. */
const qAt = (sql: string): string => {
  const result = psql(["-t", "-A", "-c", sql]);
  if (result.status !== 0) {
    throw new Error(`psql failed: ${result.stderr || result.stdout}`);
  }
  return result.stdout.trim();
};

/**
 * PrivilegeSqlExecutor backed by psql -t -A JSON output. Avoids importing `pg` (
 * network-containment: no driver in this package). Params are substituted as dollar-quoted
 * literals after a strict alphabet check — tests never pass untrusted input here.
 */
function psqlExecutor(): PrivilegeSqlExecutor {
  return {
    async query<R>(text: string, params: readonly unknown[] = []): Promise<{ rows: R[] }> {
      let sql = text;
      // Replace $n placeholders back-to-front so $10 is not partially eaten by $1.
      // Params are restricted to [A-Za-z0-9_]+ so a single-quoted literal is safe.
      for (let n = params.length; n >= 1; n -= 1) {
        const value = params[n - 1];
        if (typeof value !== "string" || !/^[A-Za-z0-9_]+$/.test(value)) {
          throw new Error(`refusing non-identifier param $${n}: ${String(value)}`);
        }
        sql = sql.replaceAll(`$${n}`, `'${value}'`);
      }
      // Wrap so multi-row results come back as a JSON array of objects.
      const wrapped = `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json) FROM (${sql}) q`;
      const raw = qAt(wrapped);
      const rows = JSON.parse(raw === "" ? "[]" : raw) as R[];
      return { rows: Array.isArray(rows) ? rows : [] };
    },
  };
}

const SCHEMA = "privilege_readiness_privilege_readiness";
let reachable = false;
let appRoleExists = false;

describe.skipIf(databaseUrl === undefined)("privilege readiness (real Postgres)", () => {
  beforeAll(() => {
    reachable = psql(["-c", "SELECT 1"]).status === 0;
    if (!reachable) return;

    // Apply privileges.sql (cluster role + public grants). May NOTICE without CREATEROLE.
    const privApplied = psql(["-f", privilegesSqlPath]);
    expect(privApplied.status, `privileges.sql apply: ${privApplied.stderr}`).toBe(0);

    appRoleExists = qAt("select exists (select 1 from pg_roles where rolname = 'node_core_app')") === "t";

    // Materialize two public tables the revoke scan covers (nodes/implementers), then
    // re-apply the REVOKE half so tables created after the first privileges.sql run are
    // covered even when ALTER DEFAULT PRIVILEGES did not attach (role-owner mismatch).
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    // Tables must live in public for privileges.sql's grant target. Use a unique prefix
    // so concurrent lanes do not collide, and drop them in afterAll.
    psql([
      "-c",
      `DROP TABLE IF EXISTS public.privilege_readiness_nodes CASCADE`,
      "-c",
      `DROP TABLE IF EXISTS public.privilege_readiness_implementers CASCADE`,
      "-c",
      `CREATE TABLE public.privilege_readiness_nodes (id uuid PRIMARY KEY)`,
      "-c",
      `CREATE TABLE public.privilege_readiness_implementers (id uuid PRIMARY KEY)`,
    ]);

    if (appRoleExists) {
      const regrant = psql([
        "-c",
        `GRANT SELECT, INSERT, UPDATE ON public.privilege_readiness_nodes, public.privilege_readiness_implementers TO node_core_app`,
        "-c",
        `REVOKE DELETE, TRUNCATE ON public.privilege_readiness_nodes, public.privilege_readiness_implementers FROM node_core_app`,
      ]);
      expect(regrant.status, regrant.stderr).toBe(0);
    }

    // registry SQL is only read to keep the path live in the module graph / avoid unused.
    expect(readFileSync(registrySqlPath, "utf8").length).toBeGreaterThan(0);
  });

  afterAll(() => {
    if (!reachable) return;
    psql([
      "-c",
      `DROP TABLE IF EXISTS public.privilege_readiness_nodes CASCADE`,
      "-c",
      `DROP TABLE IF EXISTS public.privilege_readiness_implementers CASCADE`,
      "-c",
      `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`,
    ]);
  });

  it("allows boot on a database with role present and revokes intact", async (ctx) => {
    if (!reachable) ctx.skip();
    if (!appRoleExists) ctx.skip();
    await expect(assertPrivilegeReadiness(psqlExecutor())).resolves.toBeUndefined();
  });

  it("refuses boot when the runtime role does not exist", async (ctx) => {
    if (!reachable) ctx.skip();
    await expect(
      assertPrivilegeReadiness(psqlExecutor(), { roleName: "node_core_app_absent_probe" }),
    ).rejects.toThrow(/role "node_core_app_absent_probe" does not exist/);
    await expect(
      assertPrivilegeReadiness(psqlExecutor(), { roleName: "node_core_app_absent_probe" }),
    ).rejects.toBeInstanceOf(PrivilegeReadinessError);
  });

  it("refuses boot when DELETE is re-granted, allows it again after REVOKE", async (ctx) => {
    if (!reachable) ctx.skip();
    if (!appRoleExists) ctx.skip();

    const grant = psql(["-c", "GRANT DELETE ON public.privilege_readiness_nodes TO node_core_app"]);
    expect(grant.status).toBe(0);
    await expect(assertPrivilegeReadiness(psqlExecutor())).rejects.toThrow(
      /privilege_readiness_nodes \(DELETE\)/,
    );

    const revoke = psql(["-c", "REVOKE DELETE ON public.privilege_readiness_nodes FROM node_core_app"]);
    expect(revoke.status).toBe(0);
    await expect(assertPrivilegeReadiness(psqlExecutor())).resolves.toBeUndefined();
  });

  it("refuses boot when TRUNCATE is re-granted on a covered table", async (ctx) => {
    if (!reachable) ctx.skip();
    if (!appRoleExists) ctx.skip();

    const grant = psql([
      "-c",
      "GRANT TRUNCATE ON public.privilege_readiness_implementers TO node_core_app",
    ]);
    expect(grant.status).toBe(0);
    await expect(assertPrivilegeReadiness(psqlExecutor())).rejects.toThrow(
      /privilege_readiness_implementers \(TRUNCATE\)/,
    );
    // Clean up so later suites see a clean grant state.
    psql(["-c", "REVOKE TRUNCATE ON public.privilege_readiness_implementers FROM node_core_app"]);
  });
});

// Loud fail under PG_REQUIRED=1 when global-setup did not assign a URL (pattern).
describe("privilege readiness PG gate", () => {
  it("is assigned TEST_DATABASE_URL when PG_REQUIRED=1", () => {
    if (process.env.PG_REQUIRED === "1" && databaseUrl === undefined) {
      throw new Error(
        "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisions it when Postgres is reachable",
      );
    }
    expect(true).toBe(true);
  });
});
