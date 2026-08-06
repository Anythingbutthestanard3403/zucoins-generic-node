// census + real-PostgreSQL behavioral proof for node-implementer-registry.sql
// The census block binds the frozen invariant inventory to the literal SQL and runs
// always; the live-PostgreSQL block is gated on TEST_DATABASE_URL and discharges the schema-apply
// execution obligations (domain accept/reject, PK/UNIQUE/NOT NULL/CHECK enforcement). psql runs
// as a child process (node:child_process), keeping the in-process network-containment
// guard (setup-network-guard.ts) intact -- exactly as migration-integrity.test.ts does.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  SCHEMA_EXECUTION_OBLIGATIONS,
  NODE_IMPLEMENTER_SCHEMA_FILE,
  NODE_IMPLEMENTER_SCHEMA_INVARIANTS,
} from "../src/schema/node-implementer-registry.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", NODE_IMPLEMENTER_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("node/implementer registry census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = NODE_IMPLEMENTER_SCHEMA_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares exactly the two registry tables and re-declares the pubkey domain", () => {
    expect(sql).toContain("CREATE TABLE nodes (");
    expect(sql).toContain("CREATE TABLE implementers (");
    expect(sql).toMatch(/CREATE DOMAIN padded_base64url_pubkey AS text/);
    // signing-key tables belong to never this slice.
    expect(sql).not.toContain("CREATE TABLE implementer_reporting_keys");
    expect(sql).not.toContain("CREATE TABLE node_signing_keys");
  });

  it("keeps the bare-id PK (no surrogate node_id/implementer_id PK)", () => {
    expect(sql).not.toMatch(/node_id uuid PRIMARY KEY/);
    expect(sql).not.toMatch(/implementer_id uuid PRIMARY KEY/);
  });

  it("mutation negative: removing an anchored clause is caught by the census", () => {
    const mutated = sql.replace("UNIQUE (identity_public_key)", "");
    const missing = NODE_IMPLEMENTER_SCHEMA_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["NODE_IDENTITY_KEY_UNIQUE"]);
  });

  it("schema-apply execution obligations are inventoried and non-trivial", () => {
    expect(SCHEMA_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of SCHEMA_EXECUTION_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});

// A valid padded base64url public key: 43 chars from [A-Za-z0-9_-] then '='.
const VALID_KEY = `${"A".repeat(43)}=`;
const SECOND_KEY = `${"B".repeat(43)}=`;
const NODE_ID = "00000000-0000-0000-0000-000000000001";
const IMPL_ID = "00000000-0000-0000-0000-000000000002";

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

const SCHEMA = "node_implementer_node_implementer_registry";
let reachable = false;

// Runs a statement inside the applied schema. search_path persists across -c args in one
// psql session, so a failing INSERT yields a non-zero status the negative tests assert on.
const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

describe.skipIf(databaseUrl === undefined)("against a live PostgreSQL", () => {
  beforeAll(() => {
    reachable = psql(["-c", "SELECT 1"]).status === 0;
    if (!reachable) return;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    const applied = psql([
      "-c",
      `CREATE SCHEMA ${SCHEMA}`,
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-f",
      sqlPath,
    ]);
    expect(applied.stderr, "greenfield apply should be clean").toBe("");
    expect(applied.status, "greenfield apply should succeed").toBe(0);
    // Baseline rows the negative constraint tests collide against.
    run(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ('${NODE_ID}', 'node one', '${VALID_KEY}')`,
    );
    run(`INSERT INTO implementers (id, name) VALUES ('${IMPL_ID}', 'impl one')`);
  });

  afterAll(() => {
    if (!reachable) return;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
  });

  it("materializes exactly the columns for nodes and implementers", (ctx) => {
    if (!reachable) ctx.skip();
    const columns = (table: string): string[] =>
      psql([
        "-t",
        "-A",
        "-c",
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema = '${SCHEMA}' AND table_name = '${table}'
         ORDER BY ordinal_position`,
      ])
        .stdout.trim()
        .split("\n")
        .filter(Boolean);
    expect(columns("nodes")).toEqual([
      "id",
      "display_name",
      "identity_public_key",
      "created_at",
      "retired_at",
    ]);
    expect(columns("implementers")).toEqual(["id", "name", "created_at", "retired_at"]);
  });

  it("baseline seed rows applied (greenfield apply + valid inserts succeeded)", (ctx) => {
    if (!reachable) ctx.skip();
    const nodeCount = run("SELECT count(*) FROM nodes").stdout;
    expect(run("SELECT count(*) FROM nodes").status).toBe(0);
    expect(nodeCount).toContain("1");
  });

  it("domain accept: a second valid padded base64url key inserts", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO nodes (id, display_name, identity_public_key)
       VALUES ('00000000-0000-0000-0000-0000000000aa', 'node two', '${SECOND_KEY}')`,
    );
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });

  it("domain reject: malformed identity keys are refused by the pubkey domain", (ctx) => {
    if (!reachable) ctx.skip();
    const malformed = [
      `${"A".repeat(42)}=`, // too short (43 chars)
      `${"A".repeat(42)}!=`, // illegal char in body
      "A".repeat(44), // right length, missing '=' pad
    ];
    for (const key of malformed) {
      const result = run(
        `INSERT INTO nodes (id, display_name, identity_public_key)
         VALUES ('00000000-0000-0000-0000-0000000000bb', 'bad', '${key}')`,
      );
      expect(result.status, `key ${JSON.stringify(key)} must be rejected`).not.toBe(0);
      expect(result.stderr).toContain("padded_base64url_pubkey");
    }
  });

  it("unique: a duplicate identity_public_key is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO nodes (id, display_name, identity_public_key)
       VALUES ('00000000-0000-0000-0000-0000000000cc', 'dup key', '${VALID_KEY}')`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/duplicate key|unique/i);
  });

  it("primary key: a duplicate node id is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO nodes (id, display_name, identity_public_key)
       VALUES ('${NODE_ID}', 'dup id', '${"C".repeat(43)}=')`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/duplicate key|nodes_pkey/i);
  });

  it("not null: NULL display_name (nodes) and NULL name (implementers) are rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const node = run(
      `INSERT INTO nodes (id, display_name, identity_public_key)
       VALUES ('00000000-0000-0000-0000-0000000000dd', NULL, '${"D".repeat(43)}=')`,
    );
    expect(node.status).not.toBe(0);
    expect(node.stderr).toMatch(/null value in column "display_name"|not-null/i);
    const impl = run(
      `INSERT INTO implementers (id, name) VALUES ('00000000-0000-0000-0000-0000000000ee', NULL)`,
    );
    expect(impl.status).not.toBe(0);
    expect(impl.stderr).toMatch(/null value in column "name"|not-null/i);
  });

  it("check: retired_at earlier than created_at is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO nodes (id, display_name, identity_public_key, created_at, retired_at)
       VALUES ('00000000-0000-0000-0000-0000000000ff', 'time travel', '${"E".repeat(43)}=',
               '2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z')`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/check constraint/i);
  });
});

/* ─── fail-closed harness guard ─────────────────────────────
 * Same contract as migration-integrity.test.ts's guard: top-level so it runs even when the gated
 * describe skips, and under PG_REQUIRED=1 an unassigned TEST_DATABASE_URL or an unreachable
 * server is a broken harness rather than an absent Postgres. The schema-apply execution obligations this
 * file discharges are real-PostgreSQL properties; a skipped run proves none of them. */
it("schema-apply execution obligations must run against real PostgreSQL under PG_REQUIRED=1", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    databaseUrl,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisioned no test database, so the live block skipped",
  ).toBeDefined();
  expect(
    reachable,
    "PG_REQUIRED=1 but the live block never reached the server — the schema-apply execution obligations went undischarged",
  ).toBe(true);
});
