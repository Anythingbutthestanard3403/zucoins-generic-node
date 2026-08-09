// census + real-PostgreSQL behavioural proof for vault-root-kdf-salt.sql (ZTR-1159).
//
// The census block binds the frozen invariant inventory to the literal SQL and runs always.
// The live block is gated on TEST_DATABASE_URL, applies the slice ALONE into a scratch schema
// (it declares no foreign key, so it needs no prerequisite chain) and discharges every
// VAULT_ROOT_KDF_SALT_EXECUTION_OBLIGATION against a real database.
//
// The insert-only claim is the one that matters. A salt row that can be edited in place is the
// same key-loss trap the ticket exists to close: the row would say what boot derives under
// while the envelopes stayed sealed under the old value. "Insert-only by convention" is not a
// property; only an engine-level refusal is, and only a live database can prove it.
//
// psql runs as a child process (node:child_process), keeping the in-process
// network-containment guard (setup-network-guard.ts) intact — exactly as
// migration-integrity.test.ts and vault-store.pg.test.ts do.
//
// No key material crosses this file's database boundary: a salt is not secret.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  VAULT_ROOT_KDF_SALT_EXECUTION_OBLIGATIONS,
  VAULT_ROOT_KDF_SALT_INVARIANTS,
  VAULT_ROOT_KDF_SALT_SCHEMA_FILE,
} from "../src/schema/vault-root-kdf-salt.contract.ts";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const sqlPath = resolve(schemaDir, VAULT_ROOT_KDF_SALT_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

// A `--` comment runs to end of line; strip them so a word appearing only in prose cannot
// satisfy a structural check.
const sqlBody = sql.replace(/--.*$/gm, "");

/* ─── census (no database required) ───────────────────────────────── */

describe("vault root-KDF salt schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = VAULT_ROOT_KDF_SALT_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares exactly the one table and re-declares no prerequisite", () => {
    expect(sqlBody).toContain("CREATE TABLE vault_root_kdf_salt (");
    expect(sqlBody.match(/CREATE TABLE/g)).toHaveLength(1);
    expect(sqlBody).not.toContain("CREATE DOMAIN");
    // A tenant FK would make this row unreadable at vault-unlock on a node whose `nodes` row
    // genesis writes in the same boot.
    expect(sqlBody).not.toMatch(/REFERENCES/);
  });

  it("stores the salt as raw bytes, never as text or a numeric type", () => {
    expect(sqlBody).toMatch(/^\s*salt bytea NOT NULL,$/m);
    expect(sqlBody).not.toMatch(/salt (text|varchar|jsonb|json|numeric)/i);
  });

  it("carries no key material column (the key-custody rule)", () => {
    expect(sqlBody).not.toMatch(
      /private_key|secret_key|\bseed\b|plaintext|key_material|master_key|\bdek\b|root_key|\bmnemonic\b/i,
    );
  });

  it("guards UPDATE, DELETE and TRUNCATE — insert-only at the engine", () => {
    expect(sqlBody).toContain("BEFORE UPDATE ON vault_root_kdf_salt");
    expect(sqlBody).toContain("BEFORE DELETE ON vault_root_kdf_salt");
    expect(sqlBody).toContain("BEFORE TRUNCATE ON vault_root_kdf_salt");
  });

  it("mutation negative: removing an anchored clause is caught by the census", () => {
    const mutated = sql.replace("BEFORE TRUNCATE ON vault_root_kdf_salt", "-- removed");
    const missing = VAULT_ROOT_KDF_SALT_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["ROOT_SALT_NOT_TRUNCATABLE"]);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(VAULT_ROOT_KDF_SALT_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(5);
    for (const obligation of VAULT_ROOT_KDF_SALT_EXECUTION_OBLIGATIONS) {
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

/* ─── psql harness ────────────────────────────────────────────────── */

const databaseUrl = process.env.TEST_DATABASE_URL;
const SCHEMA = "vault_root_kdf_salt_slice";
const NODE_ID = "11111111-1111-4111-8111-111111111111";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";
const SQLSTATE_RAISE_EXCEPTION = "55000";
let liveReady = false;

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

// VERBOSITY=verbose makes psql emit the machine-readable `ERROR:  <sqlstate>:` line the
// negative drills assert on.
const psql = (args: readonly string[]): PsqlResult => {
  try {
    const stdout = execFileSync(
      "psql",
      ["-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-q", ...args],
      { env: pgEnv(), stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 },
    );
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

const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}, public`, "-c", statement]);

const sqlstateOf = (stderr: string): string =>
  /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr)?.[1] ?? `<no sqlstate in: ${stderr.slice(0, 200)}>`;

const saltLiteral = (bytes: Buffer): string => `'\\x${bytes.toString("hex")}'::bytea`;

describe.skipIf(!databaseUrl)("vault_root_kdf_salt against real PostgreSQL", () => {
  beforeAll(() => {
    const dropped = psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    expect(dropped.stderr, "scratch schema drop").toBe("");
    const created = psql(["-c", `CREATE SCHEMA ${SCHEMA}`]);
    expect(created.stderr, "scratch schema create").toBe("");
    // Applied ALONE — the slice's greenfield claim (migration-integrity GREENFIELD
    // `applies: true`) is discharged here rather than asserted on paper.
    const applied = psql(["-c", `SET search_path TO ${SCHEMA}, public`, "-f", sqlPath]);
    expect(applied.stderr, "vault-root-kdf-salt.sql must apply into an empty schema alone").toBe("");
    liveReady = true;
  });

  afterAll(() => {
    if (databaseUrl !== undefined) psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
  });

  it("materializes exactly the four declared columns", () => {
    const result = psql([
      "-t",
      "-A",
      "-c",
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = '${SCHEMA}' AND table_name = 'vault_root_kdf_salt'
        ORDER BY ordinal_position`,
    ]);
    expect(result.stderr).toBe("");
    expect(result.stdout.split("\n").filter((l) => l.length > 0)).toEqual([
      "node_id",
      "salt",
      "source",
      "created_at",
    ]);
  });

  it("accepts one row per node and rejects a second with unique_violation 23505", () => {
    const first = run(
      `INSERT INTO vault_root_kdf_salt (node_id, salt, source)
       VALUES ('${NODE_ID}', ${saltLiteral(Buffer.alloc(32, 7))}, 'genesis_random')`,
    );
    expect(first.stderr, "first insert must apply").toBe("");

    const second = run(
      `INSERT INTO vault_root_kdf_salt (node_id, salt, source)
       VALUES ('${NODE_ID}', ${saltLiteral(Buffer.alloc(32, 9))}, 'environment')`,
    );
    expect(sqlstateOf(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
  });

  it("ON CONFLICT DO NOTHING leaves the first salt in place — the first-boot race converges", () => {
    const racer = run(
      `INSERT INTO vault_root_kdf_salt (node_id, salt, source)
       VALUES ('${NODE_ID}', ${saltLiteral(Buffer.alloc(32, 9))}, 'environment')
       ON CONFLICT (node_id) DO NOTHING`,
    );
    expect(racer.stderr).toBe("");
    const read = psql([
      "-t",
      "-A",
      "-c",
      `SET search_path TO ${SCHEMA}, public`,
      "-c",
      `SELECT encode(salt, 'hex') || '|' || source FROM vault_root_kdf_salt WHERE node_id = '${NODE_ID}'`,
    ]);
    expect(read.stdout.trim()).toBe(`${Buffer.alloc(32, 7).toString("hex")}|genesis_random`);
  });

  it("rejects a salt shorter than 8 bytes with check_violation 23514", () => {
    const result = run(
      `INSERT INTO vault_root_kdf_salt (node_id, salt, source)
       VALUES ('22222222-2222-4222-8222-222222222222', ${saltLiteral(Buffer.alloc(4))}, 'environment')`,
    );
    expect(sqlstateOf(result.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
  });

  it("rejects a provenance outside the three enumerated sources with check_violation 23514", () => {
    const result = run(
      `INSERT INTO vault_root_kdf_salt (node_id, salt, source)
       VALUES ('33333333-3333-4333-8333-333333333333', ${saltLiteral(Buffer.alloc(32))}, 'guessed')`,
    );
    expect(sqlstateOf(result.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
  });

  it("refuses UPDATE — the salt cannot be edited out from under the envelopes", () => {
    const result = run(
      `UPDATE vault_root_kdf_salt SET salt = ${saltLiteral(Buffer.alloc(32, 1))} WHERE node_id = '${NODE_ID}'`,
    );
    expect(sqlstateOf(result.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
    expect(result.stderr).toContain("append-only");
  });

  it("refuses DELETE", () => {
    const result = run(`DELETE FROM vault_root_kdf_salt WHERE node_id = '${NODE_ID}'`);
    expect(sqlstateOf(result.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
  });

  it("refuses TRUNCATE — a row-level DELETE guard alone would leave this bypass open", () => {
    const result = run(`TRUNCATE TABLE vault_root_kdf_salt`);
    expect(sqlstateOf(result.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
  });

  it("the row survives every refused mutation intact", () => {
    const read = psql([
      "-t",
      "-A",
      "-c",
      `SET search_path TO ${SCHEMA}, public`,
      "-c",
      `SELECT encode(salt, 'hex') FROM vault_root_kdf_salt WHERE node_id = '${NODE_ID}'`,
    ]);
    expect(read.stdout.trim()).toBe(Buffer.alloc(32, 7).toString("hex"));
  });
});

registerPgRequiredGuard({
  name: "vault_root_kdf_salt slice",
  databaseUrl,
  isReady: () => liveReady,
});
