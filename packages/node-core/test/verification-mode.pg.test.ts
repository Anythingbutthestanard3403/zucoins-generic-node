// Real-PostgreSQL proof for verification-mode.sql (ZTR-1300).
//
// Engine-only properties:
//   1. Slice applies after minimal ops / projection / settings stubs.
//   2. verification_mode DEFAULT 'INDEPENDENT' on INSERT omit.
//   3. CHECK rejects a third mode label (SQLSTATE 23514) — AC4.
//   4. INDEPENDENT and NODE_VERIFIED insert cleanly.
//   5. BEFORE UPDATE immutability rejects mode rewrite.
//   6. receive_release_status admits RELEASED_NODE_VERIFIED and rejects unknown.
//
// Stubs are intentionally minimal: only the relations the slice ALTER/CHECKs touch.
// Full money-pack cold-apply is covered by migration-integrity + money-schema-pack gates.
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { registerPgRequiredGuard } from "./pg-required-guard.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

const SQLSTATE_CHECK_VIOLATION = "23514";
const SQLSTATE_RAISE_EXCEPTION = "P0001";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

/** Minimal relations the verification-mode slice ALTER/CHECKs. */
const stubDdl = `
CREATE TABLE operations (
  id uuid PRIMARY KEY,
  receive_release_status text
    CHECK (
      receive_release_status IS NULL
      OR receive_release_status IN (
        'RELEASED_T0_UNCHANGED',
        'RELEASED_PROVEN_NOT_STARTED',
        'RELEASED_OPERATOR_ACCEPTED_RISK'
      )
    )
);

CREATE TABLE receive_operations (
  operation_id uuid PRIMARY KEY
);

CREATE TABLE send_operations (
  operation_id uuid PRIMARY KEY
);

CREATE TABLE node_settings (
  setting_key text PRIMARY KEY,
  setting_value text NOT NULL,
  row_version bigint NOT NULL DEFAULT 1
);

CREATE TABLE audit_log (
  id uuid PRIMARY KEY,
  action text NOT NULL
);
`;

const modeDdl = readSchema("verification-mode.sql");
const schemaDdl = `${stubDdl}\n${modeDdl}\n`;

const scratchDb = `verification_mode_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;

const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

const adminPsql = (url: string, sql: string): void => {
  execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
    encoding: "utf-8",
    timeout: 60_000,
  });
};

const runPsql = (sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    execFile(
      "psql",
      [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs },
      (err, stdout, stderr) => {
        resolve({ ok: !err, stdout: stdout ?? "", stderr: stderr ?? (err ? String(err) : "") });
      },
    );
  });

const must = async (sql: string): Promise<string> => {
  const outcome = await runPsql(sql);
  if (!outcome.ok) {
    throw new Error(`psql failed for [${sql}]: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout.trim();
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const mustReject = async (sql: string, sqlstate: string): Promise<void> => {
  const outcome = await runPsql(sql);
  expect(outcome.ok, `expected rejection but succeeded: ${sql}\n${outcome.stderr}`).toBe(false);
  expect(extractSqlstate(outcome.stderr), `SQLSTATE for: ${sql}\n${outcome.stderr}`).toBe(
    sqlstate,
  );
};

const OP1 = "a0000000-0000-4000-8000-000000000001";
const OP2 = "a0000000-0000-4000-8000-000000000002";
const OP3 = "a0000000-0000-4000-8000-000000000003";
const OP4 = "a0000000-0000-4000-8000-000000000004";
const R1 = "b0000000-0000-4000-8000-000000000001";
const S1 = "c0000000-0000-4000-8000-000000000001";

beforeAll(() => {
  if (!TEST_DATABASE_URL) return;
  adminPsql(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: schemaDdl,
    encoding: "utf-8",
    timeout: 60_000,
  });
  schemaReady = true;
}, 90_000);

afterAll(() => {
  if (!schemaReady) return;
  try {
    adminPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  } catch {
    /* best-effort teardown */
  }
});

registerPgRequiredGuard({
  name: "verification-mode.pg",
  databaseUrl: TEST_DATABASE_URL,
  isReady: () => schemaReady,
});

describe("verification-mode PG drills (ZTR-1300)", () => {
  it("INSERT omit verification_mode defaults to INDEPENDENT on all three tables", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM operations WHERE id = '${OP1}'`);
    await must(`DELETE FROM receive_operations WHERE operation_id = '${R1}'`);
    await must(`DELETE FROM send_operations WHERE operation_id = '${S1}'`);

    await must(`INSERT INTO operations (id) VALUES ('${OP1}')`);
    await must(`INSERT INTO receive_operations (operation_id) VALUES ('${R1}')`);
    await must(`INSERT INTO send_operations (operation_id) VALUES ('${S1}')`);

    expect(await must(`SELECT verification_mode FROM operations WHERE id = '${OP1}'`)).toBe(
      "INDEPENDENT",
    );
    expect(
      await must(`SELECT verification_mode FROM receive_operations WHERE operation_id = '${R1}'`),
    ).toBe("INDEPENDENT");
    expect(
      await must(`SELECT verification_mode FROM send_operations WHERE operation_id = '${S1}'`),
    ).toBe("INDEPENDENT");
  });

  it("explicit INDEPENDENT and NODE_VERIFIED insert cleanly", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM operations WHERE id IN ('${OP2}', '${OP3}')`);
    await must(
      `INSERT INTO operations (id, verification_mode) VALUES ('${OP2}', 'INDEPENDENT')`,
    );
    await must(
      `INSERT INTO operations (id, verification_mode) VALUES ('${OP3}', 'NODE_VERIFIED')`,
    );
    expect(await must(`SELECT verification_mode FROM operations WHERE id = '${OP2}'`)).toBe(
      "INDEPENDENT",
    );
    expect(await must(`SELECT verification_mode FROM operations WHERE id = '${OP3}'`)).toBe(
      "NODE_VERIFIED",
    );
  });

  it("AC4: CHECK rejects a third verification_mode value (23514)", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM operations WHERE id = '${OP4}'`);
    await mustReject(
      `INSERT INTO operations (id, verification_mode) VALUES ('${OP4}', 'HYBRID')`,
      SQLSTATE_CHECK_VIOLATION,
    );
    await mustReject(
      `INSERT INTO receive_operations (operation_id, verification_mode)
       VALUES ('${OP4}', 'HYBRID')`,
      SQLSTATE_CHECK_VIOLATION,
    );
    await mustReject(
      `INSERT INTO send_operations (operation_id, verification_mode)
       VALUES ('${OP4}', 'HYBRID')`,
      SQLSTATE_CHECK_VIOLATION,
    );
  });

  it("immutability trigger rejects verification_mode rewrite", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM operations WHERE id = '${OP1}'`);
    await must(
      `INSERT INTO operations (id, verification_mode) VALUES ('${OP1}', 'INDEPENDENT')`,
    );
    await mustReject(
      `UPDATE operations SET verification_mode = 'NODE_VERIFIED' WHERE id = '${OP1}'`,
      SQLSTATE_RAISE_EXCEPTION,
    );
    expect(await must(`SELECT verification_mode FROM operations WHERE id = '${OP1}'`)).toBe(
      "INDEPENDENT",
    );
  });

  it("receive_release_status admits RELEASED_NODE_VERIFIED and rejects unknown", async () => {
    if (!schemaReady) return;
    await must(`DELETE FROM operations WHERE id = '${OP2}'`);
    await must(`INSERT INTO operations (id) VALUES ('${OP2}')`);
    await must(
      `UPDATE operations SET receive_release_status = 'RELEASED_NODE_VERIFIED' WHERE id = '${OP2}'`,
    );
    expect(
      await must(`SELECT receive_release_status FROM operations WHERE id = '${OP2}'`),
    ).toBe("RELEASED_NODE_VERIFIED");

    await mustReject(
      `UPDATE operations SET receive_release_status = 'RELEASED_UNKNOWN' WHERE id = '${OP2}'`,
      SQLSTATE_CHECK_VIOLATION,
    );
  });

  it("slice is idempotent on re-apply", async () => {
    if (!schemaReady) return;
    const outcome = await runPsql(modeDdl, 30_000);
    expect(outcome.ok, outcome.stderr).toBe(true);
    // Column still present and constrained.
    expect(
      await must(
        `SELECT verification_mode FROM operations LIMIT 0; SELECT 1`,
      ),
    ).toContain("1");
  });
});
