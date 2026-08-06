/**
 * reporting-rate-limit-buckets-pk-collapse.pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database, that the load-bearing de-dupe
 * DELETE in reporting-rate-limit-buckets-pk-collapse.sql collapses a populated table
 * correctly before the PK swap — the path every empty-table suite never exercises
 * (review B gap).
 *
 * Fixture (matches the lane-B manual proof):
 *   (N1, pA) × 3 windows, (N1, pB) × 2 windows, (N2, pA) × 1  →  6 rows
 * After migration:
 *   6 → 3 survivors: latest window_start_ms per (node_id, principal); cross-node
 *   same-principal NOT merged; new PK (node_id, principal) rejects a duplicate insert
 *   with SQLSTATE 23505.
 *
 * Non-vacuity: applying only the ADD CONSTRAINT half (no DELETE) against the same
 * seed fails with 23505 — so dropping the DELETE from the migration would fail this
 * suite rather than silently pass.
 *
 * Isolation: nodes(id) is an id-only stub parent (reporting-security-ports.sql FKs
 * nodes(id); the slice under test is the child table + collapse ALTER). Both real
 * schema files are applied verbatim via psql -f. Fail-closed under PG_REQUIRED=1.
 *
 * Governing: packages/node-core/src/schema/reporting-rate-limit-buckets-pk-collapse.sql
 * signing custody durable rate-limit bound.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  REPORTING_RATE_LIMIT_BUCKETS_PK_COLLAPSE_SCHEMA_FILE,
} from "../src/schema/reporting-rate-limit-buckets-pk-collapse.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const PSQL_TIMEOUT_MS = 90_000;

const N1 = "11111111-1111-4111-8111-111111111111";
const N2 = "22222222-2222-4222-8222-222222222222";
const PA = "principal-a";
const PB = "principal-b";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) {
    args.push("-v", "VERBOSITY=verbose");
  }
  args.push("-qAt", "-c", sql);
  try {
    const stdout = execFileSync("psql", args, {
      encoding: "utf-8",
      timeout: PSQL_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const applyFile = (db: string, file: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)], {
      encoding: "utf-8",
      timeout: PSQL_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const extractSqlstate = (stderr: string): string => {
  // VERBOSITY=verbose: "ERROR:  23505: ..." ; default: "ERROR:  duplicate key ..." +
  // "SQLSTATE: 23505" on a later line. Accept either form.
  const verbose = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  if (verbose !== null) return verbose[1];
  const plain = /\bSQLSTATE:\s+([0-9A-Z]{5})\b/.exec(stderr);
  return plain === null ? "" : plain[1];
};

/** Six-row seed matching the lane-B manual proof. */
const seedDuplicatePrincipals = (db: string): void => {
  psqlMust(
    db,
    `
    INSERT INTO nodes (id) VALUES ('${N1}'), ('${N2}');
    INSERT INTO reporting_rate_limit_buckets
      (node_id, principal, window_start_ms, request_count, updated_at)
    VALUES
      ('${N1}', '${PA}', 1000, 1, now()),
      ('${N1}', '${PA}', 2000, 2, now()),
      ('${N1}', '${PA}', 3000, 3, now()),
      ('${N1}', '${PB}', 5000, 1, now()),
      ('${N1}', '${PB}', 6000, 4, now()),
      ('${N2}', '${PA}', 8000, 1, now());
    `,
  );
};

const rowCount = (db: string): number =>
  Number(runPsql(db, "SELECT count(*)::int FROM reporting_rate_limit_buckets;").stdout.trim());

const survivorsTsv = (db: string): string =>
  runPsql(
    db,
    `SELECT node_id::text || '|' || principal || '|' || window_start_ms::text
       FROM reporting_rate_limit_buckets
       ORDER BY node_id, principal;`,
  ).stdout.trim();

let assertionsRun = 0;
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

describeIfPg("reporting_rate_limit_buckets pk-collapse de-dupe (hermetic scratch DB)", () => {
  const scratchDb = `reporting_rate_limit_pkcol_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    // Id-only stub parent — correct isolation: the FK target is nodes(id); the proof lives
    // entirely in the child table + collapse ALTER (observation-anomaly-indexes.pg.test.ts
    // precedent).
    psqlMust(scratchDb, "CREATE TABLE nodes (id uuid PRIMARY KEY);");
    applyFile(scratchDb, "reporting-security-ports.sql");
    seedDuplicatePrincipals(scratchDb);
    expect(rowCount(scratchDb), "seed must land all 6 duplicate-principal rows").toBe(6);
    applyFile(scratchDb, REPORTING_RATE_LIMIT_BUCKETS_PK_COLLAPSE_SCHEMA_FILE);
  });

  afterAll(() => {
    psqlMust(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("(a) 6 → 3 collapse keeps the latest window per (node_id, principal)", () => {
    expect(rowCount(scratchDb)).toBe(3);
    // Latest windows: (N1,pA)@3000, (N1,pB)@6000, (N2,pA)@8000
    expect(survivorsTsv(scratchDb)).toBe(
      [`${N1}|${PA}|3000`, `${N1}|${PB}|6000`, `${N2}|${PA}|8000`].join("\n"),
    );
    assertionsRun += 1;
  });

  it("(b) cross-node same principal is NOT merged", () => {
    const n2 = runPsql(
      scratchDb,
      `SELECT count(*)::int FROM reporting_rate_limit_buckets
        WHERE node_id = '${N2}' AND principal = '${PA}';`,
    ).stdout.trim();
    expect(n2).toBe("1");
    const n1Pa = runPsql(
      scratchDb,
      `SELECT window_start_ms::text FROM reporting_rate_limit_buckets
        WHERE node_id = '${N1}' AND principal = '${PA}';`,
    ).stdout.trim();
    expect(n1Pa).toBe("3000");
    assertionsRun += 1;
  });

  it("(c) post-migration duplicate (node_id, principal) insert raises 23505", () => {
    const dup = runPsql(
      scratchDb,
      `INSERT INTO reporting_rate_limit_buckets
         (node_id, principal, window_start_ms, request_count, updated_at)
       VALUES ('${N1}', '${PA}', 9999, 1, now());`,
      true,
    );
    expect(dup.ok, "duplicate (node_id, principal) must be rejected by the collapsed PK").toBe(
      false,
    );
    expect(extractSqlstate(dup.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    assertionsRun += 1;
  });

  it("(d) PK is (node_id, principal); updated_at index is dropped", () => {
    const pkCols = runPsql(
      scratchDb,
      `SELECT string_agg(a.attname, ',' ORDER BY u.ord)
         FROM pg_constraint c
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS u(attnum, ord) ON true
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = u.attnum
        WHERE c.conrelid = 'reporting_rate_limit_buckets'::regclass
          AND c.contype = 'p';`,
    ).stdout.trim();
    expect(pkCols).toBe("node_id,principal");

    const idx = runPsql(
      scratchDb,
      `SELECT count(*)::int FROM pg_indexes
        WHERE indexname = 'reporting_rate_limit_buckets_updated_at_idx';`,
    ).stdout.trim();
    expect(idx).toBe("0");
    assertionsRun += 1;
  });

  it("(e) NON-VACUOUS: ADD CONSTRAINT alone (no DELETE) fails 23505 on the same seed", () => {
    // Fresh scratch: prove the de-dupe DELETE is load-bearing. If a future edit drops the
    // DELETE from the migration, this control still documents that the ADD alone cannot
    // succeed against duplicates — and the main describe's applyFile would itself fail.
    // Here we re-seed a throwaway DB and apply only the constraint-swap half.
    const controlDb = `reporting_rate_limit_ctrl_${Date.now()}_${process.pid}`;
    try {
      psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${controlDb}`);
      psqlMust(controlDb, "CREATE TABLE nodes (id uuid PRIMARY KEY);");
      applyFile(controlDb, "reporting-security-ports.sql");
      seedDuplicatePrincipals(controlDb);
      expect(rowCount(controlDb)).toBe(6);

      // Extract only the ALTER TABLE ... ADD CONSTRAINT half from the frozen file so this
      // control cannot drift if comments change — but deliberately OMIT the DELETE.
      const collapseSql = readFileSync(
        resolve(schemaDir, REPORTING_RATE_LIMIT_BUCKETS_PK_COLLAPSE_SCHEMA_FILE),
        "utf8",
      );
      expect(
        collapseSql,
        "migration must still carry the load-bearing DELETE (census pin)",
      ).toContain("DELETE FROM reporting_rate_limit_buckets a");

      // Twin of the migration's constraint swap with the DELETE deliberately omitted.
      const addConstraintOnly = `
        ALTER TABLE reporting_rate_limit_buckets
          DROP CONSTRAINT reporting_rate_limit_buckets_pkey,
          ADD CONSTRAINT reporting_rate_limit_buckets_pkey PRIMARY KEY (node_id, principal);
      `;
      const outcome = runPsql(controlDb, addConstraintOnly, true);
      expect(
        outcome.ok,
        "ADD CONSTRAINT without prior DELETE must fail on duplicate (node_id, principal)",
      ).toBe(false);
      expect(extractSqlstate(outcome.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    } finally {
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${controlDb} WITH (FORCE)`);
    }
    assertionsRun += 1;
  });
});

const EXPECTED_ASSERTIONS = 5;

it("obligation guard: real-PG pk-collapse de-dupe drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: the ` +
          "real-PG reporting_rate_limit_buckets pk-collapse de-dupe fixture could not " +
          "run and the local verification lane must not silently skip it.",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG pk-collapse de-dupe drills did not all run — undischarged",
  ).toBe(EXPECTED_ASSERTIONS);
});
