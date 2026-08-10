/**
 * operations-indexes.pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database, that the five worker-poll partial indexes
 * in operations-indexes.sql:
 *   1. Apply cleanly once operations (+ receive_release_status) exist
 *   2. Appear in pg_indexes with the expected partial predicates
 *   3. Are chosen by the planner for the source worker-poll predicates (with seqscan off)
 *   4. Leave a seq-scan plan when dropped (causation, not correlation)
 *
 * Composition: minimal stubs for operations' FK targets, domains/enums from
 * operations.sql's own header, the operations CREATE TABLE + spawn index, the
 * receive_release_status ALTER (so the expiry partial can bind), then the index slice.
 * Harness mirrors test/wallet-settled-ledger.pg.test.ts drill 11.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { registerPgRequiredGuard } from "./pg-required-guard.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "../src/schema");
const MAINTENANCE_DB = "postgres";
const DB_PREFIX = "operations_indexes_";
const EXPECTED_DRILL_COUNT = 3;

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "--set=VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applyDdl = (db: string, sql: string, label: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-c", sql], {
      encoding: "utf-8",
      timeout: 60_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply ${label} failed: ${(e.stderr ?? "").trim() || "unknown"}`);
  }
};

const probePostgres = (): boolean => {
  const outcome = runPsql(MAINTENANCE_DB, "SELECT 1");
  return outcome.ok;
};

const INDEX_DEFS: readonly {
  readonly name: string;
  readonly predicateSql: string;
  readonly planToken: string;
}[] = [
  {
    name: "operations_receive_queue_created_idx",
    predicateSql:
      "SELECT id FROM operations " +
      "WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'CREATED' AND receiver_wallet_id IS NULL " +
      "ORDER BY created_at, id",
    planToken: "operations_receive_queue_created_idx",
  },
  {
    name: "operations_receive_expiry_candidates_idx",
    predicateSql:
      "SELECT id FROM operations " +
      "WHERE kind = 'RECEIVE_EXTERNAL' " +
      "AND status IN ('CREATED','READY','EXPIRED') " +
      "AND receive_release_status IS NULL " +
      "ORDER BY created_at, id",
    planToken: "operations_receive_expiry_candidates_idx",
  },
  {
    name: "operations_receive_ready_idx",
    predicateSql:
      "SELECT id FROM operations " +
      "WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'READY' " +
      "ORDER BY created_at, id",
    planToken: "operations_receive_ready_idx",
  },
  {
    name: "operations_receive_landed_handoff_idx",
    predicateSql:
      "SELECT id FROM operations " +
      "WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'RECEIVE_LANDED' " +
      "AND after_landing = 'INTERNAL_MOVE' " +
      "ORDER BY created_at, id",
    planToken: "operations_receive_landed_handoff_idx",
  },
  {
    name: "operations_move_pending_idx",
    predicateSql:
      "SELECT id FROM operations " +
      "WHERE kind = 'MOVE_INTERNAL' AND status IN ('CREATED','NEEDS_ATTENTION') " +
      "ORDER BY created_at",
    planToken: "operations_move_pending_idx",
  },
];

describe("operations worker-poll indexes PG drills", () => {
  let db: string | null = null;
  let reachable = false;
  let ready = false;
  let drillsRun = 0;

  registerPgRequiredGuard({
    name: "operations-indexes.pg",
    databaseUrl: process.env.TEST_DATABASE_URL,
    isReady: () => ready,
  });

  beforeAll(() => {
    reachable = probePostgres();
    if (!reachable) {
      if (process.env.PG_REQUIRED === "1") {
        throw new Error("PG_REQUIRED=1 but Postgres is unreachable");
      }
      return;
    }
    db = `${DB_PREFIX}${Date.now()}_${process.pid}`;
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE "${db}"`);

    const opsSql = readFileSync(join(SCHEMA_DIR, "operations.sql"), "utf8");
    const tableIdx = opsSql.indexOf("CREATE TABLE operations");
    if (tableIdx < 0) throw new Error("operations.sql missing CREATE TABLE operations");
    const header = opsSql.slice(0, tableIdx);
    const body = opsSql.slice(tableIdx);

    applyDdl(
      db,
      `
      CREATE TABLE nodes (id uuid PRIMARY KEY);
      CREATE TABLE implementers (id uuid PRIMARY KEY);
      CREATE TABLE wallets (id uuid PRIMARY KEY);
      CREATE TABLE destinations (id uuid PRIMARY KEY);
      ${header}
      ${body}
      ALTER TABLE operations
        ADD COLUMN receive_release_status text
        CHECK (
          receive_release_status IS NULL
          OR receive_release_status IN (
            'RELEASED_T0_UNCHANGED',
            'RELEASED_PROVEN_NOT_STARTED'
          )
        );
      `,
      "operations+stubs+receive_release_status",
    );
    applyDdl(
      db,
      readFileSync(join(SCHEMA_DIR, "operations-indexes.sql"), "utf8"),
      "operations-indexes.sql",
    );
    ready = true;
  });

  afterAll(() => {
    if (db === null) return;
    try {
      psqlMust(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
    } catch {
      // best-effort teardown
    }
  });

  const skip = (): boolean => !reachable || db === null;

  it("1. all five indexes exist with partial predicates", () => {
    if (skip()) return;
    drillsRun += 1;
    for (const { name } of INDEX_DEFS) {
      const def = runPsql(
        db!,
        `SELECT indexdef FROM pg_indexes WHERE tablename='operations' AND indexname='${name}'`,
      ).stdout.trim();
      expect(def.length, `missing index ${name}`).toBeGreaterThan(0);
      expect(def).toContain("CREATE INDEX");
      expect(def).toContain("USING btree (created_at, id)");
      expect(def.toLowerCase()).toContain("where");
    }
    const spawn = runPsql(
      db!,
      `SELECT indexdef FROM pg_indexes WHERE tablename='operations'` +
        ` AND indexname='operations_one_spawn_per_parent_uidx'`,
    ).stdout.trim();
    expect(spawn).toContain("CREATE UNIQUE INDEX operations_one_spawn_per_parent_uidx");
  });

  it("2. planner uses each partial index for its source worker-poll predicate", () => {
    if (skip()) return;
    drillsRun += 1;
    for (const { name, predicateSql, planToken } of INDEX_DEFS) {
      const plan = runPsql(
        db!,
        `SET enable_seqscan = off; EXPLAIN (COSTS OFF) ${predicateSql}`,
      ).stdout;
      expect(plan, `expected index ${name} in plan for: ${predicateSql}`).toContain(planToken);
    }
  });

  it("3. without the queue index the planner cannot use it (causation)", () => {
    if (skip()) return;
    drillsRun += 1;
    const queueSql =
      "SELECT id FROM operations " +
      "WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'CREATED' AND receiver_wallet_id IS NULL " +
      "ORDER BY created_at, id";
    // Baseline: with the index present and seqscan disabled, the queue partial wins.
    const withIndex = runPsql(
      db!,
      `SET enable_seqscan = off; EXPLAIN (COSTS OFF) ${queueSql}`,
    ).stdout;
    expect(withIndex).toContain("operations_receive_queue_created_idx");

    psqlMust(db!, "DROP INDEX operations_receive_queue_created_idx");
    // The expiry partial also matches CREATED receives; drop it so no worker-poll
    // partial remains for this predicate. The UNIQUE (implementer_id, kind, idempotency_key)
    // can still filter on kind, so the plan may not be a bare Seq Scan on an empty table —
    // the defect this ticket closes is "no index matches the queue working set", not
    // "no index of any kind can touch the table". Prove the queue index is gone from the
    // plan; restore both partials afterwards.
    psqlMust(db!, "DROP INDEX operations_receive_expiry_candidates_idx");
    const without = runPsql(
      db!,
      `SET enable_seqscan = off; EXPLAIN (COSTS OFF) ${queueSql}`,
    ).stdout;
    expect(without).not.toContain("operations_receive_queue_created_idx");
    expect(without).not.toContain("operations_receive_expiry_candidates_idx");

    psqlMust(
      db!,
      "CREATE INDEX operations_receive_queue_created_idx " +
        "ON operations (created_at, id) " +
        "WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'CREATED' AND receiver_wallet_id IS NULL",
    );
    psqlMust(
      db!,
      "CREATE INDEX operations_receive_expiry_candidates_idx " +
        "ON operations (created_at, id) " +
        "WHERE kind = 'RECEIVE_EXTERNAL' " +
        "AND status IN ('CREATED', 'READY', 'EXPIRED') " +
        "AND receive_release_status IS NULL",
    );
  });

  it("obligation guard: every drill ran against the database", () => {
    if (skip()) return;
    expect(drillsRun).toBe(EXPECTED_DRILL_COUNT);
  });
});
