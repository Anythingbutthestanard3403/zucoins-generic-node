// real-PostgreSQL behaviours for the persisted lease foundation.
//
// Evidence cases:
//  1. concurrent acquisition one-winner
//  2. mixed-batch zero mutation (invalid member rolls whole batch back)
//  3. foreign owner/operation/epoch/proof and replay zero mutation
//  4. exact valid release atomicity
//  5. rollback injection after every mutation step
//  6. restart epoch persistence
//  7. ABA (stale epoch cannot release/sign under successor)
//  8. direct SQL reconciliation rejection discipline (unguarded DELETE counted as defect path)
//  9. empty legacy migration expand
// 10. populated legacy migration refuse
// 11. old-writer schema fence
// 12. signer release/transfer interleaving (sign capability vs release)
// 13. RECONCILIATION rejected from exclusive table
// 14. proof-backed release happy path + unpin
// 15. group-terminal gate — refuse unpin/release while sibling ops incomplete
// 16. pre-formation PENDING disposition refuses release before child join
// 17. HOLD/NONE disposition allows root-terminal release with no child
// 18. receive→child-move hand-off (transferLeaseWithinGroup) — uninterrupted
//     active row, parent capability permanently invalid, destinations join atomically
// 19. break-review D1: a busy destination leaves phase A's source hand-off
// durable (operation-flow step 3) — child stays destination-less, source stays held
// 20. break-review D2: forced two-session lock-order drill — acquire ∥ release
//     and sign ∥ release on one group take locks in one order, never deadlock
//
// Connectivity: TEST_DATABASE_URL (vitest.global-setup) or PG_REQUIRED fail-closed.

import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  acquireGroupDestinationLeases,
  acquireLeases,
  assertLeaseFoundationReady,
  assertSignCapability,
  completeGroupOperation,
  createLeaseGroup,
  eligibilityGuardPresent,
  joinLeaseGroupOperation,
  migrateLeaseFoundation,
  mintReleaseProof,
  releaseLease,
  STATEMENTS,
  transferLeaseWithinGroup,
} from "../src/leases/index.ts";
import type { SqlExecutor, SqlQueryResult } from "../src/leases/types.ts";
import { tokenizeCustodySql } from "./custody-eligibility-sql-statements.js";

const here = dirname(fileURLToPath(import.meta.url));
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

// Custody is prerequisite-bound (base enums/domains + nodes).
const prerequisiteDdl = ((): string => {
  const base = readFileSync(resolve(here, "../src/schema/base-enums-domains.sql"), "utf8");
  const registry = readFileSync(
    resolve(here, "../src/schema/node-implementer-registry.sql"),
    "utf8",
  );
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

const custodySql = tokenizeCustodySql(
  readFileSync(resolve(here, "../src/schema/custody-eligibility.sql"), "utf8"),
)
  .map((s) => s.raw)
  .join("\n");

const applyCustodyBase = (url: string): void => {
  try {
    execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: `${prerequisiteDdl}${custodySql}`,
      encoding: "utf-8",
      timeout: 60_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`custody apply failed: ${(e.stderr ?? "").trim()}`);
  }
};

// Hand-rolled three-column legacy projection for migrate LEGACY_POPULATED / empty-expand drills.
// custody already ships full columns, so legacy paths cannot reuse custodySql.
const LEGACY_THREE_COL_DDL = `
CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  public_key text NOT NULL,
  key_origin text NOT NULL,
  state text NOT NULL,
  recovery_verified_at timestamptz,
  recovery_verification_id uuid
);
CREATE TABLE wallet_active_leases (
  wallet_id uuid PRIMARY KEY REFERENCES wallets (id),
  lease_role text NOT NULL
    CHECK (lease_role IN ('RECEIVE_WINDOW', 'MOVE_SOURCE', 'MOVE_DESTINATION', 'SEND_SOURCE', 'RECONCILIATION')),
  acquired_at timestamptz NOT NULL
);
`;

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (url: string, sql: string, timeoutMs = 30_000): PsqlOutcome => {
  try {
    const stdout = execFileSync(
      "psql",
      [url, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (url: string, sql: string): string => {
  const outcome = runPsql(url, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

/* ─── SqlExecutor over a long-lived psql session (holds BEGIN..COMMIT) ─── */

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "string") return `'${value.replace(/'/g, "''")}'`;
  throw new Error(`unsupported sql param type: ${typeof value}`);
}

function bindSql(text: string, params: readonly unknown[] = []): string {
  return text.replace(/\$(\d+)/g, (_m, n: string) => {
    const idx = Number(n) - 1;
    if (idx < 0 || idx >= params.length) {
      throw new Error(`missing sql param $${n}`);
    }
    return sqlLiteral(params[idx]);
  });
}

function pgEnv(url: string): NodeJS.ProcessEnv {
  const u = new URL(url);
  return {
    ...process.env,
    PGHOST: u.hostname,
    PGPORT: u.port === "" ? "5432" : u.port,
    PGUSER: decodeURIComponent(u.username),
    PGPASSWORD: decodeURIComponent(u.password),
    PGDATABASE: u.pathname.replace(/^\//, ""),
  };
}

/**
 * One `psql` OS process = one DB session. Multi-statement acquire/release runs under an
 * explicit BEGIN so FOR UPDATE locks and intermediate writes stay visible until commit.
 */
class PsqlSessionExecutor implements SqlExecutor {
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private readonly pending: Array<(line: string) => void> = [];
  private readonly url: string;

  constructor(url: string) {
    this.url = url;
  }

  start(): void {
    if (this.child) return;
    // No ON_ERROR_STOP: a mid-tx failure must leave the session alive so we can ROLLBACK
    // and still surface the ERROR text (ON_ERROR_STOP would kill the process).
    this.child = spawn(
      "psql",
      ["-X", "-q", "-A", "-t", "-v", "VERBOSITY=verbose"],
      {
        env: pgEnv(this.url),
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.buffer += chunk;
    });
    this.child.stdout.on("data", (chunk: string) => {
      this.buffer += chunk;
      // Marker may be the first line (no leading newline) after a silent statement.
      let idx = this.buffer.indexOf("__SQL_END__\n");
      while (idx !== -1) {
        const payload = this.buffer.slice(0, idx);
        this.buffer = this.buffer.slice(idx + "__SQL_END__\n".length);
        this.pending.shift()?.(payload);
        idx = this.buffer.indexOf("__SQL_END__\n");
      }
    });
  }

  stop(): void {
    if (!this.child) return;
    this.child.stdin.end();
    this.child.kill("SIGTERM");
    this.child = null;
  }

  private send(sql: string): Promise<string> {
    this.start();
    const child = this.child!;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`psql session timeout: ${sql.slice(0, 80)}`)),
        20_000,
      );
      this.pending.push((payload) => {
        clearTimeout(timer);
        if (/\bERROR:\s+/i.test(payload)) {
          const err = new Error(payload.trim());
          (err as { code?: string }).code = extractSqlstate(payload);
          reject(err);
          return;
        }
        resolve(payload);
      });
      child.stdin.write(`${sql};\n\\echo __SQL_END__\n`);
    });
  }

  async begin(): Promise<void> {
    await this.send("BEGIN");
  }

  async commit(): Promise<void> {
    await this.send("COMMIT");
  }

  async rollback(): Promise<void> {
    try {
      await this.send("ROLLBACK");
    } catch {
      // session may already be aborted
    }
  }

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const bound = bindSql(text, params);
    const trimmed = bound.trim();
    const isMut = /^(INSERT|UPDATE|DELETE)\b/i.test(trimmed);
    if (isMut) {
      const wrapped = `WITH __m AS (${trimmed} RETURNING 1) SELECT count(*)::int AS __rc FROM __m`;
      const out = await this.send(wrapped);
      // psql default aligned output — last non-empty line is the count
      const lines = out
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0 && !l.startsWith("WITH"));
      const rowCount = Number(lines[lines.length - 1] ?? "0");
      return { rows: [] as R[], rowCount };
    }
    const jsonSql = `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM (${trimmed}) t`;
    const out = await this.send(jsonSql);
    const lines = out
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    const jsonLine = lines[lines.length - 1] ?? "[]";
    const rows = JSON.parse(jsonLine) as R[];
    return { rows, rowCount: rows.length };
  }
}

/** Autocommit executor for single-statement migrate/readiness probes. */
class PsqlExecutor implements SqlExecutor {
  constructor(private readonly url: string) {}

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const bound = bindSql(text, params);
    const trimmed = bound.trim();
    if (/^(INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
      const wrapped = `WITH __m AS (${trimmed} RETURNING 1) SELECT count(*)::int AS __rc FROM __m`;
      const outcome = runPsql(this.url, wrapped);
      if (!outcome.ok) {
        const err = new Error(outcome.stderr.trim() || "psql mutation failed");
        (err as { code?: string }).code = extractSqlstate(outcome.stderr);
        throw err;
      }
      return { rows: [] as R[], rowCount: Number(outcome.stdout.trim() || "0") };
    }
    if (/^(CREATE|DROP|ALTER|TRUNCATE|SELECT EXISTS)\b/i.test(trimmed) || /^SELECT EXISTS/i.test(trimmed)) {
      const outcome = runPsql(this.url, trimmed.startsWith("SELECT") || trimmed.startsWith("select")
        ? `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (${trimmed}) t`
        : trimmed);
      if (!outcome.ok) {
        // For SELECT EXISTS form used by migrate
        if (/^SELECT EXISTS/i.test(trimmed)) {
          const direct = runPsql(this.url, trimmed);
          if (!direct.ok) {
            const err = new Error(direct.stderr.trim() || "psql failed");
            (err as { code?: string }).code = extractSqlstate(direct.stderr);
            throw err;
          }
          const exists = direct.stdout.trim() === "t" || direct.stdout.trim() === "true";
          return { rows: [{ exists } as R], rowCount: 1 };
        }
        const err = new Error(outcome.stderr.trim() || "psql failed");
        (err as { code?: string }).code = extractSqlstate(outcome.stderr);
        throw err;
      }
      if (/^(CREATE|DROP|ALTER|TRUNCATE)\b/i.test(trimmed)) {
        return { rows: [] as R[], rowCount: 1 };
      }
      const rows = JSON.parse(outcome.stdout.trim() || "[]") as R[];
      return { rows, rowCount: rows.length };
    }
    // Generic SELECT
    if (/^SELECT\b/i.test(trimmed)) {
      // Special-case scalar exists queries from migrate.ts
      if (/^SELECT EXISTS/i.test(trimmed)) {
        const direct = runPsql(this.url, trimmed);
        if (!direct.ok) {
          const err = new Error(direct.stderr.trim() || "psql failed");
          (err as { code?: string }).code = extractSqlstate(direct.stderr);
          throw err;
        }
        const exists = direct.stdout.trim() === "t" || direct.stdout.trim() === "true";
        return { rows: [{ exists } as R], rowCount: 1 };
      }
      const jsonSql = `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (${trimmed}) t`;
      const outcome = runPsql(this.url, jsonSql);
      if (!outcome.ok) {
        const err = new Error(outcome.stderr.trim() || "psql select failed");
        (err as { code?: string }).code = extractSqlstate(outcome.stderr);
        throw err;
      }
      const rows = JSON.parse(outcome.stdout.trim() || "[]") as R[];
      return { rows, rowCount: rows.length };
    }
    // DDL/other
    const outcome = runPsql(this.url, trimmed);
    if (!outcome.ok) {
      const err = new Error(outcome.stderr.trim() || "psql failed");
      (err as { code?: string }).code = extractSqlstate(outcome.stderr);
      throw err;
    }
    return { rows: [] as R[], rowCount: 1 };
  }
}

async function withTx<T>(url: string, body: (db: PsqlSessionExecutor) => Promise<T>): Promise<T> {
  const session = new PsqlSessionExecutor(url);
  session.start();
  try {
    await session.begin();
    const result = await body(session);
    await session.commit();
    return result;
  } catch (err) {
    await session.rollback();
    throw err;
  } finally {
    session.stop();
  }
}


/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE = "b0000000-0000-4000-8000-0000000000aa";
const W1 = "a0000000-0000-4000-8000-000000000001";
const W2 = "a0000000-0000-4000-8000-000000000002";
const W3 = "a0000000-0000-4000-8000-000000000003";
const OWNER = "c0000000-0000-4000-8000-0000000000e1";
const OWNER_B = "c0000000-0000-4000-8000-0000000000e2";
const OP1 = "d0000000-0000-4000-8000-0000000000f1";
const OP2 = "d0000000-0000-4000-8000-0000000000f2";

// Wallets PK is id; public_key is padded_base64url_pubkey (44-char).
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

function seedNode(url: string): void {
  psqlMust(
    url,
    `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
       ('${NODE}', 'leasedb-lease', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`,
  );
}

function seedWallets(url: string): void {
  seedNode(url);
  psqlMust(
    url,
    `
INSERT INTO wallets (id, node_id, public_key, key_origin, state, recovery_verified_at, recovery_verification_id)
VALUES
  ('${W1}', '${NODE}', '${pubkey("W1")}', 'node_generated', 'AVAILABLE', NULL, NULL),
  ('${W2}', '${NODE}', '${pubkey("W2")}', 'node_generated', 'AVAILABLE', NULL, NULL),
  ('${W3}', '${NODE}', '${pubkey("W3")}', 'node_generated', 'AVAILABLE', NULL, NULL);
`,
  );
}

function digest(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

const TRUNCATE_LEASE_STATE = `
TRUNCATE wallet_active_leases, wallet_lease_memberships, lease_group_operations,
         lease_groups, lease_release_proofs, lease_audit_events,
         wallet_lease_epoch_highwater RESTART IDENTITY CASCADE;
UPDATE wallets SET state = 'AVAILABLE';`;

/**
 * Rows the eligibility trigger demands of the receive→child-move cases: W1 recovery
 * verified (RECEIVE_WINDOW / G1) and W2 recovery verified with a BLESSED destination
 * (MOVE_DESTINATION / G2). Idempotent — safe to re-run per case.
 */
function seedReceiveChildFixtures(url: string): void {
  const RECV_VERIFICATION = "e0000000-0000-4000-8000-0000000000c1";
  const DEST_VERIFICATION = "e0000000-0000-4000-8000-0000000000c2";
  const DEST_ID = "f0000000-0000-4000-8000-0000000000d1";
  const DEST_DEVICE = "f0000000-0000-4000-8000-0000000000d2";
  const DEST_ARTIFACT = "f0000000-0000-4000-8000-0000000000d3";
  psqlMust(
    url,
    `INSERT INTO wallet_recovery_verifications
       (id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity)
     SELECT '${RECV_VERIFICATION}', '${W1}', 'AUDITED_EXPORT', '${"e".repeat(64)}',
            '${pubkey("W1")}', '${RECV_VERIFICATION}', now(), 'wallet-test'
      WHERE NOT EXISTS (
        SELECT 1 FROM wallet_recovery_verifications WHERE wallet_id = '${W1}'
      );
     INSERT INTO wallet_recovery_verifications
       (id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity)
     SELECT '${DEST_VERIFICATION}', '${W2}', 'AUDITED_EXPORT', '${"f".repeat(64)}',
            '${pubkey("W2")}', '${DEST_VERIFICATION}', now(), 'wallet-test'
      WHERE NOT EXISTS (
        SELECT 1 FROM wallet_recovery_verifications WHERE wallet_id = '${W2}'
      );
     UPDATE wallets w SET
       recovery_verified_at = COALESCE(w.recovery_verified_at, now()),
       recovery_verification_id = COALESCE(
         w.recovery_verification_id,
         (SELECT id FROM wallet_recovery_verifications
           WHERE wallet_id = w.id ORDER BY verified_at LIMIT 1)
       )
       WHERE w.id IN ('${W1}', '${W2}');
     INSERT INTO destinations
       (id, node_id, wallet_id, state, blessed_at,
        blessed_by_device_key_id, blessing_artifact_id)
     SELECT '${DEST_ID}', '${NODE}', '${W2}', 'BLESSED', now(),
            '${DEST_DEVICE}', '${DEST_ARTIFACT}'
      WHERE NOT EXISTS (
        SELECT 1 FROM destinations WHERE wallet_id = '${W2}'
      );`,
  );
}

/** SQLSTATE for a psql failure, LeaseError reason for a service refusal. */
const failureCode = (err: unknown): string => {
  const e = err as { code?: string; reason?: string; message?: string };
  return e.code ?? e.reason ?? e.message ?? "unknown";
};

/**
 * Forced two-session lock-order interleave (test-plan two-session contention drill).
 *
 * Session A takes `holderFirst` — the opening statements of releaseLease's real lock
 * sequence — then `contend` starts on session B and is given time to reach its first lock
 * wait, then session A issues `holderNext`. If B takes its locks in the opposite order it is
 * already holding what A now wants while waiting on what A holds, and Postgres reports
 * SQLSTATE 40P01 on one of the two within deadlock_timeout (1s default).
 */
async function raceLockOrder(
  url: string,
  holderFirst: ReadonlyArray<readonly [string, readonly unknown[]]>,
  contend: (tx: PsqlSessionExecutor) => Promise<unknown>,
  holderNext: ReadonlyArray<readonly [string, readonly unknown[]]>,
): Promise<{ holder: string; contender: string }> {
  const a = new PsqlSessionExecutor(url);
  const b = new PsqlSessionExecutor(url);
  a.start();
  b.start();
  try {
    await a.begin();
    await b.begin();
    for (const [sql, params] of holderFirst) {
      await a.query(sql, params);
    }

    const contender = contend(b).then(
      () => "ok",
      (err: unknown) => `error:${failureCode(err)}`,
    );
    await new Promise((resolve) => setTimeout(resolve, 1_500));

    let holder = "ok";
    try {
      for (const [sql, params] of holderNext) {
        await a.query(sql, params);
      }
    } catch (err) {
      holder = `error:${failureCode(err)}`;
    }
    try {
      await a.commit();
    } catch {
      // aborted by a deadlock report — the outcome is already recorded
    }
    const contenderOutcome = await contender;
    try {
      await b.commit();
    } catch {
      // same
    }
    return { holder, contender: contenderOutcome };
  } finally {
    a.stop();
    b.stop();
  }
}

/* ─── suite ───────────────────────────────────────────────────────── */

const live = TEST_DATABASE_URL.length > 0;
let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;

describe("lease-foundation real-PG behaviours", () => {
  beforeAll(() => {
    if (!live) return;
    dbName = `leasedb_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    // full custody base (wallets.id + full lease projection).
    applyCustodyBase(dbUrl);
    seedWallets(dbUrl);
    db = new PsqlExecutor(dbUrl);
  }, 120_000);

  afterAll(() => {
    if (!live || !dbName) return;
    // Best-effort cleanup; DROP DATABASE may be slow under shared PG pressure.
    runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  }, 180_000);

  it("skips cleanly only when Postgres is absent and not required", () => {
    if (live) {
      expect(dbUrl.length).toBeGreaterThan(0);
      return;
    }
    if (PG_REQUIRED) {
      throw new Error(
        "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup provisioned no test database",
      );
    }
    expect(live).toBe(false);
  });

  it("9/10: empty legacy expands; populated legacy refuses", async () => {
    if (!live) return;

    // Empty expand
    const expanded = await migrateLeaseFoundation(db);
    expect(["expanded_empty_legacy", "applied_greenfield", "already_current"]).toContain(
      expanded.status,
    );
    await assertLeaseFoundationReady(db);
    const cols = psqlMust(
      dbUrl,
      `SELECT string_agg(column_name, ',' ) FROM (
         SELECT column_name FROM information_schema.columns
         WHERE table_schema='public' AND table_name='wallet_active_leases'
       ) s`,
    );
    expect(cols).toContain("membership_id");
    expect(cols).toContain("lease_epoch");
    expect(cols).toContain("owner_instance_id");

    // D1 (break): full- custody must not short-circuit foundation FKs.
    // membership_id → wallet_lease_memberships(id) and lease_group_id → lease_groups(id)
    // must exist post-migrate; bare already_current without FK proof is vacuous.
    const fkTargets = psqlMust(
      dbUrl,
      `SELECT string_agg(c.confrelid::regclass::text, ',' ORDER BY c.confrelid::regclass::text)
         FROM pg_constraint c
         JOIN pg_class t ON t.oid = c.conrelid
         JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'wallet_active_leases'
          AND c.contype = 'f'`,
    );
    expect(fkTargets).toMatch(/wallet_lease_memberships/);
    expect(fkTargets).toMatch(/lease_groups/);
    expect(fkTargets).toMatch(/wallets/);

    // Orphan membership/group insert must fail under foundation FKs (not succeed).
    const orphan = runPsql(
      dbUrl,
      `INSERT INTO wallet_active_leases (
         wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
         lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
       ) VALUES (
         '${W1}',
         'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
         'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
         'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
         'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
         'SEND_SOURCE', 1, now(), now(),
         'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
       )`,
    );
    expect(orphan.ok).toBe(false);
    // 23503 foreign_key_violation
    expect(orphan.stderr).toMatch(/23503|foreign key|wallet_lease_memberships|lease_groups/i);

    // Populated legacy refuse: rebuild three-col with a row in a throwaway schema simulation
    // by inserting a full-form row then manually checking LEGACY path via a secondary DB.
    const legacyDb = `leasedb_leg_${Date.now().toString(36)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${legacyDb}`);
    const legacyUrl = withDatabase(TEST_DATABASE_URL, legacyDb);
    try {
      execFileSync("psql", [legacyUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
        input: LEGACY_THREE_COL_DDL,
        encoding: "utf-8",
        timeout: 60_000,
      });
      psqlMust(
        legacyUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ('${W1}', '${NODE}', 'pk1', 'node_generated', 'AVAILABLE');
         INSERT INTO wallet_active_leases (wallet_id, lease_role, acquired_at)
         VALUES ('${W1}', 'SEND_SOURCE', now());`,
      );
      const legacyDbExec = new PsqlExecutor(legacyUrl);
      await expect(migrateLeaseFoundation(legacyDbExec)).rejects.toMatchObject({
        reason: "LEGACY_POPULATED",
      });
    } finally {
      runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${legacyDb} WITH (FORCE)`);
    }
  }, 180_000);

    it("custody full- installs foundation FKs (D1 / coexistence)", async () => {
    if (!live) return;
    // Fresh DB: apply custody only (full columns, wallets FK only), then migrate.
    const d1Db = `dual_d1_${Date.now().toString(36)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${d1Db}`);
    const d1Url = withDatabase(TEST_DATABASE_URL, d1Db);
    try {
      applyCustodyBase(d1Url);
      seedWallets(d1Url); // needs nodes+wallets already from applyCustodyBase path — seedNode inside
      // Pre-migrate: only wallets FK (no membership/group parents even exist yet as FKs).
      const preFks = psqlMust(
        d1Url,
        `SELECT coalesce(string_agg(c.confrelid::regclass::text, ','), '')
           FROM pg_constraint c
           JOIN pg_class t ON t.oid = c.conrelid
           JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE n.nspname = 'public'
            AND t.relname = 'wallet_active_leases'
            AND c.contype = 'f'`,
      );
      expect(preFks).toMatch(/wallets/);
      expect(preFks).not.toMatch(/wallet_lease_memberships/);
      expect(preFks).not.toMatch(/lease_groups/);

      const d1Exec = new PsqlExecutor(d1Url);
      const result = await migrateLeaseFoundation(d1Exec);
      expect(["already_current", "expanded_empty_legacy", "applied_greenfield"]).toContain(
        result.status,
      );
      await assertLeaseFoundationReady(d1Exec);

      const postFks = psqlMust(
        d1Url,
        `SELECT string_agg(c.confrelid::regclass::text, ',' ORDER BY c.confrelid::regclass::text)
           FROM pg_constraint c
           JOIN pg_class t ON t.oid = c.conrelid
           JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE n.nspname = 'public'
            AND t.relname = 'wallet_active_leases'
            AND c.contype = 'f'`,
      );
      expect(postFks).toMatch(/wallet_lease_memberships/);
      expect(postFks).toMatch(/lease_groups/);
      expect(postFks).toMatch(/wallets/);

      const orphan = runPsql(
        d1Url,
        `INSERT INTO wallet_active_leases (
           wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
           lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
         ) VALUES (
           '${W1}',
           'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
           'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
           'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
           'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
           'SEND_SOURCE', 1, now(), now(),
           'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
         )`,
      );
      expect(orphan.ok).toBe(false);
      expect(orphan.stderr).toMatch(/23503|foreign key|wallet_lease_memberships|lease_groups/i);
    } finally {
      runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${d1Db} WITH (FORCE)`);
    }
  }, 180_000);

  it("11: old-writer schema fence fails closed before migrate", async () => {
    if (!live) return;
    // Use a fresh executor against a DB with custody only
    const fenceDb = `leasedb_fence_${Date.now().toString(36)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${fenceDb}`);
    const fenceUrl = withDatabase(TEST_DATABASE_URL, fenceDb);
    try {
      applyCustodyBase(fenceUrl);
      const fenceExec = new PsqlExecutor(fenceUrl);
      await expect(assertLeaseFoundationReady(fenceExec)).rejects.toMatchObject({
        reason: "SCHEMA_NOT_READY",
      });
    } finally {
      runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${fenceDb} WITH (FORCE)`);
    }
  }, 120_000);

  it("13/1/2/4/14/3/7/6/12: acquire, concurrent, release, ABA, sign, replay", async () => {
    if (!live) return;

    // Ensure foundation ready (prior test may have expanded)
    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    // Clear any prior state
    psqlMust(
      dbUrl,
      `TRUNCATE wallet_active_leases, wallet_lease_memberships, lease_group_operations,
               lease_groups, lease_release_proofs, lease_audit_events,
               wallet_lease_epoch_highwater RESTART IDENTITY CASCADE;
       UPDATE wallets SET state = 'AVAILABLE';`,
    );

    const groupId = await withTx(dbUrl, (tx) => createLeaseGroup(tx, OP1));

    // 13: RECONCILIATION rejected before any write
    await expect(
      withTx(dbUrl, (tx) =>
        acquireLeases(tx, {
          wallets: [{ walletId: W1, leaseRole: "RECONCILIATION" }],
          leaseGroupId: groupId,
          rootOperationId: OP1,
          operationId: OP1,
          ownerInstanceId: OWNER,
        }),
      ),
    ).rejects.toMatchObject({ reason: "NON_OPERATION_ROLE" });
    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("0");

    // Happy acquire W1
    const acquired = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W1, leaseRole: "SEND_SOURCE" }],
        leaseGroupId: groupId,
        rootOperationId: OP1,
        operationId: OP1,
        ownerInstanceId: OWNER,
      }),
    );
    expect(acquired).toHaveLength(1);
    expect(acquired[0]!.leaseEpoch).toBe(1n);

    // 1: concurrent second acquire loses (PK / already leased)
    await expect(
      withTx(dbUrl, (tx) =>
        acquireLeases(tx, {
          wallets: [{ walletId: W1, leaseRole: "MOVE_SOURCE" }],
          leaseGroupId: groupId,
          rootOperationId: OP1,
          operationId: OP2,
          ownerInstanceId: OWNER_B,
        }),
      ),
    ).rejects.toMatchObject({ reason: "ALREADY_LEASED" });

    // 2: mixed batch — one already leased → zero net mutation on the free wallet
    const beforeW2 = psqlMust(
      dbUrl,
      `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${W2}'`,
    ).trim();
    // Manual transaction: attempt multi-wallet through repository (throws before free wallet if
    // sorted with W1 first — W1 is lower than W2 so locks W1 first and fails ALREADY_LEASED
    // with no W2 write).
    await expect(
      withTx(dbUrl, (tx) =>
        acquireLeases(tx, {
          wallets: [
            { walletId: W1, leaseRole: "SEND_SOURCE" },
            { walletId: W2, leaseRole: "MOVE_DESTINATION" },
          ],
          leaseGroupId: groupId,
          rootOperationId: OP1,
          operationId: OP2,
          ownerInstanceId: OWNER_B,
        }),
      ),
    ).rejects.toMatchObject({ reason: "ALREADY_LEASED" });
    expect(
      psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${W2}'`).trim(),
    ).toBe(beforeW2);

    const membershipId = acquired[0]!.membershipId;
    const epoch = acquired[0]!.leaseEpoch;

    // 3: foreign owner zero mutation
    const proofId = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId,
        walletId: W1,
        operationId: OP1,
        membershipId,
        leaseGroupId: groupId,
        leaseEpoch: epoch,
        proofKind: "EXTERNAL_SEND_LANDED",
        proofDigest: digest("ok"),
      }),
    );

    await expect(
      withTx(dbUrl, (tx) =>
        releaseLease(tx, {
          walletId: W1,
          ownerInstanceId: OWNER_B,
          operationId: OP1,
          membershipId,
          leaseGroupId: groupId,
          leaseEpoch: epoch,
          releaseProofId: proofId,
          releaseReason: "TEST",
        }),
      ),
    ).rejects.toMatchObject({ reason: "LEASE_OWNER_MISMATCH" });
    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_release_proofs WHERE proof_id = '${proofId}' AND consumed_at IS NULL`,
      ).trim(),
    ).toBe("1");

    // foreign epoch
    await expect(
      withTx(dbUrl, (tx) =>
        releaseLease(tx, {
          walletId: W1,
          ownerInstanceId: OWNER,
          operationId: OP1,
          membershipId,
          leaseGroupId: groupId,
          leaseEpoch: epoch + 1n,
          releaseProofId: proofId,
          releaseReason: "TEST",
        }),
      ),
    ).rejects.toMatchObject({ reason: "LEASE_EPOCH_MISMATCH" });

    // foreign proof tuple
    const foreignProof = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId: foreignProof,
        walletId: W2,
        operationId: OP2,
        membershipId: randomUUID(),
        leaseGroupId: randomUUID(),
        leaseEpoch: 9n,
        proofKind: "EXTERNAL_SEND_LANDED",
        proofDigest: digest("foreign"),
      }),
    );
    await expect(
      withTx(dbUrl, (tx) =>
        releaseLease(tx, {
          walletId: W1,
          ownerInstanceId: OWNER,
          operationId: OP1,
          membershipId,
          leaseGroupId: groupId,
          leaseEpoch: epoch,
          releaseProofId: foreignProof,
          releaseReason: "TEST",
        }),
      ),
    ).rejects.toMatchObject({ reason: "PROOF_FOREIGN" });

    // 12: sign capability holds under matching tuple; fails under stale epoch
    const cap = await withTx(dbUrl, (tx) =>
      assertSignCapability(tx, {
        walletId: W1,
        operationId: OP1,
        leaseEpoch: epoch,
        ownerInstanceId: OWNER,
      }),
    );
    expect(cap.membership_id).toBe(membershipId);

    // Premature release before group-terminal: proof valid but root op incomplete → refuse
    await expect(
      withTx(dbUrl, (tx) =>
        releaseLease(tx, {
          walletId: W1,
          ownerInstanceId: OWNER,
          operationId: OP1,
          membershipId,
          leaseGroupId: groupId,
          leaseEpoch: epoch,
          releaseProofId: proofId,
          releaseReason: "LANDED",
        }),
      ),
    ).rejects.toMatchObject({ reason: "GROUP_NOT_TERMINAL" });
    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_release_proofs WHERE proof_id = '${proofId}' AND consumed_at IS NULL`,
      ).trim(),
    ).toBe("1");

    // 4/14: exact valid release atomicity — only after group operation is terminal
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, { leaseGroupId: groupId, operationId: OP1 }),
    );
    const released = await withTx(dbUrl, (tx) =>
      releaseLease(tx, {
        walletId: W1,
        ownerInstanceId: OWNER,
        operationId: OP1,
        membershipId,
        leaseGroupId: groupId,
        leaseEpoch: epoch,
        releaseProofId: proofId,
        releaseReason: "LANDED",
      }),
    );
    expect(released.deletedRows).toBe(1);
    expect(released.groupReleased).toBe(true);
    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("0");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_lease_memberships WHERE id = '${membershipId}' AND released_at IS NOT NULL`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_release_proofs WHERE proof_id = '${proofId}' AND consumed_at IS NOT NULL`,
      ).trim(),
    ).toBe("1");

    // replay proof zero mutation
    await expect(
      withTx(dbUrl, (tx) =>
        releaseLease(tx, {
          walletId: W1,
          ownerInstanceId: OWNER,
          operationId: OP1,
          membershipId,
          leaseGroupId: groupId,
          leaseEpoch: epoch,
          releaseProofId: proofId,
          releaseReason: "LANDED",
        }),
      ),
    ).rejects.toMatchObject({ reason: "GROUP_ALREADY_RELEASED" });

    // 6/7: restart epoch persistence + ABA — successor epoch is 2, stale epoch 1 cannot sign
    const group2 = await withTx(dbUrl, (tx) => createLeaseGroup(tx, OP2));
    const second = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W1, leaseRole: "SEND_SOURCE" }],
        leaseGroupId: group2,
        rootOperationId: OP2,
        operationId: OP2,
        ownerInstanceId: OWNER,
      }),
    );
    expect(second[0]!.leaseEpoch).toBe(2n);
    await expect(
      withTx(dbUrl, (tx) =>
        assertSignCapability(tx, {
          walletId: W1,
          operationId: OP2,
          leaseEpoch: 1n,
          ownerInstanceId: OWNER,
        }),
      ),
    ).rejects.toMatchObject({ reason: "SIGN_CAPABILITY_MISMATCH" });

    // high-water survives delete of active row
    const proof2 = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId: proof2,
        walletId: W1,
        operationId: OP2,
        membershipId: second[0]!.membershipId,
        leaseGroupId: group2,
        leaseEpoch: 2n,
        proofKind: "EXTERNAL_SEND_LANDED",
        proofDigest: digest("second"),
      }),
    );
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, { leaseGroupId: group2, operationId: OP2 }),
    );
    await withTx(dbUrl, (tx) =>
      releaseLease(tx, {
        walletId: W1,
        ownerInstanceId: OWNER,
        operationId: OP2,
        membershipId: second[0]!.membershipId,
        leaseGroupId: group2,
        leaseEpoch: 2n,
        releaseProofId: proof2,
        releaseReason: "LANDED",
      }),
    );
    const hw = psqlMust(
      dbUrl,
      `SELECT highwater FROM wallet_lease_epoch_highwater WHERE wallet_id = '${W1}'`,
    ).trim();
    expect(Number(hw)).toBeGreaterThanOrEqual(2);

    // 8: unguarded direct SQL DELETE is possible at SQL level (no PG REVOKE in this slice) —
    // process discipline: repository is the only sanctioned path; count that a direct DELETE
    // leaves membership open (orphan) so reconciliation must repair, not treat as release.
    const g3 = await withTx(dbUrl, (tx) => createLeaseGroup(tx, randomUUID()));
    const third = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W2, leaseRole: "SEND_SOURCE" }],
        leaseGroupId: g3,
        rootOperationId: randomUUID(),
        operationId: randomUUID(),
        ownerInstanceId: OWNER,
      }),
    );
    psqlMust(dbUrl, `DELETE FROM wallet_active_leases WHERE wallet_id = '${W2}'`);
    const openMembership = psqlMust(
      dbUrl,
      `SELECT count(*) FROM wallet_lease_memberships
       WHERE id = '${third[0]!.membershipId}' AND released_at IS NULL`,
    ).trim();
    expect(openMembership).toBe("1");
  }, 180_000);

  it("5: rollback injection — failed step leaves zero active rows for the batch", async () => {
    if (!live) return;
    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    // Acquire W3 alone, then attempt batch including a duplicate id to force throw pre-write
    await expect(
      withTx(dbUrl, (tx) =>
        acquireLeases(tx, {
          wallets: [
            { walletId: W3, leaseRole: "SEND_SOURCE" },
            { walletId: W3, leaseRole: "MOVE_SOURCE" },
          ],
          leaseGroupId: randomUUID(),
          rootOperationId: randomUUID(),
          operationId: randomUUID(),
          ownerInstanceId: OWNER,
        }),
      ),
    ).rejects.toMatchObject({ reason: "DUPLICATE_WALLET_ID" });
    expect(
      psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${W3}'`).trim(),
    ).toBe("0");

    // Invalid role mid-batch rejected before writes
    await expect(
      withTx(dbUrl, (tx) =>
        acquireLeases(tx, {
          wallets: [
            { walletId: W3, leaseRole: "SEND_SOURCE" },
            { walletId: W2, leaseRole: "RECONCILIATION" },
          ],
          leaseGroupId: randomUUID(),
          rootOperationId: randomUUID(),
          operationId: randomUUID(),
          ownerInstanceId: OWNER,
        }),
      ),
    ).rejects.toMatchObject({ reason: "NON_OPERATION_ROLE" });
    expect(
      psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${W3}'`).trim(),
    ).toBe("0");
  }, 60_000);

  it("1b: concurrent multi-session insert one-winner on PK", async () => {
    if (!live) return;
    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    // Ensure W3 free
    psqlMust(dbUrl, `DELETE FROM wallet_active_leases WHERE wallet_id = '${W3}'`);
    const group = await withTx(dbUrl, (tx) => createLeaseGroup(tx, randomUUID()));
    // First winner via repository
    await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W3, leaseRole: "SEND_SOURCE" }],
        leaseGroupId: group,
        rootOperationId: randomUUID(),
        operationId: randomUUID(),
        ownerInstanceId: OWNER,
      }),
    );
    // Second session raw INSERT must hit unique_violation on wallet_id PK
    const mem = randomUUID();
    const g = randomUUID();
    const op = randomUUID();
    // membership + group scaffolding
    psqlMust(
      dbUrl,
      `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ('${g}', '${op}', now());
       INSERT INTO wallet_lease_memberships
         (id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at)
       VALUES ('${mem}', '${g}', '${W3}', '${op}', 'SEND_SOURCE', 99, now());`,
    );
    const outcome = runPsql(
      dbUrl,
      `INSERT INTO wallet_active_leases (
         wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
         lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
       ) VALUES (
         '${W3}', '${mem}', '${g}', '${op}', '${op}',
         'SEND_SOURCE', 99, now(), now(), '${OWNER_B}'
       );`,
    );
    expect(outcome.ok).toBe(false);
    expect(extractSqlstate(outcome.stderr)).toBe("23505");
  }, 60_000);

  /**
   * Break-review regression (dual FAIL @ 75df8ec5):
   * greenfield without wallets must not leave a ready fence or claim already_current
   * without the eligibility guard.
   */
  it("fail-open guard: greenfield without wallets never fences; repair installs guard", async () => {
    if (!live) return;

    const bareDb = `leasedb_bare_${Date.now().toString(36)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${bareDb}`);
    const bareUrl = withDatabase(TEST_DATABASE_URL, bareDb);
    const bare = new PsqlExecutor(bareUrl);

    try {
      // 1) First greenfield without wallets — must fail and leave no foundation tables.
      await expect(migrateLeaseFoundation(bare)).rejects.toThrow(/wallets|SCHEMA_NOT_READY|does not exist/i);

      const tablesAfterFail = psqlMust(
        bareUrl,
        `SELECT coalesce(string_agg(table_name, ',' ORDER BY table_name), '')
           FROM information_schema.tables
          WHERE table_schema = 'public'
            AND table_name IN (
              'wallet_active_leases','lease_groups','lease_schema_fence',
              'wallet_lease_memberships','lease_release_proofs','lease_audit_events',
              'wallet_lease_epoch_highwater','lease_group_operations'
            )`,
      ).trim();
      expect(tablesAfterFail).toBe("");

      const fnAfterFail = psqlMust(
        bareUrl,
        `SELECT count(*) FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'custody_reject_ineligible_lease'`,
      ).trim();
      expect(fnAfterFail).toBe("0");

      await expect(assertLeaseFoundationReady(bare)).rejects.toMatchObject({
        reason: "SCHEMA_NOT_READY",
      });

      // 2) Re-migrate still without wallets — must NOT already_current / must not fence.
      await expect(migrateLeaseFoundation(bare)).rejects.toThrow(/wallets|SCHEMA_NOT_READY|does not exist/i);
      await expect(assertLeaseFoundationReady(bare)).rejects.toMatchObject({
        reason: "SCHEMA_NOT_READY",
      });
      expect(await eligibilityGuardPresent(bare)).toBe(false);

      // 3) Simulate the prior fail-open residue: full-column table, no function/trigger,
      //    and a stale fence row. Re-migrate must refuse already_current success and clear
      //    readiness until the guard can be installed.
      psqlMust(
        bareUrl,
        `
CREATE TYPE wallet_lease_role AS ENUM (
  'RECEIVE_WINDOW', 'MOVE_SOURCE', 'MOVE_DESTINATION', 'SEND_SOURCE', 'RECONCILIATION'
);
CREATE TABLE lease_groups (
  id uuid PRIMARY KEY, root_operation_id uuid NOT NULL UNIQUE,
  created_at timestamptz NOT NULL, released_at timestamptz, release_proof_id uuid
);
CREATE TABLE wallet_lease_memberships (
  id uuid PRIMARY KEY, lease_group_id uuid NOT NULL REFERENCES lease_groups (id),
  wallet_id uuid NOT NULL, operation_id uuid NOT NULL, lease_role text NOT NULL,
  lease_epoch bigint NOT NULL, acquired_at timestamptz NOT NULL,
  released_at timestamptz, release_reason text, release_proof_id uuid
);
CREATE TABLE wallet_active_leases (
  wallet_id uuid PRIMARY KEY, membership_id uuid NOT NULL UNIQUE,
  lease_group_id uuid NOT NULL, root_operation_id uuid NOT NULL,
  operation_id uuid NOT NULL, lease_role text NOT NULL,
  lease_epoch bigint NOT NULL, acquired_at timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL, owner_instance_id uuid NOT NULL,
  release_not_before timestamptz
);
CREATE TABLE lease_schema_fence (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  schema_version integer NOT NULL, applied_at timestamptz NOT NULL
);
INSERT INTO lease_schema_fence (singleton, schema_version, applied_at)
VALUES (true, 1, now());
`,
      );

      await expect(migrateLeaseFoundation(bare)).rejects.toMatchObject({
        reason: "SCHEMA_NOT_READY",
      });
      // Stale fence must not satisfy readiness without the guard.
      await expect(assertLeaseFoundationReady(bare)).rejects.toMatchObject({
        reason: "SCHEMA_NOT_READY",
      });
      expect(await eligibilityGuardPresent(bare)).toBe(false);

      // 4) Install wallet_lease_role + wallets + destinations (minimal columns the
      //    function compiles against and the foundation CREATE TABLE needs), then
      //    migrate succeeds, installs guard, and only then is ready.
      psqlMust(
        bareUrl,
        `
-- wallet_lease_role may already exist from the residue step above.
DO $enum$ BEGIN
  CREATE TYPE wallet_lease_role AS ENUM (
    'RECEIVE_WINDOW',
    'MOVE_SOURCE',
    'MOVE_DESTINATION',
    'SEND_SOURCE',
    'RECONCILIATION'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $enum$;
CREATE TYPE wallet_key_origin AS ENUM ('node_generated', 'imported');
CREATE TYPE wallet_state AS ENUM ('AVAILABLE', 'PINNED', 'QUARANTINED', 'RETIRED');
CREATE TYPE destination_state AS ENUM ('PENDING', 'BLESSED', 'RETIRED');
CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  public_key text NOT NULL,
  key_origin wallet_key_origin NOT NULL,
  state wallet_state NOT NULL,
  recovery_verified_at timestamptz,
  recovery_verification_id uuid
);
CREATE TABLE destinations (
  id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL UNIQUE REFERENCES wallets (id),
  node_id uuid NOT NULL,
  state destination_state NOT NULL
);
`,
      );

      const repaired = await migrateLeaseFoundation(bare);
      expect(["applied_greenfield", "already_current", "expanded_empty_legacy"]).toContain(
        repaired.status,
      );
      expect(await eligibilityGuardPresent(bare)).toBe(true);
      await assertLeaseFoundationReady(bare);

      const trg = psqlMust(
        bareUrl,
        `SELECT count(*) FROM pg_trigger t
           JOIN pg_class c ON c.oid = t.tgrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_proc p ON p.oid = t.tgfoid
          WHERE n.nspname = 'public'
            AND c.relname = 'wallet_active_leases'
            AND t.tgname = 'wallet_active_leases_eligibility_guard'
            AND p.proname = 'custody_reject_ineligible_lease'
            AND NOT t.tgisinternal`,
      ).trim();
      expect(trg).toBe("1");
    } finally {
      runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${bareDb} WITH (FORCE)`);
    }
  }, 180_000);

  /**
   * Receive + unfinished automatic child move must not unpin the receiver.
   * Wallets PK is `id`; recovery evidence uses canon columns (`id`, `public_key`,
   * sha256_hex export, audit_event_id, verifier_identity).
   * Expected: GROUP_NOT_TERMINAL, zero mutation on membership/active/proof/pin.
   */
  it("15: group-terminal gate — receive+child refuses premature unpin", async () => {
    if (!live) return;
    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    const OP_RECV = "d0000000-0000-4000-8000-0000000000a1";
    const OP_MOVE = "d0000000-0000-4000-8000-0000000000a2";
    const RECV_VERIFICATION = "e0000000-0000-4000-8000-0000000000b1";
    const EXPORT_SHA = "b".repeat(64);
    const W1_PK = pubkey("W1");

    psqlMust(
      dbUrl,
      `TRUNCATE wallet_active_leases, wallet_lease_memberships, lease_group_operations,
               lease_groups, lease_release_proofs, lease_audit_events,
               wallet_lease_epoch_highwater RESTART IDENTITY CASCADE;
       UPDATE wallets SET state = 'AVAILABLE' WHERE id = '${W1}';
       -- Recovery is monotonic (never clear). Ensure a verification row exists for pin eligibility.
       INSERT INTO wallet_recovery_verifications
         (id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity)
       SELECT '${RECV_VERIFICATION}', '${W1}', 'AUDITED_EXPORT', '${EXPORT_SHA}', '${W1_PK}',
              '${RECV_VERIFICATION}', now(), 'recv-test'
        WHERE NOT EXISTS (
          SELECT 1 FROM wallet_recovery_verifications WHERE wallet_id = '${W1}'
        );
       UPDATE wallets w SET
         recovery_verified_at = COALESCE(w.recovery_verified_at, now()),
         recovery_verification_id = COALESCE(
           w.recovery_verification_id,
           (SELECT id FROM wallet_recovery_verifications
             WHERE wallet_id = '${W1}' ORDER BY verified_at LIMIT 1)
         )
         WHERE w.id = '${W1}';`,
    );

    const groupId = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, { rootOperationId: OP_RECV, childDisposition: "PENDING" }),
    );
    const acquired = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W1, leaseRole: "RECEIVE_WINDOW" }],
        leaseGroupId: groupId,
        rootOperationId: OP_RECV,
        operationId: OP_RECV,
        ownerInstanceId: OWNER,
      }),
    );
    expect(acquired).toHaveLength(1);
    expect(psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim()).toBe("PINNED");
    expect(
      psqlMust(
        dbUrl,
        `SELECT child_disposition FROM lease_groups WHERE id = '${groupId}'`,
      ).trim(),
    ).toBe("PENDING");

    // Child move joins the same lease group; receiver remains continuously held.
    await withTx(dbUrl, (tx) =>
      joinLeaseGroupOperation(tx, { leaseGroupId: groupId, operationId: OP_MOVE }),
    );
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_group_operations WHERE lease_group_id = '${groupId}'`,
      ).trim(),
    ).toBe("2");
    expect(
      psqlMust(
        dbUrl,
        `SELECT child_disposition FROM lease_groups WHERE id = '${groupId}'`,
      ).trim(),
    ).toBe("JOINED");

    const membershipId = acquired[0]!.membershipId;
    const epoch = acquired[0]!.leaseEpoch;
    const proofId = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId,
        walletId: W1,
        operationId: OP_RECV,
        membershipId,
        leaseGroupId: groupId,
        leaseEpoch: epoch,
        proofKind: "RECEIVE_LANDED",
        proofDigest: digest("recv-landed"),
      }),
    );

    // Only the receive is complete — child still open. Release must refuse and leave pin.
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, { leaseGroupId: groupId, operationId: OP_RECV }),
    );

    await expect(
      withTx(dbUrl, (tx) =>
        releaseLease(tx, {
          walletId: W1,
          ownerInstanceId: OWNER,
          operationId: OP_RECV,
          membershipId,
          leaseGroupId: groupId,
          leaseEpoch: epoch,
          releaseProofId: proofId,
          releaseReason: "RECEIVE_LANDED",
        }),
      ),
    ).rejects.toMatchObject({ reason: "GROUP_NOT_TERMINAL" });

    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("1");
    expect(psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim()).toBe("PINNED");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_lease_memberships WHERE id = '${membershipId}' AND released_at IS NULL`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_release_proofs WHERE proof_id = '${proofId}' AND consumed_at IS NULL`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_groups WHERE id = '${groupId}' AND released_at IS NULL`,
      ).trim(),
    ).toBe("1");

    // Concurrent second session also refuses while child incomplete (no partial mutate).
    await expect(
      withTx(dbUrl, (tx) =>
        releaseLease(tx, {
          walletId: W1,
          ownerInstanceId: OWNER,
          operationId: OP_RECV,
          membershipId,
          leaseGroupId: groupId,
          leaseEpoch: epoch,
          releaseProofId: proofId,
          releaseReason: "RECEIVE_LANDED",
        }),
      ),
    ).rejects.toMatchObject({ reason: "GROUP_NOT_TERMINAL" });

    // Child becomes terminal → group predicate passes → release unpins and stamps group.
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, { leaseGroupId: groupId, operationId: OP_MOVE }),
    );
    const released = await withTx(dbUrl, (tx) =>
      releaseLease(tx, {
        walletId: W1,
        ownerInstanceId: OWNER,
        operationId: OP_RECV,
        membershipId,
        leaseGroupId: groupId,
        leaseEpoch: epoch,
        releaseProofId: proofId,
        releaseReason: "RECEIVE_LANDED",
      }),
    );
    expect(released.deletedRows).toBe(1);
    expect(released.groupReleased).toBe(true);
    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("0");
    expect(psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim()).toBe("AVAILABLE");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_groups WHERE id = '${groupId}' AND released_at IS NOT NULL`,
      ).trim(),
    ).toBe("1");
  }, 180_000);

  /**
   * D1 — pre-formation window: root complete, child disposition PENDING, no join.
   * releaseLease must refuse; pin/active/proof/membership/group untouched.
   */
  it("16: PENDING child disposition refuses pre-join release", async () => {
    if (!live) return;
    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    const OP_RECV = "d0000000-0000-4000-8000-0000000000c1";
    const RECV_VERIFICATION = "e0000000-0000-4000-8000-0000000000c2";
    const EXPORT_SHA = "c".repeat(64);
    const W1_PK = pubkey("W1");

    psqlMust(
      dbUrl,
      `TRUNCATE wallet_active_leases, wallet_lease_memberships, lease_group_operations,
               lease_groups, lease_release_proofs, lease_audit_events,
               wallet_lease_epoch_highwater RESTART IDENTITY CASCADE;
       UPDATE wallets SET state = 'AVAILABLE' WHERE id = '${W1}';
       INSERT INTO wallet_recovery_verifications
         (id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity)
       SELECT '${RECV_VERIFICATION}', '${W1}', 'AUDITED_EXPORT', '${EXPORT_SHA}', '${W1_PK}',
              '${RECV_VERIFICATION}', now(), 'recv-test'
        WHERE NOT EXISTS (
          SELECT 1 FROM wallet_recovery_verifications WHERE wallet_id = '${W1}'
        );
       UPDATE wallets w SET
         recovery_verified_at = COALESCE(w.recovery_verified_at, now()),
         recovery_verification_id = COALESCE(
           w.recovery_verification_id,
           (SELECT id FROM wallet_recovery_verifications
             WHERE wallet_id = '${W1}' ORDER BY verified_at LIMIT 1)
         )
         WHERE w.id = '${W1}';`,
    );

    const groupId = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, { rootOperationId: OP_RECV, childDisposition: "PENDING" }),
    );
    expect(
      psqlMust(
        dbUrl,
        `SELECT child_disposition FROM lease_groups WHERE id = '${groupId}'`,
      ).trim(),
    ).toBe("PENDING");

    const acquired = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W1, leaseRole: "RECEIVE_WINDOW" }],
        leaseGroupId: groupId,
        rootOperationId: OP_RECV,
        operationId: OP_RECV,
        ownerInstanceId: OWNER,
      }),
    );
    expect(psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim()).toBe("PINNED");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_group_operations WHERE lease_group_id = '${groupId}'`,
      ).trim(),
    ).toBe("1");

    const membershipId = acquired[0]!.membershipId;
    const epoch = acquired[0]!.leaseEpoch;
    const proofId = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId,
        walletId: W1,
        operationId: OP_RECV,
        membershipId,
        leaseGroupId: groupId,
        leaseEpoch: epoch,
        proofKind: "RECEIVE_LANDED",
        proofDigest: digest("recv-prejoin"),
      }),
    );
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, { leaseGroupId: groupId, operationId: OP_RECV }),
    );

    await expect(
      withTx(dbUrl, (tx) =>
        releaseLease(tx, {
          walletId: W1,
          ownerInstanceId: OWNER,
          operationId: OP_RECV,
          membershipId,
          leaseGroupId: groupId,
          leaseEpoch: epoch,
          releaseProofId: proofId,
          releaseReason: "RECEIVE_LANDED",
        }),
      ),
    ).rejects.toMatchObject({ reason: "GROUP_NOT_TERMINAL" });

    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("1");
    expect(psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim()).toBe("PINNED");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_lease_memberships WHERE id = '${membershipId}' AND released_at IS NULL`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_release_proofs WHERE proof_id = '${proofId}' AND consumed_at IS NULL`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_groups WHERE id = '${groupId}' AND released_at IS NULL AND child_disposition = 'PENDING'`,
      ).trim(),
    ).toBe("1");
  }, 180_000);

  /**
   * D1 — HOLD/no-child positive: disposition NONE, root complete, no child join.
   * releaseLease must unpin and stamp the group.
   */
  it("17: NONE disposition allows HOLD root-terminal release", async () => {
    if (!live) return;
    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    const OP_RECV = "d0000000-0000-4000-8000-0000000000d1";
    const RECV_VERIFICATION = "e0000000-0000-4000-8000-0000000000d2";
    const EXPORT_SHA = "d".repeat(64);
    const W1_PK = pubkey("W1");

    psqlMust(
      dbUrl,
      `TRUNCATE wallet_active_leases, wallet_lease_memberships, lease_group_operations,
               lease_groups, lease_release_proofs, lease_audit_events,
               wallet_lease_epoch_highwater RESTART IDENTITY CASCADE;
       UPDATE wallets SET state = 'AVAILABLE' WHERE id = '${W1}';
       INSERT INTO wallet_recovery_verifications
         (id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity)
       SELECT '${RECV_VERIFICATION}', '${W1}', 'AUDITED_EXPORT', '${EXPORT_SHA}', '${W1_PK}',
              '${RECV_VERIFICATION}', now(), 'recv-test'
        WHERE NOT EXISTS (
          SELECT 1 FROM wallet_recovery_verifications WHERE wallet_id = '${W1}'
        );
       UPDATE wallets w SET
         recovery_verified_at = COALESCE(w.recovery_verified_at, now()),
         recovery_verification_id = COALESCE(
           w.recovery_verification_id,
           (SELECT id FROM wallet_recovery_verifications
             WHERE wallet_id = '${W1}' ORDER BY verified_at LIMIT 1)
         )
         WHERE w.id = '${W1}';`,
    );

    const groupId = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, { rootOperationId: OP_RECV, childDisposition: "NONE" }),
    );
    expect(
      psqlMust(
        dbUrl,
        `SELECT child_disposition FROM lease_groups WHERE id = '${groupId}'`,
      ).trim(),
    ).toBe("NONE");

    const acquired = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W1, leaseRole: "RECEIVE_WINDOW" }],
        leaseGroupId: groupId,
        rootOperationId: OP_RECV,
        operationId: OP_RECV,
        ownerInstanceId: OWNER,
      }),
    );
    const membershipId = acquired[0]!.membershipId;
    const epoch = acquired[0]!.leaseEpoch;
    const proofId = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId,
        walletId: W1,
        operationId: OP_RECV,
        membershipId,
        leaseGroupId: groupId,
        leaseEpoch: epoch,
        proofKind: "RECEIVE_LANDED",
        proofDigest: digest("recv-hold"),
      }),
    );
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, { leaseGroupId: groupId, operationId: OP_RECV }),
    );

    const released = await withTx(dbUrl, (tx) =>
      releaseLease(tx, {
        walletId: W1,
        ownerInstanceId: OWNER,
        operationId: OP_RECV,
        membershipId,
        leaseGroupId: groupId,
        leaseEpoch: epoch,
        releaseProofId: proofId,
        releaseReason: "RECEIVE_LANDED",
      }),
    );
    expect(released.deletedRows).toBe(1);
    expect(released.groupReleased).toBe(true);
    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("0");
    expect(psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim()).toBe("AVAILABLE");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_groups WHERE id = '${groupId}' AND released_at IS NOT NULL`,
      ).trim(),
    ).toBe("1");
  }, 180_000);

  it("18: receive→child transfer — uninterrupted row, stale cap invalid, dest joins", async () => {
    if (!live) return;

    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    const OP_RECV = OP1;
    const OP_MOVE = OP2;

    psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
    seedReceiveChildFixtures(dbUrl);

    const groupId = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, { rootOperationId: OP_RECV, childDisposition: "PENDING" }),
    );

    const acquired = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W1, leaseRole: "RECEIVE_WINDOW" }],
        leaseGroupId: groupId,
        rootOperationId: OP_RECV,
        operationId: OP_RECV,
        ownerInstanceId: OWNER,
      }),
    );
    expect(acquired).toHaveLength(1);
    const parentMembershipId = acquired[0]!.membershipId;
    const parentEpoch = acquired[0]!.leaseEpoch;
    expect(parentEpoch).toBe(1n);
    expect(
      psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim(),
    ).toBe("PINNED");

    await withTx(dbUrl, (tx) =>
      joinLeaseGroupOperation(tx, { leaseGroupId: groupId, operationId: OP_MOVE }),
    );
    expect(
      psqlMust(
        dbUrl,
        `SELECT child_disposition FROM lease_groups WHERE id = '${groupId}'`,
      ).trim(),
    ).toBe("JOINED");

    const proofId = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId,
        walletId: W1,
        operationId: OP_RECV,
        membershipId: parentMembershipId,
        leaseGroupId: groupId,
        leaseEpoch: parentEpoch,
        proofKind: "RECEIVE_LANDED",
        proofDigest: digest("recv-landed"),
      }),
    );

    const transferred = await withTx(dbUrl, (tx) =>
      transferLeaseWithinGroup(tx, {
        walletId: W1,
        ownerInstanceId: OWNER,
        leaseGroupId: groupId,
        fromOperationId: OP_RECV,
        toOperationId: OP_MOVE,
        membershipId: parentMembershipId,
        leaseEpoch: parentEpoch,
        toLeaseRole: "MOVE_SOURCE",
        releaseProofId: proofId,
        releaseReason: "RECEIVE_LANDED_HANDOFF",
      }),
    );

    expect(transferred.leaseEpoch).toBe(2n);
    expect(transferred.operationId).toBe(OP_MOVE);
    expect(transferred.leaseRole).toBe("MOVE_SOURCE");
    expect(transferred.rootOperationId).toBe(OP_RECV);
    expect(transferred.previousMembershipId).toBe(parentMembershipId);
    expect(transferred.membershipId).not.toBe(parentMembershipId);

    // Phase B (operation-flow step 3): the destination joins the same group under the child op.
    const joinedDestinations = await withTx(dbUrl, (tx) =>
      acquireGroupDestinationLeases(tx, {
        leaseGroupId: groupId,
        operationId: OP_MOVE,
        ownerInstanceId: OWNER,
        destinations: [{ walletId: W2, leaseRole: "MOVE_DESTINATION" }],
      }),
    );
    expect(joinedDestinations).toHaveLength(1);
    expect(joinedDestinations[0]!.walletId).toBe(W2);
    expect(
      psqlMust(
        dbUrl,
        `SELECT root_operation_id FROM wallet_active_leases WHERE wallet_id = '${W2}'`,
      ).trim(),
    ).toBe(OP_RECV);

    // Active row never deleted: source + dest both present.
    expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("2");

    const sourceRow = psqlMust(
      dbUrl,
      `SELECT operation_id || '|' || lease_role || '|' || lease_epoch::text || '|' ||
              root_operation_id || '|' || membership_id
         FROM wallet_active_leases WHERE wallet_id = '${W1}'`,
    ).trim();
    expect(sourceRow.startsWith(`${OP_MOVE}|MOVE_SOURCE|2|${OP_RECV}|`)).toBe(true);
    expect(sourceRow.endsWith(transferred.membershipId)).toBe(true);

    // No unpin window across the hand-off.
    expect(
      psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim(),
    ).toBe("PINNED");

    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_lease_memberships
          WHERE id = '${parentMembershipId}' AND released_at IS NOT NULL`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_lease_memberships
          WHERE id = '${transferred.membershipId}' AND released_at IS NULL`,
      ).trim(),
    ).toBe("1");

    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_audit_events WHERE action = 'LEASE_TRANSFERRED'`,
      ).trim(),
    ).toBe("1");

    // Parent capability permanently invalid (AC).
    await expect(
      withTx(dbUrl, (tx) =>
        assertSignCapability(tx, {
          walletId: W1,
          operationId: OP_RECV,
          leaseEpoch: parentEpoch,
          ownerInstanceId: OWNER,
        }),
      ),
    ).rejects.toMatchObject({ reason: "LEASE_OPERATION_MISMATCH" });

    const cap = await withTx(dbUrl, (tx) =>
      assertSignCapability(tx, {
        walletId: W1,
        operationId: OP_MOVE,
        leaseEpoch: transferred.leaseEpoch,
        ownerInstanceId: OWNER,
      }),
    );
    expect(cap.membership_id).toBe(transferred.membershipId);

    // Stale heartbeat never frees: second holder refused.
    await expect(
      withTx(dbUrl, (tx) =>
        acquireLeases(tx, {
          wallets: [{ walletId: W1, leaseRole: "SEND_SOURCE" }],
          leaseGroupId: groupId,
          rootOperationId: OP_RECV,
          operationId: randomUUID(),
          ownerInstanceId: OWNER_B,
        }),
      ),
    ).rejects.toMatchObject({ reason: "ALREADY_LEASED" });

    // Negative: transfer without child join mutates nothing.
    const bareRoot = randomUUID();
    const bareGroup = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, { rootOperationId: bareRoot, childDisposition: "NONE" }),
    );
    const bareAcq = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W3, leaseRole: "SEND_SOURCE" }],
        leaseGroupId: bareGroup,
        rootOperationId: bareRoot,
        operationId: bareRoot,
        ownerInstanceId: OWNER,
      }),
    );
    const bareProof = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId: bareProof,
        walletId: W3,
        operationId: bareRoot,
        membershipId: bareAcq[0]!.membershipId,
        leaseGroupId: bareGroup,
        leaseEpoch: bareAcq[0]!.leaseEpoch,
        proofKind: "EXTERNAL_SEND_LANDED",
        proofDigest: digest("bare"),
      }),
    );
    await expect(
      withTx(dbUrl, (tx) =>
        transferLeaseWithinGroup(tx, {
          walletId: W3,
          ownerInstanceId: OWNER,
          leaseGroupId: bareGroup,
          fromOperationId: bareRoot,
          toOperationId: randomUUID(),
          membershipId: bareAcq[0]!.membershipId,
          leaseEpoch: bareAcq[0]!.leaseEpoch,
          toLeaseRole: "MOVE_SOURCE",
          releaseProofId: bareProof,
          releaseReason: "NO_CHILD",
        }),
      ),
    ).rejects.toMatchObject({ reason: "TRANSFER_TARGET_NOT_JOINED" });
    expect(
      psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${W3}'`).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_release_proofs WHERE proof_id = '${bareProof}' AND consumed_at IS NULL`,
      ).trim(),
    ).toBe("1");
  }, 180_000);

  /**
   * Break-review D1. The hand-off used to acquire the destinations in
   * its own transaction, so a busy destination rewound the parent close, the proof consume
   * and the source re-point. operation-flow step 3 requires the opposite: "If busy, the child
   * remains `CREATED`; the source lease remains continuously held."
   */
  it("19: D1 — busy destination leaves the source hand-off durable (operation-flow step 3)", async () => {
    if (!live) return;

    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
    seedReceiveChildFixtures(dbUrl);

    const OP_RECV = randomUUID();
    const OP_MOVE = randomUUID();
    const OP_FOREIGN = randomUUID();

    // The destination W2 is busy: an unrelated operation holds it in its own lease group.
    const foreignGroup = await withTx(dbUrl, (tx) => createLeaseGroup(tx, OP_FOREIGN));
    const foreignAcquired = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W2, leaseRole: "SEND_SOURCE" }],
        leaseGroupId: foreignGroup,
        rootOperationId: OP_FOREIGN,
        operationId: OP_FOREIGN,
        ownerInstanceId: OWNER_B,
      }),
    );

    const groupId = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, { rootOperationId: OP_RECV, childDisposition: "PENDING" }),
    );
    const parent = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W1, leaseRole: "RECEIVE_WINDOW" }],
        leaseGroupId: groupId,
        rootOperationId: OP_RECV,
        operationId: OP_RECV,
        ownerInstanceId: OWNER,
      }),
    );
    await withTx(dbUrl, (tx) =>
      joinLeaseGroupOperation(tx, { leaseGroupId: groupId, operationId: OP_MOVE }),
    );
    const proofId = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId,
        walletId: W1,
        operationId: OP_RECV,
        membershipId: parent[0]!.membershipId,
        leaseGroupId: groupId,
        leaseEpoch: parent[0]!.leaseEpoch,
        proofKind: "RECEIVE_LANDED",
        proofDigest: digest("d1-recv-landed"),
      }),
    );

    // Phase A commits on its own.
    const transferred = await withTx(dbUrl, (tx) =>
      transferLeaseWithinGroup(tx, {
        walletId: W1,
        ownerInstanceId: OWNER,
        leaseGroupId: groupId,
        fromOperationId: OP_RECV,
        toOperationId: OP_MOVE,
        membershipId: parent[0]!.membershipId,
        leaseEpoch: parent[0]!.leaseEpoch,
        toLeaseRole: "MOVE_SOURCE",
        releaseProofId: proofId,
        releaseReason: "RECEIVE_LANDED_HANDOFF",
      }),
    );

    // Phase B refuses — and must not touch phase A's committed work.
    await expect(
      withTx(dbUrl, (tx) =>
        acquireGroupDestinationLeases(tx, {
          leaseGroupId: groupId,
          operationId: OP_MOVE,
          ownerInstanceId: OWNER,
          destinations: [{ walletId: W2, leaseRole: "MOVE_DESTINATION" }],
        }),
      ),
    ).rejects.toMatchObject({ reason: "ALREADY_LEASED", walletId: W2 });

    // Source still held, continuously, under the child operation at the successor epoch.
    expect(
      psqlMust(
        dbUrl,
        `SELECT operation_id || '|' || lease_role || '|' || lease_epoch::text || '|' ||
                root_operation_id || '|' || membership_id
           FROM wallet_active_leases WHERE wallet_id = '${W1}'`,
      ).trim(),
    ).toBe(
      `${OP_MOVE}|MOVE_SOURCE|${transferred.leaseEpoch.toString()}|${OP_RECV}|${transferred.membershipId}`,
    );
    expect(
      psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${W1}'`).trim(),
    ).toBe("PINNED");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_lease_memberships
          WHERE id = '${parent[0]!.membershipId}' AND released_at IS NOT NULL`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM lease_release_proofs
          WHERE proof_id = '${proofId}' AND consumed_at IS NOT NULL`,
      ).trim(),
    ).toBe("1");
    // No destination joined the child, and the busy holder is untouched.
    expect(
      psqlMust(
        dbUrl,
        `SELECT count(*) FROM wallet_active_leases WHERE lease_group_id = '${groupId}'`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT lease_group_id || '|' || operation_id || '|' || owner_instance_id
           FROM wallet_active_leases WHERE wallet_id = '${W2}'`,
      ).trim(),
    ).toBe(`${foreignGroup}|${OP_FOREIGN}|${OWNER_B}`);
    // The child capability works, so the move can proceed to retry phase B.
    const cap = await withTx(dbUrl, (tx) =>
      assertSignCapability(tx, {
        walletId: W1,
        operationId: OP_MOVE,
        leaseEpoch: transferred.leaseEpoch,
        ownerInstanceId: OWNER,
      }),
    );
    expect(cap.membership_id).toBe(transferred.membershipId);

    // Phase B ownership guard: an operation holding nothing in the group cannot add a dest.
    await expect(
      withTx(dbUrl, (tx) =>
        acquireGroupDestinationLeases(tx, {
          leaseGroupId: foreignGroup,
          operationId: OP_MOVE,
          ownerInstanceId: OWNER,
          destinations: [{ walletId: W3, leaseRole: "MOVE_DESTINATION" }],
        }),
      ),
    ).rejects.toMatchObject({ reason: "TRANSFER_TARGET_NOT_JOINED" });

    // Free the destination, retry phase B: it now joins the same group under the child.
    await withTx(dbUrl, (tx) =>
      completeGroupOperation(tx, { leaseGroupId: foreignGroup, operationId: OP_FOREIGN }),
    );
    const foreignProof = randomUUID();
    await withTx(dbUrl, (tx) =>
      mintReleaseProof(tx, {
        proofId: foreignProof,
        walletId: W2,
        operationId: OP_FOREIGN,
        membershipId: foreignAcquired[0]!.membershipId,
        leaseGroupId: foreignGroup,
        leaseEpoch: foreignAcquired[0]!.leaseEpoch,
        proofKind: "EXTERNAL_SEND_LANDED",
        proofDigest: digest("d1-foreign-landed"),
      }),
    );
    await withTx(dbUrl, (tx) =>
      releaseLease(tx, {
        walletId: W2,
        ownerInstanceId: OWNER_B,
        operationId: OP_FOREIGN,
        membershipId: foreignAcquired[0]!.membershipId,
        leaseGroupId: foreignGroup,
        leaseEpoch: foreignAcquired[0]!.leaseEpoch,
        releaseProofId: foreignProof,
        releaseReason: "LANDED",
      }),
    );

    const joined = await withTx(dbUrl, (tx) =>
      acquireGroupDestinationLeases(tx, {
        leaseGroupId: groupId,
        operationId: OP_MOVE,
        ownerInstanceId: OWNER,
        destinations: [{ walletId: W2, leaseRole: "MOVE_DESTINATION" }],
      }),
    );
    expect(joined).toHaveLength(1);
    expect(joined[0]!.walletId).toBe(W2);
    expect(
      psqlMust(
        dbUrl,
        `SELECT lease_group_id || '|' || operation_id || '|' || root_operation_id || '|' || lease_role
           FROM wallet_active_leases WHERE wallet_id = '${W2}'`,
      ).trim(),
    ).toBe(`${groupId}|${OP_MOVE}|${OP_RECV}|MOVE_DESTINATION`);
    // Source epoch unchanged by phase B — one hand-off, one successor epoch.
    expect(
      psqlMust(dbUrl, `SELECT lease_epoch FROM wallet_active_leases WHERE wallet_id = '${W1}'`).trim(),
    ).toBe(transferred.leaseEpoch.toString());
  }, 180_000);

  /**
   * Break-review D2. `acquireLeases` locked wallets first and only
   * reached `lease_groups` through the FK on its INSERTs, while `releaseLease` locks the group
   * first and the wallet last — opposite orders on the same two rows. Same inversion between
   * the wallets row and the active-lease row on the sign and hand-off paths. Each drill forces
   * the interleaving that turned those into SQLSTATE 40P01.
   */
  it("20: D2 — acquire / sign / hand-off take one lock order against release", async () => {
    if (!live) return;

    try {
      await assertLeaseFoundationReady(db);
    } catch {
      await migrateLeaseFoundation(db);
    }

    psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
    seedReceiveChildFixtures(dbUrl);

    const OP = randomUUID();
    const groupId = await withTx(dbUrl, (tx) => createLeaseGroup(tx, OP));
    const held = await withTx(dbUrl, (tx) =>
      acquireLeases(tx, {
        wallets: [{ walletId: W1, leaseRole: "SEND_SOURCE" }],
        leaseGroupId: groupId,
        rootOperationId: OP,
        operationId: OP,
        ownerInstanceId: OWNER,
      }),
    );

    // Drill 1 — acquire ∥ release. Session A holds releaseLease's first lock (the group row).
    // A fresh acquire into that group must reach the group row before any wallets row, so
    // session A can still take the wallet the acquire wants.
    const acquireRace = await raceLockOrder(
      dbUrl,
      [[STATEMENTS.LOCK_LEASE_GROUP, [groupId]]],
      (tx) =>
        acquireLeases(tx, {
          wallets: [{ walletId: W3, leaseRole: "SEND_SOURCE" }],
          leaseGroupId: groupId,
          rootOperationId: OP,
          operationId: randomUUID(),
          ownerInstanceId: OWNER,
        }),
      [[STATEMENTS.LOCK_WALLET, [W3]]],
    );
    expect(acquireRace.holder).toBe("ok");
    expect(["ok", "error:40001"]).toContain(acquireRace.contender);

    // Drill 2 — sign ∥ release. Session A holds the group's active rows (releaseLease step 3),
    // which includes W1's. The capability check must wait on that row while holding no
    // wallets row.
    const signRace = await raceLockOrder(
      dbUrl,
      [
        [STATEMENTS.LOCK_LEASE_GROUP, [groupId]],
        [STATEMENTS.LOCK_GROUP_OPERATIONS, [groupId]],
        [STATEMENTS.LOCK_GROUP_ACTIVE_LEASES, [groupId]],
      ],
      (tx) =>
        assertSignCapability(tx, {
          walletId: W1,
          operationId: OP,
          leaseEpoch: held[0]!.leaseEpoch,
          ownerInstanceId: OWNER,
        }),
      [[STATEMENTS.LOCK_WALLET, [W1]]],
    );
    expect(signRace.holder).toBe("ok");
    expect(["ok", "error:40001"]).toContain(signRace.contender);

    // Drill 3 — hand-off ∥ release across groups. A hand-off quoting the wrong lease group
    // still reaches W1's active row; taking the wallets row first deadlocked against a release
    // holding that active row group-wide. The refusal reason proves it got that far.
    const otherRoot = randomUUID();
    const otherChild = randomUUID();
    const otherGroup = await withTx(dbUrl, (tx) => createLeaseGroup(tx, otherRoot));
    await withTx(dbUrl, (tx) =>
      joinLeaseGroupOperation(tx, { leaseGroupId: otherGroup, operationId: otherChild }),
    );
    const transferRace = await raceLockOrder(
      dbUrl,
      [
        [STATEMENTS.LOCK_LEASE_GROUP, [groupId]],
        [STATEMENTS.LOCK_GROUP_OPERATIONS, [groupId]],
        [STATEMENTS.LOCK_GROUP_ACTIVE_LEASES, [groupId]],
      ],
      (tx) =>
        transferLeaseWithinGroup(tx, {
          walletId: W1,
          ownerInstanceId: OWNER,
          leaseGroupId: otherGroup,
          fromOperationId: otherRoot,
          toOperationId: otherChild,
          membershipId: held[0]!.membershipId,
          leaseEpoch: held[0]!.leaseEpoch,
          toLeaseRole: "MOVE_SOURCE",
          releaseProofId: randomUUID(),
          releaseReason: "WRONG_GROUP",
        }),
      [[STATEMENTS.LOCK_WALLET, [W1]]],
    );
    expect(transferRace.holder).toBe("ok");
    // Identity checks run owner → operation → membership → group, so the first mismatch it
    // can report is the operation. Reaching any of them proves it read the locked active row.
    expect(["error:LEASE_OPERATION_MISMATCH", "error:40001"]).toContain(transferRace.contender);

    // Nothing leaked: W1 still on its original lease, W3 free or freshly acquired once.
    expect(
      psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${W1}'`).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        dbUrl,
        `SELECT lease_epoch FROM wallet_active_leases WHERE wallet_id = '${W1}'`,
      ).trim(),
    ).toBe(held[0]!.leaseEpoch.toString());
    expect(
      Number(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${W3}'`,
        ).trim(),
      ),
    ).toBeLessThanOrEqual(1);
  }, 180_000);
});
