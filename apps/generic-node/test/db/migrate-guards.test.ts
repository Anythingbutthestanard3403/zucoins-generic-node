import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Local cold migrate can be slow; PG suites need a wide budget.
const PG_TEST_TIMEOUT_MS = 180_000;
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Client, Pool } from "pg";
import { SIGNER_LEADERSHIP_LOCK_ID } from "@zucoins/node-core";

import {
  MIGRATION_ADVISORY_LOCK_ID,
  MigrationLockBusyError,
  releaseMigrationLock,
  tryAcquireMigrationLock,
} from "../../src/db/migration-lock.js";
import { OverlapMigrationRefusedError } from "../../src/db/overlap-guard.js";
import { PooledDatabaseEndpointError } from "../../src/db/session-endpoint.js";

const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";

function adminClientConfig(database = "postgres") {
  return {
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database,
    password: process.env.PGPASSWORD,
  };
}

function hasClientTool(bin: string): boolean {
  try {
    execFileSync(bin, bin === "pg_isready" ? ["-q"] : ["--version"], {
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

const HAS_CREATEDB = hasClientTool("createdb");
const HAS_DROPDB = hasClientTool("dropdb");

const PG_AVAILABLE = (() => {
  try {
    if (hasClientTool("pg_isready")) {
      execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
      return true;
    }
  } catch {
    /* fall through to TCP probe */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require('pg');const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:'postgres',password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      {
        stdio: "ignore",
        env: process.env,
        cwd: fileURLToPath(new URL("../..", import.meta.url)),
      },
    );
    return true;
  } catch {
    return false;
  }
})();

function assertSafeDbName(dbName: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) {
    throw new Error(`unsafe test db name: ${dbName}`);
  }
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync("createdb", [dbName]);
    return;
  }
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${dbName}`);
  } finally {
    await admin.end();
  }
}

async function dropTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_DROPDB) {
    execFileSync("dropdb", ["--if-exists", dbName]);
    return;
  }
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [dbName],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
  } finally {
    await admin.end();
  }
}

function pgPool(dbName: string): Pool {
  return new Pool({
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database: dbName,
    password: process.env.PGPASSWORD,
  });
}

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  const host = PG_HOST === "/tmp" ? "localhost" : PG_HOST;
  return `postgres://${auth}@${host}:${PG_PORT}/${dbName}`;
}

describe("runMigrations preflight composition", () => {
  it("exports the guard entry points the boot lane depends on", async () => {
    process.env.DATABASE_URL ??= "postgresql://node:secret@db.internal:5432/zunode";
    const migrate = await import("../../src/db/migrate.js");
    expect(typeof migrate.runMigrations).toBe("function");
    expect(typeof migrate.runMigrationsOnPool).toBe("function");
    expect(typeof migrate.assertJournalOrdering).toBe("function");
    expect(migrate.MIGRATION_LOCK_TIMEOUT_MS).toBeGreaterThan(0);
    expect(migrate.MIGRATION_STATEMENT_TIMEOUT_MS).toBeGreaterThan(0);
    // Migrations must not inherit the shorter money-path statement_timeout (ZTR-1156).
    expect(migrate.MIGRATION_STATEMENT_TIMEOUT_MS).toBeGreaterThan(15_000);
  });

  it("migrate.ts createPool call has no money-path statement_timeout option", async () => {
    // Source census: migrate constructs the pool with URL only (or pool opts for
    // connect/idle/max/keepAlive) — never a money-path statement bound.
    const src = readFileSync(
      fileURLToPath(new URL("../../src/db/migrate.ts", import.meta.url)),
      "utf8",
    );
    expect(src).toMatch(/createPool\(databaseUrl\)/);
    expect(src).not.toMatch(/MONEY_PATH_STATEMENT_TIMEOUT/);
    expect(src).toMatch(/applyMigrationTimeouts/);
  });

  it("session-endpoint + overlap + lock modules are independently refuse-closed", async () => {
    const { assertDirectSessionDatabaseUrl } = await import("../../src/db/session-endpoint.js");
    expect(() =>
      assertDirectSessionDatabaseUrl("postgresql://u:p@h:6543/db"),
    ).toThrow(PooledDatabaseEndpointError);

    const { runOverlapGuard } = await import("../../src/db/overlap-guard.js");
    const fakePool = {
      query: async (sql: string) => {
        if (sql.includes("drizzle.__drizzle_migrations")) {
          return { rows: [] };
        }
        return { rows: [{ classid: 0, objid: SIGNER_LEADERSHIP_LOCK_ID, objsubid: 1 }] };
      },
    } as unknown as Pool;

    const migrationsFolder = fileURLToPath(new URL("../../drizzle", import.meta.url));
    await expect(runOverlapGuard(fakePool, migrationsFolder)).rejects.toBeInstanceOf(
      OverlapMigrationRefusedError,
    );

    expect(MIGRATION_ADVISORY_LOCK_ID).toBe(0x474e6d67);
    expect(MigrationLockBusyError).toBeDefined();
  });

  it("runMigrationsOnPool refuses pooled DATABASE_URL before taking a client", async () => {
    process.env.DATABASE_URL = "postgresql://u:p@db.internal:6543/zunode";
    const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
    let connectCalled = false;
    const fakePool = {
      connect: async () => {
        connectCalled = true;
        throw new Error("connect must not run after pooled-URL refuse");
      },
    } as unknown as Pool;

    await expect(runMigrationsOnPool(fakePool)).rejects.toBeInstanceOf(PooledDatabaseEndpointError);
    expect(connectCalled).toBe(false);

    // Explicit options.databaseUrl also enforced (env alone is not the only gate).
    process.env.DATABASE_URL = "postgresql://u:p@db.internal:5432/zunode";
    await expect(
      runMigrationsOnPool(fakePool, {
        databaseUrl: "postgresql://u:p@pooler.supabase.com:5432/zunode",
      }),
    ).rejects.toBeInstanceOf(PooledDatabaseEndpointError);
    expect(connectCalled).toBe(false);
  });
});

// Rework: Review A found that runMigrations still re-read process.env.DATABASE_URL
// with a bare presence check, independent of and weaker than each composition root's validated
// config, even though main.ts/stage1-main.ts had a validated value sitting in scope. These tests
// pin the fix: runMigrations() now takes the validated value as a required argument and performs
// no env read or format validation of its own; only the bare CLI entrypoint (no outer composition
// root) still reads process.env.DATABASE_URL, and only through resolveCliDatabaseUrl's schema.
describe("runMigrations composition-root contract (rework)", () => {
  it("requires an explicit databaseUrl argument — no zero-arg process.env fallback", async () => {
    const { runMigrations } = await import("../../src/db/migrate.js");
    expect(runMigrations.length).toBe(1);
  });

  it("validates the PASSED databaseUrl, not process.env.DATABASE_URL — a pooled env value does not block a direct argument", async () => {
    const prev = process.env.DATABASE_URL;
    // Pooled endpoint in env. If runMigrations still read process.env instead of its argument,
    // this alone would throw PooledDatabaseEndpointError before any connection attempt.
    process.env.DATABASE_URL = "postgresql://u:p@db.internal:6543/zunode";
    try {
      const { runMigrations } = await import("../../src/db/migrate.js");
      // Direct-session-shaped but unreachable — must get past the pooled-endpoint guard and
      // fail on the connection attempt instead, proving the argument (not env) governed it.
      await expect(
        runMigrations("postgresql://u:p@127.0.0.1:1/does-not-matter"),
      ).rejects.not.toBeInstanceOf(PooledDatabaseEndpointError);
    } finally {
      if (prev === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prev;
    }
  });

  it("validates the PASSED databaseUrl, not process.env.DATABASE_URL — a direct env value does not launder a pooled argument", async () => {
    const prev = process.env.DATABASE_URL;
    process.env.DATABASE_URL = "postgresql://u:p@db.internal:5432/zunode";
    try {
      const { runMigrations } = await import("../../src/db/migrate.js");
      await expect(
        runMigrations("postgresql://u:p@db.internal:6543/zunode"),
      ).rejects.toBeInstanceOf(PooledDatabaseEndpointError);
    } finally {
      if (prev === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prev;
    }
  });
});

describe("resolveCliDatabaseUrl — the bare CLI entrypoint's own composition-root validation", () => {
  it("trims incidental whitespace — a .env line with leading/trailing spaces or a \\r line ending — the same way loadNodeConfig's schema does", async () => {
    const { resolveCliDatabaseUrl } = await import("../../src/db/migrate.js");
    expect(resolveCliDatabaseUrl({ DATABASE_URL: "  postgres://u:p@h:5432/db  " })).toBe(
      "postgres://u:p@h:5432/db",
    );
    expect(resolveCliDatabaseUrl({ DATABASE_URL: "postgres://u:p@h:5432/db\r" })).toBe(
      "postgres://u:p@h:5432/db",
    );
  });

  it("rejects a malformed scheme with an actionable message — not the old bare presence-only check", async () => {
    const { resolveCliDatabaseUrl } = await import("../../src/db/migrate.js");
    expect(() => resolveCliDatabaseUrl({ DATABASE_URL: "mysql://u:p@h:5432/db" })).toThrow(
      /postgres/i,
    );
  });

  it("rejects blank / whitespace-only / missing DATABASE_URL with an actionable message", async () => {
    const { resolveCliDatabaseUrl } = await import("../../src/db/migrate.js");
    expect(() => resolveCliDatabaseUrl({ DATABASE_URL: "   " })).toThrow(/DATABASE_URL/);
    expect(() => resolveCliDatabaseUrl({})).toThrow(/DATABASE_URL/);
  });

  it("db/migrate.ts's CLI entrypoint calls resolveCliDatabaseUrl() before runMigrations(), not a raw env read", () => {
    const source = readFileSync(
      fileURLToPath(new URL("../../src/db/migrate.ts", import.meta.url)),
      "utf8",
    );
    expect(source).toMatch(/databaseUrl\s*=\s*resolveCliDatabaseUrl\(\)/);
    expect(source).toMatch(/runMigrations\(databaseUrl\)/);
    expect(source).not.toMatch(/const databaseUrl = process\.env\.DATABASE_URL/);
  });
});

describe.skipIf(!PG_AVAILABLE)("runMigrationsOnPool — lock + overlap integration", () => {
  it("refuses when another connection holds the migrator lock (two-process)", { timeout: PG_TEST_TIMEOUT_MS }, async () => {
    const dbName = `gn_mig_onpool_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    await createTestDatabase(dbName);
    const prev = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);

    const holderPool = pgPool(dbName);
    const runnerPool = pgPool(dbName);
    const holder = await holderPool.connect();
    try {
      const acquired = await tryAcquireMigrationLock(holder);
      expect(acquired).toBe(true);

      const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
      await expect(runMigrationsOnPool(runnerPool)).rejects.toBeInstanceOf(MigrationLockBusyError);
    } finally {
      await releaseMigrationLock(holder).catch(() => undefined);
      holder.release();
      await holderPool.end();
      await runnerPool.end();
      if (prev === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prev;
      await dropTestDatabase(dbName);
    }
  });

  it("applies the real 0000 migration on a cold DB (no overlap, lock free)", { timeout: PG_TEST_TIMEOUT_MS }, async () => {
    const dbName = `gn_mig_cold_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    await createTestDatabase(dbName);
    const prev = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);

    const runnerPool = pgPool(dbName);
    try {
      const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
      // Full cold path = reporting drizzle 0000/0001 + money pack.
      // Must complete without SQLSTATE 42710 (shared catalog redeclare).
      await runMigrationsOnPool(runnerPool);

      const tables = await runnerPool.query<{ tablename: string }>(
        `SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'nodes'`,
      );
      expect(tables.rows).toHaveLength(1);

      // Money pack applied: receive barriers + money floor domains.
      const receive = await runnerPool.query<{ tablename: string }>(
        `SELECT tablename FROM pg_tables
           WHERE schemaname = 'public'
             AND tablename IN ('receive_codes', 'receive_arms', 'receive_release_proofs')
           ORDER BY tablename`,
      );
      expect(receive.rows.map((r) => r.tablename)).toEqual([
        "receive_arms",
        "receive_codes",
        "receive_release_proofs",
      ]);

      // landing-proof-verifications slice applied — unblocks wallet_settled_ledger's
      // landed-verbatim trigger, which reads operation_verifications at runtime.
      const landingProofs = await runnerPool.query<{ tablename: string }>(
        `SELECT tablename FROM pg_tables
           WHERE schemaname = 'public'
             AND tablename IN ('operation_landing_proofs', 'operation_verifications')
           ORDER BY tablename`,
      );
      expect(landingProofs.rows.map((r) => r.tablename)).toEqual([
        "operation_landing_proofs",
        "operation_verifications",
      ]);

      const domains = await runnerPool.query<{ typname: string }>(
        `SELECT t.typname
           FROM pg_type t
           JOIN pg_namespace n ON n.oid = t.typnamespace
          WHERE n.nspname = 'public'
            AND t.typtype = 'd'
            AND t.typname IN ('sha256_hex', 'zkz_balance_text', 'zkz_amount_positive_text')
          ORDER BY t.typname`,
      );
      expect(domains.rows.map((r) => r.typname)).toEqual([
        "sha256_hex",
        "zkz_amount_positive_text",
        "zkz_balance_text",
      ]);

      // Pack journal completeness: every MONEY_SCHEMA_PACK_ORDER version is present
      // (not merely "count > 0" — D2).
      const { MONEY_SCHEMA_PACK_ORDER, MONEY_SCHEMA_PACK_VERSION_BASE } =
        await import("@zucoins/node-core/data");
      const expectedPackLen = MONEY_SCHEMA_PACK_ORDER.length;
      const moneyJournal = await runnerPool.query<{ version: number; description: string }>(
        `SELECT version, description FROM schema_migrations
           WHERE version >= $1
           ORDER BY version`,
        [MONEY_SCHEMA_PACK_VERSION_BASE],
      );
      expect(moneyJournal.rows).toHaveLength(expectedPackLen);
      for (let i = 0; i < expectedPackLen; i += 1) {
        expect(moneyJournal.rows[i].version).toBe(MONEY_SCHEMA_PACK_VERSION_BASE + i);
        expect(moneyJournal.rows[i].description).toBe(
          MONEY_SCHEMA_PACK_ORDER[i].replace(/-/g, "_"),
        );
      }

      // Money integrity: wallet_active_leases FKs after cold combined apply.
      const walFks = await runnerPool.query<{ conname: string; def: string }>(
        `SELECT c.conname,
                pg_get_constraintdef(c.oid) AS def
           FROM pg_constraint c
           JOIN pg_class rel ON rel.oid = c.conrelid
           JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
          WHERE nsp.nspname = 'public'
            AND rel.relname = 'wallet_active_leases'
            AND c.contype = 'f'
          ORDER BY c.conname`,
      );
      const fkDefs = walFks.rows.map((r) => `${r.conname}: ${r.def}`).join("\n");
      expect(fkDefs).toMatch(/wallet_id/i);
      expect(fkDefs).toMatch(/wallets/i);
      expect(fkDefs).toMatch(/membership_id/i);
      expect(fkDefs).toMatch(/wallet_lease_memberships/i);
      expect(fkDefs).toMatch(/lease_group_id/i);
      expect(fkDefs).toMatch(/lease_groups/i);

      // Eligibility trigger owner is custody (first owner); lease_foundation fn must
      // not remain as an unattached orphan.
      const walTrig = await runnerPool.query<{ tgname: string; def: string }>(
        `SELECT t.tgname, pg_get_triggerdef(t.oid) AS def
           FROM pg_trigger t
           JOIN pg_class rel ON rel.oid = t.tgrelid
           JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
          WHERE nsp.nspname = 'public'
            AND rel.relname = 'wallet_active_leases'
            AND NOT t.tgisinternal
          ORDER BY t.tgname`,
      );
      expect(walTrig.rows.map((r) => r.tgname)).toContain(
        "wallet_active_leases_eligibility_guard",
      );
      const guardDef = walTrig.rows.find(
        (r) => r.tgname === "wallet_active_leases_eligibility_guard",
      )?.def;
      expect(guardDef).toMatch(/custody_reject_ineligible_lease/i);

      const orphanFn = await runnerPool.query<{ n: string }>(
        `SELECT COUNT(*)::text AS n
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'lease_foundation_reject_ineligible_lease'`,
      );
      expect(Number(orphanFn.rows[0]?.n ?? 0)).toBe(0);

      // schema_migrations journal is the honest readiness proof for the migrator
      // (boot stamps NodeCoreReadinessState after this path succeeds — not a tautology here).
      expect(moneyJournal.rows.length).toBe(expectedPackLen);

      const probe = await runnerPool.connect();
      try {
        await expect(tryAcquireMigrationLock(probe)).resolves.toBe(true);
        await releaseMigrationLock(probe);
      } finally {
        probe.release();
      }
    } finally {
      await runnerPool.end();
      if (prev === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prev;
      await dropTestDatabase(dbName);
    }
  });

  it(
    "clean apply and previous-version→current upgrade apply yield identical schema (migration-pack parity)",
    { timeout: PG_TEST_TIMEOUT_MS },
    async () => {
      const { runMigrationsOnPool, migrationsFolder } = await import("../../src/db/migrate.js");

      // "Previous version" baseline = every drizzle journal entry except the last one
      // (the 0002 slice) — simulates a node deployed before this ticket.
      const fullJournal = JSON.parse(
        readFileSync(join(migrationsFolder, "meta", "_journal.json"), "utf8"),
      ) as { version: string; dialect: string; entries: { idx: number; tag: string }[] };
      const baselineEntries = fullJournal.entries.slice(0, -1);
      expect(baselineEntries.length).toBe(fullJournal.entries.length - 1);

      const baselineFolder = mkdtempSync(join(tmpdir(), "gn-mig-baseline-"));
      mkdirSync(join(baselineFolder, "meta"));
      writeFileSync(
        join(baselineFolder, "meta", "_journal.json"),
        JSON.stringify({
          version: fullJournal.version,
          dialect: fullJournal.dialect,
          entries: baselineEntries,
        }),
      );
      for (const entry of baselineEntries) {
        cpSync(
          join(migrationsFolder, `${entry.tag}.sql`),
          join(baselineFolder, `${entry.tag}.sql`),
        );
      }

      const suffix = `${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
      const cleanDbName = `gn_mig_clean_${suffix}`;
      const upgradeDbName = `gn_mig_upg_${suffix}`;
      await createTestDatabase(cleanDbName);
      await createTestDatabase(upgradeDbName);
      const cleanPool = pgPool(cleanDbName);
      const upgradePool = pgPool(upgradeDbName);
      try {
        // Clean: current full migrate.ts path in one shot on a cold DB.
        await runMigrationsOnPool(cleanPool, { databaseUrl: pgDatabaseUrl(cleanDbName) });

        // Upgrade: pretend this node was already at the previous version (0000+0001
        // only, applied by drizzle's own migrate() the way an older migrate.ts would
        // have), then run the CURRENT migrate.ts path on top — mirrors a real
        // production upgrade, where 0002 + the money pack apply fresh via IF NOT
        // EXISTS DDL against tables the baseline already created.
        // pgcrypto must precede 0000 here too (see migrate.ts's own pre-migrate
        // provisioning): 0000 calls pgcrypto's digest() at CREATE FUNCTION time.
        await upgradePool.query("CREATE EXTENSION IF NOT EXISTS pgcrypto");
        await migrate(drizzle(upgradePool), { migrationsFolder: baselineFolder });
        await runMigrationsOnPool(upgradePool, { databaseUrl: pgDatabaseUrl(upgradeDbName) });

        const relations = [
          "admin_mutation_idempotency",
          "admin_operators",
          "operations",
          "admin_sessions",
        ];
        const describeColumns = async (pool: Pool) => {
          const result = await pool.query<{
            table_name: string;
            column_name: string;
            data_type: string;
            is_nullable: string;
            column_default: string | null;
          }>(
            `SELECT table_name, column_name, data_type, is_nullable, column_default
               FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = ANY($1::text[])
              ORDER BY table_name, column_name`,
            [relations],
          );
          return result.rows;
        };

        const cleanColumns = await describeColumns(cleanPool);
        const upgradeColumns = await describeColumns(upgradePool);
        expect(cleanColumns.length).toBeGreaterThan(0);
        expect(upgradeColumns).toEqual(cleanColumns);
      } finally {
        await cleanPool.end();
        await upgradePool.end();
        await dropTestDatabase(cleanDbName);
        await dropTestDatabase(upgradeDbName);
        rmSync(baselineFolder, { recursive: true, force: true });
      }
    },
  );

  it("standalone money pack foundation (no reporting prefix) owns the shared scalar domains", { timeout: PG_TEST_TIMEOUT_MS }, async () => {
    const dbName = `gn_money_alone_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    await createTestDatabase(dbName);
    const runnerPool = pgPool(dbName);
    try {
      const client = await runnerPool.connect();
      try {
        await client.query("CREATE EXTENSION IF NOT EXISTS pgcrypto");
        const { loadMoneySchemaMigrations, runMigrations } = await import(
          "@zucoins/node-core/data"
        );
        const { poolClientMigrationExecutor } = await import("../../src/db/migrate.js");
        const standalone = loadMoneySchemaMigrations(); // afterReportingPrefix default false
        // AC4: shared domains materialise without a reporting prefix via slice 0.
        await runMigrations(poolClientMigrationExecutor(client), [standalone[0]]);

        const domains = await client.query<{ typname: string }>(
          `SELECT t.typname
             FROM pg_type t
             JOIN pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname = 'public'
              AND t.typtype = 'd'
              AND t.typname IN (
                'sha256_hex',
                'padded_base64url_pubkey',
                'zkz_balance_text'
              )
            ORDER BY t.typname`,
        );
        expect(domains.rows.map((r) => r.typname)).toEqual([
          "padded_base64url_pubkey",
          "sha256_hex",
          "zkz_balance_text",
        ]);
      } finally {
        client.release();
      }
    } finally {
      await runnerPool.end();
      await dropTestDatabase(dbName);
    }
  });
});
