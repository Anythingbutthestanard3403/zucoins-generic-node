import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import type { Pool, PoolClient } from "pg";

import {
  loadMoneySchemaMigrations,
  runMigrations as runMoneySchemaMigrations,
  type MigrationSqlExecutor,
  type TransactionIsolationLevel,
} from "@zucoins/node-core/data";

import { createPool } from "./client.js";
import { assertMigrationLockAcquired, releaseMigrationLock } from "./migration-lock.js";
import { runOverlapGuard } from "./overlap-guard.js";
import { assertDirectSessionDatabaseUrl } from "./session-endpoint.js";

// generic-node migration runner.
// Composition root is the sole production owner of schema apply:
// 1. stop-first deploy safety sequence (session endpoint, migrator lock, overlap guard)
//   2. Reporting prefix via drizzle (0000 + 0001) — history already shipped
//   3. Money pack via node-core `schema_migrations` + MigrationFile[] from
//      packages/node-core/src/schema (receive_codes/arms + Layer-1 pack)
// Both steps run under the same pinned connection and migrator lock so there is
// no concurrent dual-owner window.

export const migrationsFolder = fileURLToPath(new URL("../../drizzle", import.meta.url));

// Bounded timeouts for the migration connection. `lock_timeout` bounds how long the migration
// WAITS for a contended lock so a blocked exclusive request fails fast (Postgres 55P03) and
// aborts boot loudly instead of stalling a live node; `statement_timeout` bounds how long any
// single migration statement may run. Defensive guard only.
export const MIGRATION_LOCK_TIMEOUT_MS = 5_000;
export const MIGRATION_STATEMENT_TIMEOUT_MS = 30_000;

// Plain (session-level) SET — deliberately NOT SET LOCAL — so the bound persists across the
// per-migration transactions drizzle's migrator opens on this same connection. Values are
// internal integer constants (never external input), so interpolation into the SET (which cannot
// be parameterized) is safe.
export async function applyMigrationTimeouts(
  client: Pick<PoolClient, "query">,
  lockTimeoutMs: number = MIGRATION_LOCK_TIMEOUT_MS,
  statementTimeoutMs: number = MIGRATION_STATEMENT_TIMEOUT_MS,
): Promise<void> {
  await client.query(`SET lock_timeout = ${Math.trunc(lockTimeoutMs)}`);
  await client.query(`SET statement_timeout = ${Math.trunc(statementTimeoutMs)}`);
}

export interface RunMigrationsOnPoolOptions {
  /**
   * Connection string to enforce as direct/session-mode. Defaults to
   * `process.env.DATABASE_URL`. Every DDL entry must pass this check — a caller
   * that only hits {@link runMigrationsOnPool} must not be able to bypass the
   * pooled-endpoint refusal that {@link runMigrations} applies.
   */
  readonly databaseUrl?: string;
}

/**
 * Runner core: migrate on ONE dedicated connection with the bounded timeouts and the
 * migrator singleton advisory lock held on it. A single pinned connection guarantees the
 * SETs and the lock govern every migration statement and self-release if the process dies.
 *
 * Overlap guard runs INSIDE the lock so pending tags are re-read after serialising with any
 * peer migrator. Callers that want a cheap pre-lock refuse (production `runMigrations`) run
 * {@link runOverlapGuard} once before calling this.
 *
 * Always enforces direct/session `DATABASE_URL` before taking a client — the
 * session-scoped migrator lock and leadership probe fail open through a
 * transaction-mode pooler.
 */
export async function runMigrationsOnPool(
  targetPool: Pool,
  options: RunMigrationsOnPoolOptions = {},
): Promise<void> {
  const databaseUrl = options.databaseUrl ?? process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required to connect to the generic-node database");
  }
  assertDirectSessionDatabaseUrl(databaseUrl);

  const client = await targetPool.connect();
  let lockHeld = false;
  try {
    await applyMigrationTimeouts(client);
    // Singleton migrator: two concurrent boots must not both write the journal / DDL.
    // Acquired on this pinned connection so it spans drizzle and dies with the connection.
    await assertMigrationLockAcquired(client);
    lockHeld = true;

    // Re-read pending + classify AFTER the lock so a race with another migrator that just
    // finished cannot leave us classifying a stale pending set.
    await runOverlapGuard(targetPool, migrationsFolder);

    // The frozen reporting-persistence migration (0000) defines
    // reporting_logical_fingerprint(...), whose body calls pgcrypto's digest(); with
    // check_function_bodies=on (the default, never disabled here) CREATE FUNCTION resolves
    // digest at migration time, so a fresh node DB without pgcrypto aborts migration 0000 with
    // 42883 (`function digest(bytea, unknown) does not exist`) and the node never boots.
    // Provision the extension on this same pinned connection, before any migration applies,
    // and outside drizzle's per-migration transactions. pgcrypto is a PG13+ *trusted*
    // extension the connecting DB-owner role may install without superuser. Idempotent, and it
    // leaves the byte-frozen migration SQL (and its inert node-core twin) untouched.
    await client.query("CREATE EXTENSION IF NOT EXISTS pgcrypto");
    // Reporting journal prefix (historical drizzle tags 0000/0001).
    await migrate(drizzle(client), { migrationsFolder });
    // Layer-1 money schema pack (receive barriers + wallets/ops/…).
    // path (b): composition root feeds MigrationFile[] into node-core runMigrations.
    // afterReportingPrefix: reporting drizzle 0000 owns the shared scalar domains / reporting
    // enums / helper functions — pack slice 0 must not re-CREATE them (SQLSTATE 42710).
    await runMoneySchemaMigrations(poolClientMigrationExecutor(client), [
      ...loadMoneySchemaMigrations({ afterReportingPrefix: true }),
    ]);
  } finally {
    if (lockHeld) {
      try {
        await releaseMigrationLock(client);
      } catch {
        /* unlock best-effort; connection destroy below covers the stuck case */
      }
    }
    // The timeouts are SESSION-level, so they persist on this physical connection after release()
    // hands it back to the pool. Restore session defaults BEFORE the connection re-enters the
    // pool; if RESET itself fails (broken connection / aborted transaction), DESTROY the client
    // rather than return one that may still carry the bound. release() is called exactly once.
    let reset = false;
    try {
      await client.query("RESET ALL");
      reset = true;
    } catch {
      /* reset failed — fall through and destroy the client below */
    }
    client.release(reset ? undefined : true);
  }
}

/**
 * Adapt a pinned pg client to node-core's MigrationSqlExecutor. Runs on the
 * same connection that already holds the migrator advisory lock so money pack
 * DDL cannot race a peer boot's drizzle apply or another money pack apply.
 */
export function poolClientMigrationExecutor(
  client: Pick<PoolClient, "query">,
): MigrationSqlExecutor {
  return {
    async query(sql: string): Promise<void> {
      await client.query(sql);
    },
    async select<T>(sql: string): Promise<readonly T[]> {
      const result = await client.query(sql);
      return result.rows as T[];
    },
    async transaction(
      isolation: TransactionIsolationLevel,
      body: () => Promise<void>,
    ): Promise<void> {
      await client.query(`BEGIN ISOLATION LEVEL ${isolation}`);
      try {
        await body();
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    },
  };
}

/**
 * Applies all pending migrations. Safety sequence:
 *   1. direct/session DATABASE_URL enforcement (pooled endpoints fail open the probe)
 *   2. journal-ordering guard (non-monotonic `when` silently skips later migrations)
 *   3. pre-lock overlap guard (fail-fast classify + leadership probe without holding a client)
 *   4. pinned connection: timeouts → migrator singleton lock → in-lock overlap re-check
 *      → reporting drizzle DDL → money schema_migrations pack
 *
 * `databaseUrl` is a required parameter, not an internal `process.env.DATABASE_URL`
 * read. This function has no composition root above it in the boot graph — main.ts and
 * stage1-main.ts each validate DATABASE_URL exactly once (loadNodeConfig / loadStage1Config)
 * and must pass that same validated value in, so migrations run against byte-identical config
 * to the app's own pool. The bare CLI entrypoint below (`isMain`) is the one caller with no
 * outer composition root, so it is the one place left that reads `process.env.DATABASE_URL`
 * directly — through `resolveCliDatabaseUrl`, the same field schema `loadNodeConfig` applies,
 * not a bare presence check.
 */
export async function runMigrations(databaseUrl: string): Promise<void> {
  // Fail-fast before journal I/O / overlap classify; runMigrationsOnPool repeats
  // the check so pool-only callers cannot bypass it.
  assertDirectSessionDatabaseUrl(databaseUrl);
  assertJournalOrdering(migrationsFolder);
  // Pool is constructed here, from the caller's already-validated databaseUrl,
  // rather than imported as a module-level singleton — db/client.ts no longer builds one at
  // import time.
  const pool = createPool(databaseUrl);
  try {
    // Pre-lock pass: refuse blocking-during-overlap before we pin a client or take the
    // migrator lock. The in-lock pass inside runMigrationsOnPool re-reads pending after serialising.
    await runOverlapGuard(pool, migrationsFolder);
    await runMigrationsOnPool(pool, { databaseUrl });
  } finally {
    await pool.end();
  }
}

// ---- journal ordering guard (self-contained mirror of apps/node/src/db/journal-ordering.ts) ----

interface JournalEntry {
  idx: number;
  when: number;
  tag: string;
}

function parseJournalEntries(raw: string): JournalEntry[] {
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== "object" || parsed === null || !("entries" in parsed)) {
    throw new Error("migration journal is malformed: missing `entries`");
  }
  const { entries } = parsed as { entries: unknown };
  if (!Array.isArray(entries)) {
    throw new Error("migration journal is malformed: `entries` is not an array");
  }
  return entries.map((entry, position) => {
    if (typeof entry !== "object" || entry === null) {
      throw new Error(`migration journal is malformed: entry ${position} is not an object`);
    }
    const { idx, when, tag } = entry as { idx?: unknown; when?: unknown; tag?: unknown };
    if (typeof idx !== "number" || typeof when !== "number" || typeof tag !== "string") {
      throw new Error(`migration journal is malformed: entry ${position} is missing idx/when/tag`);
    }
    return { idx, when, tag };
  });
}

export function assertStrictlyIncreasingWhen(entries: readonly JournalEntry[]): void {
  for (let i = 1; i < entries.length; i += 1) {
    const previous = entries[i - 1];
    const current = entries[i];
    if (current.when > previous.when) {
      continue;
    }
    throw new Error(
      `migration journal 'when' values are not strictly increasing: entry ${current.idx} ` +
        `(${current.tag}, when=${current.when}) is not greater than entry ${previous.idx} ` +
        `(${previous.tag}, when=${previous.when}). drizzle applies only migrations whose journal ` +
        `'when' exceeds the DB's recorded max created_at, so a non-monotonic 'when' silently ` +
        `skips every later migration. Correct the journal before deploying.`,
    );
  }
}

export function assertJournalOrdering(folder: string): void {
  const raw = readFileSync(`${folder}/meta/_journal.json`, "utf8");
  assertStrictlyIncreasingWhen(parseJournalEntries(raw));
}

/**
 * Validates `DATABASE_URL` the same way every composition root's config schema does — trim,
 * then require a postgres(ql):// scheme — so a bare `node db/migrate.js` invocation gets the
 * same actionable, whitespace-tolerant validation as every other composition root, not a
 * weaker presence-only check.
 *
 * Deliberately standalone rather than importing `CONFIG_FIELD_SCHEMAS` from `../config/`: that
 * zod schema sits behind the `@zucoins/node-core` root barrel, which re-exports the money
 * submit write path (reach census) — a migrations CLI has no legitimate reason
 * to reach that. `loadStage1Config` already validates this same field independently (its own
 * trim + `postgres(ql)://` check, no zod) for the identical reason; this mirrors that.
 */
export function resolveCliDatabaseUrl(
  source: Readonly<Record<string, string | undefined>> = process.env,
): string {
  const trimmed = source.DATABASE_URL?.trim();
  if (!trimmed) {
    throw new Error(
      "DATABASE_URL failed validation:\n  - DATABASE_URL is required: the node cannot boot without a database connection string",
    );
  }
  if (!/^postgres(ql)?:\/\//.test(trimmed)) {
    throw new Error(
      "DATABASE_URL failed validation:\n  - DATABASE_URL must be a postgres connection URL (postgres:// or postgresql:// scheme)",
    );
  }
  return trimmed;
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  // The CLI has no outer composition root, so it is the sole remaining caller that reads
  // process.env.DATABASE_URL directly — through the schema above, once.
  let databaseUrl: string;
  try {
    databaseUrl = resolveCliDatabaseUrl();
  } catch (err) {
    console.error(`generic-node database migrations did not complete; ${(err as Error).message}`);
    process.exit(1);
  }
  // runMigrations() owns its own pool's lifecycle (construct → use → end), see above.
  runMigrations(databaseUrl)
    .then(() => {
      console.log("generic-node migrations applied");
    })
    .catch((err: unknown) => {
      console.error(
        "generic-node database migrations did not complete; service startup is blocked to prevent running against an incompatible schema. Inspect the migration error, database connectivity, lock contention, and migration journal before retrying.",
        err,
      );
      process.exit(1);
    });
}
