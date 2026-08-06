/**
 * Database transaction and migration conventions for the generic node.
 *
 * Database-wide conventions: the reference database is PostgreSQL, the canonical ZKZ
 * amount representation is decimal text (never a JavaScript-number-derived numeric), and
 * every status transition, event append, lease change, TOTP burn, and signature
 * persistence described as atomic runs in a transaction. Those atomicity requirements,
 * plus the invariant set the mandatory database tests pin, are what a transaction must
 * preserve under concurrency. The two-level isolation split and the serialization-failure
 * retry/backoff policy below are an execution regime, not a restatement of the invariants:
 * they are derived from the one-in-flight-per-wallet rule ("one in-flight transaction per wallet") plus those
 * atomicity requirements, as the regime that preserves them.
 *
 * Two isolation levels, by path class:
 * - SERIALIZABLE for money-path transactions — anything that moves or commits a ZKZ
 * amount, takes or releases a wallet lease, persists a signature, or appends to an
 * authoritative byte ledger. Serializable is the only PostgreSQL level that gives a
 * correctness guarantee equivalent to running the transactions one at a time, which is
 * what "one in-flight transaction per wallet" and the byte-immutability invariants
 * require under concurrent access.
 * - READ COMMITTED for everything else — advisory reads, observation reporting that does
 * not write authoritative bytes, and idempotent lookups. Cheaper, and sufficient where
 * a re-read of committed data is acceptable.
 *
 * Retry policy: a SERIALIZABLE transaction can fail with SQLSTATE 40001
 * (serialization_failure) when PostgreSQL detects a concurrent-write anomaly; the whole
 * transaction is rolled back, so re-running it from the start is safe and is the
 * documented recovery. This retry is bounded and idempotent — it is NOT a blind retry of
 * a chain submit (the never-blind-retry rule): a serialization failure means no row landed, so there
 * is nothing to double-spend. A chain submit decision is never retried by this policy.
 */

import { createHash } from "node:crypto";

// --- Transaction isolation ---

export const SERIALIZATION_FAILURE_SQLSTATE = "40001" as const;
export const DEADLOCK_DETECTED_SQLSTATE = "40P01" as const;

export type TransactionIsolationLevel = "SERIALIZABLE" | "READ COMMITTED";

export const MONEY_PATH_ISOLATION: TransactionIsolationLevel = "SERIALIZABLE";
export const DEFAULT_ISOLATION: TransactionIsolationLevel = "READ COMMITTED";

// --- Serialization-failure retry ---

export interface SerializationRetryPolicy {
  readonly maxAttempts: number;
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
}

export const DEFAULT_SERIALIZATION_RETRY_POLICY: SerializationRetryPolicy = {
  maxAttempts: 5,
  baseDelayMs: 25,
  maxDelayMs: 1000,
};

export function isRetriableSerializationFailure(
  sqlState: string | undefined,
): boolean {
  return (
    sqlState === SERIALIZATION_FAILURE_SQLSTATE ||
    sqlState === DEADLOCK_DETECTED_SQLSTATE
  );
}

/**
 * Exponential backoff with full jitter, deterministic given `jitter` in [0, 1).
 * attemptNo is 1-based: the delay before the second attempt uses attemptNo = 1.
 */
export function serializationRetryDelayMs(
  policy: SerializationRetryPolicy,
  attemptNo: number,
  jitter: number,
): number {
  if (attemptNo < 1) {
    throw new RangeError("attemptNo must be >= 1");
  }
  if (jitter < 0 || jitter >= 1) {
    throw new RangeError("jitter must be in [0, 1)");
  }
  const exponential = policy.baseDelayMs * 2 ** (attemptNo - 1);
  const capped = Math.min(exponential, policy.maxDelayMs);
  return Math.floor(capped * jitter);
}

export interface DatabaseErrorLike {
  readonly code?: string | undefined;
}

/**
 * Run an idempotent transaction body under the serialization-retry policy. The body must
 * be safe to re-run from the start: on a 40001/40P01 the prior attempt has fully rolled
 * back, so re-invoking it cannot double-apply. Any other error is rethrown immediately.
 *
 * The never-blind-retry rule — caller discipline, NOT enforced here: re-running body is safe ONLY for
 * an idempotent, DB-only body. A chain submit must never be placed inside body — a 40001
 * retry would re-invoke it and re-submit the transaction (a blind submit retry). This
 * function cannot detect a submit inside body; keeping submits out of the retried body is
 * the caller's responsibility.
 */
export async function withSerializationRetry<T>(
  policy: SerializationRetryPolicy,
  body: () => Promise<T>,
  sleep: (ms: number) => Promise<void> = defaultSleep,
  random: () => number = Math.random,
): Promise<T> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await body();
    } catch (error) {
      const code = (error as DatabaseErrorLike | null)?.code;
      if (!isRetriableSerializationFailure(code) || attempt >= policy.maxAttempts) {
        throw error;
      }
      await sleep(serializationRetryDelayMs(policy, attempt, random()));
    }
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// --- Migration naming ---

export const MIGRATION_FILE_PATTERN = /^\d{4}_[a-z][a-z0-9_]*\.sql$/;

export interface ParsedMigrationName {
  readonly version: number;
  readonly description: string;
}

export function parseMigrationName(fileName: string): ParsedMigrationName {
  if (!MIGRATION_FILE_PATTERN.test(fileName)) {
    throw new Error(
      `migration file name "${fileName}" must match NNNN_description.sql ` +
        "(four-digit zero-padded version, lowercase snake_case description)",
    );
  }
  const separator = fileName.indexOf("_");
  const version = Number.parseInt(fileName.slice(0, separator), 10);
  const description = fileName.slice(separator + 1, fileName.length - ".sql".length);
  return { version, description };
}

export function formatMigrationName(version: number, description: string): string {
  if (!Number.isInteger(version) || version < 0 || version > 9999) {
    throw new RangeError("migration version must be an integer in [0, 9999]");
  }
  if (!/^[a-z][a-z0-9_]*$/.test(description)) {
    throw new Error("migration description must be lowercase snake_case");
  }
  return `${version.toString().padStart(4, "0")}_${description}.sql`;
}

// --- Migration journal ---

export const MIGRATION_JOURNAL_TABLE = "schema_migrations" as const;

/**
 * `schema_migrations` is the node's own bootstrap journal, not part of the greenfield schema
 * It is created as the FIRST
 * statement of every run, before any application migration file, so it must be self-contained:
 * `sql_sha256` is a plain `text` column with an inline hex CHECK identical in semantics to the
 * schema's `sha256_hex` DOMAIN — but NOT the domain itself. Typing the column with that domain
 * here would fail bootstrap on a fresh DB with `type "sha256_hex" does not exist`, because the
 * domain is created by a later application migration, which has not run yet. Using an
 * inline CHECK keeps the journal free of any dependency on that migration having run first.
 *
 * `sql_sha256` records the SHA-256 of the exact migration SQL bytes. It is PERSISTED for
 * future drift detection; it is NOT actively compared today. plan/runMigrations select
 * pending files by version only and discard the fetched hash, so an already-applied migration
 * whose bytes later change on disk is neither re-run nor flagged. Adding a throw-on-mismatch
 * check to this bootstrap path is deliberately out of scope: it could brick node startup on a
 * benign hash difference.
 */
export const MIGRATION_JOURNAL_DDL = `CREATE TABLE IF NOT EXISTS ${MIGRATION_JOURNAL_TABLE} (
  version integer PRIMARY KEY,
  description text NOT NULL,
  sql_sha256 text NOT NULL CHECK (sql_sha256 ~ '^[0-9a-f]{64}$'),
  applied_at timestamptz NOT NULL DEFAULT now()
);` as const;

export interface MigrationRecord {
  readonly version: number;
  readonly description: string;
  readonly sqlSha256: string;
}

export interface MigrationFile {
  readonly fileName: string;
  readonly sql: string;
}

export function planMigrations(
  files: readonly MigrationFile[],
  appliedVersions: readonly number[],
): MigrationFile[] {
  const seenVersions = new Set<number>();
  for (const file of files) {
    const { version } = parseMigrationName(file.fileName);
    if (seenVersions.has(version)) {
      throw new Error(`duplicate migration version ${version}`);
    }
    seenVersions.add(version);
  }

  const applied = new Set(appliedVersions);
  return files
    .filter((file) => !applied.has(parseMigrationName(file.fileName).version))
    .sort(
      (a, b) =>
        parseMigrationName(a.fileName).version - parseMigrationName(b.fileName).version,
    );
}

// --- Migration runner ---

/**
 * Minimal SQL execution port. The generic node owns no driver; a product or platform
 * shell adapts its Postgres client to this interface.
 */
export interface MigrationSqlExecutor {
  query(sql: string): Promise<void>;
  select<T>(sql: string): Promise<readonly T[]>;
  transaction(
    isolation: TransactionIsolationLevel,
    body: () => Promise<void>,
  ): Promise<void>;
}

export interface MigrationRunnerOptions {
  readonly retryPolicy?: SerializationRetryPolicy;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly random?: () => number;
  readonly sha256?: (sql: string) => string;
}

export interface MigrationRunResult {
  readonly applied: readonly MigrationRecord[];
  readonly skippedVersions: readonly number[];
}

function defaultSha256(sql: string): string {
  return createHash("sha256").update(sql, "utf8").digest("hex");
}

/**
 * Apply pending migrations by ascending version. Each migration runs in its own SERIALIZABLE
 * transaction (a migration rewrites the authoritative schema and is therefore money-path),
 * under the serialization-retry policy. The journal insert lands in the same transaction
 * as the migration body, so a crash cannot record an unapplied migration or apply one
 * unrecorded.
 */
export async function runMigrations(
  executor: MigrationSqlExecutor,
  files: readonly MigrationFile[],
  options: MigrationRunnerOptions = {},
): Promise<MigrationRunResult> {
  const policy = options.retryPolicy ?? DEFAULT_SERIALIZATION_RETRY_POLICY;
  const sleep = options.sleep ?? defaultSleep;
  const random = options.random ?? Math.random;
  const sha256 = options.sha256 ?? defaultSha256;

  await executor.query(MIGRATION_JOURNAL_DDL);

  const appliedRows = await executor.select<MigrationRecord>(
    `SELECT version, description, sql_sha256 AS "sqlSha256" FROM ${MIGRATION_JOURNAL_TABLE};`,
  );
  const appliedVersions = appliedRows
    .slice()
    .sort((a, b) => a.version - b.version)
    .map((row) => row.version);

  const pending = planMigrations(files, appliedVersions);
  const applied: MigrationRecord[] = [];

  for (const file of pending) {
    const parsed = parseMigrationName(file.fileName);
    const sqlSha256 = sha256(file.sql);
    await withSerializationRetry(
      policy,
      async () => {
        await executor.transaction(MONEY_PATH_ISOLATION, async () => {
          await executor.query(file.sql);
          await executor.query(
            `INSERT INTO ${MIGRATION_JOURNAL_TABLE} (version, description, sql_sha256) ` +
              `VALUES (${parsed.version}, '${parsed.description.replace(/'/g, "''")}', '${sqlSha256}');`,
          );
        });
      },
      sleep,
      random,
    );
    applied.push({ version: parsed.version, description: parsed.description, sqlSha256 });
  }

  return { applied, skippedVersions: appliedVersions };
}

// --- Destructive-migration guard (retention safety) ---

/**
 * SQL prelude a destructive migration MUST open with when it retypes or reformats an
 * already-populated authoritative-byte column. The `DO` block
 * raises and aborts the surrounding transaction if `table` holds any row, so historical exact
 * bytes are never cast in place — a retype happens via a new column or table plus a back-fill,
 * and the original is retired in a later migration. The refusal shape is an
 * `IF EXISTS (SELECT 1 FROM …) THEN RAISE EXCEPTION` guard. The returned string is embedded verbatim in the .sql migration file; the
 * block runs server-side against live PostgreSQL, so nothing in this package executes it.
 */
export function failIfNonEmptyGuardSql(table: string): string {
  if (!/^[a-z_][a-z0-9_]*$/.test(table)) {
    throw new Error(
      `failIfNonEmptyGuardSql: unsafe table identifier ${JSON.stringify(table)}`,
    );
  }
  return `DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM ${table}) THEN
    RAISE EXCEPTION 'destructive migration refused: ${table} is non-empty; retype via a new column/table and back-fill, never cast historical rows in place';
  END IF;
END
$$;`;
}
