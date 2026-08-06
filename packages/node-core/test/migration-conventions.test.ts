import { describe, expect, it } from "vitest";

import {
  DEFAULT_SERIALIZATION_RETRY_POLICY,
  MIGRATION_FILE_PATTERN,
  MIGRATION_JOURNAL_DDL,
  failIfNonEmptyGuardSql,
  formatMigrationName,
  isRetriableSerializationFailure,
  parseMigrationName,
  planMigrations,
  runMigrations,
  serializationRetryDelayMs,
  withSerializationRetry,
  type MigrationFile,
  type MigrationSqlExecutor,
  type TransactionIsolationLevel,
} from "../src/data/migrations.js";

describe("migration naming convention", () => {
  it("accepts canonical NNNN_description.sql names", () => {
    expect(MIGRATION_FILE_PATTERN.test("0001_initial_schema.sql")).toBe(true);
    expect(MIGRATION_FILE_PATTERN.test("0042_add_wallet_leases.sql")).toBe(true);
    expect(MIGRATION_FILE_PATTERN.test("9999_z9.sql")).toBe(true);
  });

  it("rejects names that violate the convention", () => {
    const invalid = [
      "1_initial.sql", // version not zero-padded to four digits
      "00001_initial.sql", // version too long
      "0001-Initial.sql", // wrong separator and uppercase
      "0001_initial.SQL", // uppercase extension
      "0001_initial", // missing extension
      "0001_.sql", // empty description
      "0001_9lives.sql", // description must start with a letter
      "0001_initial schema.sql", // space in description
      "abcd_initial.sql", // non-numeric version
    ];
    for (const name of invalid) {
      expect(MIGRATION_FILE_PATTERN.test(name), name).toBe(false);
      expect(() => parseMigrationName(name), name).toThrow();
    }
  });

  it("parses version and description", () => {
    expect(parseMigrationName("0007_add_observation_cursors.sql")).toEqual({
      version: 7,
      description: "add_observation_cursors",
    });
  });

  it("round-trips format and parse", () => {
    const fileName = formatMigrationName(12, "add_sign_intents");
    expect(fileName).toBe("0012_add_sign_intents.sql");
    expect(parseMigrationName(fileName)).toEqual({
      version: 12,
      description: "add_sign_intents",
    });
  });

  it("rejects out-of-range versions and bad descriptions in formatMigrationName", () => {
    expect(() => formatMigrationName(-1, "x")).toThrow(RangeError);
    expect(() => formatMigrationName(10000, "x")).toThrow(RangeError);
    expect(() => formatMigrationName(1.5, "x")).toThrow(RangeError);
    expect(() => formatMigrationName(1, "Bad-Case")).toThrow();
    expect(() => formatMigrationName(1, "9lives")).toThrow();
  });
});

describe("serialization retry policy", () => {
  it("classifies retriable SQLSTATEs", () => {
    expect(isRetriableSerializationFailure("40001")).toBe(true);
    expect(isRetriableSerializationFailure("40P01")).toBe(true);
    expect(isRetriableSerializationFailure("23505")).toBe(false);
    expect(isRetriableSerializationFailure(undefined)).toBe(false);
  });

  it("computes bounded exponential backoff with jitter", () => {
    const policy = DEFAULT_SERIALIZATION_RETRY_POLICY;
    expect(serializationRetryDelayMs(policy, 1, 0)).toBe(0);
    expect(serializationRetryDelayMs(policy, 1, 0.5)).toBe(12); // floor(25 * 0.5)
    expect(serializationRetryDelayMs(policy, 2, 1 - Number.EPSILON)).toBeLessThanOrEqual(50);
    // Capped at maxDelayMs regardless of attempt.
    expect(serializationRetryDelayMs(policy, 30, 1 - Number.EPSILON)).toBeLessThanOrEqual(
      policy.maxDelayMs,
    );
    expect(() => serializationRetryDelayMs(policy, 0, 0.5)).toThrow(RangeError);
    expect(() => serializationRetryDelayMs(policy, 1, 1)).toThrow(RangeError);
  });

  it("retries a serialization failure then succeeds", async () => {
    let attempts = 0;
    const result = await withSerializationRetry(
      { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 2 },
      async () => {
        attempts += 1;
        if (attempts < 3) {
          throw Object.assign(new Error("serialization_failure"), { code: "40001" });
        }
        return "ok";
      },
      async () => {},
      () => 0.5,
    );
    expect(result).toBe("ok");
    expect(attempts).toBe(3);
  });

  it("rethrows a non-retriable error immediately", async () => {
    let attempts = 0;
    await expect(
      withSerializationRetry(
        { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 2 },
        async () => {
          attempts += 1;
          throw Object.assign(new Error("unique_violation"), { code: "23505" });
        },
        async () => {},
        () => 0.5,
      ),
    ).rejects.toThrow("unique_violation");
    expect(attempts).toBe(1);
  });

  it("gives up after maxAttempts and rethrows the last serialization failure", async () => {
    let attempts = 0;
    await expect(
      withSerializationRetry(
        { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 2 },
        async () => {
          attempts += 1;
          throw Object.assign(new Error("still_serializing"), { code: "40001" });
        },
        async () => {},
        () => 0.5,
      ),
    ).rejects.toThrow("still_serializing");
    expect(attempts).toBe(3);
  });
});

describe("migration planning", () => {
  const file = (fileName: string): MigrationFile => ({ fileName, sql: `-- ${fileName}` });

  it("returns pending migrations in ascending version order", () => {
    const pending = planMigrations(
      [file("0003_c.sql"), file("0001_a.sql"), file("0002_b.sql")],
      [1],
    );
    expect(pending.map((f) => f.fileName)).toEqual(["0002_b.sql", "0003_c.sql"]);
  });

  it("rejects duplicate versions", () => {
    expect(() => planMigrations([file("0001_a.sql"), file("0001_b.sql")], [])).toThrow(
      /duplicate migration version 1/,
    );
  });
});

describe("migration runner", () => {
  interface RecordedQuery {
    readonly kind: "query" | "transaction";
    readonly sql?: string;
    readonly isolation?: TransactionIsolationLevel;
  }

  function fakeExecutor(applied: number[] = []) {
    const log: RecordedQuery[] = [];
    const executor: MigrationSqlExecutor = {
      async query(sql: string): Promise<void> {
        log.push({ kind: "query", sql });
      },
      async select<T>(): Promise<readonly T[]> {
        return applied.map((version) => ({
          version,
          description: `m${version}`,
          sqlSha256: "0".repeat(64),
        })) as readonly T[];
      },
      async transaction(
        isolation: TransactionIsolationLevel,
        body: () => Promise<void>,
      ): Promise<void> {
        log.push({ kind: "transaction", isolation });
        await body();
      },
    };
    return { executor, log };
  }

  it("creates the journal, then applies each pending migration in a SERIALIZABLE transaction", async () => {
    const { executor, log } = fakeExecutor([1]);
    const result = await runMigrations(
      executor,
      [
        { fileName: "0001_a.sql", sql: "CREATE TABLE a();" },
        { fileName: "0002_b.sql", sql: "CREATE TABLE b();" },
      ],
      { sha256: () => "f".repeat(64), sleep: async () => {}, random: () => 0.5 },
    );

    expect(result.applied.map((r) => r.version)).toEqual([2]);
    expect(result.skippedVersions).toEqual([1]);

    // First statement is the journal DDL.
    expect(log[0]?.sql).toContain("CREATE TABLE IF NOT EXISTS schema_migrations");
    // Each applied migration ran inside a SERIALIZABLE transaction.
    const transactions = log.filter((entry) => entry.kind === "transaction");
    expect(transactions).toHaveLength(1);
    expect(transactions[0]?.isolation).toBe("SERIALIZABLE");
    // The migration body and its journal insert both ran.
    const sqls = log.filter((entry) => entry.kind === "query").map((entry) => entry.sql);
    expect(sqls.some((sql) => sql?.includes("CREATE TABLE b();"))).toBe(true);
    expect(sqls.some((sql) => sql?.includes("INSERT INTO schema_migrations"))).toBe(true);
  });

  it("applies nothing when every version is already recorded", async () => {
    const { executor, log } = fakeExecutor([1, 2]);
    const result = await runMigrations(
      executor,
      [
        { fileName: "0001_a.sql", sql: "CREATE TABLE a();" },
        { fileName: "0002_b.sql", sql: "CREATE TABLE b();" },
      ],
      { sha256: () => "0".repeat(64), sleep: async () => {}, random: () => 0.5 },
    );
    expect(result.applied).toEqual([]);
    expect(log.filter((entry) => entry.kind === "transaction")).toHaveLength(0);
  });

  it("does NOT detect drift: an already-applied migration whose bytes changed on disk is neither re-run nor flagged", async () => {
    // The journal records sqlSha256 "0…0" for versions 1 and 2 (see fakeExecutor), but the
    // on-disk files now hash to "f…f". plan/runMigrations filter by version only and discard
    // the recorded hash, so both are silently skipped — no re-apply, no throw. sql_sha256 is
    // PERSISTED for future drift detection; it is not an active guarantee today. This test
    // pins that honest behaviour so the persisted-hash column is not mistaken for tamper
    // detection.
    const { executor, log } = fakeExecutor([1, 2]);
    const result = await runMigrations(
      executor,
      [
        { fileName: "0001_a.sql", sql: "CREATE TABLE a();" },
        { fileName: "0002_b.sql", sql: "CREATE TABLE b();" },
      ],
      { sha256: () => "f".repeat(64), sleep: async () => {}, random: () => 0.5 },
    );
    expect(result.applied).toEqual([]);
    expect(result.skippedVersions).toEqual([1, 2]);
    expect(log.filter((entry) => entry.kind === "transaction")).toHaveLength(0);
  });
});

describe("migration journal bootstrap on a fresh database", () => {
  // A fresh DB has no application schema, so the sha256_hex DOMAIN does not exist yet. The
  // journal is created as runMigrations' FIRST statement, before any migration file, so its
  // DDL must not reference that domain. This stub rejects exactly as PostgreSQL would when a
  // statement references the missing domain type.
  function domainlessExecutor(): { executor: MigrationSqlExecutor; log: string[] } {
    const log: string[] = [];
    const executor: MigrationSqlExecutor = {
      async query(sql: string): Promise<void> {
        log.push(sql);
        if (sql.includes("sha256_hex")) {
          throw Object.assign(new Error('type "sha256_hex" does not exist'), {
            code: "42704",
          });
        }
      },
      async select<T>(): Promise<readonly T[]> {
        return [] as readonly T[];
      },
      async transaction(
        _isolation: TransactionIsolationLevel,
        body: () => Promise<void>,
      ): Promise<void> {
        await body();
      },
    };
    return { executor, log };
  }

  it("creates the journal without depending on the sha256_hex domain (RED on the domain-typed DDL, GREEN on text + CHECK)", async () => {
    // No migration files: the bootstrap DDL is the first and only statement under test. With
    // the old `sql_sha256 sha256_hex` DDL the stub rejects it → runMigrations rejects → this
    // assertion fails (RED). With the self-contained `text` + inline CHECK DDL it resolves.
    const { executor } = domainlessExecutor();
    await expect(
      runMigrations(executor, [], { sleep: async () => {}, random: () => 0.5 }),
    ).resolves.toMatchObject({ applied: [], skippedVersions: [] });
  });

  it("the journal DDL is self-contained: no sha256_hex domain reference, inline hex CHECK instead", () => {
    expect(MIGRATION_JOURNAL_DDL).not.toContain("sha256_hex");
    expect(MIGRATION_JOURNAL_DDL).toContain("CHECK (sql_sha256 ~ '^[0-9a-f]{64}$')");
  });
});

describe("fail-if-non-empty destructive-migration guard", () => {
  it("emits a DO block that refuses when the target table is non-empty (0008 precedent shape)", () => {
    const guard = failIfNonEmptyGuardSql("operation_transactions");
    expect(guard).toContain("IF EXISTS (SELECT 1 FROM operation_transactions)");
    expect(guard).toContain("RAISE EXCEPTION");
    expect(guard).toContain("operation_transactions is non-empty");
    // Refuses in place: the guard itself never casts historical rows via ALTER/UPDATE.
    expect(guard).not.toMatch(/ALTER TABLE|UPDATE\s/);
  });

  it("rejects an unsafe table identifier before building any SQL", () => {
    expect(() => failIfNonEmptyGuardSql("x; DROP TABLE y")).toThrow(
      /unsafe table identifier/,
    );
    expect(() => failIfNonEmptyGuardSql("")).toThrow(/unsafe table identifier/);
  });

  // A fake executor that models PostgreSQL evaluating the guard's EXISTS(...) against modeled
  // row-presence: when it runs a statement that carries `SELECT 1 FROM <table>` AND a
  // `RAISE EXCEPTION`, and <table> is in `nonEmpty`, it raises SQLSTATE P0001 exactly as the
  // DO block would. Same executor-modeling idiom the fresh-DB bootstrap test uses for 42704.
  function guardAwareExecutor(nonEmpty: ReadonlySet<string>): {
    executor: MigrationSqlExecutor;
    queries: string[];
  } {
    const queries: string[] = [];
    const executor: MigrationSqlExecutor = {
      async query(sql: string): Promise<void> {
        queries.push(sql);
        const guardedTable = /SELECT 1 FROM (\w+)/.exec(sql)?.[1];
        if (
          guardedTable !== undefined &&
          nonEmpty.has(guardedTable) &&
          sql.includes("RAISE EXCEPTION")
        ) {
          throw Object.assign(new Error("destructive migration refused"), { code: "P0001" });
        }
      },
      async select<T>(): Promise<readonly T[]> {
        return [] as readonly T[];
      },
      async transaction(
        _isolation: TransactionIsolationLevel,
        body: () => Promise<void>,
      ): Promise<void> {
        await body();
      },
    };
    return { executor, queries };
  }

  const destructiveMigration = (table: string): MigrationFile => ({
    fileName: "0009_retype_audit_body.sql",
    sql: `${failIfNonEmptyGuardSql(table)}\nALTER TABLE ${table} ALTER COLUMN body SET DATA TYPE text;`,
  });

  it("refuses to apply the destructive migration against a NON-EMPTY table (nothing recorded)", async () => {
    const { executor, queries } = guardAwareExecutor(new Set(["audit_log"]));
    await expect(
      runMigrations(executor, [destructiveMigration("audit_log")], {
        sha256: () => "a".repeat(64),
        sleep: async () => {},
        random: () => 0.5,
      }),
    ).rejects.toThrow(/refused/);
    // The guard fired, so the migration body aborted before its journal INSERT could run.
    expect(queries.some((sql) => sql.includes("INSERT INTO schema_migrations"))).toBe(false);
  });

  it("applies the same migration against an EMPTY table and records it", async () => {
    const { executor, queries } = guardAwareExecutor(new Set()); // audit_log modeled empty
    const result = await runMigrations(executor, [destructiveMigration("audit_log")], {
      sha256: () => "a".repeat(64),
      sleep: async () => {},
      random: () => 0.5,
    });
    expect(result.applied.map((record) => record.version)).toEqual([9]);
    expect(queries.some((sql) => sql.includes("INSERT INTO schema_migrations"))).toBe(true);
  });
});
