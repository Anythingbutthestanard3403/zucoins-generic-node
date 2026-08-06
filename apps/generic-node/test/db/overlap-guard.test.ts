import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const PG_TEST_TIMEOUT_MS = 180_000;
import { Pool } from "pg";
import { SIGNER_LEADERSHIP_LOCK_ID } from "@zucoins/node-core";

import * as migrationClassifier from "../../src/db/migration-classifier.js";
import {
  acknowledgedStopFirstTags,
  advisoryLockHeld,
  classifyPendingMigrations,
  detectAdvisoryLockHeld,
  INFLIGHT_BACKSTOP_ACK_ENV,
  INFLIGHT_BACKSTOP_OBJECTS,
  InflightBackstopAckRequiredError,
  inflightBackstopObjectsRemovedBy,
  OverlapMigrationRefusedError,
  readPendingMigrationTags,
  runOverlapGuard,
} from "../../src/db/overlap-guard.js";

function migrationFolder(entries: Array<{ tag: string; when: number; sql: string }>): string {
  const folder = mkdtempSync(join(tmpdir(), "gn-overlap-guard-"));
  mkdirSync(join(folder, "meta"));
  writeFileSync(
    join(folder, "meta", "_journal.json"),
    JSON.stringify({
      version: "7",
      dialect: "postgresql",
      entries: entries.map((entry, idx) => ({
        idx,
        version: "7",
        when: entry.when,
        tag: entry.tag,
        breakpoints: true,
      })),
    }),
  );
  for (const entry of entries) writeFileSync(join(folder, `${entry.tag}.sql`), entry.sql);
  return folder;
}

function poolWithQueries(
  handler: (sql: string) => Promise<{ rows: unknown[] }> | { rows: unknown[] },
): Pool {
  return { query: (sql: string) => handler(sql) } as unknown as Pool;
}

const PG_AVAILABLE = (() => {
  try {
    execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

describe("advisory-lock overlap probe (signer leadership)", () => {
  it("scopes the pg_locks probe to the current database (not the whole cluster)", async () => {
    let seenSql = "";
    const pool = poolWithQueries(async (sql) => {
      seenSql = sql;
      return { rows: [] };
    });
    await expect(detectAdvisoryLockHeld(pool, BigInt(SIGNER_LEADERSHIP_LOCK_ID))).resolves.toBe(
      false,
    );
    expect(seenSql).toMatch(/current_database\s*\(\s*\)/);
    expect(seenSql).toMatch(/database\s*=/);
  });

  it("matches the single-bigint encoding of SIGNER_LEADERSHIP_LOCK_ID", () => {
    expect(
      advisoryLockHeld(
        [{ classid: 0, objid: SIGNER_LEADERSHIP_LOCK_ID, objsubid: 1 }],
        BigInt(SIGNER_LEADERSHIP_LOCK_ID),
      ),
    ).toBe(true);
    expect(
      advisoryLockHeld([{ classid: 0, objid: 7, objsubid: 1 }], BigInt(SIGNER_LEADERSHIP_LOCK_ID)),
    ).toBe(false);
  });

  it("matches an id above 2^32, whose high word lands in classid", () => {
    expect(advisoryLockHeld([{ classid: 1, objid: 5918273, objsubid: 1 }], 4300885569n)).toBe(true);
    expect(advisoryLockHeld([{ classid: 0, objid: 5918273, objsubid: 1 }], 4300885569n)).toBe(
      false,
    );
  });

  it("matches the two-integer encoding of the same id", () => {
    expect(
      advisoryLockHeld(
        [{ classid: 0, objid: SIGNER_LEADERSHIP_LOCK_ID, objsubid: 2 }],
        BigInt(SIGNER_LEADERSHIP_LOCK_ID),
      ),
    ).toBe(true);
  });

  it("fails closed for unreadable or unknown advisory-lock rows", () => {
    expect(advisoryLockHeld([{ classid: 0, objid: 7, objsubid: 9 }], 0x534c4cn)).toBe(true);
    expect(
      advisoryLockHeld(
        [{ classid: null as unknown as number, objid: 7, objsubid: 1 }],
        0x534c4cn,
      ),
    ).toBe(true);
  });
});

describe("pending journal discovery", () => {
  const folder = migrationFolder([
    { tag: "0000_first", when: 100, sql: "CREATE TABLE first(id integer);" },
    { tag: "0001_second", when: 200, sql: "ALTER TABLE first ADD COLUMN value text;" },
  ]);

  it("returns only unapplied journal entries", async () => {
    const pool = poolWithQueries(async () => ({ rows: [{ created_at: "100" }] }));
    await expect(readPendingMigrationTags(pool, folder)).resolves.toEqual(["0001_second"]);
  });

  it("treats undefined journal table as fresh DB but propagates every other DB error", async () => {
    const missing = poolWithQueries(async () => {
      throw Object.assign(new Error("missing"), { code: "42P01" });
    });
    await expect(readPendingMigrationTags(missing, folder)).resolves.toEqual([
      "0000_first",
      "0001_second",
    ]);

    const denied = poolWithQueries(async () => {
      throw Object.assign(new Error("denied"), { code: "42501" });
    });
    await expect(readPendingMigrationTags(denied, folder)).rejects.toThrow("denied");
  });
});

describe("pending SQL uses the sole out-of-process classifier", () => {
  it("classifies only named pending files and fails closed on missing SQL", async () => {
    const folder = migrationFolder([
      { tag: "0000_online", when: 100, sql: "CREATE TABLE new_table(id integer);" },
      { tag: "0001_drain", when: 200, sql: "ALTER TABLE wallets ADD COLUMN note text;" },
    ]);

    const online = await classifyPendingMigrations(folder, ["0000_online"]);
    expect(online).toHaveLength(1);
    expect(online[0]?.lockClass).toBe("online");

    const drain = await classifyPendingMigrations(folder, ["0001_drain"]);
    expect(drain.some((statement) => statement.lockClass === "blocking")).toBe(true);

    const unreadable = await classifyPendingMigrations(folder, ["9999_missing"]);
    expect(unreadable).toMatchObject([
      { migrationTag: "9999_missing", lockClass: "blocking", rule: "classifier-error" },
    ]);
  });
});

describe("guard ordering and rollback-safe refusal", () => {
  const folder = migrationFolder([
    { tag: "0000_online", when: 100, sql: "CREATE TABLE new_table(id integer);" },
    { tag: "0001_drain", when: 200, sql: "ALTER TABLE wallets ADD COLUMN note text;" },
  ]);

  it("does not reclassify historical drain migrations on a fully migrated DB", async () => {
    const pool = poolWithQueries(async (sql) => {
      if (sql.includes("drizzle.__drizzle_migrations")) {
        return { rows: [{ created_at: "100" }, { created_at: "200" }] };
      }
      return { rows: [{ classid: 0, objid: SIGNER_LEADERSHIP_LOCK_ID, objsubid: 1 }] };
    });
    await expect(runOverlapGuard(pool, folder)).resolves.toMatchObject({
      overlapDetected: true,
      blockingMigrations: [],
      shouldProceed: true,
    });
  });

  it("allows an online-only pending set during overlap", async () => {
    const pool = poolWithQueries(async (sql) => {
      if (sql.includes("drizzle.__drizzle_migrations")) return { rows: [] };
      return { rows: [{ classid: 0, objid: SIGNER_LEADERSHIP_LOCK_ID, objsubid: 1 }] };
    });
    const onlineOnly = migrationFolder([
      { tag: "0000_online", when: 100, sql: "CREATE TABLE new_table(id integer);" },
    ]);
    await expect(runOverlapGuard(pool, onlineOnly)).resolves.toMatchObject({
      overlapDetected: true,
      shouldProceed: true,
    });
  });

  it("refuses a pending drain migration before any migration write is available", async () => {
    const observedSql: string[] = [];
    const pool = poolWithQueries(async (sql) => {
      observedSql.push(sql);
      if (sql.includes("drizzle.__drizzle_migrations")) return { rows: [{ created_at: "100" }] };
      return { rows: [{ classid: 0, objid: SIGNER_LEADERSHIP_LOCK_ID, objsubid: 1 }] };
    });

    await expect(runOverlapGuard(pool, folder)).rejects.toBeInstanceOf(
      OverlapMigrationRefusedError,
    );
    expect(observedSql).toHaveLength(2);
    expect(observedSql.every((sql) => /^\s*SELECT/i.test(sql))).toBe(true);
    expect(observedSql.some((sql) => /advisory_lock/i.test(sql))).toBe(false);
  });

  it("classifies fail-closed but proceeds on cold boot without another signer", async () => {
    const pool = poolWithQueries(async (sql) => {
      if (sql.includes("drizzle.__drizzle_migrations")) return { rows: [{ created_at: "100" }] };
      return { rows: [] };
    });
    await expect(runOverlapGuard(pool, folder)).resolves.toMatchObject({
      overlapDetected: false,
      shouldProceed: true,
    });
  });
});

describe("one-in-flight-per-wallet backstop strictest tier", () => {
  afterEach(() => {
    delete process.env[INFLIGHT_BACKSTOP_ACK_ENV];
  });

  const DROP_BACKSTOP = `DROP INDEX "idx_wallet_active_leases_one_inflight";`;

  function backstopFolder(tag = "0001_drop_backstop"): string {
    return migrationFolder([{ tag, when: 200, sql: DROP_BACKSTOP }]);
  }

  function poolWithLock(held: boolean): Pool {
    return poolWithQueries(async (sql) => {
      if (sql.includes("drizzle.__drizzle_migrations")) return { rows: [] };
      return {
        rows: held ? [{ classid: 0, objid: SIGNER_LEADERSHIP_LOCK_ID, objsubid: 1 }] : [],
      };
    });
  }

  it("recognises removal of each backstop object and ignores its creation", () => {
    expect(inflightBackstopObjectsRemovedBy(DROP_BACKSTOP)).toEqual([
      "idx_wallet_active_leases_one_inflight",
    ]);
    expect(
      inflightBackstopObjectsRemovedBy(
        `ALTER TABLE "wallet_active_leases" DROP CONSTRAINT "wallet_active_leases_wallet_public_key_key";`,
      ),
    ).toEqual(["wallet_active_leases_wallet_public_key_key"]);

    expect(
      inflightBackstopObjectsRemovedBy(
        `CREATE UNIQUE INDEX IF NOT EXISTS "idx_wallet_active_leases_one_inflight" ON "wallet_active_leases" (wallet_public_key);`,
      ),
    ).toEqual([]);
  });

  it("refuses a backstop removal with the lock FREE and no acknowledgement", async () => {
    await expect(runOverlapGuard(poolWithLock(false), backstopFolder())).rejects.toBeInstanceOf(
      InflightBackstopAckRequiredError,
    );
    await expect(runOverlapGuard(poolWithLock(false), backstopFolder())).rejects.toThrow(
      /STRICTEST TIER[\s\S]*idx_wallet_active_leases_one_inflight/,
    );
  });

  it("proceeds only when the acknowledgement names that exact migration", async () => {
    process.env[INFLIGHT_BACKSTOP_ACK_ENV] = "0001_drop_backstop";
    await expect(
      runOverlapGuard(poolWithLock(false), backstopFolder("0001_drop_backstop")),
    ).resolves.toMatchObject({ overlapDetected: false, shouldProceed: true });

    await expect(
      runOverlapGuard(poolWithLock(false), backstopFolder("0002_drop_another")),
    ).rejects.toBeInstanceOf(InflightBackstopAckRequiredError);
  });

  it("never lets the acknowledgement clear an OVERLAP refusal", async () => {
    process.env[INFLIGHT_BACKSTOP_ACK_ENV] = "0001_drop_backstop";
    const error = await runOverlapGuard(poolWithLock(true), backstopFolder()).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(OverlapMigrationRefusedError);
    expect((error as Error).message).toMatch(
      /STRICTEST TIER[\s\S]*idx_wallet_active_leases_one_inflight/,
    );
  });

  it("parses the acknowledgement as a comma-separated tag list", () => {
    expect([...acknowledgedStopFirstTags({ [INFLIGHT_BACKSTOP_ACK_ENV]: " a , b ,, c " })]).toEqual([
      "a",
      "b",
      "c",
    ]);
    expect(acknowledgedStopFirstTags({}).size).toBe(0);
  });

  it("finds no backstop removal in any shipped drizzle migration", () => {
    const drizzleFolder = fileURLToPath(new URL("../../drizzle", import.meta.url));
    const offenders = readdirSync(drizzleFolder)
      .filter((file) => file.endsWith(".sql"))
      .flatMap((file) => {
        const removed = inflightBackstopObjectsRemovedBy(
          readFileSync(join(drizzleFolder, file), "utf8"),
        );
        return removed.length > 0 ? [`${file}: ${removed.join(", ")}`] : [];
      });
    expect(offenders).toEqual([]);
    expect(INFLIGHT_BACKSTOP_OBJECTS.length).toBeGreaterThan(0);
  });

  it("refuses One-in-flight DROP when classifier returns FAIL_CLOSED_BLOCKING empty sql (no overlap)", async () => {
    // Reproduce the production fail-closed classifier shape exactly:
    // `{ sql: "" … "Classifier unavailable" }`. Scanning only statement.sql
    // would miss the DROP; the file-byte One-in-flight scan must still refuse without
    // tag-exact ack (strictest tier / the one-in-flight-per-wallet rule).
    const drainClosed = {
      lockClass: "blocking" as const,
      statements: [
        {
          sql: "",
          lockClass: "blocking" as const,
          reason: "Classifier unavailable — fail-closed",
        },
      ],
    };
    const spy = vi
      .spyOn(migrationClassifier, "classifyMigrationSql")
      .mockResolvedValue(drainClosed);

    try {
      delete process.env[INFLIGHT_BACKSTOP_ACK_ENV];
      await expect(
        runOverlapGuard(poolWithLock(false), backstopFolder("0001_drop_backstop_unavail")),
      ).rejects.toBeInstanceOf(InflightBackstopAckRequiredError);

      await expect(
        runOverlapGuard(poolWithLock(false), backstopFolder("0001_drop_backstop_unavail")),
      ).rejects.toThrow(/STRICTEST TIER[\s\S]*idx_wallet_active_leases_one_inflight/);

      const folder = backstopFolder("0001_drop_backstop_unavail");
      const classified = await classifyPendingMigrations(folder, ["0001_drop_backstop_unavail"]);
      expect(spy).toHaveBeenCalled();
      expect(
        classified.some(
          (s) =>
            s.inflightBackstopObjects.includes("idx_wallet_active_leases_one_inflight") &&
            s.lockClass === "blocking",
        ),
      ).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });
});

describe.skipIf(!PG_AVAILABLE)("real Postgres refusal boundary", () => {
  it("observes signer leadership and refuses before pending DDL changes the schema", { timeout: PG_TEST_TIMEOUT_MS }, async () => {
    const dbName = `gn_overlap_guard_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    execFileSync("createdb", [dbName]);
    const pool = new Pool({
      host: process.env.PGHOST ?? "/tmp",
      port: Number(process.env.PGPORT ?? "5432"),
      database: dbName,
    });
    const holder = await pool.connect();
    const folder = migrationFolder([
      { tag: "0000_drain", when: 100, sql: "ALTER TABLE wallets ADD COLUMN note text;" },
    ]);

    try {
      await pool.query("CREATE TABLE wallets (id integer PRIMARY KEY)");
      await pool.query("CREATE SCHEMA drizzle");
      await pool.query(
        "CREATE TABLE drizzle.__drizzle_migrations (id serial PRIMARY KEY, hash text NOT NULL, created_at bigint)",
      );
      await holder.query("SELECT pg_advisory_lock($1)", [SIGNER_LEADERSHIP_LOCK_ID]);

      await expect(runOverlapGuard(pool, folder)).rejects.toBeInstanceOf(
        OverlapMigrationRefusedError,
      );
      const columns = await pool.query<{ column_name: string }>(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'wallets' ORDER BY column_name",
      );
      expect(columns.rows.map((row) => row.column_name)).toEqual(["id"]);
    } finally {
      await holder.query("SELECT pg_advisory_unlock($1)", [SIGNER_LEADERSHIP_LOCK_ID]);
      holder.release();
      await pool.end();
      execFileSync("dropdb", ["--if-exists", dbName]);
    }
  });

  it("ignores signer leadership held only on a sibling database", { timeout: PG_TEST_TIMEOUT_MS }, async () => {
    const stamp = `${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    const holderDb = `gn_overlap_holder_${stamp}`;
    const probeDb = `gn_overlap_probe_${stamp}`;
    execFileSync("createdb", [holderDb]);
    execFileSync("createdb", [probeDb]);
    const holderPool = new Pool({
      host: process.env.PGHOST ?? "/tmp",
      port: Number(process.env.PGPORT ?? "5432"),
      database: holderDb,
    });
    const probePool = new Pool({
      host: process.env.PGHOST ?? "/tmp",
      port: Number(process.env.PGPORT ?? "5432"),
      database: probeDb,
    });
    const holder = await holderPool.connect();
    const folder = migrationFolder([
      { tag: "0000_drain", when: 100, sql: "ALTER TABLE wallets ADD COLUMN note text;" },
    ]);
    try {
      await holder.query("SELECT pg_advisory_lock($1)", [SIGNER_LEADERSHIP_LOCK_ID]);
      await expect(runOverlapGuard(probePool, folder)).resolves.toMatchObject({
        overlapDetected: false,
        shouldProceed: true,
      });
    } finally {
      await holder.query("SELECT pg_advisory_unlock($1)", [SIGNER_LEADERSHIP_LOCK_ID]);
      holder.release();
      await holderPool.end();
      await probePool.end();
      execFileSync("dropdb", ["--if-exists", holderDb]);
      execFileSync("dropdb", ["--if-exists", probeDb]);
    }
  });
});
