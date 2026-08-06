import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";

// Local createdb is slow (~50s) on this host; PG suites need a wide budget.
const PG_TEST_TIMEOUT_MS = 180_000;

async function acquireAfterBackendExit(client: Parameters<typeof tryAcquireMigrationLock>[0]) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (await tryAcquireMigrationLock(client)) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return false;
}

import {
  assertMigrationLockAcquired,
  MIGRATION_ADVISORY_LOCK_ID,
  MigrationLockBusyError,
  releaseMigrationLock,
  tryAcquireMigrationLock,
} from "../../src/db/migration-lock.js";

const PG_AVAILABLE = (() => {
  try {
    execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

describe("migration advisory lock constants", () => {
  it("uses a stable ASCII-derived id distinct from signer leadership (0x534c4c)", () => {
    expect(MIGRATION_ADVISORY_LOCK_ID).toBe(0x474e6d67);
    expect(MIGRATION_ADVISORY_LOCK_ID).not.toBe(0x534c4c);
  });
});

describe.skipIf(!PG_AVAILABLE)("migration singleton lock — two-process exclusion", () => {
  it("second connection cannot acquire while the first holds the lock", { timeout: PG_TEST_TIMEOUT_MS }, async () => {
    const dbName = `gn_mig_lock_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    execFileSync("createdb", [dbName]);
    const pool = new Pool({
      host: process.env.PGHOST ?? "/tmp",
      port: Number(process.env.PGPORT ?? "5432"),
      database: dbName,
      max: 4,
    });
    const holder = await pool.connect();
    const contender = await pool.connect();
    try {
      await assertMigrationLockAcquired(holder);
      await expect(tryAcquireMigrationLock(contender)).resolves.toBe(false);
      await expect(assertMigrationLockAcquired(contender)).rejects.toBeInstanceOf(
        MigrationLockBusyError,
      );

      await releaseMigrationLock(holder);
      await expect(tryAcquireMigrationLock(contender)).resolves.toBe(true);
      await releaseMigrationLock(contender);
    } finally {
      holder.release();
      contender.release();
      await pool.end();
      execFileSync("dropdb", ["--if-exists", dbName]);
    }
  });

  it("lock self-releases when the holder connection is destroyed (two-process race)", { timeout: PG_TEST_TIMEOUT_MS }, async () => {
    const dbName = `gn_mig_lock_crash_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    execFileSync("createdb", [dbName]);
    const poolA = new Pool({
      host: process.env.PGHOST ?? "/tmp",
      port: Number(process.env.PGPORT ?? "5432"),
      database: dbName,
      max: 1,
    });
    const poolB = new Pool({
      host: process.env.PGHOST ?? "/tmp",
      port: Number(process.env.PGPORT ?? "5432"),
      database: dbName,
      max: 1,
    });
    const clientA = await poolA.connect();
    const clientB = await poolB.connect();
    try {
      await assertMigrationLockAcquired(clientA);
      await expect(tryAcquireMigrationLock(clientB)).resolves.toBe(false);

      // Process A crashes: destroy the connection without explicit unlock.
      clientA.release(true);
      await poolA.end();

      // Process B retries and must now acquire.
      // TCP teardown/backend exit is asynchronous even after pg-pool has
      // destroyed its client. Retry the non-blocking probe for at most 500ms;
      // this still proves self-release without turning the test into a wait.
      await expect(acquireAfterBackendExit(clientB)).resolves.toBe(true);
      await releaseMigrationLock(clientB);
    } finally {
      try {
        clientB.release();
      } catch {
        /* already released */
      }
      await poolB.end().catch(() => undefined);
      execFileSync("dropdb", ["--if-exists", dbName]);
    }
  });
});
