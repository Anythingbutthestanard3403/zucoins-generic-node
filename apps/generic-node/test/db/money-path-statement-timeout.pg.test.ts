// ZTR-1156 — money-path statement_timeout aborts a stuck statement rather than
// blocking indefinitely. Migrations deliberately use a longer session-level SET
// and must NOT inherit the money-path bound (see migrate-guards + applyMigrationTimeouts).
import { execFileSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  applyMoneyPathStatementTimeout,
  createPool,
} from "../../src/db/client.js";
import {
  applyMigrationTimeouts,
  MIGRATION_STATEMENT_TIMEOUT_MS,
} from "../../src/db/migrate.js";

const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";

const PG_AVAILABLE = (() => {
  try {
    execFileSync("pg_isready", ["-q", "-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER]);
    return true;
  } catch {
    try {
      execFileSync(
        "node",
        [
          "-e",
          `const {Client}=require("pg");const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:"postgres",password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
        ],
        { stdio: "ignore", env: process.env },
      );
      return true;
    } catch {
      return false;
    }
  }
})();

describe.runIf(PG_AVAILABLE)("money-path statement_timeout (ZTR-1156)", () => {
  let pool: Pool;

  beforeAll(() => {
    pool = createPool(
      `postgres://${encodeURIComponent(PG_USER)}${
        process.env.PGPASSWORD ? `:${encodeURIComponent(process.env.PGPASSWORD)}` : ""
      }@${PG_HOST}:${PG_PORT}/postgres`,
    );
  });

  afterAll(async () => {
    await pool.end();
  });

  it("createPool exposes keepAlive + connect/idle timeouts (composition proof)", () => {
    expect(pool.options.keepAlive).toBe(true);
    expect(pool.options.connectionTimeoutMillis).toBeGreaterThan(0);
    expect(pool.options.idleTimeoutMillis).toBeGreaterThan(0);
    expect(pool.options.max).toBeGreaterThan(0);
  });

  it("transaction-local money-path timeout aborts a long statement", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await applyMoneyPathStatementTimeout(client, 200);
      const started = performance.now();
      await expect(client.query("SELECT pg_sleep(10)")).rejects.toMatchObject({
        code: "57014", // query_canceled
      });
      expect(performance.now() - started).toBeLessThan(3_000);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  });

  it("money-path timeout does not stick on the pooled connection after COMMIT", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await applyMoneyPathStatementTimeout(client, 200);
      await client.query("COMMIT");
      // Session-level statement_timeout should still be 0 (disabled) after LOCAL dies.
      const { rows } = await client.query<{ statement_timeout: string }>(
        "SHOW statement_timeout",
      );
      expect(rows[0]?.statement_timeout).toMatch(/^(0|0ms|0s)$/i);
    } finally {
      client.release();
    }
  });

  it("migration timeouts are session-level and longer than the money-path default", async () => {
    expect(MIGRATION_STATEMENT_TIMEOUT_MS).toBeGreaterThan(15_000);
    const client = await pool.connect();
    try {
      await applyMigrationTimeouts(client);
      const { rows } = await client.query<{ statement_timeout: string }>(
        "SHOW statement_timeout",
      );
      // 30000ms shows as "30s" on most builds.
      expect(rows[0]?.statement_timeout).toMatch(/30s|30000ms/i);
    } finally {
      // Reset so the pool is not left with a migration timeout.
      await client.query("RESET statement_timeout").catch(() => {});
      await client.query("RESET lock_timeout").catch(() => {});
      client.release();
    }
  });
});
