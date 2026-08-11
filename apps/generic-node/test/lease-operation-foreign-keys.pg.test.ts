// ZTR-1139: production-assembled lease ownership foreign-key proof.
// This suite invokes the same composition-root migrator as generic-node boot, then reads
// PostgreSQL's catalog and exercises enforcement. Source-text assertions are insufficient:
// first-declaration-wins assembly previously discarded these constraints.
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import { runMigrationsOnPool } from "../src/db/migrate.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const DATABASE_NAME = `lease_operation_fks_${process.pid}_${Date.now()}`;
const SQLSTATE_FOREIGN_KEY_VIOLATION = "23503";
const upgradeSql = readFileSync(
  fileURLToPath(
    new URL(
      "../../../packages/node-core/src/schema/lease-operation-foreign-keys.sql",
      import.meta.url,
    ),
  ),
  "utf8",
);

function withDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

const adminUrl = TEST_DATABASE_URL === "" ? "" : withDatabase(TEST_DATABASE_URL, "postgres");
const databaseUrl = TEST_DATABASE_URL === "" ? "" : withDatabase(TEST_DATABASE_URL, DATABASE_NAME);

async function databaseReachable(): Promise<boolean> {
  if (adminUrl === "") return false;
  const client = new Client({ connectionString: adminUrl, connectionTimeoutMillis: 2_000 });
  try {
    await client.connect();
    return true;
  } catch {
    return false;
  } finally {
    await client.end().catch(() => undefined);
  }
}

const PG_AVAILABLE = await databaseReachable();
if (PG_REQUIRED && !PG_AVAILABLE) {
  throw new Error("PG_REQUIRED=1 but PostgreSQL is unreachable for lease FK acceptance");
}

interface LeaseForeignKeyRow {
  readonly table_name: string;
  readonly column_name: string;
  readonly foreign_table_name: string;
  readonly foreign_column_name: string;
  readonly delete_rule: string;
}

describe.skipIf(!PG_AVAILABLE)("production money pack lease operation foreign keys", () => {
  let pool: Pool;

  beforeAll(async () => {
    const admin = new Client({ connectionString: adminUrl });
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE ${DATABASE_NAME}`);
    } finally {
      await admin.end();
    }
    pool = new Pool({ connectionString: databaseUrl });
    await runMigrationsOnPool(pool, { databaseUrl });
  }, 120_000);

  afterAll(async () => {
    await pool?.end();
    const admin = new Client({ connectionString: adminUrl });
    await admin.connect();
    try {
      await admin.query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
        [DATABASE_NAME],
      );
      await admin.query(`DROP DATABASE IF EXISTS ${DATABASE_NAME}`);
    } finally {
      await admin.end();
    }
  }, 120_000);

  it("materialises all four operations(id) foreign keys with NO ACTION", async () => {
    const result = await pool.query<LeaseForeignKeyRow>(`
      SELECT tc.table_name,
             kcu.column_name,
             ccu.table_name AS foreign_table_name,
             ccu.column_name AS foreign_column_name,
             rc.delete_rule
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON kcu.constraint_catalog = tc.constraint_catalog
         AND kcu.constraint_schema = tc.constraint_schema
         AND kcu.constraint_name = tc.constraint_name
        JOIN information_schema.constraint_column_usage ccu
          ON ccu.constraint_catalog = tc.constraint_catalog
         AND ccu.constraint_schema = tc.constraint_schema
         AND ccu.constraint_name = tc.constraint_name
        JOIN information_schema.referential_constraints rc
          ON rc.constraint_catalog = tc.constraint_catalog
         AND rc.constraint_schema = tc.constraint_schema
         AND rc.constraint_name = tc.constraint_name
       WHERE tc.constraint_schema = 'public'
         AND tc.constraint_type = 'FOREIGN KEY'
         AND (tc.table_name, kcu.column_name) IN (
           ('wallet_active_leases', 'operation_id'),
           ('wallet_active_leases', 'root_operation_id'),
           ('lease_groups', 'root_operation_id'),
           ('lease_group_operations', 'operation_id')
         )
       ORDER BY tc.table_name, kcu.column_name
    `);

    expect(result.rows).toEqual([
      {
        table_name: "lease_group_operations",
        column_name: "operation_id",
        foreign_table_name: "operations",
        foreign_column_name: "id",
        delete_rule: "NO ACTION",
      },
      {
        table_name: "lease_groups",
        column_name: "root_operation_id",
        foreign_table_name: "operations",
        foreign_column_name: "id",
        delete_rule: "NO ACTION",
      },
      {
        table_name: "wallet_active_leases",
        column_name: "operation_id",
        foreign_table_name: "operations",
        foreign_column_name: "id",
        delete_rule: "NO ACTION",
      },
      {
        table_name: "wallet_active_leases",
        column_name: "root_operation_id",
        foreign_table_name: "operations",
        foreign_column_name: "id",
        delete_rule: "NO ACTION",
      },
    ]);
  });

  it("rejects a lease group naming a non-existent operation with SQLSTATE 23503", async () => {
    try {
      await pool.query(
        "INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ($1, $2, now())",
        [randomUUID(), randomUUID()],
      );
      throw new Error("expected lease operation foreign key violation");
    } catch (error) {
      expect((error as { code?: string }).code).toBe(SQLSTATE_FOREIGN_KEY_VIOLATION);
    }
  });

  it("refuses a deployed-schema upgrade with dangling rows before adding any constraint", async () => {
    const schema = `ztr1139_upgrade_${process.pid}`;
    await pool.query(`CREATE SCHEMA ${schema}`);
    const client = await pool.connect();
    try {
      await client.query(`SET search_path TO ${schema}`);
      await client.query(`
        CREATE TABLE operations (id uuid PRIMARY KEY);
        CREATE TABLE wallet_lease_memberships (id uuid PRIMARY KEY);
        CREATE TABLE lease_groups (
          id uuid PRIMARY KEY,
          root_operation_id uuid NOT NULL
        );
        CREATE TABLE lease_group_operations (
          lease_group_id uuid NOT NULL,
          operation_id uuid NOT NULL
        );
        CREATE TABLE wallet_active_leases (
          membership_id uuid NOT NULL,
          lease_group_id uuid NOT NULL,
          root_operation_id uuid NOT NULL,
          operation_id uuid NOT NULL
        );
        INSERT INTO lease_groups (id, root_operation_id)
        VALUES ('11111111-1111-4111-8111-111111111111',
                '22222222-2222-4222-8222-222222222222');
      `);

      try {
        await client.query(upgradeSql);
        throw new Error("expected dangling-row upgrade refusal");
      } catch (error) {
        expect((error as { code?: string }).code).toBe(SQLSTATE_FOREIGN_KEY_VIOLATION);
      }

      const constraints = await client.query<{ count: string }>(`
        SELECT count(*)::text AS count
          FROM pg_constraint c
          JOIN pg_class rel ON rel.oid = c.conrelid
          JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = $1
           AND c.contype = 'f'
      `, [schema]);
      expect(constraints.rows[0]?.count).toBe("0");
    } finally {
      client.release();
      await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    }
  });
});
