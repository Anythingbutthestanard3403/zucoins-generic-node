import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool, type PoolClient } from "pg";

import {
  createSqlAutoApprovePolicy,
  createSqlDeviceSignaturePolicy,
  createSqlDualControlPolicy,
  AUTO_APPROVE_SETTING_KEY,
  DEVICE_SIGNATURE_POLICY_SETTING_KEY,
  DUAL_CONTROL_SETTING_KEY,
} from "@zucoins/node-core";

import { SqlAdminIdempotencyStore } from "../src/ops/admin-idempotency.js";
import { createAtomicAdminMutationExecutor } from "../src/ops/atomic-admin-mutation.js";

const PG_TEST_TIMEOUT_MS = 120_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";

function hasClientTool(name: string): boolean {
  try {
    execFileSync(name, ["--version"], { stdio: "ignore" });
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
      execFileSync(
        "pg_isready",
        ["-q", "-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER],
        { stdio: "ignore" },
      );
      return true;
    }
  } catch {
    // Fall through to the direct driver probe.
  }
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
})();

function adminConfig(database = "postgres") {
  return {
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database,
    password: process.env.PGPASSWORD,
  };
}

function assertSafeDbName(name: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) throw new Error(`unsafe database name: ${name}`);
}

async function createDatabase(name: string): Promise<void> {
  assertSafeDbName(name);
  if (HAS_CREATEDB) {
    execFileSync("createdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, name], {
      env: process.env,
    });
    return;
  }
  const admin = new Client(adminConfig());
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }
}

async function dropDatabase(name: string): Promise<void> {
  assertSafeDbName(name);
  if (HAS_DROPDB) {
    execFileSync(
      "dropdb",
      ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, "--if-exists", name],
      { env: process.env, stdio: "ignore" },
    );
    return;
  }
  const admin = new Client(adminConfig());
  await admin.connect();
  try {
    await admin.query(
      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
      [name],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${name}`);
  } finally {
    await admin.end();
  }
}

interface EffectPorts {
  insertEffect(value: string): Promise<void>;
}

function portsFor(client: PoolClient): EffectPorts {
  return {
    async insertEffect(value) {
      await client.query("INSERT INTO atomic_admin_mutation_child_effects (value) VALUES ($1)", [value]);
    },
  };
}

function fingerprint(bodySha256 = "a".repeat(64)) {
  return { method: "POST", rawTarget: "/admin/v1/halt", bodySha256 };
}

describe.skipIf(!PG_AVAILABLE)("atomic REQUIRED admin mutation (disposable PG)", () => {
  const dbName = `atomic_admin_mutation_${process.pid}_${Date.now()}`;
  const nodeId = randomUUID();
  let pool: Pool;

  beforeAll(async () => {
    await createDatabase(dbName);
    pool = new Pool(adminConfig(dbName));
    await pool.query("CREATE DOMAIN sha256_hex AS text CHECK (VALUE ~ '^[0-9a-f]{64}$')");
    await pool.query("CREATE TABLE nodes (id uuid PRIMARY KEY)");
    await pool.query("INSERT INTO nodes (id) VALUES ($1::uuid)", [nodeId]);
    await pool.query(
      "CREATE TABLE atomic_admin_mutation_child_effects (seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, value text NOT NULL)",
    );
    // ensureSchema is a deliberate no-op (DDL owned exclusively by migrate.ts, see
    // apps/generic-node/drizzle/0002_admin_and_operations_ownership.sql). This suite uses a
    // disposable per-run database with a hand-rolled minimal prerequisite schema (nodes,
    // sha256_hex domain, atomic_admin_mutation_child_effects above) rather than running the full migration
    // pack — that is this codebase's established convention for every non-migrator PG test
    // (only test/db/migrate-guards.test.ts, which tests the migrator itself, runs migrate()).
    // Column list below is byte-parity with 0002's admin_mutation_idempotency definition.
    await pool.query(`CREATE TABLE admin_mutation_idempotency (
      id uuid PRIMARY KEY,
      node_id uuid NOT NULL REFERENCES nodes(id),
      route_id text NOT NULL,
      idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[!-~]{16,255}$'),
      method text NOT NULL,
      raw_target text NOT NULL,
      body_sha256 sha256_hex NOT NULL,
      response_status integer NOT NULL CHECK (response_status BETWEEN 100 AND 599),
      response_bytes bytea NOT NULL,
      completed_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (node_id, route_id, idempotency_key)
    )`);
    // Minimal node_settings + audit_log for ZTR-1143 TX-bound policy rollback proof.
    await pool.query(`CREATE TABLE node_settings (
      setting_key text PRIMARY KEY,
      setting_value text NOT NULL,
      row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
      updated_at timestamptz NOT NULL DEFAULT now()
    )`);
    await pool.query(`CREATE TABLE audit_log (
      seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      id uuid NOT NULL UNIQUE,
      node_id uuid NOT NULL REFERENCES nodes(id),
      actor_kind text NOT NULL,
      actor_id text,
      action text NOT NULL,
      operation_id uuid,
      wallet_id uuid,
      details_text text NOT NULL,
      details_sha256 sha256_hex NOT NULL,
      created_at timestamptz NOT NULL,
      UNIQUE (id, node_id)
    )`);
    await new SqlAdminIdempotencyStore(pool).ensureSchema();
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    await pool?.end().catch(() => {});
    await dropDatabase(dbName).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  it("commits the child effect and exact response together, then a fresh executor replays after restart", async () => {
    const store = new SqlAdminIdempotencyStore(pool);
    const execute = createAtomicAdminMutationExecutor({ pool, idempotencyStore: store, portsFor });
    const mutation = {
      nodeId,
      routeId: "admin_halt",
      idempotencyKey: `atomic-admin-mutation-restart-${randomUUID()}`,
      fingerprint: fingerprint(),
    };
    const first = await execute(mutation, async (ports) => {
      await ports.insertEffect("restart-once");
      return { outcome: "commit" as const, status: 201, responseBody: { z: 1, a: "exact" } };
    });
    expect(first.outcome).toBe("committed");
    if (first.outcome !== "committed") return;
    expect(first.responseBytes.toString("utf8")).toBe('{"z":1,"a":"exact"}');

    const restarted = createAtomicAdminMutationExecutor({
      pool,
      idempotencyStore: new SqlAdminIdempotencyStore(pool),
      portsFor,
    });
    const replay = await restarted(mutation, async () => {
      throw new Error("replay must not execute child effect");
    });
    expect(replay).toMatchObject({ outcome: "replay", status: 201 });
    if (replay.outcome === "replay") expect(replay.responseBytes).toEqual(first.responseBytes);
    const effects = await pool.query("SELECT value FROM atomic_admin_mutation_child_effects WHERE value = 'restart-once'");
    expect(effects.rows).toHaveLength(1);
  });

  it("serializes two instances on the same key: one effect, one exact replay", async () => {
    const mutation = {
      nodeId,
      routeId: "admin_destination_bless",
      idempotencyKey: `atomic-admin-mutation-concurrent-${randomUUID()}`,
      fingerprint: fingerprint("b".repeat(64)),
    };
    let actionCalls = 0;
    const action = async (ports: EffectPorts) => {
      actionCalls += 1;
      await ports.insertEffect("concurrent-once");
      return { outcome: "commit" as const, status: 200, responseBody: { blessed: true } };
    };
    const one = createAtomicAdminMutationExecutor({
      pool,
      idempotencyStore: new SqlAdminIdempotencyStore(pool),
      portsFor,
    });
    const two = createAtomicAdminMutationExecutor({
      pool,
      idempotencyStore: new SqlAdminIdempotencyStore(pool),
      portsFor,
    });
    const results = await Promise.all([one(mutation, action), two(mutation, action)]);
    expect(results.map((result) => result.outcome).sort()).toEqual(["committed", "replay"]);
    expect(actionCalls).toBe(1);
    const bytes = results.map((result) =>
      result.outcome === "committed" || result.outcome === "replay" ? result.responseBytes.toString("utf8") : "",
    );
    expect(new Set(bytes)).toEqual(new Set(['{"blessed":true}']));
    const effects = await pool.query("SELECT value FROM atomic_admin_mutation_child_effects WHERE value = 'concurrent-once'");
    expect(effects.rows).toHaveLength(1);
  });

  it("returns conflict for the same key with a changed fingerprint without executing the child", async () => {
    const idempotencyKey = `atomic-admin-mutation-conflict-${randomUUID()}`;
    const execute = createAtomicAdminMutationExecutor({
      pool,
      idempotencyStore: new SqlAdminIdempotencyStore(pool),
      portsFor,
    });
    const base = { nodeId, routeId: "admin_api_keys_revoke", idempotencyKey };
    await execute({ ...base, fingerprint: fingerprint("c".repeat(64)) }, async (ports) => {
      await ports.insertEffect("conflict-winner");
      return { outcome: "commit" as const, status: 200, responseBody: { revoked: true } };
    });
    const conflict = await execute(
      { ...base, fingerprint: fingerprint("d".repeat(64)) },
      async () => { throw new Error("conflict must not execute child"); },
    );
    expect(conflict).toEqual({ outcome: "conflict" });
  });

  it("rolls back the child effect when completed-response persistence fails", async () => {
    const store = new SqlAdminIdempotencyStore(pool);
    const execute = createAtomicAdminMutationExecutor({ pool, idempotencyStore: store, portsFor });
    await pool.query("ALTER TABLE admin_mutation_idempotency RENAME TO admin_mutation_idempotency_offline");
    try {
      await expect(
        execute(
          {
            nodeId,
            routeId: "admin_halt",
            idempotencyKey: `atomic-admin-mutation-db-failure-${randomUUID()}`,
            fingerprint: fingerprint("e".repeat(64)),
          },
          async (ports) => {
            await ports.insertEffect("must-roll-back");
            return { outcome: "commit" as const, status: 200, responseBody: { engaged: true } };
          },
        ),
      ).rejects.toMatchObject({ code: "42P01" });
    } finally {
      await pool.query("ALTER TABLE admin_mutation_idempotency_offline RENAME TO admin_mutation_idempotency");
    }
    const effects = await pool.query("SELECT value FROM atomic_admin_mutation_child_effects WHERE value = 'must-roll-back'");
    expect(effects.rows).toHaveLength(0);
  });

  it("rolls back device-signature policy setMode when post-write mutation aborts (ZTR-1143 D1)", async () => {
    // Seed required so a leaked optional write is observable.
    await pool.query(
      `INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
       VALUES ($1, 'required', 1, now())
       ON CONFLICT (setting_key) DO UPDATE
       SET setting_value = 'required', row_version = node_settings.row_version + 1, updated_at = now()`,
      [DEVICE_SIGNATURE_POLICY_SETTING_KEY],
    );
    const execute = createAtomicAdminMutationExecutor({
      pool,
      idempotencyStore: new SqlAdminIdempotencyStore(pool),
      portsFor: (client: PoolClient) => ({
        deviceSignaturePolicy: createSqlDeviceSignaturePolicy(client),
      }),
    });
    await pool.query("ALTER TABLE admin_mutation_idempotency RENAME TO admin_mutation_idempotency_offline");
    try {
      await expect(
        execute(
          {
            nodeId,
            routeId: "admin_device_signature_policy",
            idempotencyKey: `device-policy-rollback-${randomUUID()}`,
            fingerprint: fingerprint("f".repeat(64)),
          },
          async (ports) => {
            await ports.deviceSignaturePolicy.setMode!("optional", {
              actorId: "op-rollback",
              nodeId,
            });
            return { outcome: "commit" as const, status: 200, responseBody: { mode: "optional" } };
          },
        ),
      ).rejects.toMatchObject({ code: "42P01" });
    } finally {
      await pool.query("ALTER TABLE admin_mutation_idempotency_offline RENAME TO admin_mutation_idempotency");
    }
    const setting = await pool.query<{ setting_value: string }>(
      "SELECT setting_value FROM node_settings WHERE setting_key = $1",
      [DEVICE_SIGNATURE_POLICY_SETTING_KEY],
    );
    expect(setting.rows[0]?.setting_value).toBe("required");
    const audits = await pool.query(
      "SELECT 1 FROM audit_log WHERE action = 'approval.device_signature_policy_changed'",
    );
    expect(audits.rows).toHaveLength(0);
  });

  it("rolls back dual-control policy setMode when post-write mutation aborts (ZTR-1214)", async () => {
    await pool.query(
      `INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
       VALUES ($1, 'single_operator', 1, now())
       ON CONFLICT (setting_key) DO UPDATE
       SET setting_value = 'single_operator', row_version = node_settings.row_version + 1, updated_at = now()`,
      [DUAL_CONTROL_SETTING_KEY],
    );
    const execute = createAtomicAdminMutationExecutor({
      pool,
      idempotencyStore: new SqlAdminIdempotencyStore(pool),
      portsFor: (client: PoolClient) => ({
        dualControlPolicy: createSqlDualControlPolicy(client, {
          defaultMode: "single_operator",
        }),
      }),
    });
    await pool.query("ALTER TABLE admin_mutation_idempotency RENAME TO admin_mutation_idempotency_offline");
    try {
      await expect(
        execute(
          {
            nodeId,
            routeId: "admin_dual_control_policy",
            idempotencyKey: `dual-control-policy-rollback-${randomUUID()}`,
            fingerprint: fingerprint("a".repeat(64)),
          },
          async (ports) => {
            await ports.dualControlPolicy.setMode!("two_human", {
              actorId: "op-rollback",
              nodeId,
            });
            return { outcome: "commit" as const, status: 200, responseBody: { mode: "two_human" } };
          },
        ),
      ).rejects.toMatchObject({ code: "42P01" });
    } finally {
      await pool.query("ALTER TABLE admin_mutation_idempotency_offline RENAME TO admin_mutation_idempotency");
    }
    const setting = await pool.query<{ setting_value: string }>(
      "SELECT setting_value FROM node_settings WHERE setting_key = $1",
      [DUAL_CONTROL_SETTING_KEY],
    );
    expect(setting.rows[0]?.setting_value).toBe("single_operator");
    const audits = await pool.query(
      "SELECT 1 FROM audit_log WHERE action = 'ops.dual_control_mode_changed'",
    );
    expect(audits.rows).toHaveLength(0);
  });

  it("rolls back auto-approve policy setPolicy when post-write mutation aborts (ZTR-1237)", async () => {
    const seedDoc = JSON.stringify({
      enabled: true,
      rules: [
        {
          rule_id: "seed",
          implementer_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          per_send_max_zkz: "1",
          per_send_min_zkz: null,
          window_hours: 24,
          window_cap_zkz: "10",
          expires_at: null,
          enabled: true,
        },
      ],
    });
    await pool.query(
      `INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
       VALUES ($1, $2, 1, now())
       ON CONFLICT (setting_key) DO UPDATE
       SET setting_value = EXCLUDED.setting_value,
           row_version = node_settings.row_version + 1,
           updated_at = now()`,
      [AUTO_APPROVE_SETTING_KEY, seedDoc],
    );
    const execute = createAtomicAdminMutationExecutor({
      pool,
      idempotencyStore: new SqlAdminIdempotencyStore(pool),
      portsFor: (client: PoolClient) => ({
        autoApprovePolicy: createSqlAutoApprovePolicy(client),
      }),
    });
    await pool.query("ALTER TABLE admin_mutation_idempotency RENAME TO admin_mutation_idempotency_offline");
    try {
      await expect(
        execute(
          {
            nodeId,
            routeId: "admin_auto_approve_policy",
            idempotencyKey: `auto-approve-policy-rollback-${randomUUID()}`,
            fingerprint: fingerprint("b".repeat(64)),
          },
          async (ports) => {
            const next = JSON.stringify({
              enabled: true,
              rules: [
                {
                  rule_id: "rolled",
                  implementer_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                  per_send_max_zkz: "9",
                  per_send_min_zkz: null,
                  window_hours: 12,
                  window_cap_zkz: "90",
                  expires_at: null,
                  enabled: true,
                },
              ],
            });
            await ports.autoApprovePolicy!.setPolicy!(next, {
              actorId: "op-rollback",
              nodeId,
            });
            return { outcome: "commit" as const, status: 200, responseBody: { status: "enabled" } };
          },
        ),
      ).rejects.toMatchObject({ code: "42P01" });
    } finally {
      await pool.query("ALTER TABLE admin_mutation_idempotency_offline RENAME TO admin_mutation_idempotency");
    }
    const setting = await pool.query<{ setting_value: string }>(
      "SELECT setting_value FROM node_settings WHERE setting_key = $1",
      [AUTO_APPROVE_SETTING_KEY],
    );
    expect(setting.rows[0]?.setting_value).toBe(seedDoc);
    const audits = await pool.query(
      "SELECT 1 FROM audit_log WHERE action = 'ops.auto_approve_sends_changed'",
    );
    expect(audits.rows).toHaveLength(0);
  });
});
