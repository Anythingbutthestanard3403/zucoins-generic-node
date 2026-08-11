// Consumer-facing proof (ZTR-1146): all nine DURABLE_EVENTS values can be
// dual-chain appended and read back from implementer_events in order.
//
// Individual path PG tests cover each emitter's state-change co-commit; this
// file pins the full nine-value surface on one tenant stream via the production
// dual-chain appender and the implementer event log reader.

import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import { ensureNodeRow } from "../src/bootstrap/genesis.js";

import { DURABLE_EVENTS } from "@zucoins/generic-node-contracts/operations/events";
import {
  appendDurableDualChainEvent,
  createPgImplementerEventLog,
  deriveRootKey,
  ensureActiveNodeSigningKey,
  listEvents,
  migrateLeaseFoundation,
  toBase64UrlPadded,
  type NodeEventSigner,
} from "@zucoins/node-core";

const here = dirname(fileURLToPath(import.meta.url));
const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "durable-nine-master-key-32b!!!!!!!!!";

function hasClientTool(bin: string): boolean {
  try {
    execFileSync(bin, bin === "pg_isready" ? ["-q"] : ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const PG_AVAILABLE = (() => {
  try {
    if (hasClientTool("pg_isready")) {
      execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
      return true;
    }
  } catch {
    /* fall through */
  }
  return false;
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

function assertSafeDbName(dbName: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) {
    throw new Error(`unsafe test db name: ${dbName}`);
  }
}

async function adminExec(sql: string): Promise<void> {
  const client = new Client(adminConfig());
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  return `postgres://${auth}@${PG_HOST}:${PG_PORT}/${dbName}`;
}

const sqlOn = (client: { query: (t: string, p?: unknown[]) => Promise<{ rows: unknown[] }> }) => ({
  async query<R>(text: string, params?: readonly unknown[]) {
    const result = await client.query(text, params as unknown[]);
    return { rows: result.rows as R[], rowCount: result.rows.length };
  },
});

describe.skipIf(!PG_AVAILABLE)("all nine durable events reach implementer_events (ZTR-1146)", () => {
  const dbName = `durable_nine_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let nodeId: string;
  let implementerId: string;
  let signer: NodeEventSigner;

  beforeAll(async () => {
    assertSafeDbName(dbName);
    await adminExec(`CREATE DATABASE ${dbName}`);
    pool = new Pool(adminConfig(dbName));

    const previousUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
    try {
      const migrateMod = resolve(here, "../src/db/migrate.js");
      const { runMigrationsOnPool } = await import(migrateMod);
      await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
    } finally {
      if (previousUrl === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = previousUrl;
    }
    await migrateLeaseFoundation(sqlOn(pool));

    nodeId = randomUUID();
    implementerId = randomUUID();

    // Match ensureNodeRow shape used by receive-ready dual-chain PG drills.
    await ensureNodeRow(pool, {
      nodeId,
      displayName: "durable-nine",
      identityPublicKey: toBase64UrlPadded(Buffer.alloc(32, 7)),
    });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-impl', now())`,
      [implementerId],
    );

    const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const key = await ensureActiveNodeSigningKey({
        sql: sqlOn(client),
        rootKey,
        nodeId,
        purpose: "EVENT_SIGNING",
      });
      await client.query("COMMIT");
      signer = {
        signingKeyId: key.signingKeyId,
        sign: (bytes) => toBase64UrlPadded(Buffer.from(key.sign(bytes))),
      };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    await pool?.end().catch(() => {});
    await adminExec(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  it(
    "appends all nine event types on both chains; implementer log lists every type",
    async () => {
      const client = await pool.connect();
      const observed: string[] = [];
      try {
        await client.query("BEGIN");
        const query = async (text: string, values?: readonly unknown[]) => {
          const result = await client.query(text, values as never);
          return result.rows as Record<string, unknown>[];
        };

        for (const eventType of DURABLE_EVENTS) {
          const operationId = randomUUID();
          // node_events.operation_id FK → operations(id). Seed a minimal CREATED row.
          const reqSha = "a".repeat(64);
          await client.query(
            `INSERT INTO operations (
               id, node_id, implementer_id, kind, status, amount_zkz, after_landing,
               discriminator, anchor, idempotency_key, request_sha256, formation_state
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL'::operation_kind,
               'CREATED'::operation_status, '0.01', 'HOLD', $1::uuid, 'ztr-1146-nine', $4, $5,
               'NOT_REQUIRED'::external_formation_state
             )`,
            [operationId, nodeId, implementerId, `idem-${operationId}`, reqSha],
          );
          const dataText = JSON.stringify({
            event: eventType,
            operation_id: operationId,
            probe: "ztr-1146-nine",
          });
          const outcome = await appendDurableDualChainEvent(query, {
            nodeId,
            implementerId,
            operationId,
            walletId: null,
            eventType,
            dataText,
            createdAt: new Date().toISOString(),
            signer,
          });
          expect(outcome.kind).toBe("APPENDED");
          observed.push(eventType);
        }
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        throw err;
      } finally {
        client.release();
      }

      expect(observed).toEqual([...DURABLE_EVENTS]);

      const log = createPgImplementerEventLog({
        nodeId,
        query: async (text, values) => (await pool.query(text, values as unknown[])).rows,
        withTransaction: async (body) =>
          body(async (text, values) => (await pool.query(text, values as unknown[])).rows),
      });
      const page = await listEvents(log, {
        implementerId,
        afterImplementerSeq: null,
        limit: 20,
      });
      const types = page.events.map((e) => e.eventType);
      expect(types).toEqual([...DURABLE_EVENTS]);
      expect(new Set(types).size).toBe(9);
    },
    PG_TEST_TIMEOUT_MS,
  );
});
