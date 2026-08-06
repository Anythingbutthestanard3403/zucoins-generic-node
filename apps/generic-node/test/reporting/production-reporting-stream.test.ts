// Composition census + durable subscription_handle restart semantics.
//
// Reporting client lists events and streams op updates; handles restart.

import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  authorizeOperationSubscribe,
  createSqlSubscriptionHandleStore,
  hashSubscriptionHandle,
  mintSubscriptionHandlePlaintext,
  type SubscriptionHandleStore,
} from "@zucoins/node-core";

import {
  createProductionRouteSurface,
  DURABLE_SUBSCRIPTION_HANDLES,
  LIVE_EVENTS_LIST_ENGINE,
  LIVE_EVENTS_STREAM_ENGINE,
  LIVE_STATE_SNAPSHOT_ENGINE,
  LIVE_VERIFICATION_MATERIAL_ENGINE,
} from "../../src/full-http-mount.js";

const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const stubPool = () =>
  ({
    query: async () => ({ rows: [] }),
    connect: async () => ({
      query: async () => ({ rows: [] }),
      release: () => {},
    }),
  }) as never;

const NODE_FOR_STUB = "11111111-1111-4111-8111-111111111111";

describe("reporting list/stream/snapshot composition census (no PG)", () => {
  it("AC: production source never maps eventsList/stream/snapshot/vm to failClosed", () => {
    const mountSrc = readFileSync(
      fileURLToPath(new URL("../../src/full-http-mount.ts", import.meta.url)),
      "utf8",
    );
    const liveSrc = readFileSync(
      fileURLToPath(new URL("../../src/reporting/live-reporting-reads.ts", import.meta.url)),
      "utf8",
    );
    expect(mountSrc).toMatch(/createLiveReportingReads/);
    expect(liveSrc).toMatch(/\[REPORTING_ROUTE_IDS\.eventsList\]:\s*brandLiveHandler\(createEventsListRouteHandler/);
    expect(liveSrc).toMatch(/\[REPORTING_ROUTE_IDS\.eventsStream\]:\s*brandLiveHandler\(createEventsStreamRouteHandler/);
    expect(liveSrc).toMatch(/\[REPORTING_ROUTE_IDS\.stateSnapshot\]:\s*brandLiveHandler\(createStateSnapshotRouteHandler/);
    expect(liveSrc).toMatch(
      /\[REPORTING_ROUTE_IDS\.verificationMaterial\]:\s*brandLiveHandler\(createVerificationMaterialRouteHandler/,
    );
    expect(liveSrc).toContain("[REPORTING_ROUTE_IDS.operationArmed]: brandLiveHandler(config.liveArm)");
    expect(liveSrc).not.toMatch(/\[REPORTING_ROUTE_IDS\.eventsList\]:\s*config\.failClosed/);
    expect(liveSrc).toMatch(/createSqlSubscriptionHandleStore/);

    const adapterSrc = readFileSync(
      fileURLToPath(new URL("../../src/http-adapter.ts", import.meta.url)),
      "utf8",
    );
    // Events stream liveStream hold + openSink side-channel (not write-then-end only).
    expect(adapterSrc).toMatch(/liveStream/);
    expect(adapterSrc).toMatch(/openSink/);

    const runtimeSrc = readFileSync(
      fileURLToPath(new URL("../../src/runtime-listener.ts", import.meta.url)),
      "utf8",
    );
    expect(runtimeSrc).toMatch(/liveConnection/);
    expect(runtimeSrc).toMatch(/request\.once\("close"/);
  });

  it("surface reports the reporting engines live + durable subscription_handles", () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_FOR_STUB,
      pool: stubPool(),
      env: {},
    });
    const routeIds = surface.liveReportingEngines.map((e) => e.routeId);
    expect(routeIds).toContain(LIVE_EVENTS_LIST_ENGINE.routeId);
    expect(routeIds).toContain(LIVE_EVENTS_STREAM_ENGINE.routeId);
    expect(routeIds).toContain(LIVE_STATE_SNAPSHOT_ENGINE.routeId);
    expect(routeIds).toContain(LIVE_VERIFICATION_MATERIAL_ENGINE.routeId);
    expect(routeIds).toContain("operation_armed");
    expect(surface.subscriptionHandlesKind).toEqual(DURABLE_SUBSCRIPTION_HANDLES);
    expect(surface.subscribeDeps.handleStore.lookupByHandleHash).toBeTypeOf("function");
  });

  it("AC: no reporting headers on GET /v1/events → 401 (credential gate still holds)", async () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_FOR_STUB,
      pool: stubPool(),
      env: {},
    });
    const response = await surface.reportingHandle({
      method: "GET",
      rawTarget: "/v1/events",
      rawHeaders: [],
      bodyBytes: new Uint8Array(),
      receivedAtMs: Date.now(),
    });
    expect(response.status).toBe(401);
    const body = JSON.parse(new TextDecoder().decode(response.bodyBytes)) as {
      error: { code: string };
    };
    expect(body.error.code).toBe("missing_reporting_headers");
  });
});

// ---------------------------------------------------------------------------
// Real PG: durable handle survives store restart
// ---------------------------------------------------------------------------

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

const PG_AVAILABLE = (() => {
  try {
    if (hasClientTool("pg_isready")) {
      execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
      return true;
    }
  } catch {
    /* fall through */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require('pg');const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:'postgres',password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env },
    );
    return true;
  } catch {
    return false;
  }
})();

const describePg = PG_AVAILABLE ? describe : describe.skip;

describePg("durable subscription_handles restart (real PG)", () => {
  const dbName = `production_reporting_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  let pool: Pool;

  beforeAll(async () => {
    const admin = new Client(adminClientConfig("postgres"));
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE ${dbName}`);
    } finally {
      await admin.end();
    }
    pool = new Pool({
      host: PG_HOST,
      port: PG_PORT,
      user: PG_USER,
      database: dbName,
      password: process.env.PGPASSWORD,
    });
    // Minimal shape for handle lookup (join operations).
    await pool.query(`
      CREATE DOMAIN sha256_hex AS text CHECK (VALUE ~ '^[0-9a-f]{64}$');
      CREATE TABLE nodes (id uuid PRIMARY KEY);
      CREATE TABLE implementers (id uuid PRIMARY KEY);
      CREATE TABLE operations (
        id uuid PRIMARY KEY,
        node_id uuid NOT NULL,
        implementer_id uuid NOT NULL,
        kind text NOT NULL DEFAULT 'RECEIVE_EXTERNAL',
        status text NOT NULL DEFAULT 'READY',
        row_version bigint NOT NULL DEFAULT 1,
        attention_required boolean NOT NULL DEFAULT false,
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE TABLE subscription_handles (
        id uuid PRIMARY KEY,
        node_id uuid NOT NULL,
        operation_id uuid NOT NULL,
        handle_hash sha256_hex NOT NULL,
        expires_at timestamptz NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        consumed_at timestamptz,
        UNIQUE (handle_hash),
        UNIQUE (operation_id)
      );
    `);
  }, 60_000);

  afterAll(async () => {
    await pool?.end();
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
  }, 60_000);

  it("handle lookup survives a fresh store instance (restart semantics)", async () => {
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const operationId = randomUUID();
    const handleId = randomUUID();
    const plain = mintSubscriptionHandlePlaintext();
    const handleHash = hashSubscriptionHandle(plain);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query(`INSERT INTO nodes (id) VALUES ($1)`, [nodeId]);
    await pool.query(`INSERT INTO implementers (id) VALUES ($1)`, [implementerId]);
    await pool.query(
      `INSERT INTO operations (id, node_id, implementer_id, kind, status)
       VALUES ($1, $2, $3, 'RECEIVE_EXTERNAL', 'READY')`,
      [operationId, nodeId, implementerId],
    );
    await pool.query(
      `INSERT INTO subscription_handles
         (id, node_id, operation_id, handle_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5::timestamptz)`,
      [handleId, nodeId, operationId, handleHash, expiresAt.toISOString()],
    );

    const sqlA = {
      query: async <R extends Record<string, unknown>>(
        text: string,
        params?: readonly unknown[],
      ) => {
        const r = await pool.query(text, (params ?? []) as unknown[]);
        return { rows: r.rows as R[] };
      },
    };
    const storeA: SubscriptionHandleStore = createSqlSubscriptionHandleStore(sqlA);
    const foundA = await storeA.lookupByHandleHash(handleHash);
    expect(foundA).not.toBeNull();
    expect(foundA?.operationId).toBe(operationId);
    expect(foundA?.implementerId).toBe(implementerId);
    expect(foundA?.handleHash).toBe(handleHash);

    // Drop A, open B on the same DB — restart survival.
    const storeB = createSqlSubscriptionHandleStore(sqlA);
    const foundB = await storeB.lookupByHandleHash(handleHash);
    expect(foundB).toEqual(foundA);

    const auth = await authorizeOperationSubscribe({
      requestId: randomUUID(),
      pathOperationId: operationId,
      headers: { authorization: `Bearer ${plain}` },
      handleStore: storeB,
      lifecycleStore: {
        getLifecycle: async (id) =>
          id === operationId
            ? {
                operationId,
                operationType: "RECEIVE_EXTERNAL",
                state: "READY",
                rowVersion: 1,
                attentionRequired: false,
                updatedAt: "2026-07-30T00:00:00.000Z",
              }
            : null,
        subscribe: () => () => {},
      },
      nowMs: () => Date.now(),
    });
    expect(auth.kind).toBe("AUTHORIZED");
    // Never leak plaintext handle / private key material in auth surface.
    expect(JSON.stringify(auth)).not.toContain(plain.slice(3));
    expect(JSON.stringify(auth)).not.toContain("private_key");
    void sha256Hex;
  });

  it("expired handle denies after restart", async () => {
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const operationId = randomUUID();
    const plain = mintSubscriptionHandlePlaintext();
    const handleHash = hashSubscriptionHandle(plain);
    await pool.query(`INSERT INTO nodes (id) VALUES ($1) ON CONFLICT DO NOTHING`, [nodeId]);
    await pool.query(`INSERT INTO implementers (id) VALUES ($1) ON CONFLICT DO NOTHING`, [
      implementerId,
    ]);
    await pool.query(
      `INSERT INTO operations (id, node_id, implementer_id) VALUES ($1, $2, $3)`,
      [operationId, nodeId, implementerId],
    );
    await pool.query(
      `INSERT INTO subscription_handles
         (id, node_id, operation_id, handle_hash, expires_at, created_at)
       VALUES ($1, $2, $3, $4, now() - interval '1 minute', now() - interval '1 hour')`,
      [randomUUID(), nodeId, operationId, handleHash],
    );
    const store = createSqlSubscriptionHandleStore({
      query: async <R extends Record<string, unknown>>(text: string, params?: readonly unknown[]) => {
        const r = await pool.query(text, (params ?? []) as unknown[]);
        return { rows: r.rows as R[] };
      },
    });
    const record = await store.lookupByHandleHash(handleHash);
    expect(record).not.toBeNull();
    const auth = await authorizeOperationSubscribe({
      requestId: randomUUID(),
      pathOperationId: operationId,
      headers: { authorization: `Bearer ${plain}` },
      handleStore: store,
      lifecycleStore: {
        getLifecycle: async () => ({
          operationId,
          operationType: "RECEIVE_EXTERNAL",
          state: "READY",
          rowVersion: 1,
          attentionRequired: false,
          updatedAt: "2026-07-30T00:00:00.000Z",
        }),
        subscribe: () => () => {},
      },
      nowMs: () => Date.now(),
    });
    expect(auth.kind).toBe("DENIED");
  });
});
