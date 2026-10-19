// PUT /admin/v1/implementers/:id/reserve-wallets and .../custom-routing
// against PostgreSQL. Session + CSRF + TOTP. The registry statement is the
// same one the operator route calls.

import { createHmac, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";
import { SqlImplementerRegistry } from "../../../packages/node-core/src/implementer/sql-store.ts";
import { CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE } from "../../../packages/node-core/src/schema/connector-reserve-wallets.contract.ts";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const SCHEMA = "ztr1324_admin_bind";
const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPL = "33333333-3333-4333-8333-333333333341";
const RESERVE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa41";
const WORKER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa42";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");

const here = dirname(fileURLToPath(import.meta.url));
const sliceSql = readFileSync(
  resolve(here, "../../../packages/node-core/src/schema", CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE),
  "utf8",
);

const STUBS = `
CREATE TABLE nodes (id uuid PRIMARY KEY);
CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes (id),
  public_key text NOT NULL,
  state text NOT NULL DEFAULT 'ACTIVE',
  retired_at timestamptz NULL,
  allow_internal_move boolean NOT NULL DEFAULT true,
  money_mode text NOT NULL DEFAULT 'INTERNAL_ONLY'
);
CREATE TABLE destinations (
  id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL REFERENCES wallets (id) ON DELETE CASCADE,
  state text NOT NULL
);
CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz NULL,
  funding_wallet_id uuid NULL REFERENCES wallets (id)
);
CREATE TABLE audit_log (
  id uuid PRIMARY KEY,
  node_id uuid,
  actor_kind text,
  actor_id text,
  action text,
  operation_id uuid,
  wallet_id uuid,
  details_text text,
  details_sha256 text,
  created_at timestamptz
);
`;

let pool: Pool | undefined;

function psql(sql: string): void {
  execFileSync("psql", [TEST_DATABASE_URL, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], {
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function generateTotp(secret: Uint8Array, nowMs: number): string {
  const timestep = Math.floor(nowMs / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestep));
  const h = createHmac("sha1", secret).update(buf).digest();
  const offset = h[h.length - 1]! & 0x0f;
  const code =
    ((h[offset]! & 0x7f) << 24) |
    (h[offset + 1]! << 16) |
    (h[offset + 2]! << 8) |
    h[offset + 3]!;
  return (code % 1_000_000).toString().padStart(6, "0");
}

function encodeBase32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

describe("admin reserve binding routes (real PG)", () => {
  beforeAll(() => {
    if (!live) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      return;
    }
    psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
    psql(`SET search_path TO ${SCHEMA}; ${STUBS}`);
    psql(`SET search_path TO ${SCHEMA}; ${sliceSql}`);
    psql(`SET search_path TO ${SCHEMA};
      INSERT INTO nodes (id) VALUES ('${NODE_ID}');
      INSERT INTO wallets (id, node_id, public_key, money_mode, display_label)
      VALUES ('${RESERVE}', '${NODE_ID}', 'pub-reserve', 'INTERNAL_ONLY', 'Main Reserve'),
             ('${WORKER}', '${NODE_ID}', 'pub-worker', 'SEND_ONLY', 'Worker');
      INSERT INTO destinations (id, wallet_id, state) VALUES
        ('d${RESERVE.slice(1)}', '${RESERVE}', 'BLESSED'),
        ('d${WORKER.slice(1)}', '${WORKER}', 'WORKER');
      INSERT INTO implementers (id, name) VALUES ('${IMPL}', 'connector');`);
    pool = new Pool({ connectionString: TEST_DATABASE_URL });
  }, 120_000);

  afterAll(async () => {
    await pool?.end();
    if (!live) return;
    try {
      psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    } catch {
      // Shared PostgreSQL may already be dropping the schema.
    }
  });

  it("binds a blessed reserve, refuses a worker wallet, and sets custom routing", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const registry = new SqlImplementerRegistry({
      async query(text, params) {
        const client = await db.connect();
        try {
          await client.query(`SET search_path TO ${SCHEMA}`);
          const result = await client.query(text, params as unknown[] | undefined);
          return { rows: result.rows as Record<string, unknown>[] };
        } finally {
          client.release();
        }
      },
    });
    let nowMs = 1_700_000_060_000;
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    const atomic = createTestAdminAtomicDeps({ implementerRegistry: registry });
    const router = createAdminRouter({
      sessions,
      userStore,
      csrf: { allowedOrigins: [ORIGIN] },
      totp: { secret: SECRET, windowSteps: 1 },
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE_ID,
      challengeStore: {
        findIssuedByOperation: async () => null,
        findByNonce: async () => null,
        insertIssued: async () => {},
        commitApprovalMutation: async () => {
          throw new Error("unused");
        },
      },
      loadOperation: async () => null,
      sendDecisionStore: {
        rejectCreated: async () => {
          throw new Error("unused");
        },
        approveCreated: async () => {
          throw new Error("unused");
        },
      },
      deviceStore: null,
      recoveryStore: {
        listNeedsAttention: async () => ({ items: [], total: 0, has_more: false, next_cursor: null }),
        loadRecoveryFacts: async () => null,
        issueRecoveryNonce: async () => {
          throw new Error("unused");
        },
      },
      recoveryActionStore: {
        lookupIdempotency: async () => ({ kind: "miss" }),
        loadRecoveryFactsLocked: async () => null,
        commitRecoveryAction: async () => {
          throw new Error("unused");
        },
        storeIdempotency: async () => {},
      },
      destinationService: createFailClosedDestinationService(),
      newRequestId: () => randomUUID(),
      nowMs: () => nowMs,
      halt: {
        gate: createHaltGate(RUNNING),
        store: createInMemoryOperatorHaltStore(RUNNING),
        evidence: createInMemoryHaltEvidenceRecorder(),
      },
      implementerRegistry: registry,
      adminIdempotencyStore: atomic.adminIdempotencyStore,
      atomicAdminMutation: atomic.atomicAdminMutation,
    });
    const user: AdminUser = {
      id: randomUUID(),
      username: "admin",
      passwordHash: await hashPassword("p"),
      role: "admin",
      mustChangePassword: false,
      mustEnrolTotp: false,
      disabledAt: null,
      createdAt: Date.now(),
    };
    await userStore.insert(user);
    await userStore.setActiveTotpSecret(user.id, encodeBase32(SECRET));
    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password: "p" })),
      { "content-type": "application/json" },
    );
    expect(login.status).toBe(200);
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;
    const headers = {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
      "content-type": "application/json",
    };

    const refused = await router(
      "PUT",
      `/admin/v1/implementers/${IMPL}/reserve-wallets`,
      Buffer.from(JSON.stringify({ wallet_ids: [WORKER], default_wallet_id: WORKER })),
      {
        ...headers,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "idempotency-key": "idem-pg-reserve-worker-0001",
      },
    );
    expect(refused.status).toBe(400);
    expect(JSON.parse(refused.body)).toMatchObject({
      error: { code: "validation_error", message: "wallet_ineligible" },
    });

    nowMs += 60_000;
    const bound = await router(
      "PUT",
      `/admin/v1/implementers/${IMPL}/reserve-wallets`,
      Buffer.from(JSON.stringify({ wallet_ids: [RESERVE], default_wallet_id: RESERVE })),
      {
        ...headers,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "idempotency-key": "idem-pg-reserve-bind-000001",
      },
    );
    expect(bound.status).toBe(200);
    expect(JSON.parse(bound.body)).toMatchObject({
      id: IMPL,
      funding_wallet_id: RESERVE,
    });

    nowMs += 60_000;
    const routing = await router(
      "PUT",
      `/admin/v1/implementers/${IMPL}/custom-routing`,
      Buffer.from(JSON.stringify({ allow_custom_routing: true })),
      {
        ...headers,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "idempotency-key": "idem-pg-custom-routing-001",
      },
    );
    expect(routing.status).toBe(200);
    expect(JSON.parse(routing.body)).toEqual({ id: IMPL, allow_custom_routing: true });

    const client = await db.connect();
    try {
      await client.query(`SET search_path TO ${SCHEMA}`);
      const junction = await client.query(
        `SELECT wallet_id::text AS wallet_id, is_default
           FROM implementer_reserve_wallets WHERE implementer_id = $1`,
        [IMPL],
      );
      expect(junction.rows).toEqual([{ wallet_id: RESERVE, is_default: true }]);
      const flag = await client.query(
        `SELECT allow_custom_routing FROM implementers WHERE id = $1`,
        [IMPL],
      );
      expect(flag.rows[0]?.allow_custom_routing).toBe(true);
    } finally {
      client.release();
    }
  });
});
