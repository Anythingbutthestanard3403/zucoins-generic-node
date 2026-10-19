// POST /admin/v1/reserve-wallets against real PostgreSQL.
// The route mints one named INTERNAL_ONLY reserve. It does not write the
// node-wide default funding setting.

import { createHmac, randomUUID } from "node:crypto";
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
  type EncryptedWalletKeyStore,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createReservePoolController } from "../src/bootstrap/reserve-pool.js";
import {
  applyReservePoolSchema,
  psqlMust,
  seedReserveNode,
  withDatabase,
} from "../../../packages/node-core/test/receive/reserve-pool-schema.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;
const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");

let dbName = "";
let pool: Pool | undefined;

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

describe("admin reserve wallet mint (real PG)", () => {
  beforeAll(() => {
    if (!live) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      return;
    }
    dbName = `ztr1325_admin_${Date.now().toString(36)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    const url = withDatabase(TEST_DATABASE_URL, dbName);
    applyReservePoolSchema(url);
    seedReserveNode(url, NODE_ID);
    pool = new Pool({ connectionString: url });
  }, 120_000);

  afterAll(async () => {
    await pool?.end();
    if (!live || dbName === "") return;
    try {
      psqlMust(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    } catch {
      // Best-effort cleanup under shared PostgreSQL contention.
    }
  });

  it("mints a named reserve and leaves the default funding setting unset", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const vault = {
      seal: async (_identity: unknown, secret: Uint8Array) => {
        expect(secret.length).toBe(64);
      },
    } as unknown as EncryptedWalletKeyStore;
    const controller = createReservePoolController({
      pool: db,
      nodeId: NODE_ID,
      poolCapTotal: 50,
      vault,
    });
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
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
      nowMs: () => 1_700_000_030_000,
      halt: {
        gate: createHaltGate(RUNNING),
        store: createInMemoryOperatorHaltStore(RUNNING),
        evidence: createInMemoryHaltEvidenceRecorder(),
      },
      mintNamedReserveWallet: (input) => controller.mintNamed(input.displayLabel),
    });
    const user: AdminUser = {
      id: randomUUID(),
      username: "admin",
      passwordHash: await hashPassword("reserve-pg-pass"),
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
      Buffer.from(JSON.stringify({ username: "admin", password: "reserve-pg-pass" })),
      { "content-type": "application/json" },
    );
    expect(login.status).toBe(200);
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;
    const minted = await router(
      "POST",
      "/admin/v1/reserve-wallets",
      Buffer.from(JSON.stringify({ label: "Client Holding A" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "content-type": "application/json",
        "idempotency-key": "idem-reserve-wallets-client-a-001",
        "x-zp-totp": generateTotp(SECRET, 1_700_000_030_000),
      },
    );
    expect(minted.status).toBe(201);
    const body = JSON.parse(minted.body) as {
      wallet_id: string;
      money_mode: string;
      display_label: string;
      destination_state: string;
    };
    expect(body).toEqual({
      wallet_id: body.wallet_id,
      money_mode: "INTERNAL_ONLY",
      display_label: "Client Holding A",
      destination_state: "BLESSED",
    });
    const rows = await db.query<{
      money_mode: string;
      display_label: string;
      stamped: boolean;
      dest_state: string;
    }>(
      `SELECT w.money_mode::text AS money_mode,
              w.display_label,
              (w.recovery_verified_at IS NOT NULL) AS stamped,
              d.state::text AS dest_state
         FROM wallets w
         JOIN destinations d ON d.wallet_id = w.id
        WHERE w.id = $1::uuid`,
      [body.wallet_id],
    );
    expect(rows.rows).toEqual([
      {
        money_mode: "INTERNAL_ONLY",
        display_label: "Client Holding A",
        stamped: true,
        dest_state: "BLESSED",
      },
    ]);
    const setting = await db.query(
      `SELECT setting_value FROM node_settings WHERE setting_key = $1`,
      ["integration.default_funding_wallet_id"],
    );
    expect(setting.rows).toEqual([]);
  }, 120_000);

  it("refuses a second active label that differs only by case or surrounding space", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const vault = {
      seal: async (_identity: unknown, secret: Uint8Array) => {
        expect(secret.length).toBe(64);
      },
    } as unknown as EncryptedWalletKeyStore;
    const controller = createReservePoolController({
      pool: db,
      nodeId: NODE_ID,
      poolCapTotal: 50,
      vault,
    });
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    let now = 1_700_000_180_000;
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
      nowMs: () => now,
      halt: {
        gate: createHaltGate(RUNNING),
        store: createInMemoryOperatorHaltStore(RUNNING),
        evidence: createInMemoryHaltEvidenceRecorder(),
      },
      mintNamedReserveWallet: (input) => controller.mintNamed(input.displayLabel),
    });
    const user: AdminUser = {
      id: randomUUID(),
      username: "admin-label",
      passwordHash: await hashPassword("reserve-pg-pass"),
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
      Buffer.from(JSON.stringify({ username: "admin-label", password: "reserve-pg-pass" })),
      { "content-type": "application/json" },
    );
    expect(login.status).toBe(200);
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;
    const post = async (label: string, idem: string) => {
      const res = await router(
        "POST",
        "/admin/v1/reserve-wallets",
        Buffer.from(JSON.stringify({ label })),
        {
          cookie,
          origin: ORIGIN,
          "x-csrf-token": csrf,
          "content-type": "application/json",
          "idempotency-key": idem,
          "x-zp-totp": generateTotp(SECRET, now),
        },
      );
      now += 60_000;
      return res;
    };
    const first = await post("Client Holding B", "idem-reserve-label-holding-b-001");
    expect(first.status).toBe(201);
    const folded = await post("  client holding b  ", "idem-reserve-label-holding-b-002");
    expect(folded.status).toBe(409);
    expect(JSON.parse(folded.body)).toMatchObject({
      error: { code: "conflict", message: "reserve wallet label already exists" },
    });
    const main = await post("Main Reserve", "idem-reserve-label-main-0000001");
    expect(main.status).toBe(201);
    const mainFolded = await post(" main reserve ", "idem-reserve-label-main-0000002");
    expect(mainFolded.status).toBe(409);
    expect(JSON.parse(mainFolded.body)).toMatchObject({
      error: { code: "conflict", message: "reserve wallet label already exists" },
    });
    const count = await db.query<{ n: string }>(
      `SELECT count(*)::text AS n
         FROM wallets
        WHERE node_id = $1::uuid
          AND retired_at IS NULL
          AND lower(btrim(display_label)) = lower(btrim($2))`,
      [NODE_ID, "Client Holding B"],
    );
    expect(count.rows[0]?.n).toBe("1");
  }, 120_000);
});
