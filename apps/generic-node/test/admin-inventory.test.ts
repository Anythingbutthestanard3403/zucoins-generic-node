// Admin inventory HTTP contract tests (session-gated GETs).
// Session+CSRF admin inventory surface; product boundary: three money ops only.
// Offline composition first — no Railway curl fiction.

import {
  ADMIN_SESSION_COOKIE,
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  WALLET_CUSTODY_VIEW_FIELDS,
  type AdminUser,
} from "@zucoins/node-core";
import { OPERATION_KINDS } from "@zucoins/generic-node-contracts/operations";
import {
  DESTINATION_STATES,
  WALLET_KEY_ORIGINS,
  WALLET_STATES,
} from "@zucoins/generic-node-contracts/custody";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  createAdminRouter,
  createFailClosedAdminRouteDeps,
} from "../src/admin-router.js";
import {
  ADMIN_INVENTORY_ROUTES,
  AUDIT_INVENTORY_FIELDS,
  createMemoryAdminInventoryStore,
  createSqlAdminInventoryStore,
  DESTINATION_INVENTORY_FIELDS,
  INVENTORY_OPERATION_KINDS,
  loadObservedBalance,
  OBSERVED_BALANCE_SQL_FRAGMENT,
  OPERATION_INVENTORY_DETAIL_FIELDS,
  OPERATION_INVENTORY_LIST_FIELDS,
  WALLET_INVENTORY_FIELDS,
  type InventorySqlExecutor,
} from "../src/admin-inventory/index.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const WALLET_ID = "22222222-2222-4222-8222-222222222222";
const OP_ID = "33333333-3333-4333-8333-333333333333";
const DEST_ID = "44444444-4444-4444-8444-444444444444";
const AUDIT_ID = "55555555-5555-4555-8555-555555555555";

async function seedAdmin(store: InMemoryAdminUserStore, password: string): Promise<AdminUser> {
  const user: AdminUser = {
    id: randomUUID(),
    username: "admin",
    passwordHash: await hashPassword(password),
    role: "admin",
    mustChangePassword: false,
    mustEnrolTotp: false,
    disabledAt: null,
    createdAt: Date.now(),
  };
  await store.insert(user);
  // Money-adjacent GETs (recovery / needs-attention) require an active factor.
  await store.setActiveTotpSecret(user.id, "JBSWY3DPEHPK3PXP");
  return user;
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

function inventorySeed() {
  return createMemoryAdminInventoryStore({
    wallets: [
      {
        custody: {
          walletId: WALLET_ID as never,
          nodeId: NODE_ID as never,
          publicKey: PUBKEY as never,
          keyOrigin: "node_generated",
          state: "AVAILABLE",
          createdAt: "2026-07-01T00:00:00.000Z",
          retiredAt: null,
          quarantineReason: null,
          recoveryVerifiedAt: "2026-07-02T00:00:00.000Z",
          recoveryVerificationId: null,
        },
        observed_balance_zkz: "1.25",
      },
      {
        custody: {
          walletId: "66666666-6666-4666-8666-666666666666" as never,
          nodeId: NODE_ID as never,
          publicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" as never,
          keyOrigin: "node_generated",
          state: "PINNED",
          createdAt: "2026-07-01T01:00:00.000Z",
          retiredAt: null,
          quarantineReason: null,
          recoveryVerifiedAt: null,
          recoveryVerificationId: null,
        },
        observed_balance_zkz: null,
      },
    ],
    operations: [
      {
        list: {
          operation_id: OP_ID,
          operation_type: "RECEIVE_EXTERNAL",
          status: "READY",
          amount_zkz: "0.01",
          row_version: 2,
          attention_required: false,
          attention_reason: null,
          created_at: "2026-07-03T00:00:00.000Z",
          updated_at: "2026-07-03T00:01:00.000Z",
          terminal_at: null,
        },
        detail: {
          source_wallet_id: null,
          receiver_wallet_id: WALLET_ID,
          destination_id: null,
          destination_address: null,
          after_landing: "HOLD",
          after_landing_destination_id: null,
          formation_state: "NOT_REQUIRED",
          verification_verdict: "PENDING",
          implementer_id: "77777777-7777-4777-8777-777777777777",
          client_reference: "ord_1",
        },
      },
      {
        list: {
          operation_id: "88888888-8888-4888-8888-888888888888",
          operation_type: "SEND_EXTERNAL",
          status: "CREATED",
          amount_zkz: "0.01",
          row_version: 1,
          attention_required: true,
          attention_reason: "AWAITING_OPERATOR",
          created_at: "2026-07-03T02:00:00.000Z",
          updated_at: "2026-07-03T02:00:00.000Z",
          terminal_at: null,
        },
      },
    ],
    destinations: [
      {
        destination_id: DEST_ID,
        node_id: NODE_ID,
        wallet_id: WALLET_ID,
        wallet_public_key: PUBKEY,
        state: "BLESSED",
        label: "primary",
        blessed_at: "2026-07-02T12:00:00.000Z",
        blessed_by_device_key_id: null,
        blessing_artifact_id: null,
        retired_at: null,
        created_at: "2026-07-01T00:00:00.000Z",
        move_eligible: true,
        ineligibility_reason: null,
      },
    ],
    audit: [
      {
        item: {
          id: AUDIT_ID,
          actor_kind: "OPERATOR_SESSION",
          actor_id: "admin",
          action: "destination.bless",
          operation_id: null,
          wallet_id: WALLET_ID,
          details: { destination_id: DEST_ID },
          details_sha256: "a".repeat(64),
          created_at: "2026-07-02T12:00:00.000Z",
        },
      },
      {
        item: {
          id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          actor_kind: "OPERATOR_SESSION",
          actor_id: "admin",
          action: "wallet.list",
          operation_id: null,
          wallet_id: null,
          details: {},
          details_sha256: "b".repeat(64),
          created_at: "2026-07-02T13:00:00.000Z",
        },
      },
      {
        item: {
          id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          actor_kind: "SYSTEM",
          actor_id: null,
          action: "node.boot",
          operation_id: null,
          wallet_id: null,
          details: {},
          details_sha256: "c".repeat(64),
          created_at: "2026-07-02T11:00:00.000Z",
        },
      },
    ],
  });
}

async function buildAuthedRouter(password = "inventory-secret-1") {
  const userStore = new InMemoryAdminUserStore();
  await seedAdmin(userStore, password);
  const sessionStore = new InMemoryAdminSessionStore();
  const sessions = createAdminSessionService({ nodeId: NODE_ID }, sessionStore, userStore);
  const deps = createFailClosedAdminRouteDeps({
    sessions,
    userStore,
    csrf: { allowedOrigins: ["https://node.example"] },
    totp: { secret: new Uint8Array(32), windowSteps: 1 },
    nodeId: NODE_ID,
    destinationService: createFailClosedDestinationService(),
    inventoryStore: inventorySeed(),
    newRequestId: () => randomUUID(),
  });
  const router = createAdminRouter(deps);
  const login = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: "admin", password })),
    {},
  );
  const cookie = cookieFrom(login.headers["set-cookie"]);
  expect(login.status).toBe(200);
  expect(cookie).toContain(ADMIN_SESSION_COOKIE);
  return { router, cookie };
}

describe("admin inventory HTTP (contract)", () => {
  it("ADMIN_INVENTORY_ROUTES lists the six inventory GETs", () => {
    expect(ADMIN_INVENTORY_ROUTES).toHaveLength(6);
    expect(ADMIN_INVENTORY_ROUTES.map((r) => `${r.method} ${r.path}`)).toEqual([
      "GET /admin/v1/wallets",
      "GET /admin/v1/wallets/:id",
      "GET /admin/v1/operations",
      "GET /admin/v1/operations/:id",
      "GET /admin/v1/destinations",
      "GET /admin/v1/audit",
    ]);
  });

  it("closed sets derive from contracts (no hand-copied drift)", () => {
    expect([...INVENTORY_OPERATION_KINDS]).toEqual([...OPERATION_KINDS]);
    expect([...WALLET_STATES]).toEqual(["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"]);
    expect([...WALLET_KEY_ORIGINS]).toEqual(["node_generated", "imported"]);
    expect([...DESTINATION_STATES]).toEqual(["PENDING", "BLESSED", "RETIRED"]);
  });

  it("unauthenticated inventory GETs are 401", async () => {
    const { router } = await buildAuthedRouter("inventory-secret-ua");
    for (const path of [
      "/admin/v1/wallets",
      `/admin/v1/wallets/${WALLET_ID}`,
      "/admin/v1/operations",
      `/admin/v1/operations/${OP_ID}`,
      "/admin/v1/destinations",
      "/admin/v1/audit",
    ]) {
      const res = await router("GET", path, new Uint8Array(), {});
      expect(res.status, path).toBe(401);
    }
  });

  it("GET /admin/v1/wallets — paginated, never private keys, allowlisted fields", async () => {
    const { router, cookie } = await buildAuthedRouter("inventory-secret-w");
    const res = await router("GET", "/admin/v1/wallets?limit=1", new Uint8Array(), { cookie });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      object: string;
      data: Record<string, unknown>[];
      has_more: boolean;
      next_cursor: string | null;
    };
    expect(body.object).toBe("list");
    expect(body.data).toHaveLength(1);
    expect(body.has_more).toBe(true);
    expect(body.next_cursor).toBeTruthy();
    const row = body.data[0]!;
    for (const key of WALLET_INVENTORY_FIELDS) {
      expect(row, key).toHaveProperty(key);
    }
    for (const forbidden of [
      "private_key",
      "ciphertext",
      "nonce",
      "auth_tag",
      "secret",
      "transfer_code",
    ]) {
      expect(row).not.toHaveProperty(forbidden);
    }
    expect(row.recovery_verified).toBeTypeOf("boolean");
    expect(typeof row.observed_balance_zkz === "string" || row.observed_balance_zkz === null).toBe(
      true,
    );
    // Custody allowlist still present under inventory extension.
    for (const key of WALLET_CUSTODY_VIEW_FIELDS) {
      expect(row).toHaveProperty(key);
    }
  });

  it("GET /admin/v1/wallets/:id — detail by wallet_id and by public_key", async () => {
    const { router, cookie } = await buildAuthedRouter("inventory-secret-wd");
    const byId = await router("GET", `/admin/v1/wallets/${WALLET_ID}`, new Uint8Array(), {
      cookie,
    });
    expect(byId.status).toBe(200);
    const w = JSON.parse(byId.body) as Record<string, unknown>;
    expect(w.wallet_id).toBe(WALLET_ID);
    expect(w.observed_balance_zkz).toBe("1.25");
    expect(w.recovery_verified).toBe(true);
    expect(w).not.toHaveProperty("private_key");

    const byPk = await router(
      "GET",
      `/admin/v1/wallets/${encodeURIComponent(PUBKEY)}`,
      new Uint8Array(),
      { cookie },
    );
    expect(byPk.status).toBe(200);
    expect(JSON.parse(byPk.body).wallet_id).toBe(WALLET_ID);

    const missing = await router(
      "GET",
      "/admin/v1/wallets/99999999-9999-4999-8999-999999999999",
      new Uint8Array(),
      { cookie },
    );
    expect(missing.status).toBe(404);
  });

  it("GET /admin/v1/operations — filters + detail aggregate (receive/move/send)", async () => {
    const { router, cookie } = await buildAuthedRouter("inventory-secret-op");
    const list = await router(
      "GET",
      "/admin/v1/operations?kind=RECEIVE_EXTERNAL",
      new Uint8Array(),
      { cookie },
    );
    expect(list.status).toBe(200);
    const page = JSON.parse(list.body) as {
      data: Record<string, unknown>[];
      has_more: boolean;
    };
    expect(page.data).toHaveLength(1);
    expect(page.data[0]!.operation_type).toBe("RECEIVE_EXTERNAL");
    for (const key of OPERATION_INVENTORY_LIST_FIELDS) {
      expect(page.data[0]!).toHaveProperty(key);
    }

    const badKind = await router("GET", "/admin/v1/operations?kind=REFUND", new Uint8Array(), {
      cookie,
    });
    expect(badKind.status).toBe(400);

    const detail = await router("GET", `/admin/v1/operations/${OP_ID}`, new Uint8Array(), {
      cookie,
    });
    expect(detail.status).toBe(200);
    const op = JSON.parse(detail.body) as Record<string, unknown>;
    for (const key of OPERATION_INVENTORY_DETAIL_FIELDS) {
      expect(op).toHaveProperty(key);
    }
    expect(op.receiver_wallet_id).toBe(WALLET_ID);
    expect(op).not.toHaveProperty("transfer_code");
    expect(op).not.toHaveProperty("private_key");

    // Recovery path still distinct from inventory detail.
    const recovery = await router(
      "GET",
      `/admin/v1/operations/${OP_ID}/recovery`,
      new Uint8Array(),
      { cookie },
    );
    expect(recovery.status).toBe(404);

    const attn = await router(
      "GET",
      "/admin/v1/operations?attention_required=true",
      new Uint8Array(),
      { cookie },
    );
    expect(attn.status).toBe(200);
    const attnPage = JSON.parse(attn.body) as { data: { operation_type: string }[] };
    expect(attnPage.data.every((r) => r.operation_type === "SEND_EXTERNAL")).toBe(true);
  });

  it("GET /admin/v1/destinations — admin session mirror with bless state", async () => {
    const { router, cookie } = await buildAuthedRouter("inventory-secret-d");
    const res = await router("GET", "/admin/v1/destinations?state=BLESSED", new Uint8Array(), {
      cookie,
    });
    expect(res.status).toBe(200);
    const page = JSON.parse(res.body) as { data: Record<string, unknown>[] };
    expect(page.data).toHaveLength(1);
    const d = page.data[0]!;
    for (const key of DESTINATION_INVENTORY_FIELDS) {
      expect(d).toHaveProperty(key);
    }
    expect(d.state).toBe("BLESSED");
    expect(d.move_eligible).toBe(true);
  });

  it("GET /admin/v1/audit — paginated tail, redacted details", async () => {
    const { router, cookie } = await buildAuthedRouter("inventory-secret-a");
    const res = await router("GET", "/admin/v1/audit", new Uint8Array(), { cookie });
    expect(res.status).toBe(200);
    const page = JSON.parse(res.body) as { object: string; data: Record<string, unknown>[] };
    expect(page.object).toBe("list");
    expect(page.data.length).toBeGreaterThanOrEqual(1);
    const row = page.data[0]!;
    for (const key of AUDIT_INVENTORY_FIELDS) {
      expect(row).toHaveProperty(key);
    }
    expect(row).not.toHaveProperty("private_key");
  });

  it("D1: audit after= is id keyset (next_cursor page-2), not timestamptz", async () => {
    const { router, cookie } = await buildAuthedRouter("inventory-secret-a2");
    const page1 = await router("GET", "/admin/v1/audit?limit=1", new Uint8Array(), { cookie });
    expect(page1.status).toBe(200);
    const p1 = JSON.parse(page1.body) as {
      data: { id: string }[];
      has_more: boolean;
      next_cursor: string | null;
    };
    expect(p1.data).toHaveLength(1);
    expect(p1.has_more).toBe(true);
    expect(p1.next_cursor).toBeTruthy();
    const cursor = p1.next_cursor!;
    // UUID-shaped next_cursor must work as ?after= — same pattern as wallets/ops.
    expect(cursor).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );

    const page2 = await router(
      "GET",
      `/admin/v1/audit?limit=1&after=${encodeURIComponent(cursor)}`,
      new Uint8Array(),
      { cookie },
    );
    expect(page2.status).toBe(200);
    const p2 = JSON.parse(page2.body) as {
      data: { id: string }[];
      has_more: boolean;
      next_cursor: string | null;
    };
    expect(p2.data).toHaveLength(1);
    expect(p2.data[0]!.id).not.toBe(p1.data[0]!.id);
    // Not an infinite same-page loop.
    expect(p2.data[0]!.id).not.toBe(cursor);

    const viaStarting = await router(
      "GET",
      `/admin/v1/audit?limit=1&starting_after=${encodeURIComponent(cursor)}`,
      new Uint8Array(),
      { cookie },
    );
    expect(viaStarting.status).toBe(200);
    expect(JSON.parse(viaStarting.body).data[0].id).toBe(p2.data[0]!.id);
  });

  it("D2: SQL loadObservedBalance queries gateway_observations.b_amount", async () => {
    expect(OBSERVED_BALANCE_SQL_FRAGMENT).toContain("gateway_observations");
    expect(OBSERVED_BALANCE_SQL_FRAGMENT).not.toContain("observation_records");

    const captured: { text: string; params: readonly unknown[] | undefined }[] = [];
    const sql: InventorySqlExecutor = {
      async query(text, params) {
        captured.push({ text, params });
        if (text.includes("gateway_observations")) {
          return { rows: [{ b_amount: "3.50" }] };
        }
        return { rows: [] };
      },
    };
    const bal = await loadObservedBalance(sql, WALLET_ID);
    expect(bal).toBe("3.50");
    expect(captured).toHaveLength(1);
    expect(captured[0]!.text).toContain("gateway_observations");
    expect(captured[0]!.text).toContain("b_amount");
    expect(captured[0]!.text).not.toContain("observation_records");
    expect(captured[0]!.text).not.toContain("b_zkz");
    expect(captured[0]!.params).toEqual([WALLET_ID]);

    // createSqlAdminInventoryStore must surface that balance on wallet reads.
    const walletSql: InventorySqlExecutor = {
      async query(text, _params) {
        if (text.includes("FROM wallets") && text.includes("LIMIT")) {
          return {
            rows: [
              {
                id: WALLET_ID,
                node_id: NODE_ID,
                public_key: PUBKEY,
                key_origin: "node_generated",
                state: "AVAILABLE",
                created_at: "2026-07-01T00:00:00.000Z",
                retired_at: null,
                quarantine_reason: null,
                recovery_verified_at: null,
                recovery_verification_id: null,
              },
            ],
          };
        }
        if (text.includes("gateway_observations")) {
          return { rows: [{ b_amount: "9.01" }] };
        }
        if (text.includes("wallet_recovery_verifications")) {
          return { rows: [] };
        }
        return { rows: [] };
      },
    };
    const store = createSqlAdminInventoryStore(walletSql);
    const wallet = await store.getWallet(NODE_ID, WALLET_ID);
    expect(wallet).not.toBeNull();
    expect(wallet!.observed_balance_zkz).toBe("9.01");

    const listed = await store.listWallets(NODE_ID, { limit: 10 });
    expect(listed.data[0]!.observed_balance_zkz).toBe("9.01");
  });

  it("D2: SQL listAudit uses id keyset for after= (timestamptz is created_*)", async () => {
    const texts: string[] = [];
    const paramsLog: unknown[][] = [];
    const sql: InventorySqlExecutor = {
      async query(text, params) {
        texts.push(text);
        paramsLog.push([...(params ?? [])]);
        return { rows: [] };
      },
    };
    const store = createSqlAdminInventoryStore(sql);
    await store.listAudit(NODE_ID, {
      after: AUDIT_ID,
      created_after: "2026-01-01T00:00:00.000Z",
      created_before: "2026-12-31T00:00:00.000Z",
      limit: 5,
    });
    expect(texts).toHaveLength(1);
    const q = texts[0]!;
    // after is uuid keyset subquery, not cast to timestamptz on the cursor value alone.
    expect(q).toContain("FROM audit_log a2 WHERE a2.id");
    expect(q).toMatch(/a\.created_at > \$\d+::timestamptz/);
    expect(q).toMatch(/a\.created_at < \$\d+::timestamptz/);
    // AUDIT_ID appears as keyset param (not as the only timestamptz value).
    expect(paramsLog[0]).toContain(AUDIT_ID);
    expect(paramsLog[0]).toContain("2026-01-01T00:00:00.000Z");
  });

  it("empty inventory store still returns 200 list envelopes (fail-soft SPA)", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "inventory-secret-e");
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    const deps = createFailClosedAdminRouteDeps({
      sessions,
      userStore,
      csrf: { allowedOrigins: [] },
      totp: { secret: new Uint8Array(32), windowSteps: 1 },
      nodeId: NODE_ID,
      destinationService: createFailClosedDestinationService(),
      newRequestId: () => randomUUID(),
    });
    const router = createAdminRouter(deps);
    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: "admin", password: "inventory-secret-e" })),
      {},
    );
    const cookie = cookieFrom(login.headers["set-cookie"]);
    for (const path of [
      "/admin/v1/wallets",
      "/admin/v1/operations",
      "/admin/v1/destinations",
      "/admin/v1/audit",
    ]) {
      const res = await router("GET", path, new Uint8Array(), { cookie });
      expect(res.status, path).toBe(200);
      const body = JSON.parse(res.body) as { object: string; data: unknown[] };
      expect(body.object).toBe("list");
      expect(body.data).toEqual([]);
    }
  });
});
