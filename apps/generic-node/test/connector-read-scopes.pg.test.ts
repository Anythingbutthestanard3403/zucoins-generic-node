// ZTR-1332 / GN-204: Scoped Connector Read API (wallets:read_linked vs ledger:read_all)
// and write-scope enforcement (receives:write / sends:write -> 403 INSUFFICIENT_CONNECTOR_SCOPE).

import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  InMemoryConnectorConfigStore,
  createConnectorReadRouter,
  createImplementerBearerAuth,
  createOperationRouter,
  createSqlConnectorConfigStore,
  createSqlConnectorReadStore,
  ed25519PublicKeyToPem,
  toBase64UrlPadded,
  type OperationRouteStore,
} from "@zucoins/node-core";
import { CONNECTOR_CONFIGS_SCHEMA_FILE } from "../../../packages/node-core/src/schema/connector-configs.contract.ts";
import { CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE } from "../../../packages/node-core/src/schema/connector-reserve-wallets.contract.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const SCHEMA = "ztr1332_connector_reads";
const NODE = "11111111-1111-4111-8111-111111111111";
const IMPL_1 = "22222222-2222-4222-8222-222222222221";
const IMPL_2 = "22222222-2222-4222-8222-222222222222";
const IMPL_3 = "22222222-2222-4222-8222-222222222223";

const WALLET_A = "aaaaaaa1-1111-4111-8111-111111111111";
const WALLET_B = "bbbbbbb2-2222-4222-8222-222222222222";
const WALLET_WORKER_RECEIVE = "ccccccc3-3333-4333-8333-333333333333";
const WALLET_WORKER_DEST = "ddddddd4-4444-4444-8444-444444444444";

const OP_1_RECEIVE = "eeeeeee1-1111-4111-8111-111111111111";
const OP_1_CHILD_MOVE = "eeeeeee2-2222-4222-8222-222222222222";
const OP_2_SEND = "eeeeeee3-3333-4333-8333-333333333333";

const KEY_1 = "ik_connector_1_linked_key_00000001";
const KEY_2 = "ik_connector_2_linked_key_00000002";
const KEY_3 = "ik_connector_3_read_all_key_000003";

const here = dirname(fileURLToPath(import.meta.url));
const reserveSliceSql = readFileSync(
  resolve(here, "../../../packages/node-core/src/schema", CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE),
  "utf8",
);
const configSliceSql = readFileSync(
  resolve(here, "../../../packages/node-core/src/schema", CONNECTOR_CONFIGS_SCHEMA_FILE),
  "utf8",
);

const { publicKey: nodePubObj } = generateKeyPairSync("ed25519");
const nodeSpki = nodePubObj.export({ format: "der", type: "spki" });
const NODE_PUB_B64 = toBase64UrlPadded(Buffer.from(nodeSpki).subarray(-32));

const STUBS = `
CREATE TABLE nodes (
  id uuid PRIMARY KEY,
  identity_public_key text NOT NULL
);
CREATE TABLE node_signing_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  purpose text NOT NULL,
  public_key text NOT NULL,
  activated_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  public_key text NOT NULL,
  state text NOT NULL DEFAULT 'AVAILABLE',
  money_mode text NOT NULL DEFAULT 'FULL',
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE TABLE destinations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  wallet_id uuid NOT NULL REFERENCES wallets(id),
  state text NOT NULL
);
CREATE TABLE gateway_observations (
  id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL REFERENCES wallets(id),
  wallet_seq bigint NOT NULL,
  b_amount text,
  observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  funding_wallet_id uuid REFERENCES wallets(id),
  retired_at timestamptz
);
CREATE TABLE integration_requests (
  id uuid PRIMARY KEY
);
CREATE TABLE operations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  kind text NOT NULL,
  status text NOT NULL,
  amount_zkz text NOT NULL,
  client_reference text,
  anchor text,
  source_wallet_id uuid REFERENCES wallets(id),
  receiver_wallet_id uuid REFERENCES wallets(id),
  destination_id uuid,
  destination_address text,
  spawned_from_operation_id uuid REFERENCES operations(id),
  references_operation_id uuid REFERENCES operations(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  terminal_at timestamptz
);
`;

let pool: Pool | undefined;

function psql(sql: string): void {
  execFileSync("psql", [TEST_DATABASE_URL, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], {
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function makeStubOperationStore(): OperationRouteStore {
  return {
    createReceive: async (input) => ({
      replayed: false,
      response: {
        operation_id: OP_1_RECEIVE,
        kind: "RECEIVE_EXTERNAL",
        state: "READY",
        created_at: "2026-04-19T00:00:00.000Z",
        updated_at: "2026-04-19T00:00:00.000Z",
        terminal_at: null,
        client_reference: input.body.client_reference ?? null,
        anchor: input.body.anchor ?? null,
        expected_amount_zkz: input.body.expected_amount_zkz,
        receiver_wallet_id: WALLET_WORKER_RECEIVE,
        receiver_wallet_public_key: NODE_PUB_B64,
        expires_at: "2026-04-19T01:00:00.000Z",
        transfer_code: "tc_test",
        expected_artifact: {
          purpose: "zp-receive-expected-v1",
          canonical_version: "zp-v1",
          signing_key_id: "00000000-0000-4000-8000-000000000001",
          payload: {},
          signature: "AA".repeat(43) + "=",
        },
        after_landing: { mode: "HOLD" },
        spawned_move_operation_id: null,
        subscription_handle: "sh_test_handle_0000000000000001",
      },
    }),
    getReceive: async () => null,
    createInternalMove: async () => {
      throw new Error("not used");
    },
    getInternalMove: async () => null,
    createExternalSend: async (input) => ({
      replayed: false,
      response: {
        operation_id: OP_2_SEND,
        kind: "SEND_EXTERNAL",
        state: "CREATED",
        created_at: "2026-04-19T00:00:00.000Z",
        updated_at: "2026-04-19T00:00:00.000Z",
        terminal_at: null,
        client_reference: input.body.client_reference ?? null,
        anchor: input.body.anchor ?? null,
        source_wallet_id: WALLET_A,
        destination_address: input.body.destination_address,
        amount_zkz: input.body.amount_zkz,
        rule_id: input.body.rule_id ?? null,
        approval_Expires_at: "2026-04-19T01:00:00.000Z",
        transfer_code: null,
        transfer_code_sha256: null,
        expected_artifact: {
          purpose: "zp-send-expected-v1",
          canonical_version: "zp-v1",
          signing_key_id: "00000000-0000-4000-8000-000000000001",
          payload: {},
          signature: "AA".repeat(43) + "=",
        },
        subscription_handle: "sh_test_handle_0000000000000002",
      } as never,
    }),
    getExternalSend: async () => null,
  };
}

describe("ZTR-1332 / GN-204 scoped connector read API and write scope enforcement", () => {
  beforeAll(() => {
    if (!live) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      return;
    }
    psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
    psql(`SET search_path TO ${SCHEMA}; ${STUBS}`);
    psql(`SET search_path TO ${SCHEMA}; ${reserveSliceSql}`);
    psql(`SET search_path TO ${SCHEMA}; ${configSliceSql}`);
    psql(
      `SET search_path TO ${SCHEMA};
       INSERT INTO nodes (id, identity_public_key) VALUES ('${NODE}', '${NODE_PUB_B64}');
       INSERT INTO wallets (id, node_id, public_key, state, money_mode, display_label) VALUES
         ('${WALLET_A}', '${NODE}', 'pub_reserve_a_00000000000000000000000000001', 'AVAILABLE', 'FULL', 'Reserve Wallet A'),
         ('${WALLET_B}', '${NODE}', 'pub_reserve_b_00000000000000000000000000002', 'AVAILABLE', 'INTERNAL_ONLY', 'Reserve Wallet B'),
         ('${WALLET_WORKER_RECEIVE}', '${NODE}', 'pub_worker_rx_00000000000000000000000000003', 'AVAILABLE', 'RECEIVE_ONLY', NULL),
         ('${WALLET_WORKER_DEST}', '${NODE}', 'pub_worker_ds_00000000000000000000000000004', 'AVAILABLE', 'FULL', NULL);
       INSERT INTO destinations (id, node_id, wallet_id, state) VALUES
         ('10000000-0000-4000-8000-000000000001', '${NODE}', '${WALLET_A}', 'BLESSED'),
         ('10000000-0000-4000-8000-000000000002', '${NODE}', '${WALLET_B}', 'BLESSED'),
         ('10000000-0000-4000-8000-000000000004', '${NODE}', '${WALLET_WORKER_DEST}', 'WORKER');
       INSERT INTO gateway_observations (id, wallet_id, wallet_seq, b_amount) VALUES
         ('20000000-0000-4000-8000-000000000001', '${WALLET_A}', 1, '125.50000000'),
         ('20000000-0000-4000-8000-000000000002', '${WALLET_B}', 1, '450.00000000');
       INSERT INTO implementers (id, name, funding_wallet_id, allow_custom_routing) VALUES
         ('${IMPL_1}', 'Connector 1 Checkout', '${WALLET_A}', false),
         ('${IMPL_2}', 'Connector 2 Promo', '${WALLET_B}', true),
         ('${IMPL_3}', 'Connector 3 Audit Dashboard', NULL, false);
       INSERT INTO implementer_reserve_wallets (implementer_id, wallet_id, is_default) VALUES
         ('${IMPL_1}', '${WALLET_A}', true),
         ('${IMPL_2}', '${WALLET_B}', true);
       INSERT INTO operations (
         id, node_id, implementer_id, kind, status, amount_zkz, client_reference,
         source_wallet_id, receiver_wallet_id, spawned_from_operation_id,
         created_at, updated_at
       ) VALUES
         ('${OP_1_RECEIVE}', '${NODE}', '${IMPL_1}', 'RECEIVE_EXTERNAL', 'LANDED', '25', 'order-101',
          NULL, '${WALLET_WORKER_RECEIVE}', NULL, '2026-04-19T01:00:00Z', '2026-04-19T01:01:00Z'),
         ('${OP_1_CHILD_MOVE}', '${NODE}', '${IMPL_2}', 'MOVE_INTERNAL', 'LANDED', '25', 'sweep-101',
          '${WALLET_WORKER_RECEIVE}', '${WALLET_A}', '${OP_1_RECEIVE}', '2026-04-19T01:02:00Z', '2026-04-19T01:03:00Z'),
         ('${OP_2_SEND}', '${NODE}', '${IMPL_2}', 'SEND_EXTERNAL', 'CREATED', '10', 'payout-202',
          '${WALLET_B}', NULL, NULL, '2026-04-19T02:00:00Z', '2026-04-19T02:00:00Z');
      `,
    );
    pool = new Pool({ connectionString: TEST_DATABASE_URL });
  }, 120_000);

  afterAll(async () => {
    await pool?.end();
    if (!live) return;
    try {
      psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    } catch {
      // ignore cleanup race
    }
  });

  it("1. Positive & Isolation (wallets:read_linked): Connector 1 sees only Reserve Wallet A, zero worker wallets, and only its own operations + child sweeps", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const sqlExecutor = {
      async query<R extends Record<string, unknown> = Record<string, unknown>>(
        text: string,
        params?: readonly unknown[],
      ) {
        const client = await db.connect();
        try {
          await client.query(`SET search_path TO ${SCHEMA}`);
          const res = await client.query(text, params as unknown[] | undefined);
          return { rows: res.rows as R[] };
        } finally {
          client.release();
        }
      },
    };
    const configStore = createSqlConnectorConfigStore(sqlExecutor);
    const readStore = createSqlConnectorReadStore(sqlExecutor);

    await configStore.upsert({
      implementerId: IMPL_1,
      displayName: "Connector 1 Checkout",
      scopes: ["receives:write", "sends:write", "wallets:read_linked"],
    });
    await configStore.upsert({
      implementerId: IMPL_2,
      displayName: "Connector 2 Promo",
      scopes: ["receives:write", "sends:write", "wallets:read_linked"],
    });

    const router = createConnectorReadRouter({
      store: readStore,
      connectorConfigStore: configStore,
      nodeId: NODE,
      validateCredential: async (rawKey) => {
        if (rawKey === KEY_1) return { implementer_id: IMPL_1, scopes: ["receive:read", "send:read"] };
        if (rawKey === KEY_2) return { implementer_id: IMPL_2, scopes: ["receive:read", "send:read"] };
        return null;
      },
      newRequestId: () => "req-1",
    });

    // GET /v1/node-info for Connector 1
    const infoRes = await router("GET", "/v1/node-info", new Uint8Array(0), {
      authorization: `Bearer ${KEY_1}`,
    });
    expect(infoRes.status).toBe(200);
    const infoBody = JSON.parse(infoRes.body) as Record<string, unknown>;
    expect(infoBody.node_id).toBe(NODE);
    expect(infoBody.node_public_key_pem).toBe(ed25519PublicKeyToPem(NODE_PUB_B64));
    expect(infoBody.implementer_id).toBe(IMPL_1);
    expect(infoBody.display_name).toBe("Connector 1 Checkout");
    expect(infoBody.policy_mode).toBe("NODE_VERIFIED");
    expect(infoBody.scopes).toEqual(["receives:write", "sends:write", "wallets:read_linked"]);
    expect(infoBody.default_reserve_wallet_id).toBe(WALLET_A);
    expect(infoBody.allow_custom_routing).toBe(false);

    // GET /v1/wallets for Connector 1 (even if ?include_workers=true is passed, worker wallets are hidden without ledger:read_all)
    const walletsRes = await router(
      "GET",
      "/v1/wallets?include_workers=true",
      new Uint8Array(0),
      { authorization: `Bearer ${KEY_1}` },
    );
    expect(walletsRes.status).toBe(200);
    const walletsBody = JSON.parse(walletsRes.body) as {
      data: Array<{
        wallet_id: string;
        display_name: string | null;
        cached_balance_zkz: string;
        is_default_for_connector: boolean;
        blessed: boolean;
        money_mode: string;
      }>;
    };
    expect(walletsBody.data).toHaveLength(1);
    expect(walletsBody.data[0]?.wallet_id).toBe(WALLET_A);
    expect(walletsBody.data[0]?.display_name).toBe("Reserve Wallet A");
    expect(walletsBody.data[0]?.cached_balance_zkz).toBe("125.50000000");
    expect(walletsBody.data[0]?.is_default_for_connector).toBe(true);
    expect(walletsBody.data[0]?.blessed).toBe(true);

    // GET /v1/operations for Connector 1: sees OP_1_RECEIVE and its child OP_1_CHILD_MOVE, never OP_2_SEND
    const opsRes = await router("GET", "/v1/operations", new Uint8Array(0), {
      authorization: `Bearer ${KEY_1}`,
    });
    expect(opsRes.status).toBe(200);
    const opsBody = JSON.parse(opsRes.body) as {
      data: Array<{ operation_id: string; kind: string; external_ref: string | null }>;
    };
    expect(opsBody.data.map((op) => op.operation_id)).toEqual([OP_1_CHILD_MOVE, OP_1_RECEIVE]);
  });

  it("2. Positive (ledger:read_all): Connector 3 sees both Reserve Wallets A and B, and operations across both Connector 1 and Connector 2", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const sqlExecutor = {
      async query<R extends Record<string, unknown> = Record<string, unknown>>(
        text: string,
        params?: readonly unknown[],
      ) {
        const client = await db.connect();
        try {
          await client.query(`SET search_path TO ${SCHEMA}`);
          const res = await client.query(text, params as unknown[] | undefined);
          return { rows: res.rows as R[] };
        } finally {
          client.release();
        }
      },
    };
    const configStore = createSqlConnectorConfigStore(sqlExecutor);
    const readStore = createSqlConnectorReadStore(sqlExecutor);

    await configStore.upsert({
      implementerId: IMPL_3,
      displayName: "Connector 3 Audit Dashboard",
      scopes: ["ledger:read_all"],
    });

    const router = createConnectorReadRouter({
      store: readStore,
      connectorConfigStore: configStore,
      nodeId: NODE,
      validateCredential: async (rawKey) => {
        if (rawKey === KEY_3) return { implementer_id: IMPL_3, scopes: ["receive:read", "send:read"] };
        return null;
      },
      newRequestId: () => "req-2",
    });

    // Default GET /v1/wallets returns both Reserve Wallet A and B, excluding worker wallets
    const walletsRes = await router("GET", "/v1/wallets", new Uint8Array(0), {
      authorization: `Bearer ${KEY_3}`,
    });
    expect(walletsRes.status).toBe(200);
    const walletsBody = JSON.parse(walletsRes.body) as {
      data: Array<{ wallet_id: string }>;
    };
    expect(walletsBody.data.map((w) => w.wallet_id)).toEqual([WALLET_A, WALLET_B]);

    // With ?include_workers=true AND ledger:read_all, worker wallets are also returned
    const withWorkersRes = await router(
      "GET",
      "/v1/wallets?include_workers=true",
      new Uint8Array(0),
      { authorization: `Bearer ${KEY_3}` },
    );
    expect(withWorkersRes.status).toBe(200);
    const withWorkersBody = JSON.parse(withWorkersRes.body) as {
      data: Array<{ wallet_id: string }>;
    };
    expect(withWorkersBody.data.map((w) => w.wallet_id)).toEqual([
      WALLET_A,
      WALLET_B,
      WALLET_WORKER_RECEIVE,
      WALLET_WORKER_DEST,
    ]);

    // GET /v1/operations with ledger:read_all returns operations across all connectors
    const opsRes = await router("GET", "/v1/operations", new Uint8Array(0), {
      authorization: `Bearer ${KEY_3}`,
    });
    expect(opsRes.status).toBe(200);
    const opsBody = JSON.parse(opsRes.body) as {
      data: Array<{ operation_id: string }>;
    };
    expect(opsBody.data.map((op) => op.operation_id)).toEqual([
      OP_2_SEND,
      OP_1_CHILD_MOVE,
      OP_1_RECEIVE,
    ]);

    // Filtering by external_ref and kind
    const filteredRes = await router(
      "GET",
      "/v1/operations?kind=SEND_EXTERNAL&external_ref=payout-202",
      new Uint8Array(0),
      { authorization: `Bearer ${KEY_3}` },
    );
    expect(filteredRes.status).toBe(200);
    const filteredBody = JSON.parse(filteredRes.body) as {
      data: Array<{ operation_id: string }>;
    };
    expect(filteredBody.data.map((op) => op.operation_id)).toEqual([OP_2_SEND]);
  });

  it("3. Negative (Read-Only Connector Attempting Write): Connector 3 with scopes: ['ledger:read_all'] receives 403 INSUFFICIENT_CONNECTOR_SCOPE on POST /v1/external-sends and POST /v1/receives", async () => {
    const configStore = new InMemoryConnectorConfigStore();
    await configStore.upsert({
      implementerId: IMPL_3,
      displayName: "Connector 3 Audit Dashboard",
      scopes: ["ledger:read_all"],
    });

    const auth = createImplementerBearerAuth({
      keys: [
        {
          token: KEY_3,
          implementerId: IMPL_3,
          // Even if the underlying key row has send:create and receive:create,
          // connector_configs.scopes = ['ledger:read_all'] gates the write routes with 403 INSUFFICIENT_CONNECTOR_SCOPE.
          scopes: ["receive:create", "receive:read", "send:create", "send:read"],
        },
      ],
    });

    const opRouter = createOperationRouter({
      store: makeStubOperationStore(),
      auth,
      connectorConfigStore: configStore,
      newRequestId: () => "req-write-gate",
    });

    const sendBody = new TextEncoder().encode(
      JSON.stringify({
        destination_address: NODE_PUB_B64,
        amount_zkz: "15",
      }),
    );
    const sendRes = await opRouter("POST", "/v1/external-sends", sendBody, {
      "content-type": "application/json",
      authorization: `Bearer ${KEY_3}`,
      "idempotency-key": "ik-send-readonly-attempt-001",
    });
    expect(sendRes.status).toBe(403);
    const sendErr = JSON.parse(sendRes.body) as { error: { code: string; message: string } };
    expect(sendErr.error.code).toBe("INSUFFICIENT_CONNECTOR_SCOPE");

    const receiveBody = new TextEncoder().encode(
      JSON.stringify({
        expected_amount_zkz: "20",
      }),
    );
    const receiveRes = await opRouter("POST", "/v1/receives", receiveBody, {
      "content-type": "application/json",
      authorization: `Bearer ${KEY_3}`,
      "idempotency-key": "ik-receive-readonly-attempt-001",
    });
    expect(receiveRes.status).toBe(403);
    const receiveErr = JSON.parse(receiveRes.body) as { error: { code: string; message: string } };
    expect(receiveErr.error.code).toBe("INSUFFICIENT_CONNECTOR_SCOPE");
  });
});
