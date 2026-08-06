// Production composition proofs.
//
// A unit-fixture resolveCredential is not enough. These tests
// mount createOperationRouter + createImplementerBearerAuth (the production
// composition path) and prove principal binding, tenant-predicated gets,
// cross-tenant 404 byte-identity, and idempotency namespace isolation.
//
// Governing: the API contract.

import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  apiErrorResponse,
  createImplementerBearerAuth,
  createOperationRouter,
  type OperationRouteStore,
  type ReceiveResponse,
  type OperationObject,
} from "../src/api/index.js";

const encode = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));

const OP_A = "00000000-0000-0000-0000-0000000000a1";
const OP_B = "00000000-0000-0000-0000-0000000000b2";
const IDEM_KEY = "idem-key-0123456789ab";
const RECEIVE_BODY = {
  amount_zkz: "5.5",
  anchor: "ord_01J2",
  after_landing: { kind: "HOLD" as const, destination_id: null },
};

const FULL_SCOPES = [
  "receive:create",
  "receive:read",
  "move:create",
  "move:read",
  "send:create",
  "send:read",
  "destination:create",
  "destination:read",
] as const;

function opBase(id: string): OperationObject {
  return {
    operation_id: id,
    operation_type: "RECEIVE_EXTERNAL",
    state: "READY",
    amount_zkz: "5.5",
    row_version: 1,
    attention_required: false,
    attention_reason: null,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:01.000Z",
    terminal_at: null,
    verification_material_available_until: null,
  };
}

function receiveBody(id: string): ReceiveResponse {
  return {
    operation: opBase(id),
    receiver_pubkey: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
    discriminator: id,
    expires_at: "2026-01-01T00:05:00.000Z",
    after_landing: { kind: "HOLD", destination_id: null },
    code_status: "AWAITING_ARM",
    transfer_code: null,
    expected_artifact: null,
    t0: null,
    subscription_handle: "sh_secret",
  };
}

interface StoredReceive {
  readonly implementerId: string;
  readonly body: ReceiveResponse;
  readonly idempotencyKey: string;
}

/** In-memory store that enforces tenant predicates — production contract surface. */
function tenantedStore(): {
  store: OperationRouteStore;
  creates: Array<{ implementerId: string; idempotencyKey: string }>;
  gets: Array<{ operationId: string; implementerId: string }>;
} {
  const rows = new Map<string, StoredReceive>();
  const creates: Array<{ implementerId: string; idempotencyKey: string }> = [];
  const gets: Array<{ operationId: string; implementerId: string }> = [];

  // Seed one row per tenant for cross-get proofs.
  rows.set(OP_A, {
    implementerId: "impl-a",
    body: receiveBody(OP_A),
    idempotencyKey: "seed-a",
  });
  rows.set(OP_B, {
    implementerId: "impl-b",
    body: receiveBody(OP_B),
    idempotencyKey: "seed-b",
  });

  const store: OperationRouteStore = {
    async createReceive(input) {
      creates.push({ implementerId: input.implementerId, idempotencyKey: input.idempotencyKey });
      // Idempotency namespace is (implementerId, key) — same key, other tenant is a new create.
      for (const row of rows.values()) {
        if (
          row.implementerId === input.implementerId &&
          row.idempotencyKey === input.idempotencyKey
        ) {
          return { status: 201 as const, body: row.body, idempotentReplay: true };
        }
      }
      const id = randomUUID();
      const body = receiveBody(id);
      rows.set(id, {
        implementerId: input.implementerId,
        body,
        idempotencyKey: input.idempotencyKey,
      });
      return { status: 201 as const, body };
    },
    async getReceive(operationId, implementerId) {
      gets.push({ operationId, implementerId });
      const row = rows.get(operationId);
      if (row === undefined || row.implementerId !== implementerId) return null;
      return row.body;
    },
    async createInternalMove() {
      throw new Error("unused");
    },
    async getInternalMove() {
      throw new Error("unused");
    },
    async createExternalSend() {
      throw new Error("unused");
    },
    async getExternalSend() {
      throw new Error("unused");
    },
  };

  return { store, creates, gets };
}

const TOKEN_A = "ik_tenant_a_composition_token_aaa";
const TOKEN_B = "ik_tenant_b_composition_token_bbb";
const TOKEN_READ_ONLY = "ik_tenant_a_readonly_token_ccc";

function dualTenantAuth() {
  return createImplementerBearerAuth({
    keys: [
      { token: TOKEN_A, implementerId: "impl-a", scopes: [...FULL_SCOPES] },
      { token: TOKEN_B, implementerId: "impl-b", scopes: [...FULL_SCOPES] },
      {
        token: TOKEN_READ_ONLY,
        implementerId: "impl-a",
        scopes: ["receive:read"],
      },
    ],
  });
}

function authHeaders(token: string, extra: Record<string, string> = {}): Record<string, string | undefined> {
  return { authorization: `Bearer ${token}`, ...extra };
}

describe("createOperationRouter production composition (D1/D2/D5)", () => {
  it("binds principal via resolveCredential — createReceive receives credential implementerId", async () => {
    const { store, creates } = tenantedStore();
    const auth = dualTenantAuth();
    expect(auth.resolveCredential).toBeDefined();

    const router = createOperationRouter({
      store,
      auth,
      newRequestId: () => "req-composition-0001",
    });

    const res = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      authHeaders(TOKEN_A, { "idempotency-key": IDEM_KEY }),
    );
    expect(res.status).toBe(201);
    expect(creates).toEqual([{ implementerId: "impl-a", idempotencyKey: IDEM_KEY }]);
  });

  it("getReceive is called with credential tenant — never bare operationId alone", async () => {
    const { store, gets } = tenantedStore();
    const router = createOperationRouter({
      store,
      auth: dualTenantAuth(),
      newRequestId: () => "req-composition-0002",
    });

    const res = await router(
      "GET",
      `/v1/receives/${OP_A}`,
      new Uint8Array(0),
      authHeaders(TOKEN_A),
    );
    expect(res.status).toBe(200);
    expect(gets).toEqual([{ operationId: OP_A, implementerId: "impl-a" }]);
  });

  it("cross-tenant get and absent get are byte-identical 404", async () => {
    const { store } = tenantedStore();
    const fixedId = () => "req-composition-404x";
    const router = createOperationRouter({
      store,
      auth: dualTenantAuth(),
      newRequestId: fixedId,
    });

    // Tenant A tries to read tenant B's operation.
    const cross = await router(
      "GET",
      `/v1/receives/${OP_B}`,
      new Uint8Array(0),
      authHeaders(TOKEN_A),
    );
    const absent = await router(
      "GET",
      "/v1/receives/00000000-0000-0000-0000-00000000dead",
      new Uint8Array(0),
      authHeaders(TOKEN_A),
    );

    expect(cross.status).toBe(404);
    expect(absent.status).toBe(404);
    expect(cross.body).toBe(absent.body);
    expect(cross.body).toBe(apiErrorResponse("not_found", "req-composition-404x").body);
    // Headers/status parity (byte-identical envelope).
    expect(cross).toEqual(absent);
  });

  it("idempotency key reuse across implementers does not collide", async () => {
    const { store, creates } = tenantedStore();
    const router = createOperationRouter({
      store,
      auth: dualTenantAuth(),
      newRequestId: () => randomUUID(),
    });

    const sharedKey = "shared-idem-key-across-tenants";
    const resA = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      authHeaders(TOKEN_A, { "idempotency-key": sharedKey }),
    );
    const resB = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      authHeaders(TOKEN_B, { "idempotency-key": sharedKey }),
    );

    expect(resA.status).toBe(201);
    expect(resB.status).toBe(201);
    // Distinct bodies (different operation ids) — not a cross-tenant replay.
    expect(resA.body).not.toBe(resB.body);
    expect(creates).toEqual([
      { implementerId: "impl-a", idempotencyKey: sharedKey },
      { implementerId: "impl-b", idempotencyKey: sharedKey },
    ]);

    // Replay within tenant A returns the same body.
    const replayA = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      authHeaders(TOKEN_A, { "idempotency-key": sharedKey }),
    );
    expect(replayA.status).toBe(201);
    expect(replayA.body).toBe(resA.body);
    expect(replayA.headers["Idempotency-Replayed"]).toBe("true");
  });

  it("scope denial is generic 401 and never reaches the store (authz-before-lookup)", async () => {
    const { store, creates, gets } = tenantedStore();
    const router = createOperationRouter({
      store,
      auth: dualTenantAuth(),
      newRequestId: () => "req-composition-scope",
    });

    // read-only key on create route.
    const createDenied = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      authHeaders(TOKEN_READ_ONLY, { "idempotency-key": IDEM_KEY }),
    );
    expect(createDenied.status).toBe(401);
    expect(createDenied.body).toBe(apiErrorResponse("invalid_api_key", "req-composition-scope").body);
    expect(creates).toEqual([]);

    // Missing token.
    const missing = await router(
      "GET",
      `/v1/receives/${OP_A}`,
      new Uint8Array(0),
      {},
    );
    expect(missing.status).toBe(401);
    expect(missing.body).toBe(createDenied.body);
    expect(gets).toEqual([]);
  });

  it("own-tenant get succeeds after cross-tenant 404 (no residual leak)", async () => {
    const { store } = tenantedStore();
    const router = createOperationRouter({
      store,
      auth: dualTenantAuth(),
      newRequestId: () => randomUUID(),
    });

    const cross = await router(
      "GET",
      `/v1/receives/${OP_B}`,
      new Uint8Array(0),
      authHeaders(TOKEN_A),
    );
    expect(cross.status).toBe(404);

    const own = await router(
      "GET",
      `/v1/receives/${OP_A}`,
      new Uint8Array(0),
      authHeaders(TOKEN_A),
    );
    expect(own.status).toBe(200);
    const parsed = JSON.parse(own.body) as { operation: { operation_id: string } };
    expect(parsed.operation.operation_id).toBe(OP_A);
    // Point read strips subscription_handle.
    expect(own.body).not.toContain("subscription_handle");
  });
});
