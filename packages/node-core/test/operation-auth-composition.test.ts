// Production operation-store auth composition gate.
//
// Acceptance:
//   - Production wiring cannot authenticate/authorize as always-true
//   - Fail-closed defaults; tests refuse permissive production composition
//   - Missing / malformed / revoked / unknown-token / insufficient-scope → 401
//   - Spread+swap of factory results cannot mint a live always-true binding
//
// Governing: the API contract; signing custody.

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  OperationRouterCompositionError,
  assertOperationAuthComposition,
  createFailClosedOperationStore,
  createImplementerBearerAuth,
  createImplementerBearerAuthFromService,
  createOperationRouter,
  createRejectAllOperationAuth,
  isFailClosedOperationStore,
  isOperationAuthBinding,
  type OperationRouteStore,
  type ReceiveResponse,
} from "../src/api/index.js";
import * as operationAuthModule from "../src/api/operation-auth.js";
import {
  CredentialService,
  type CredentialStore,
  type StoredCredential,
} from "../src/credential/index.js";

const encode = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));

const OP_ID = "00000000-0000-0000-0000-000000000001";
const IDEM_KEY = "idem-key-0123456789ab";
const RECEIVE_BODY = {
  amount_zkz: "5.5",
  anchor: "ord_01J2",
  after_landing: { kind: "HOLD", destination_id: null },
};

const RECEIVE_RESPONSE: ReceiveResponse = {
  operation: {
    operation_id: OP_ID,
    operation_type: "RECEIVE_EXTERNAL",
    state: "READY",
    amount_zkz: "5.5",
    row_version: 2,
    attention_required: false,
    attention_reason: null,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:01.000Z",
    terminal_at: null,
    verification_material_available_until: null,
  },
  receiver_pubkey: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
  discriminator: OP_ID,
  expires_at: "2026-01-01T00:05:00.000Z",
  after_landing: { kind: "HOLD", destination_id: null },
  code_status: "AWAITING_ARM",
  transfer_code: null,
  expected_artifact: {
    key_id: "00000000-0000-0000-0000-000000000099",
    preimage_text: "canonical  text  with  double  spaces",
    preimage_sha256: "a".repeat(64),
    signature: `${"A".repeat(86)}==`,
  },
  t0: null,
  subscription_handle: "sh_test_secret",
};

const TOKEN_A = "ik_tenant_a_secret_token_aaaa";
const TOKEN_B = "ik_tenant_b_secret_token_bbbb";

function liveStore(counter?: { calls: number }): OperationRouteStore {
  return {
    createReceive: async () => {
      if (counter) counter.calls += 1;
      return { status: 201 as const, body: RECEIVE_RESPONSE };
    },
    getReceive: async () => RECEIVE_RESPONSE,
    createInternalMove: async () => {
      throw new Error("unused");
    },
    getInternalMove: async () => {
      throw new Error("unused");
    },
    createExternalSend: async () => {
      throw new Error("unused");
    },
    getExternalSend: async () => {
      throw new Error("unused");
    },
  };
}

function fullAuth(token = TOKEN_A, scopes?: readonly string[], revoked = false) {
  return createImplementerBearerAuth({
    keys: [
      {
        token,
        implementerId: "impl-a",
        scopes: scopes ?? [
          "receive:create",
          "receive:read",
          "move:create",
          "move:read",
          "send:create",
          "send:read",
          "destination:create",
          "destination:read",
        ],
        revoked,
      },
    ],
  });
}

function headers(token?: string): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = { "idempotency-key": IDEM_KEY };
  if (token !== undefined) out.authorization = `Bearer ${token}`;
  return out;
}

describe("operation auth brands — forge resistance", () => {
  it("createRejectAllOperationAuth is registered and always denies", async () => {
    const auth = createRejectAllOperationAuth();
    expect(isOperationAuthBinding(auth)).toBe(true);
    expect(auth.kind).toBe("reject_all");
    expect(
      await auth.authenticate({
        method: "POST",
        path: "/v1/receives",
        rawBody: new Uint8Array(0),
        headers: { authorization: `Bearer ${TOKEN_A}` },
        query: {},
      }),
    ).toBe(false);
  });

  it("an object literal cannot forge the operation-auth identity", () => {
    const forged = {
      kind: "implementer_bearer" as const,
      authenticate: () => true,
      authorizeScope: () => true,
    };
    expect(isOperationAuthBinding(forged)).toBe(false);
    expect(() => assertOperationAuthComposition(liveStore(), forged)).toThrow(
      OperationRouterCompositionError,
    );
  });

  it("createFailClosedOperationStore is registered; a plain rejecting object is not", () => {
    const branded = createFailClosedOperationStore();
    expect(isFailClosedOperationStore(branded)).toBe(true);

    const reject = (): Promise<never> => Promise.reject(new Error("x"));
    const plain: OperationRouteStore = {
      createReceive: reject,
      getReceive: reject,
      createInternalMove: reject,
      getInternalMove: reject,
      createExternalSend: reject,
      getExternalSend: reject,
    };
    expect(isFailClosedOperationStore(plain)).toBe(false);
  });

  it("spread + always-true hooks is not a registered auth binding", () => {
    const openAuth = {
      ...createImplementerBearerAuth({
        keys: [{ token: TOKEN_A, implementerId: "impl-a", scopes: ["receive:create"] }],
      }),
      kind: "implementer_bearer" as const,
      authenticate: () => true,
      authorizeScope: () => true,
    };
    expect(isOperationAuthBinding(openAuth)).toBe(false);
    expect(() => assertOperationAuthComposition(liveStore(), openAuth)).toThrow(
      OperationRouterCompositionError,
    );
  });

  it("spread reject-all + flip kind + always-true is refused", () => {
    const flipped = {
      ...createRejectAllOperationAuth(),
      kind: "implementer_bearer" as const,
      authenticate: () => true,
      authorizeScope: () => true,
    };
    expect(isOperationAuthBinding(flipped)).toBe(false);
    expect(() => assertOperationAuthComposition(liveStore(), flipped)).toThrow(
      OperationRouterCompositionError,
    );
  });

  it("spread fail-closed store + live money methods loses registration", () => {
    const liveAsFailClosed = {
      ...createFailClosedOperationStore(),
      ...liveStore(),
    };
    expect(isFailClosedOperationStore(liveAsFailClosed)).toBe(false);
    expect(() =>
      assertOperationAuthComposition(liveAsFailClosed, createRejectAllOperationAuth()),
    ).toThrow(/reject-all operation auth cannot coexist with a live operation store/);
  });
});

describe("assertOperationAuthComposition — production gate", () => {
  it("allows reject-all only with a registered fail-closed store", () => {
    expect(() =>
      assertOperationAuthComposition(
        createFailClosedOperationStore(),
        createRejectAllOperationAuth(),
      ),
    ).not.toThrow();
  });

  it("refuses reject-all with a live store", () => {
    expect(() =>
      assertOperationAuthComposition(liveStore(), createRejectAllOperationAuth()),
    ).toThrow(/reject-all operation auth cannot coexist with a live operation store/);
  });

  it("refuses reject-all with a plain (unregistered) rejecting store", () => {
    const reject = (): Promise<never> => Promise.reject(new Error("x"));
    const plain: OperationRouteStore = {
      createReceive: reject,
      getReceive: reject,
      createInternalMove: reject,
      getInternalMove: reject,
      createExternalSend: reject,
      getExternalSend: reject,
    };
    expect(() =>
      assertOperationAuthComposition(plain, createRejectAllOperationAuth()),
    ).toThrow(OperationRouterCompositionError);
  });

  it("allows implementer-bearer with a live store", () => {
    expect(() => assertOperationAuthComposition(liveStore(), fullAuth())).not.toThrow();
  });

  it("refuses unregistered always-true hooks", () => {
    expect(() =>
      assertOperationAuthComposition(liveStore(), {
        kind: "implementer_bearer",
        authenticate: () => true,
        authorizeScope: () => true,
      }),
    ).toThrow(/unbranded|refused|must be created/i);
  });
});

describe("createOperationRouter composition — refuse permissive production wiring", () => {
  it("throws when auth is an unregistered always-true pair", () => {
    expect(() =>
      createOperationRouter({
        store: liveStore(),
        // @ts-expect-error — deliberate unregistered forge
        auth: {
          kind: "implementer_bearer",
          authenticate: () => true,
          authorizeScope: () => true,
        },
        newRequestId: () => randomUUID(),
      }),
    ).toThrow(OperationRouterCompositionError);
  });

  it("throws when reject-all rides with a live store", () => {
    expect(() =>
      createOperationRouter({
        store: liveStore(),
        auth: createRejectAllOperationAuth(),
        newRequestId: () => randomUUID(),
      }),
    ).toThrow(/live operation store/);
  });

  it("throws on spread+swap auth; unauthenticated POST never reaches the store", async () => {
    const counter = { calls: 0 };
    const forged = {
      ...fullAuth(),
      authenticate: () => true,
      authorizeScope: () => true,
    };
    expect(() =>
      createOperationRouter({
        store: liveStore(counter),
        // @ts-expect-error — spread copy is not factory identity
        auth: forged,
        newRequestId: () => randomUUID(),
      }),
    ).toThrow(OperationRouterCompositionError);
    expect(counter.calls).toBe(0);
  });

  it("throws on spread reject-all flipped to always-true bearer", () => {
    const forged = {
      ...createRejectAllOperationAuth(),
      kind: "implementer_bearer" as const,
      authenticate: () => true,
      authorizeScope: () => true,
    };
    expect(() =>
      createOperationRouter({
        store: liveStore(),
        // @ts-expect-error — stolen shape is not registered
        auth: forged,
        newRequestId: () => randomUUID(),
      }),
    ).toThrow(OperationRouterCompositionError);
  });

  it("deps.auth dual-read getter: always-true after first get cannot open money path", async () => {
    // Snapshot-once gate: getter returns registered binding on first read, then
    // an always-true pair. Hooks and assert must share the first identity so
    // unauthenticated POST cannot reach the store (prior FAIL class).
    const honest = fullAuth();
    let authReads = 0;
    const counter = { calls: 0 };
    const router = createOperationRouter({
      store: liveStore(counter),
      get auth() {
        authReads += 1;
        if (authReads === 1) return honest;
        return {
          kind: "implementer_bearer" as const,
          authenticate: () => true,
          authorizeScope: () => true,
        } as unknown as typeof honest;
      },
      newRequestId: () => randomUUID(),
    } as Parameters<typeof createOperationRouter>[0]);
    // Constructed against the snapshotted honest binding (authReads >= 1).
    expect(authReads).toBe(1);
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), {
      "idempotency-key": IDEM_KEY,
    });
    expect(res.status).toBe(401);
    expect(counter.calls).toBe(0);
    // Pipeline must not re-read deps.auth on the request path either.
    expect(authReads).toBe(1);
  });

  it("deps.store dual-read getter: dispatch uses snapshotted store only", async () => {
    // Assert may see fail-closed; a second get must not swap in a live store
    // for dispatch. Snapshot-once closes over the first identity.
    const failClosed = createFailClosedOperationStore();
    const counter = { calls: 0 };
    const live = liveStore(counter);
    let storeReads = 0;
    const auth = fullAuth();
    const router = createOperationRouter({
      get store() {
        storeReads += 1;
        if (storeReads === 1) return failClosed;
        return live;
      },
      auth,
      newRequestId: () => randomUUID(),
    } as Parameters<typeof createOperationRouter>[0]);
    expect(storeReads).toBe(1);
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), headers(TOKEN_A));
    // Authenticated against fail-closed snapshotted store → 503, never live hit.
    expect(res.status).toBe(503);
    expect(counter.calls).toBe(0);
    expect(storeReads).toBe(1);
  });

  it("deps.store dual-read with reject-all: assert sees fail-closed, never mounts live", () => {
    // If assert re-read store after auth check without snapshot, reject-all +
    // live would only fail when store is live on the assert read. Snapshot of
    // fail-closed first is a legal pair; live on later gets must be ignored.
    const failClosed = createFailClosedOperationStore();
    const live = liveStore();
    let storeReads = 0;
    expect(() =>
      createOperationRouter({
        get store() {
          storeReads += 1;
          if (storeReads === 1) return failClosed;
          return live;
        },
        auth: createRejectAllOperationAuth(),
        newRequestId: () => randomUUID(),
      } as Parameters<typeof createOperationRouter>[0]),
    ).not.toThrow();
    expect(storeReads).toBe(1);
  });
});

describe("implementer bearer — credential matrix", () => {
  async function post(
    auth = fullAuth(),
    hdrs: Record<string, string | undefined> = headers(TOKEN_A),
    counter?: { calls: number },
  ) {
    const c = counter ?? { calls: 0 };
    const router = createOperationRouter({
      store: liveStore(c),
      auth,
      newRequestId: () => randomUUID(),
    });
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), hdrs);
    return { res, calls: c.calls };
  }

  it("valid credential with receive:create reaches the store (201)", async () => {
    const { res, calls } = await post();
    expect(res.status).toBe(201);
    expect(calls).toBe(1);
  });

  it("missing Authorization → 401; store not called", async () => {
    const { res, calls } = await post(fullAuth(), headers(/* no token */));
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
    expect(calls).toBe(0);
  });

  it("malformed Authorization (no Bearer scheme) → 401", async () => {
    const { res, calls } = await post(fullAuth(), {
      "idempotency-key": IDEM_KEY,
      authorization: TOKEN_A,
    });
    expect(res.status).toBe(401);
    expect(calls).toBe(0);
  });

  it("malformed Authorization (wrong prefix, not ik_) → 401", async () => {
    const { res, calls } = await post(fullAuth(), {
      "idempotency-key": IDEM_KEY,
      authorization: "Bearer sk_not_an_implementer_key",
    });
    expect(res.status).toBe(401);
    expect(calls).toBe(0);
  });

  it("revoked credential → 401; store not called", async () => {
    const { res, calls } = await post(fullAuth(TOKEN_A, undefined, true), headers(TOKEN_A));
    expect(res.status).toBe(401);
    expect(calls).toBe(0);
  });

  it("unknown token → 401; store not called", async () => {
    // Auth only knows TOKEN_A; present TOKEN_B (not enrolled).
    const { res, calls } = await post(fullAuth(TOKEN_A), headers(TOKEN_B));
    expect(res.status).toBe(401);
    expect(calls).toBe(0);
  });

  it("insufficient scope → 401 (never 403); store not called", async () => {
    const { res, calls } = await post(
      fullAuth(TOKEN_A, ["receive:read", "send:create"]),
      headers(TOKEN_A),
    );
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
    expect(res.status).not.toBe(403);
    expect(calls).toBe(0);
  });

  it("empty Bearer token → 401", async () => {
    const { res, calls } = await post(fullAuth(), {
      "idempotency-key": IDEM_KEY,
      authorization: "Bearer ",
    });
    expect(res.status).toBe(401);
    expect(calls).toBe(0);
  });
});

describe("production main.ts source — no permissive auth seam", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  // packages/node-core/test → repo root → apps/generic-node/src/main.ts
  const mainPath = resolve(here, "../../../apps/generic-node/src/main.ts");
  const mainSrc = readFileSync(mainPath, "utf8");

  it("does not ship authNotYetEnforced / scopeNotYetEnforced always-true hooks", () => {
    expect(mainSrc).not.toMatch(/authNotYetEnforced/);
    expect(mainSrc).not.toMatch(/scopeNotYetEnforced/);
    expect(mainSrc).not.toMatch(/authenticate\s*:\s*\(\)\s*=>\s*true/);
    expect(mainSrc).not.toMatch(/authorizeScope\s*:\s*\(\)\s*=>\s*true/);
  });

  it("wires live OperationRouteStore + createImplementerBearerAuthFromService", () => {
    expect(mainSrc).toMatch(/createSqlOperationRouteStore\s*\(/);
    expect(mainSrc).toMatch(/createImplementerBearerAuthFromService\s*\(/);
    expect(mainSrc).toMatch(/CredentialService/);
    expect(mainSrc).toMatch(/operationAuth/);
    // Must not ship reject-all as the production /v1 binder.
    expect(mainSrc).not.toMatch(/createRejectAllOperationAuth\s*\(/);
    // Live store replaces fail-closed; must not keep the fail-closed factory mount.
    expect(mainSrc).not.toMatch(/createFailClosedOperationStore\s*\(/);
  });
});

describe("createImplementerBearerAuthFromService", () => {
  function emptyStore(): CredentialStore {
    return {
      async issue() {
        throw new Error("unused");
      },
      async findByHash() {
        return null;
      },
      async findById() {
        return null;
      },
      async listByImplementer() {
        return [];
      },
      async rotate() {
        return false;
      },
      async revoke() {
        return false;
      },
    };
  }

  function memoryStore(rows: StoredCredential[]): CredentialStore {
    return {
      async issue(row, audit) {
        rows.push(row);
        void audit;
      },
      async findByHash(hash) {
        return rows.find((r) => r.credential_hash === hash) ?? null;
      },
      async findById(id, implementerId) {
        return (
          rows.find((r) => r.id === id && r.implementer_id === implementerId) ?? null
        );
      },
      async listByImplementer(implementerId) {
        return rows.filter((r) => r.implementer_id === implementerId);
      },
      async rotate() {
        return false;
      },
      async revoke() {
        return false;
      },
    };
  }

  it("registers as implementer_bearer and pairs with a live store", () => {
    const auth = createImplementerBearerAuthFromService(new CredentialService(emptyStore()));
    expect(isOperationAuthBinding(auth)).toBe(true);
    expect(auth.kind).toBe("implementer_bearer");
    expect(auth.resolveCredential).toBeDefined();
    expect(() => assertOperationAuthComposition(liveStore(), auth)).not.toThrow();
  });

  it("unauthenticated /v1 create collapses to 401 invalid_api_key (no store hit)", async () => {
    const counter = { calls: 0 };
    const router = createOperationRouter({
      store: liveStore(counter),
      auth: createImplementerBearerAuthFromService(new CredentialService(emptyStore())),
      newRequestId: () => randomUUID(),
    });
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), {
      "idempotency-key": IDEM_KEY,
    });
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
    expect(counter.calls).toBe(0);
  });

  it("unknown token collapses to 401; store not called", async () => {
    const counter = { calls: 0 };
    const router = createOperationRouter({
      store: liveStore(counter),
      auth: createImplementerBearerAuthFromService(new CredentialService(emptyStore())),
      newRequestId: () => randomUUID(),
    });
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), {
      "idempotency-key": IDEM_KEY,
      authorization: "Bearer ik_unknown_service_token_xxxx",
    });
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
    expect(counter.calls).toBe(0);
  });

  it("valid CredentialService-issued key authenticates through the live store", async () => {
    const rows: StoredCredential[] = [];
    const service = new CredentialService(memoryStore(rows));
    const issued = await service.create("impl-svc", [
      "receive:create",
      "receive:read",
      "move:create",
      "move:read",
      "send:create",
      "send:read",
      "destination:create",
      "destination:read",
    ]);
    const counter = { calls: 0 };
    const router = createOperationRouter({
      store: liveStore(counter),
      auth: createImplementerBearerAuthFromService(service),
      newRequestId: () => randomUUID(),
    });
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), {
      "idempotency-key": IDEM_KEY,
      authorization: `Bearer ${issued.raw_key}`,
    });
    expect(res.status).toBe(201);
    expect(counter.calls).toBe(1);
  });

  it("refuses a non-service argument", () => {
    expect(() =>
      createImplementerBearerAuthFromService(
        // @ts-expect-error deliberate bad input
        null,
      ),
    ).toThrow(/CredentialValidationService/);
  });
});

describe("brand identity is module-private (no stealable export)", () => {
  it("does not export __testOnly brand symbols or mint helpers", () => {
    expect(
      Object.prototype.hasOwnProperty.call(operationAuthModule, "__testOnly"),
    ).toBe(false);
    expect(
      Object.keys(operationAuthModule).filter((k) => /brand|Brand|testOnly/i.test(k)),
    ).toEqual([]);
  });

  it("factory results carry no own Symbol brand keys", () => {
    const auth = createRejectAllOperationAuth();
    const store = createFailClosedOperationStore();
    expect(Object.getOwnPropertySymbols(auth)).toEqual([]);
    expect(Object.getOwnPropertySymbols(store)).toEqual([]);
  });
});
