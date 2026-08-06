import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  ApiErrorEnvelopeSchema,
  createFailClosedOperationStore,
  createImplementerBearerAuth,
  createOperationRouter,
  createRejectAllOperationAuth,
  HTTP_STATUS_BY_CODE,
  OperationRouterCompositionError,
  type OperationRouterDeps,
} from "../src/api/index.js";
import type {
  ExternalSendResponse,
  InternalMoveResponse,
  OperationObject,
  OperationRouteStore,
  ReceiveResponse,
} from "../src/api/routes/index.js";

const encode = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));

const OP_ID = "00000000-0000-0000-0000-000000000001";
const IDEM = { "idempotency-key": "idem-key-0123456789ab" } as const;
const RECEIVE_BODY = {
  amount_zkz: "5.5",
  anchor: "ord_01J2",
  after_landing: { kind: "HOLD", destination_id: null },
};

const OP_BASE: OperationObject = {
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
};

// Deliberately distinctive expected_artifact: double spaces inside preimage_text and a
// full 88-char signature. These are the signed bytes Byte-exact must never touch.
const RECEIVE_RESPONSE: ReceiveResponse = {
  operation: OP_BASE,
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

const MOVE_RESPONSE: InternalMoveResponse = {
  operation: { ...OP_BASE, operation_type: "MOVE_INTERNAL", state: "CREATED", row_version: 1 },
  source_wallet_id: "00000000-0000-0000-0000-000000000010",
  destination_id: "00000000-0000-0000-0000-000000000020",
  spawned_from_operation_id: null,
  lease_status: "WAITING",
  expected_artifact: null,
};

const SEND_RESPONSE: ExternalSendResponse = {
  operation: { ...OP_BASE, operation_type: "SEND_EXTERNAL", state: "CREATED", row_version: 1 },
  source_wallet_id: "00000000-0000-0000-0000-000000000010",
  destination_address: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
  references_operation_id: null,
  approval_status: "PENDING",
  transfer_code: null,
  transfer_code_sha256: null,
  available_until: null,
  expected_artifact: null,
};

function makeStore(overrides: Partial<OperationRouteStore> = {}): OperationRouteStore {
  return {
    createReceive: async () => ({ status: 201 as const, body: RECEIVE_RESPONSE }),
    getReceive: async () => RECEIVE_RESPONSE,
    createInternalMove: async () => ({ status: 201 as const, body: MOVE_RESPONSE }),
    getInternalMove: async () => MOVE_RESPONSE,
    createExternalSend: async () => ({ status: 201 as const, body: SEND_RESPONSE }),
    getExternalSend: async () => SEND_RESPONSE,
    ...overrides,
  };
}

// Branded fail-closed store — same seam production ships.
function failClosedStore(): OperationRouteStore {
  return createFailClosedOperationStore();
}

const TEST_TOKEN = "ik_test_operation_router_token_0001";
const TEST_AUTH = createImplementerBearerAuth({
  keys: [
    {
      token: TEST_TOKEN,
      implementerId: "impl-test",
      scopes: [
        "receive:create",
        "receive:read",
        "move:create",
        "move:read",
        "send:create",
        "send:read",
        "destination:create",
        "destination:read",
      ],
    },
  ],
});
const AUTH = { authorization: `Bearer ${TEST_TOKEN}` } as const;

function makeDeps(overrides: Partial<OperationRouterDeps> = {}): OperationRouterDeps {
  return {
    store: makeStore(),
    auth: TEST_AUTH,
    newRequestId: () => randomUUID(),
    ...overrides,
  };
}

function withAuth(
  headers: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return { ...AUTH, ...headers };
}

describe("createOperationRouter — route matching and dispatch (AC#1)", () => {
  it("dispatches all six mounted routes to their handler", async () => {
    const router = createOperationRouter(makeDeps());
    expect((await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM))).status).toBe(201);
    expect((await router("GET", `/v1/receives/${OP_ID}`, new Uint8Array(0), withAuth())).status).toBe(200);
    expect(
      (await router(
        "POST",
        "/v1/internal-moves",
        encode({
          source_wallet_id: "00000000-0000-0000-0000-000000000010",
          destination_id: "00000000-0000-0000-0000-000000000020",
          amount_zkz: "5.5",
        }),
        withAuth(IDEM),
      )).status,
    ).toBe(201);
    expect((await router("GET", `/v1/internal-moves/${OP_ID}`, new Uint8Array(0), withAuth())).status).toBe(200);
    expect(
      (await router(
        "POST",
        "/v1/external-sends",
        encode({
          source_wallet_id: "00000000-0000-0000-0000-000000000010",
          destination_address: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
          amount_zkz: "5.5",
        }),
        withAuth(IDEM),
      )).status,
    ).toBe(201);
    expect((await router("GET", `/v1/external-sends/${OP_ID}`, new Uint8Array(0), withAuth())).status).toBe(200);
  });

  it("does not mount GET /v1/operations (dropped by)", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("GET", "/v1/operations?limit=10", new Uint8Array(0), withAuth());
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body).error.code).toBe("not_found");
  });
});

describe("createOperationRouter — Byte-exact byte-exact success body (AC#3)", () => {
  it("serves the handler success body VERBATIM, unaltered and un-prettified", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM));
    expect(res.status).toBe(201);

    // The handler produces exactly JSON.stringify(store body); the router must not
    // re-serialize, reorder, or reformat it.
    const expected = JSON.stringify(RECEIVE_RESPONSE);
    expect(res.body).toBe(expected);
    // Byte-for-byte, not merely string-equal by coincidence of normalization.
    expect([...new TextEncoder().encode(res.body)]).toEqual([...new TextEncoder().encode(expected)]);
    // A re-stringify/prettify bug would collapse the significant inner whitespace or
    // pretty-print; assert neither happened.
    expect(res.body).toContain('"preimage_text":"canonical  text  with  double  spaces"');
    expect(res.body).toContain(`"signature":"${"A".repeat(86)}=="`);
    expect(res.body).not.toBe(JSON.stringify(RECEIVE_RESPONSE, null, 2));
    expect(res.headers["content-type"]).toBe("application/json; charset=utf-8");
  });
});

describe("createOperationRouter — pipeline 400s on the specific breaking input (AC#2)", () => {
  it("rejects an unknown field with 400 unknown_field", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("POST", "/v1/receives", encode({ ...RECEIVE_BODY, bogus: 1 }), withAuth(IDEM));
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.code).toBe("unknown_field");
  });

  it("rejects a JSON-number amount (non-canonical) with 400 invalid_scalar", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("POST", "/v1/receives", encode({ ...RECEIVE_BODY, amount_zkz: 5.5 }), withAuth(IDEM));
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.code).toBe("invalid_scalar");
  });

  it("rejects a missing Idempotency-Key with 400 invalid_idempotency_key", async () => {
    const router = createOperationRouter(makeDeps());
    // Auth must pass first (stage 2) so stage 4 can emit the idempotency error.
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth());
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.code).toBe("invalid_idempotency_key");
  });
});

describe("createOperationRouter — 404 unknown path (AC#5)", () => {
  it("returns 404 not_found for an unknown /v1 path", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("GET", "/v1/nonexistent", new Uint8Array(0), withAuth());
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body).error.code).toBe("not_found");
  });

  it("does not shim a forbidden path — /v1/payments is a plain 404", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("POST", "/v1/payments", encode({}), withAuth(IDEM));
    expect(res.status).toBe(404);
  });

  it("treats a trailing slash as an empty operation_id → 404, not a match", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("GET", "/v1/receives/", new Uint8Array(0), withAuth());
    expect(res.status).toBe(404);
  });
});

describe("createOperationRouter — known path, wrong method → 404 (frozen taxonomy has no 405) (AC#5)", () => {
  it("collapses GET on the POST-only collection to 404 not_found, with no Allow header", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("GET", "/v1/receives", new Uint8Array(0), withAuth());
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body).error.code).toBe("not_found");
    expect(res.headers.allow).toBeUndefined();
  });

  it("collapses POST on the GET-only item route to 404 not_found", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("POST", `/v1/receives/${OP_ID}`, encode(RECEIVE_BODY), withAuth(IDEM));
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body).error.code).toBe("not_found");
  });
});

describe("createOperationRouter — every emittable error body satisfies the frozen envelope (AC#5)", () => {
  // The guard that would have caught the out-of-taxonomy 405: for EVERY error the
  // router can emit, the body must parse as ApiErrorEnvelopeSchema (code ∈ the frozen
  // enum) AND its code must map to the emitted HTTP status via HTTP_STATUS_BY_CODE.
  const cases: { name: string; run: () => Promise<{ status: number; body: string }> }[] = [
    {
      name: "not_found (unknown path)",
      run: () => createOperationRouter(makeDeps())("GET", "/v1/nonexistent", new Uint8Array(0), withAuth()),
    },
    {
      name: "not_found (known path, wrong method)",
      run: () => createOperationRouter(makeDeps())("GET", "/v1/receives", new Uint8Array(0), withAuth()),
    },
    {
      name: "invalid_api_key (reject-all auth)",
      run: () =>
        createOperationRouter(makeDeps({ store: failClosedStore(), auth: createRejectAllOperationAuth() }))(
          "POST",
          "/v1/receives",
          encode(RECEIVE_BODY),
          withAuth(IDEM),
        ),
    },
    {
      name: "invalid_api_key (insufficient scope — ROUTE_POLICIES scope gate)",
      run: () =>
        createOperationRouter(
          makeDeps({
            auth: createImplementerBearerAuth({
              keys: [
                {
                  token: TEST_TOKEN,
                  implementerId: "impl-test",
                  scopes: ["receive:read"],
                },
              ],
            }),
          }),
        )("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM)),
    },
    {
      name: "invalid_idempotency_key (missing header)",
      run: () => createOperationRouter(makeDeps())("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth()),
    },
    {
      name: "unknown_field",
      run: () =>
        createOperationRouter(makeDeps())("POST", "/v1/receives", encode({ ...RECEIVE_BODY, bogus: 1 }), withAuth(IDEM)),
    },
    {
      name: "invalid_scalar (JSON-number amount)",
      run: () =>
        createOperationRouter(makeDeps())("POST", "/v1/receives", encode({ ...RECEIVE_BODY, amount_zkz: 5.5 }), withAuth(IDEM)),
    },
    {
      name: "malformed_json",
      run: () =>
        createOperationRouter(makeDeps())("POST", "/v1/receives", new TextEncoder().encode("{not json"), withAuth(IDEM)),
    },
    {
      name: "service_unavailable (fail-closed store)",
      run: () =>
        createOperationRouter(makeDeps({ store: failClosedStore() }))(
          "POST",
          "/v1/receives",
          encode(RECEIVE_BODY),
          withAuth(IDEM),
        ),
    },
  ];

  it.each(cases)("$name → valid envelope with status === HTTP_STATUS_BY_CODE[code]", async ({ run }) => {
    const res = await run();
    const parsed = ApiErrorEnvelopeSchema.safeParse(JSON.parse(res.body));
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(HTTP_STATUS_BY_CODE[parsed.data.error.code]).toBe(res.status);
    }
  });
});

describe("createOperationRouter — No-blind-retry exactly-once, no retry (AC#5)", () => {
  it("calls the store exactly once on success", async () => {
    let calls = 0;
    const store = makeStore({
      createReceive: async () => {
        calls += 1;
        return { status: 201 as const, body: RECEIVE_RESPONSE };
      },
    });
    const router = createOperationRouter(makeDeps({ store }));
    await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM));
    expect(calls).toBe(1);
  });

  it("calls the store exactly once even when it rejects — never blind-retries", async () => {
    let calls = 0;
    const store = makeStore({
      createReceive: async () => {
        calls += 1;
        throw new Error("submit failed");
      },
    });
    const router = createOperationRouter(makeDeps({ store }));
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM));
    expect(res.status).toBe(503);
    expect(calls).toBe(1);
  });
});

describe("createOperationRouter — fail-closed store → 503, never fake success/404 (AC#4)", () => {
  it("returns 503 service_unavailable when a create store rejects", async () => {
    const router = createOperationRouter(makeDeps({ store: failClosedStore() }));
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM));
    expect(res.status).toBe(503);
    expect(JSON.parse(res.body).error.code).toBe("service_unavailable");
  });

  it("returns 503 — NOT a fake 404 — when a GET-by-id store rejects", async () => {
    const router = createOperationRouter(makeDeps({ store: failClosedStore() }));
    const res = await router("GET", `/v1/receives/${OP_ID}`, new Uint8Array(0), withAuth());
    expect(res.status).toBe(503);
    expect(JSON.parse(res.body).error.code).toBe("service_unavailable");
  });
});

describe("createOperationRouter — authentication + ROUTE_POLICIES scope gate (AC#2, D2)", () => {
  it("returns 401 invalid_api_key when reject-all auth is wired", async () => {
    const router = createOperationRouter(
      makeDeps({ store: failClosedStore(), auth: createRejectAllOperationAuth() }),
    );
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM));
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
  });

  it("returns 401 invalid_api_key when the bearer credential is missing", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), { ...IDEM });
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
  });

  it("returns 401 invalid_api_key when the credential lacks receive:create — never 403", async () => {
    const router = createOperationRouter(
      makeDeps({
        auth: createImplementerBearerAuth({
          keys: [
            {
              token: TEST_TOKEN,
              implementerId: "impl-test",
              scopes: ["receive:read"],
            },
          ],
        }),
      }),
    );
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM));
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
  });

  it("accepts a credential with receive:create and reaches the store (201)", async () => {
    const router = createOperationRouter(makeDeps());
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), withAuth(IDEM));
    expect(res.status).toBe(201);
  });
});

describe("createOperationRouter — production composition gate", () => {
  it("refuses unbranded always-true authenticate hooks at construction", () => {
    expect(() =>
      createOperationRouter({
        store: makeStore(),
        // @ts-expect-error — unbranded permissive hooks must not type-check
        auth: {
          kind: "implementer_bearer",
          authenticate: () => true,
          authorizeScope: () => true,
        },
        newRequestId: () => randomUUID(),
      }),
    ).toThrow(OperationRouterCompositionError);
  });

  it("refuses reject-all auth paired with a live (non-fail-closed) store", () => {
    expect(() =>
      createOperationRouter(
        makeDeps({ store: makeStore(), auth: createRejectAllOperationAuth() }),
      ),
    ).toThrow(/reject-all operation auth cannot coexist with a live operation store/);
  });

  it("allows reject-all auth only with a branded fail-closed store", () => {
    expect(() =>
      createOperationRouter(
        makeDeps({ store: failClosedStore(), auth: createRejectAllOperationAuth() }),
      ),
    ).not.toThrow();
  });

  it("a plain object store is treated as live even if every method rejects", () => {
    const reject = (): Promise<never> => Promise.reject(new Error("reject"));
    const plainRejecting: OperationRouteStore = {
      createReceive: reject,
      getReceive: reject,
      createInternalMove: reject,
      getInternalMove: reject,
      createExternalSend: reject,
      getExternalSend: reject,
    };
    expect(() =>
      createOperationRouter(
        makeDeps({ store: plainRejecting, auth: createRejectAllOperationAuth() }),
      ),
    ).toThrow(OperationRouterCompositionError);
  });

  it("deps.auth dual-read cannot install always-true hooks after WeakSet assert", async () => {
    const honest = createImplementerBearerAuth({
      keys: [
        {
          token: "ik_router_toctou_token_aaaa",
          implementerId: "impl-toctou",
          scopes: [
            "receive:create",
            "receive:read",
            "move:create",
            "move:read",
            "send:create",
            "send:read",
            "destination:create",
            "destination:read",
          ],
        },
      ],
    });
    let authReads = 0;
    const calls = { n: 0 };
    const store: OperationRouteStore = {
      ...makeStore(),
      createReceive: async () => {
        calls.n += 1;
        return { status: 201 as const, body: RECEIVE_RESPONSE };
      },
    };
    const router = createOperationRouter({
      store,
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
    expect(authReads).toBe(1);
    const res = await router("POST", "/v1/receives", encode(RECEIVE_BODY), {
      "idempotency-key": IDEM["idempotency-key"],
    });
    expect(res.status).toBe(401);
    expect(calls.n).toBe(0);
    expect(authReads).toBe(1);
  });
});
