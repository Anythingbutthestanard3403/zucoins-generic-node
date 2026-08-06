import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import { describe, expect, it } from "vitest";

import {
  buildNodeIdentityDocument,
  createFailClosedOperationStore,
  createImplementerBearerAuth,
  createImplementerBearerAuthFromService,
  createRejectAllOperationAuth,
  CredentialService,
  createMetricsHooks,
  createNodeMetrics,
  type OperationRouteStore,
  type ReceiveResponse,
} from "@zucoins/node-core";

import { createNodeRuntimeListener, type NodeRuntimeListenerDeps } from "../src/runtime-listener.js";
import {
  operationPathClass,
  sanitizeFailureCause,
  type RuntimeListenerFailureEvent,
  type RuntimeListenerLogger,
} from "../src/runtime-listener.js";
import { NodeReadiness } from "../src/boot/readiness.js";

// the network-containment guard (test/setup-network-guard.ts) replaces http.request and
// net.connect with a throwing stub, so a loopback ephemeral-port round-trip is impossible
// under `--root apps/generic-node`. Instead the real factory listener is driven through
// the same node:http request/response SEAM the health test uses: an async-iterable request
// (the exact shape createServer hands the listener) and a response that captures the write.

const OP_ID = "00000000-0000-0000-0000-000000000001";
const RECEIVE_BODY = JSON.stringify({
  amount_zkz: "5.5",
  anchor: "ord_01J2",
  after_landing: { kind: "HOLD", destination_id: null },
});

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

// Branded fail-closed store — same seam main.ts ships.
function failClosedStore(): OperationRouteStore {
  return createFailClosedOperationStore();
}

const TEST_TOKEN = "ik_test_runtime_listener_token_0001";
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
const TEST_AUTH = createImplementerBearerAuth({
  keys: [{ token: TEST_TOKEN, implementerId: "impl-test", scopes: FULL_SCOPES }],
});
const AUTH_HEADER = { authorization: `Bearer ${TEST_TOKEN}` };

// Production main.ts mounts createImplementerBearerAuthFromService over an empty
// CredentialStore (zero enrolled keys). Unauthenticated and unknown tokens → 401.
const PRODUCTION_EMPTY_AUTH = createImplementerBearerAuthFromService(
  new CredentialService({
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
  }),
);

// Live success store must ride with implementer-bearer auth (composition gate).
function successStore(): OperationRouteStore {
  return {
    createReceive: async () => ({ status: 201 as const, body: RECEIVE_RESPONSE }),
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

function makeDeps(
  store: OperationRouteStore,
  auth = TEST_AUTH,
): NodeRuntimeListenerDeps {
  return {
    readiness: new NodeReadiness(3),
    // Fail-closed DB probe — matches production main.ts.
    pingDb: async () => {
      throw new Error("database adapter is not yet wired in this build — readiness stays false (fail-closed)");
    },
    operationStore: store,
    operationAuth: auth,
    newRequestId: () => randomUUID(),
  };
}

function makeFailClosedDeps(): NodeRuntimeListenerDeps {
  // Production main ships implementer-bearer (empty store), not reject-all.
  return makeDeps(failClosedStore(), PRODUCTION_EMPTY_AUTH);
}

function makeSuccessDeps(store: OperationRouteStore = successStore()): NodeRuntimeListenerDeps {
  return makeDeps(store, TEST_AUTH);
}

interface Captured {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function mockRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: string,
  rawHeaders?: string[],
): IncomingMessage {
  const chunks = body === undefined ? [] : [new TextEncoder().encode(body)];
  // Mirror node: rawHeaders is the flat [name, value, …] occurrence array. When a test
  // doesn't override it, derive a single-occurrence array from the headers map so the
  // listener's rawHeaders-based dedup + normalize path sees the same single values.
  const raw = rawHeaders ?? Object.entries(headers).flatMap(([name, value]) => [name, value]);
  return {
    method,
    url,
    headers,
    rawHeaders: raw,
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) yield chunk;
    },
  } as unknown as IncomingMessage;
}

// Invoke the real listener and resolve when it writes the response (the /v1 path is async).
function invoke(
  deps: NodeRuntimeListenerDeps,
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: string,
  rawHeaders?: string[],
): Promise<Captured> {
  const listener = createNodeRuntimeListener(deps);
  return new Promise<Captured>((resolve) => {
    const captured: Captured = { status: 0, headers: {}, body: "" };
    const response = {
      writeHead(status: number, responseHeaders: Record<string, string>) {
        captured.status = status;
        captured.headers = responseHeaders;
      },
      end(payload?: string | Uint8Array) {
        captured.body = typeof payload === "string" ? payload : Buffer.from(payload ?? "").toString("utf8");
        resolve(captured);
      },
    } as unknown as ServerResponse;
    listener(mockRequest(method, url, headers, body, rawHeaders), response);
  });
}

const IDEM = {
  "idempotency-key": "idem-key-0123456789ab",
  ...AUTH_HEADER,
};

describe("createNodeRuntimeListener — runtime dispatch through the node:http seam (AC#1–5)", () => {
  it("increments auth, idempotency, and operation-created metrics from real operation-router transitions", async () => {
    const metrics = createNodeMetrics();
    const metricsHooks = createMetricsHooks(metrics);
    const deps = { ...makeSuccessDeps(), metricsHooks };

    await invoke(deps, "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(metrics.authTotal.get({ outcome: "authorized" })).toBe(1);
    expect(metrics.idempotencyTotal.get({ outcome: "first" })).toBe(1);
    expect(metrics.operationsCreated.get({ kind: "RECEIVE_EXTERNAL" })).toBe(1);

    const replayStore: OperationRouteStore = {
      ...successStore(),
      createReceive: async () => ({ status: 201 as const, body: RECEIVE_RESPONSE, idempotentReplay: true }),
    };
    await invoke({ ...makeSuccessDeps(replayStore), metricsHooks }, "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(metrics.idempotencyTotal.get({ outcome: "replay" })).toBe(1);
    expect(metrics.operationsCreated.get({ kind: "RECEIVE_EXTERNAL" })).toBe(1);

    await invoke({ ...makeFailClosedDeps(), metricsHooks }, "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(metrics.authTotal.get({ outcome: "rejected" })).toBe(1);
  });

  it("counts SEND_EXTERNAL failed exactly once only after the admin reject transition succeeds", async () => {
    const metrics = createNodeMetrics();
    const metricsHooks = createMetricsHooks(metrics);
    const rejectPath = `/admin/v1/external-sends/${OP_ID}/reject`;
    const successfulReject = async () => ({
      status: 200,
      body: JSON.stringify({ operation_id: OP_ID, status: "REJECTED", row_version: 2 }),
      headers: { "content-type": "application/json; charset=utf-8" },
    });

    await invoke(
      { ...makeSuccessDeps(), metricsHooks, adminRouter: successfulReject },
      "POST",
      rejectPath,
      {},
      "{}",
    );
    expect(metrics.operationsFailed.get({ kind: "SEND_EXTERNAL" })).toBe(1);

    const conflictedReject = async () => ({
      status: 409,
      body: JSON.stringify({ error: { code: "operation_conflict" } }),
      headers: { "content-type": "application/json; charset=utf-8" },
    });
    await invoke(
      { ...makeSuccessDeps(), metricsHooks, adminRouter: conflictedReject },
      "POST",
      rejectPath,
      {},
      "{}",
    );
    expect(metrics.operationsFailed.get({ kind: "SEND_EXTERNAL" })).toBe(1);
  });

  it("leaves the health surface unchanged: GET /health is 200 liveness (AC#1)", async () => {
    const res = await invoke(makeFailClosedDeps(), "GET", "/health");
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as { status: string; version: string; timestamp: string };
    // Liveness shape: alive + version + timestamp (not the earlier "live" stub).
    expect(body.status).toBe("alive");
    expect(typeof body.version).toBe("string");
    expect(typeof body.timestamp).toBe("string");
  });

  it("serves async public discovery without implementer authentication", async () => {
    const document = buildNodeIdentityDocument({
      nodeId: "11111111-1111-4111-8111-111111111111",
      apiVersion: "test",
      supportedOperations: ["RECEIVE_EXTERNAL"],
      canonicalSuites: ["zp-v1"],
      eventSigningKeys: [],
      artifactSigningKeys: [],
    });
    const res = await invoke(
      { ...makeFailClosedDeps(), discoveryDocument: async () => document },
      "GET",
      "/.well-known/zupay-node",
    );
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe("application/json; charset=utf-8");
    expect(res.body).toBe(JSON.stringify(document));
  });

  it("fails discovery closed with structured 503 when the durable key read rejects", async () => {
    const res = await invoke(
      {
        ...makeFailClosedDeps(),
        discoveryDocument: async () => {
          throw new Error("simulated signing-key registry failure");
        },
      },
      "GET",
      "/.well-known/zupay-node",
    );
    expect(res.status).toBe(503);
    expect(res.headers["content-type"]).toBe("application/json; charset=utf-8");
    expect(JSON.parse(res.body).error.code).toBe("service_unavailable");
  });

  it("routes a valid POST /v1/receives to the store and returns 201 byte-exact (AC#1, AC#3)", async () => {
    const res = await invoke(makeSuccessDeps(), "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(res.status).toBe(201);
    expect(res.body).toBe(JSON.stringify(RECEIVE_RESPONSE));
    expect(res.headers["content-type"]).toBe("application/json; charset=utf-8");
  });

  it("returns 401 through the shipping implementer-bearer + fail-closed store seam", async () => {
    // Production main.ts wires implementer-bearer over empty CredentialService:
    // missing/any credential → 401 before the store (never accepted-then-503).
    const create = await invoke(makeFailClosedDeps(), "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(create.status).toBe(401);
    expect(JSON.parse(create.body).error.code).toBe("invalid_api_key");

    const get = await invoke(makeFailClosedDeps(), "GET", `/v1/receives/${OP_ID}`);
    expect(get.status).toBe(401);
    expect(JSON.parse(get.body).error.code).toBe("invalid_api_key");

    // Presenting a well-formed but unknown ik_… key is still 401, not store 503.
    const unknown = await invoke(
      makeFailClosedDeps(),
      "POST",
      "/v1/receives",
      { ...IDEM, authorization: "Bearer ik_unknown_not_enrolled_token" },
      RECEIVE_BODY,
    );
    expect(unknown.status).toBe(401);
    expect(JSON.parse(unknown.body).error.code).toBe("invalid_api_key");
  });

  it("returns 503 from a live-auth + fail-closed store path when auth passes (store still rejects)", async () => {
    const deps = makeDeps(failClosedStore(), TEST_AUTH);
    const create = await invoke(deps, "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(create.status).toBe(503);
    expect(JSON.parse(create.body).error.code).toBe("service_unavailable");
  });

  it("returns 400 on a malformed JSON body (AC#2)", async () => {
    const res = await invoke(makeDeps(failClosedStore(), TEST_AUTH), "POST", "/v1/receives", IDEM, "{not valid json");
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.code).toBe("malformed_json");
  });

  it("returns 404 for an unknown path (AC#5)", async () => {
    const res = await invoke(makeFailClosedDeps(), "GET", "/v1/nope");
    expect(res.status).toBe(404);
  });

  it("returns 404 for a known path with the wrong method — no 405 in the frozen taxonomy (AC#5)", async () => {
    const res = await invoke(makeFailClosedDeps(), "GET", "/v1/receives");
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body).error.code).toBe("not_found");
  });
});

describe("createNodeRuntimeListener — duplicate security headers rejected at the transport", () => {
  function countingStore(counter: { calls: number }): OperationRouteStore {
    return {
      ...failClosedStore(),
      createReceive: async () => {
        counter.calls += 1;
        return { status: 201 as const, body: RECEIVE_RESPONSE };
      },
    };
  }

  it("rejects two Idempotency-Key headers with 400 invalid_idempotency_key; store NOT called", async () => {
    const counter = { calls: 0 };
    const rawHeaders = [
      "Idempotency-Key",
      "idem-key-0123456789ab",
      "Idempotency-Key",
      "idem-key-ffffffffffff",
    ];
    const res = await invoke(makeDeps(countingStore(counter)), "POST", "/v1/receives", {}, RECEIVE_BODY, rawHeaders);
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.code).toBe("invalid_idempotency_key");
    expect(counter.calls).toBe(0);
  });

  it("rejects two Authorization headers with 401 invalid_api_key; store NOT called", async () => {
    const counter = { calls: 0 };
    const rawHeaders = [
      "Idempotency-Key",
      "idem-key-0123456789ab",
      "Authorization",
      "Bearer alpha",
      "Authorization",
      "Bearer beta",
    ];
    const res = await invoke(makeDeps(countingStore(counter)), "POST", "/v1/receives", {}, RECEIVE_BODY, rawHeaders);
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
    expect(counter.calls).toBe(0);
  });

  it("a single valid Idempotency-Key still routes to the store (201)", async () => {
    const res = await invoke(makeSuccessDeps(), "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(res.status).toBe(201);
    expect(res.body).toBe(JSON.stringify(RECEIVE_RESPONSE));
  });
});

describe("createNodeRuntimeListener — production composition refuses permissive auth", () => {
  it("createOperationRouter refuses unbranded always-true hooks when a live store is mounted", async () => {
    // Listener construction defers to createOperationRouter — unbranded auth throws.
    expect(() =>
      createNodeRuntimeListener({
        readiness: new NodeReadiness(3),
        pingDb: async () => {},
        operationStore: successStore(),
        // @ts-expect-error deliberate unbranded forge
        operationAuth: {
          kind: "implementer_bearer",
          authenticate: () => true,
          authorizeScope: () => true,
        },
        newRequestId: () => randomUUID(),
      }),
    ).toThrow(/unbranded|refused|OperationRouterCompositionError|operation auth must be created/i);
  });

  it("createOperationRouter refuses reject-all auth with a live store", () => {
    expect(() =>
      createNodeRuntimeListener({
        readiness: new NodeReadiness(3),
        pingDb: async () => {},
        operationStore: successStore(),
        operationAuth: createRejectAllOperationAuth(),
        newRequestId: () => randomUUID(),
      }),
    ).toThrow(/reject-all operation auth cannot coexist with a live operation store/);
  });

  it("missing Authorization on a live-auth surface yields 401, not a store hit", async () => {
    const counter = { calls: 0 };
    const store: OperationRouteStore = {
      ...successStore(),
      createReceive: async () => {
        counter.calls += 1;
        return { status: 201 as const, body: RECEIVE_RESPONSE };
      },
    };
    const res = await invoke(
      makeDeps(store, TEST_AUTH),
      "POST",
      "/v1/receives",
      { "idempotency-key": "idem-key-0123456789ab" },
      RECEIVE_BODY,
    );
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
    expect(counter.calls).toBe(0);
  });

  it("revoked credential yields 401", async () => {
    const auth = createImplementerBearerAuth({
      keys: [{ token: TEST_TOKEN, implementerId: "impl-test", scopes: FULL_SCOPES, revoked: true }],
    });
    const res = await invoke(makeDeps(successStore(), auth), "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
  });

  it("unknown token yields 401", async () => {
    const res = await invoke(
      makeDeps(successStore(), TEST_AUTH),
      "POST",
      "/v1/receives",
      {
        "idempotency-key": "idem-key-0123456789ab",
        authorization: "Bearer ik_other_tenant_token_xxxx",
      },
      RECEIVE_BODY,
    );
    expect(res.status).toBe(401);
  });

  it("deps.operationAuth dual-read getter cannot open unauthenticated money path", async () => {
    // Listener + router each snapshot auth once. A getter that returns registered
    // identity on first get and always-true thereafter must not yield 201 unauth.
    const honest = createImplementerBearerAuth({
      keys: [{ token: TEST_TOKEN, implementerId: "impl-test", scopes: FULL_SCOPES }],
    });
    let authReads = 0;
    const counter = { calls: 0 };
    const store: OperationRouteStore = {
      ...successStore(),
      createReceive: async () => {
        counter.calls += 1;
        return { status: 201 as const, body: RECEIVE_RESPONSE };
      },
    };
    const base = makeDeps(store, honest);
    const flippingDeps = {
      ...base,
      get operationAuth() {
        authReads += 1;
        if (authReads === 1) return honest;
        return {
          kind: "implementer_bearer" as const,
          authenticate: () => true,
          authorizeScope: () => true,
        } as unknown as typeof honest;
      },
    } as NodeRuntimeListenerDeps;
    const res = await invoke(
      flippingDeps,
      "POST",
      "/v1/receives",
      { "idempotency-key": "idem-key-0123456789ab" },
      RECEIVE_BODY,
    );
    expect(res.status).toBe(401);
    expect(counter.calls).toBe(0);
  });

  it("insufficient scope yields 401 (the error contract defines no 403 code)", async () => {
    const auth = createImplementerBearerAuth({
      keys: [{ token: TEST_TOKEN, implementerId: "impl-test", scopes: ["receive:read"] }],
    });
    const res = await invoke(makeDeps(successStore(), auth), "POST", "/v1/receives", IDEM, RECEIVE_BODY);
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).error.code).toBe("invalid_api_key");
  });
});

// ---------------------------------------------------------------------------
// Unexpected /v1 failures log once, keep 503 envelope, redact secrets
// ---------------------------------------------------------------------------

function capturingLogger(): {
  logger: RuntimeListenerLogger;
  events: RuntimeListenerFailureEvent[];
} {
  const events: RuntimeListenerFailureEvent[] = [];
  return {
    events,
    logger: {
      error(event) {
        events.push(event);
      },
    },
  };
}

const FIXED_REQ_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

function serviceUnavailableBody(requestId: string): string {
  return JSON.stringify({
    error: {
      code: "service_unavailable",
      message: "The service is temporarily unavailable.",
      request_id: requestId,
      details: {},
    },
  });
}

function assertOpaque503(res: Captured, requestId: string): void {
  expect(res.status).toBe(503);
  expect(res.body).toBe(serviceUnavailableBody(requestId));
  expect(res.body).not.toMatch(/stack|at\s+\S+\s+\(/i);
  expect(res.body).not.toContain("Bearer");
  expect(res.body).not.toContain("ik_");
  expect(res.body).not.toContain("transfer");
}

describe("createNodeRuntimeListener — unexpected failure evidence", () => {
  it("auth/credential resolver throw → 503 + one sanitized log", async () => {
    const { logger, events } = capturingLogger();
    const auth = createImplementerBearerAuthFromService(
      new CredentialService({
        async issue() {
          throw new Error("unused");
        },
        async findByHash() {
          throw new Error(
            "credential store down Bearer ik_leaked_token_value_xxx authorization=supersecret",
          );
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
      }),
    );
    const res = await invoke(
      {
        ...makeDeps(successStore(), auth),
        newRequestId: () => FIXED_REQ_ID,
        logger,
      },
      "POST",
      "/v1/receives",
      IDEM,
      RECEIVE_BODY,
    );
    assertOpaque503(res, FIXED_REQ_ID);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      event: "operation_listener_unexpected_failure",
      request_id: FIXED_REQ_ID,
      method: "POST",
      path_class: "POST /v1/receives",
    });
    expect(events[0]!.cause_message).not.toContain("ik_leaked");
    expect(events[0]!.cause_message).not.toContain("supersecret");
    expect(events[0]!.cause_message).toMatch(/ik_\[redacted\]|Bearer \[redacted\]|authorization=\[redacted\]/i);
  });

  it("store throw that escapes handlers is logged (router returns mapped 503 without unexpected log)", async () => {
    const { logger, events } = capturingLogger();
    // Fail-closed reject is caught inside operation-routes → ordered 503, no listener log.
    const ordered = await invoke(
      {
        ...makeDeps(failClosedStore(), TEST_AUTH),
        newRequestId: () => FIXED_REQ_ID,
        logger,
      },
      "POST",
      "/v1/receives",
      IDEM,
      RECEIVE_BODY,
    );
    expect(ordered.status).toBe(503);
    expect(JSON.parse(ordered.body).error.code).toBe("service_unavailable");
    expect(events).toHaveLength(0);

    // A live store that throws a non-Error string forces mapStoreError → still ordered.
    const throwingStore: OperationRouteStore = {
      ...successStore(),
      createReceive: async () => {
        throw new Error("db: relation operations does not exist");
      },
    };
    const mapped = await invoke(
      {
        ...makeDeps(throwingStore, TEST_AUTH),
        newRequestId: () => FIXED_REQ_ID,
        logger,
      },
      "POST",
      "/v1/receives",
      IDEM,
      RECEIVE_BODY,
    );
    expect(mapped.status).toBe(503);
    expect(events).toHaveLength(0);
  });

  it("body stream read failure → 503 + log with path class", async () => {
    const { logger, events } = capturingLogger();
    const deps = {
      ...makeDeps(successStore(), TEST_AUTH),
      newRequestId: () => FIXED_REQ_ID,
      logger,
    };
    const listener = createNodeRuntimeListener(deps);
    const res = await new Promise<Captured>((resolve) => {
      const captured: Captured = { status: 0, headers: {}, body: "" };
      const response = {
        writeHead(status: number, responseHeaders: Record<string, string>) {
          captured.status = status;
          captured.headers = responseHeaders;
        },
        end(payload?: string | Uint8Array) {
          captured.body = typeof payload === "string" ? payload : Buffer.from(payload ?? "").toString("utf8");
          resolve(captured);
        },
      } as unknown as ServerResponse;
      const request = {
        method: "POST",
        url: `/v1/receives/${OP_ID}`,
        headers: IDEM,
        rawHeaders: Object.entries(IDEM).flatMap(([n, v]) => [n, v]),
        // eslint-disable-next-line require-yield -- intentional: simulates a stream that errors before yielding
        async *[Symbol.asyncIterator]() {
          throw new Error("ECONNRESET while reading body");
        },
      } as unknown as IncomingMessage;
      listener(request, response);
    });
    assertOpaque503(res, FIXED_REQ_ID);
    expect(events).toHaveLength(1);
    expect(events[0]!.path_class).toBe("POST /v1/receives/:operation_id");
    expect(events[0]!.cause_message).toContain("ECONNRESET");
  });

  it("response write failure on success path → 503 attempt + log of write cause", async () => {
    const { logger, events } = capturingLogger();
    const deps = {
      ...makeSuccessDeps(),
      newRequestId: () => FIXED_REQ_ID,
      logger,
    };
    const listener = createNodeRuntimeListener(deps);
    await new Promise<void>((resolve) => {
      let writes = 0;
      const response = {
        writeHead() {
          writes += 1;
          // First write is the success body — throw so catch fires.
          throw new Error("EPIPE while writing response");
        },
        end() {
          throw new Error("end should not run");
        },
      } as unknown as ServerResponse;
      const raw = Object.entries(IDEM).flatMap(([n, v]) => [n, v]);
      const request = {
        method: "POST",
        url: "/v1/receives",
        headers: IDEM,
        rawHeaders: raw,
        async *[Symbol.asyncIterator]() {
          yield new TextEncoder().encode(RECEIVE_BODY);
        },
      } as unknown as IncomingMessage;
      listener(request, response);
      setTimeout(() => {
        expect(writes).toBeGreaterThanOrEqual(1);
        resolve();
      }, 40);
    });
    expect(events).toHaveLength(1);
    expect(events[0]!.path_class).toBe("POST /v1/receives");
    expect(events[0]!.cause_message).toContain("EPIPE");
  });

  it("response write failure after auth throw still logs once (write of 503 never re-throws out)", async () => {
    const { logger, events } = capturingLogger();
    const auth = createImplementerBearerAuthFromService(
      new CredentialService({
        async issue() {
          throw new Error("unused");
        },
        async findByHash() {
          throw new Error("auth resolver boom");
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
      }),
    );
    const deps = {
      ...makeDeps(successStore(), auth),
      newRequestId: () => FIXED_REQ_ID,
      logger,
    };
    const listener = createNodeRuntimeListener(deps);
    await new Promise<void>((resolve) => {
      const response = {
        writeHead() {
          throw new Error("EPIPE write failed");
        },
        end() {
          throw new Error("should not reach end after writeHead throw");
        },
      } as unknown as ServerResponse;
      const request = {
        method: "GET",
        url: `/v1/receives/${OP_ID}?q=1`,
        headers: AUTH_HEADER,
        rawHeaders: Object.entries(AUTH_HEADER).flatMap(([n, v]) => [n, v]),
        async *[Symbol.asyncIterator]() {},
      } as unknown as IncomingMessage;
      // Listener swallows; resolve on next tick after the async catch settles.
      void Promise.resolve(listener(request, response)).then(() => {
        setTimeout(resolve, 0);
      });
      setTimeout(resolve, 30);
    });
    expect(events).toHaveLength(1);
    expect(events[0]!.path_class).toBe("GET /v1/receives/:operation_id");
    expect(events[0]!.cause_message).toContain("auth resolver boom");
  });

  it("logger throw does not replace byte-exact 503", async () => {
    const logger: RuntimeListenerLogger = {
      error() {
        throw new Error("telemetry sink down Bearer ik_should_not_leak");
      },
    };
    const auth = createImplementerBearerAuthFromService(
      new CredentialService({
        async issue() {
          throw new Error("unused");
        },
        async findByHash() {
          throw new Error("auth boom");
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
      }),
    );
    const res = await invoke(
      {
        ...makeDeps(successStore(), auth),
        newRequestId: () => FIXED_REQ_ID,
        logger,
      },
      "POST",
      "/v1/receives",
      IDEM,
      RECEIVE_BODY,
    );
    assertOpaque503(res, FIXED_REQ_ID);
  });

  it("success path does not emit unexpected-failure logs", async () => {
    const { logger, events } = capturingLogger();
    const res = await invoke(
      { ...makeSuccessDeps(), logger },
      "POST",
      "/v1/receives",
      IDEM,
      RECEIVE_BODY,
    );
    expect(res.status).toBe(201);
    expect(events).toHaveLength(0);
  });
});

describe("operationPathClass + sanitizeFailureCause", () => {
  it("classifies collection and item routes without embedding ids", () => {
    expect(operationPathClass("post", "/v1/receives")).toBe("POST /v1/receives");
    expect(operationPathClass("GET", `/v1/receives/${OP_ID}?x=1`)).toBe(
      "GET /v1/receives/:operation_id",
    );
    expect(operationPathClass("POST", "/v1/internal-moves")).toBe("POST /v1/internal-moves");
    expect(operationPathClass("GET", `/v1/external-sends/${OP_ID}`)).toBe(
      "GET /v1/external-sends/:operation_id",
    );
    expect(operationPathClass("DELETE", "/v1/nope")).toBe("DELETE /v1/*");
  });

  it("redacts credentials, transfer codes, and high-entropy blobs from cause messages", () => {
    const out = sanitizeFailureCause(
      new Error(
        "failed auth Bearer ik_abcDEF1234567890 sh_sub_handle_secret authorization=totally-secret " +
          "transfer_code=ABCD1234 preimage=xyz private_key=deadbeef " +
          `${"A".repeat(60)}==`,
      ),
    );
    expect(out.cause_name).toBe("Error");
    expect(out.cause_message).not.toContain("ik_abc");
    expect(out.cause_message).not.toContain("sh_sub");
    expect(out.cause_message).not.toContain("totally-secret");
    expect(out.cause_message).not.toContain("ABCD1234");
    expect(out.cause_message).not.toMatch(/A{60}/);
    expect(out.cause_message).toMatch(/\[redacted/);
  });
});