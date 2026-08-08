/**
 * Money-create request-volume throttle on the /v1 implementer surface (ZTR-1201).
 *
 * Subject under test is production code only: createOperationRouter's `createThrottle`
 * wrapped around admission, driven through the production auth composition
 * (createImplementerBearerAuth) and the node's one limiter shape
 * (InMemoryReportingRateLimiter).
 *
 * The properties pinned here:
 *   - an over-rate create is shed with the frozen 429 `rate_limited` + Retry-After,
 *     rendered through the canonical envelope;
 *   - an under-rate caller is never shed, and one implementer's flood never sheds another's;
 *   - reads are never shed — the throttle covers the three create routes only;
 *   - the throttle is not an oracle: it runs strictly after authenticate+authorize, so a
 *     bad key and an out-of-scope key still answer the generic 401, never a 429;
 *   - it wraps admission — a shed request never reaches the store, so no money-path
 *     transaction is entered.
 */

import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  apiErrorResponse,
  createImplementerBearerAuth,
  createOperationRouter,
  type OperationObject,
  type OperationRouteStore,
  type ReceiveResponse,
} from "../src/api/index.js";
import { InMemoryReportingRateLimiter } from "../src/reporting/in-memory-rate-limiter.js";

const encode = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));

const NODE_ID = "00000000-0000-0000-0000-00000000node";
const SEEDED_OP = "00000000-0000-0000-0000-0000000000a1";
const REQUEST_ID = "req-rate-limit-0001";
const RECEIVE_BODY = {
  amount_zkz: "5.5",
  anchor: "anc_01J2",
  after_landing: { kind: "HOLD" as const, destination_id: null },
};

const TOKEN_A = "ik_rate_limit_tenant_a_token_aaaa";
const TOKEN_B = "ik_rate_limit_tenant_b_token_bbbb";
const TOKEN_READ_ONLY = "ik_rate_limit_readonly_token_cccc";

const FULL_SCOPES = ["receive:create", "receive:read"] as const;

// Two, so the ceiling is reachable without spending the test's time on volume.
const MAX_CREATES_PER_WINDOW = 2;
const WINDOW_MS = 60_000;
const RETRY_AFTER_SECONDS = WINDOW_MS / 1000;

function receiveBody(id: string): ReceiveResponse {
  const operation: OperationObject = {
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
  return {
    operation,
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

/** Records every store touch so "a shed request never reaches the store" is observable. */
function countingStore(): { store: OperationRouteStore; creates: number; reads: number } {
  const counters = { creates: 0, reads: 0 };
  const store: OperationRouteStore = {
    async createReceive() {
      counters.creates += 1;
      return { status: 201 as const, body: receiveBody(randomUUID()) };
    },
    async getReceive(operationId) {
      counters.reads += 1;
      return operationId === SEEDED_OP ? receiveBody(SEEDED_OP) : null;
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
  return {
    store,
    get creates() {
      return counters.creates;
    },
    get reads() {
      return counters.reads;
    },
  };
}

function throttledRouter(store: OperationRouteStore) {
  return createOperationRouter({
    store,
    auth: createImplementerBearerAuth({
      keys: [
        { token: TOKEN_A, implementerId: "impl-a", scopes: [...FULL_SCOPES] },
        { token: TOKEN_B, implementerId: "impl-b", scopes: [...FULL_SCOPES] },
        { token: TOKEN_READ_ONLY, implementerId: "impl-a", scopes: ["receive:read"] },
      ],
    }),
    newRequestId: () => REQUEST_ID,
    createThrottle: {
      limiter: new InMemoryReportingRateLimiter(WINDOW_MS, MAX_CREATES_PER_WINDOW),
      nodeId: NODE_ID,
      retryAfterSeconds: RETRY_AFTER_SECONDS,
    },
  });
}

const createHeaders = (token: string, key: string): Record<string, string | undefined> => ({
  authorization: `Bearer ${token}`,
  "idempotency-key": key,
});

describe("money-create volume throttle (ZTR-1201)", () => {
  it("admits the budget, then sheds with the canonical 429 rate_limited + Retry-After", async () => {
    const counting = countingStore();
    const router = throttledRouter(counting.store);

    for (let i = 0; i < MAX_CREATES_PER_WINDOW; i += 1) {
      const admitted = await router(
        "POST",
        "/v1/receives",
        encode(RECEIVE_BODY),
        createHeaders(TOKEN_A, `idem-key-under-rate-${i}`),
      );
      expect(admitted.status).toBe(201);
    }
    expect(counting.creates).toBe(MAX_CREATES_PER_WINDOW);

    const shed = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      createHeaders(TOKEN_A, "idem-key-over-rate-01"),
    );

    const expected = apiErrorResponse("rate_limited", REQUEST_ID, undefined, RETRY_AFTER_SECONDS);
    expect(shed.status).toBe(429);
    expect(shed.body).toBe(expected.body);
    expect(shed.headers["Retry-After"]).toBe(String(RETRY_AFTER_SECONDS));
    // Admission wrapper, not a money-path change: the store never saw the shed request,
    // so no operation transaction was entered for it.
    expect(counting.creates).toBe(MAX_CREATES_PER_WINDOW);
  });

  it("keys on the authenticated implementer — one tenant's flood never sheds another", async () => {
    const counting = countingStore();
    const router = throttledRouter(counting.store);

    for (let i = 0; i <= MAX_CREATES_PER_WINDOW; i += 1) {
      await router(
        "POST",
        "/v1/receives",
        encode(RECEIVE_BODY),
        createHeaders(TOKEN_A, `idem-key-tenant-a-${i}`),
      );
    }
    expect(
      (
        await router(
          "POST",
          "/v1/receives",
          encode(RECEIVE_BODY),
          createHeaders(TOKEN_A, "idem-key-tenant-a-shed"),
        )
      ).status,
    ).toBe(429);

    const otherTenant = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      createHeaders(TOKEN_B, "idem-key-tenant-b-01"),
    );
    expect(otherTenant.status).toBe(201);
  });

  it("never sheds a read — the throttle covers the create routes only", async () => {
    const counting = countingStore();
    const router = throttledRouter(counting.store);

    for (let i = 0; i <= MAX_CREATES_PER_WINDOW * 5; i += 1) {
      await router(
        "POST",
        "/v1/receives",
        encode(RECEIVE_BODY),
        createHeaders(TOKEN_A, `idem-key-flood-${i}`),
      );
    }

    const read = await router(
      "GET",
      `/v1/receives/${SEEDED_OP}`,
      new Uint8Array(0),
      { authorization: `Bearer ${TOKEN_A}` },
    );
    expect(read.status).toBe(200);
    expect(counting.reads).toBe(1);
  });

  it("is not an oracle — an unknown key and an out-of-scope key still answer 401, never 429", async () => {
    const counting = countingStore();
    const router = throttledRouter(counting.store);

    // Spend the whole budget for the tenant the read-only token also belongs to.
    for (let i = 0; i <= MAX_CREATES_PER_WINDOW; i += 1) {
      await router(
        "POST",
        "/v1/receives",
        encode(RECEIVE_BODY),
        createHeaders(TOKEN_A, `idem-key-oracle-${i}`),
      );
    }

    const unknownKey = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      createHeaders("ik_not_a_registered_token_zzzzz", "idem-key-oracle-unknown"),
    );
    // Same implementer as TOKEN_A, whose budget is spent — but no receive:create scope.
    // Scope denial is decided at stage 3, ahead of the throttle, so the exhausted budget
    // cannot leak through as a different answer.
    const outOfScope = await router(
      "POST",
      "/v1/receives",
      encode(RECEIVE_BODY),
      createHeaders(TOKEN_READ_ONLY, "idem-key-oracle-scope"),
    );

    const canonical401 = apiErrorResponse("invalid_api_key", REQUEST_ID);
    expect(unknownKey.status).toBe(401);
    expect(outOfScope.status).toBe(401);
    expect(unknownKey.body).toBe(canonical401.body);
    expect(outOfScope.body).toBe(canonical401.body);
  });
});
