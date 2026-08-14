import { describe, expect, it } from "vitest";
import {
  handleCreateReceive,
  handleGetReceive,
  handleCreateInternalMove,
  handleGetInternalMove,
  handleCreateExternalSend,
  handleGetExternalSend,
  WalletBusyError,
  ReceiveQueueFullError,
  IdempotencyConflictError,
  IdempotencyKeyReusedError,
  IdempotencyInProgressError,
  ReceiveAdmissionError,
  SendAdmissionError,
  type OperationStore,
  type OperationObject,
  type ReceiveResponse,
  type InternalMoveResponse,
  type ExternalSendResponse,
} from "../src/api/routes/index.js";
import type { PipelineContext } from "../src/api/pipeline.js";
import { CreateReceiveBody } from "../src/api/route-schemas.js";

const OP_BASE: OperationObject = {
  operation_id: "00000000-0000-0000-0000-000000000001",
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

const RECEIVE_RESPONSE: ReceiveResponse = {
  operation: OP_BASE,
  receiver_pubkey: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
  discriminator: "00000000-0000-0000-0000-000000000001",
  expires_at: "2026-01-01T00:05:00.000Z",
  after_landing: { kind: "HOLD", destination_id: null },
  code_status: "AWAITING_ARM",
  transfer_code: null,
  expected_artifact: {
    key_id: "00000000-0000-0000-0000-000000000099",
    preimage_text: "canonical-text",
    preimage_sha256: "a".repeat(64),
    signature: "A".repeat(86) + "==",
  },
  t0: { observation_id: "00000000-0000-0000-0000-000000000050", projection: { s: "", p: "", b_zkz: "0" } },
  subscription_handle: "sh_test_secret",
};

const MOVE_RESPONSE: InternalMoveResponse = {
  operation: { ...OP_BASE, operation_type: "MOVE_INTERNAL", state: "CREATED", row_version: 1 },
  source_wallet_id: "00000000-0000-0000-0000-000000000010",
  destination_id: "00000000-0000-0000-0000-000000000020",
  spawned_from_operation_id: null,
  lease_status: "WAITING",
  expected_artifact: {
    key_id: "00000000-0000-0000-0000-000000000099",
    preimage_text: "canonical-text",
    preimage_sha256: "b".repeat(64),
    signature: "B".repeat(86) + "==",
  },
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
  expected_artifact: {
    key_id: "00000000-0000-0000-0000-000000000099",
    preimage_text: "canonical-text",
    preimage_sha256: "c".repeat(64),
    signature: "C".repeat(86) + "==",
  },
};

function makeCtx(overrides: Partial<PipelineContext> = {}): PipelineContext {
  return {
    requestId: "req-00000000-0000-0000-0000-000000000001",
    request: {
      method: "POST",
      path: "/v1/receives",
      rawBody: new Uint8Array(0),
      headers: { "idempotency-key": "test-idempotency-key-1234" },
      query: {},
    },
    routeSchema: { method: "POST", path: "/v1/receives", requiresIdempotencyKey: true },
    parsedBody: {
      amount_zkz: "5.5",
      anchor: "ord_01J2",
      after_landing: { kind: "HOLD", destination_id: null },
    },
    parsedQuery: undefined,
    principal: { implementerId: "impl-test", scopes: ["receive:create", "receive:read", "move:create", "move:read", "send:create", "send:read"] },
    idempotencyTenantId: "impl-test",
    ...overrides,
  };
}

function makeStore(overrides: Partial<OperationStore> = {}): OperationStore {
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

describe("handleCreateReceive", () => {
  it("returns 201 with the receive response on success", async () => {
    const result = await handleCreateReceive(makeCtx(), makeStore());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(201);
    const body = JSON.parse(result.body);
    expect(body.operation.operation_type).toBe("RECEIVE_EXTERNAL");
    expect(body.operation.state).toBe("READY");
    expect(body.receiver_pubkey).toBe("wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=");
    expect(body.transfer_code).toBeNull();
    // the create response carries the subscription_handle plaintext (point read strips it).
    expect(body.subscription_handle).toBe("sh_test_secret");
  });

  it("returns 202 when queued", async () => {
    const queued: ReceiveResponse = {
      ...RECEIVE_RESPONSE,
      operation: { ...OP_BASE, state: "CREATED", row_version: 1 },
      receiver_pubkey: null,
      expires_at: null,
      code_status: "NOT_CREATED",
      expected_artifact: null,
      t0: null,
    };
    const store = makeStore({ createReceive: async () => ({ status: 202, body: queued }) });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(202);
    const body = JSON.parse(result.body);
    expect(body.operation.state).toBe("CREATED");
    expect(body.receiver_pubkey).toBeNull();
  });

  it("returns 503 receive_queue_full with Retry-After when store throws ReceiveQueueFullError", async () => {
    const store = makeStore({ createReceive: async () => { throw new ReceiveQueueFullError(30); } });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(503);
    expect(JSON.parse(result.error.body).error.code).toBe("receive_queue_full");
    expect(result.error.headers["Retry-After"]).toBe("30");
  });

  it("forwards ReceiveQueueFullError.retryAfterSeconds onto Retry-After", async () => {
    const store = makeStore({ createReceive: async () => { throw new ReceiveQueueFullError(45); } });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.headers["Retry-After"]).toBe("45");
  });

  it("returns 409 idempotency_conflict on duplicate key", async () => {
    const store = makeStore({ createReceive: async () => { throw new IdempotencyConflictError(); } });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("idempotency_conflict");
  });

  it("returns 409 idempotency_key_reused without Retry-After", async () => {
    const store = makeStore({ createReceive: async () => { throw new IdempotencyKeyReusedError(); } });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("idempotency_key_reused");
    expect(result.error.headers["Retry-After"]).toBeUndefined();
  });

  it("returns 409 idempotency_in_progress with Retry-After", async () => {
    const store = makeStore({
      createReceive: async () => {
        throw new IdempotencyInProgressError(1);
      },
    });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("idempotency_in_progress");
    expect(result.error.headers["Retry-After"]).toBe("1");
  });

  it("propagates Retry-After from ReceiveAdmissionError receive_queue_full", async () => {
    const store = makeStore({
      createReceive: async () => {
        throw new ReceiveAdmissionError("receive_queue_full", undefined, 30);
      },
    });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(503);
    expect(JSON.parse(result.error.body).error.code).toBe("receive_queue_full");
    expect(result.error.headers["Retry-After"]).toBe("30");
  });

  it("propagates Retry-After from ReceiveAdmissionError idempotency_in_progress", async () => {
    const store = makeStore({
      createReceive: async () => {
        throw new ReceiveAdmissionError("idempotency_in_progress", undefined, 1);
      },
    });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("idempotency_in_progress");
    expect(result.error.headers["Retry-After"]).toBe("1");
  });

  it("returns the stored result with the Idempotency-Replayed header on replay, not a duplicate create", async () => {
    // a completed-mutation replay returns the stored status and body bytes unchanged
    // with `Idempotency-Replayed: true`. Drive the actual replay signal from the store.
    const store = makeStore({
      createReceive: async () => ({ status: 201 as const, body: RECEIVE_RESPONSE, idempotentReplay: true }),
    });
    const result = await handleCreateReceive(makeCtx(), store);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(201);
    expect(result.headers?.["Idempotency-Replayed"]).toBe("true");
    // Stored body bytes returned unchanged — the same operation, not a newly minted one.
    expect(JSON.parse(result.body).operation.operation_id).toBe(OP_BASE.operation_id);
  });

  it("omits the Idempotency-Replayed header on a fresh create", async () => {
    const result = await handleCreateReceive(makeCtx(), makeStore());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.headers?.["Idempotency-Replayed"]).toBeUndefined();
  });
});

describe("handleGetReceive", () => {
  it("returns 200 with the receive representation", async () => {
    const result = await handleGetReceive(makeCtx(), makeStore(), OP_BASE.operation_id);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.operation.operation_id).toBe(OP_BASE.operation_id);
  });

  it("does not leak subscription_handle on the point read (money-path)", async () => {
    // makeStore's getReceive returns a body WITH subscription_handle set; the handler must strip it.
    const result = await handleGetReceive(makeCtx(), makeStore(), OP_BASE.operation_id);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const body = JSON.parse(result.body);
    expect("subscription_handle" in body).toBe(false);
    // transfer_code is always null on the point read; code retrieval is arm-only.
    expect(body.transfer_code).toBeNull();
  });

  it("returns 404 when operation not found", async () => {
    const store = makeStore({ getReceive: async () => null });
    const result = await handleGetReceive(makeCtx(), store, "nonexistent-id");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(404);
    expect(JSON.parse(result.error.body).error.code).toBe("not_found");
  });
});

describe("handleCreateInternalMove", () => {
  const moveCtx = makeCtx({
    request: {
      method: "POST",
      path: "/v1/internal-moves",
      rawBody: new Uint8Array(0),
      headers: { "idempotency-key": "test-idempotency-key-5678" },
      query: {},
    },
    routeSchema: { method: "POST", path: "/v1/internal-moves", requiresIdempotencyKey: true },
    parsedBody: {
      source_wallet_id: "00000000-0000-0000-0000-000000000010",
      destination_id: "00000000-0000-0000-0000-000000000020",
      amount_zkz: "5.5",
    },
  });

  it("returns 201 with the move response", async () => {
    const result = await handleCreateInternalMove(moveCtx, makeStore());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(201);
    const body = JSON.parse(result.body);
    expect(body.operation.operation_type).toBe("MOVE_INTERNAL");
    expect(body.source_wallet_id).toBe("00000000-0000-0000-0000-000000000010");
    expect(body.lease_status).toBe("WAITING");
  });

  it("returns 409 wallet_busy when source wallet is busy", async () => {
    const store = makeStore({ createInternalMove: async () => { throw new WalletBusyError(); } });
    const result = await handleCreateInternalMove(moveCtx, store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("wallet_busy");
  });
});

describe("handleGetInternalMove", () => {
  it("returns 200 with the move representation", async () => {
    const result = await handleGetInternalMove(makeCtx(), makeStore(), OP_BASE.operation_id);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.operation.operation_type).toBe("MOVE_INTERNAL");
  });

  it("returns 404 when not found", async () => {
    const store = makeStore({ getInternalMove: async () => null });
    const result = await handleGetInternalMove(makeCtx(), store, "nonexistent");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(404);
  });
});

describe("handleCreateExternalSend", () => {
  const sendCtx = makeCtx({
    request: {
      method: "POST",
      path: "/v1/external-sends",
      rawBody: new Uint8Array(0),
      headers: { "idempotency-key": "test-idempotency-key-9012" },
      query: {},
    },
    routeSchema: { method: "POST", path: "/v1/external-sends", requiresIdempotencyKey: true },
    parsedBody: {
      source_wallet_id: "00000000-0000-0000-0000-000000000010",
      destination_address: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
      amount_zkz: "5.5",
    },
  });

  it("returns 201 with the send response", async () => {
    const result = await handleCreateExternalSend(sendCtx, makeStore());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(201);
    const body = JSON.parse(result.body);
    expect(body.operation.operation_type).toBe("SEND_EXTERNAL");
    expect(body.approval_status).toBe("PENDING");
    expect(body.transfer_code).toBeNull();
    expect(body.available_until).toBeNull();
  });

  it("propagates Retry-After from SendAdmissionError idempotency_in_progress", async () => {
    const store = makeStore({
      createExternalSend: async () => {
        throw new SendAdmissionError("idempotency_in_progress", undefined, 1);
      },
    });
    const result = await handleCreateExternalSend(sendCtx, store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("idempotency_in_progress");
    expect(result.error.headers["Retry-After"]).toBe("1");
  });

  it("maps assign/top-up failures to documented HTTP codes (ZTR-1271 / ZTR-1309)", async () => {
    const cases: Array<{
      code: string;
      detail?: string;
      status: number;
      wire: string;
      reason?: string;
    }> = [
      {
        code: "no_free_send_worker",
        status: 503,
        wire: "service_unavailable",
        reason: "no_free_send_worker",
      },
      {
        code: "no_hub_liquidity",
        status: 503,
        wire: "service_unavailable",
        reason: "no_hub_liquidity",
      },
      {
        code: "insufficient_funding_wallet",
        status: 422,
        wire: "insufficient_funding_wallet",
      },
      { code: "hub_busy", status: 409, wire: "wallet_busy" },
      { code: "halted", status: 503, wire: "service_unavailable", reason: "halted" },
      {
        code: "worker_destination_missing",
        status: 503,
        wire: "service_unavailable",
        reason: "worker_destination_missing",
      },
      {
        code: "assign_not_wired",
        status: 503,
        wire: "service_unavailable",
        reason: "assign_not_wired",
      },
      {
        code: "move_rejected",
        status: 503,
        wire: "service_unavailable",
        reason: "move_rejected",
      },
      {
        code: "send_rejected",
        detail: "allow_external_send=false",
        status: 422,
        wire: "protocol_predicate_failed",
      },
      {
        code: "send_rejected",
        detail: "source_wallet_not_found",
        status: 404,
        wire: "not_found",
      },
    ];
    for (const c of cases) {
      const store = makeStore({
        createExternalSend: async () => {
          throw new SendAdmissionError(c.code, c.detail);
        },
      });
      const result = await handleCreateExternalSend(sendCtx, store);
      expect(result.ok, c.code).toBe(false);
      if (result.ok) return;
      expect(result.error.status, c.code).toBe(c.status);
      const body = JSON.parse(result.error.body);
      expect(body.error.code, c.code).toBe(c.wire);
      if (c.reason !== undefined) {
        expect(body.error.details, c.code).toEqual({ reason: c.reason });
      } else {
        expect(body.error.details, c.code).toEqual({});
      }
    }
  });

  it("forwards omitted source_wallet_id to the store (ZTR-1271)", async () => {
    let seen: unknown;
    const store = makeStore({
      createExternalSend: async (input) => {
        seen = input;
        return {
          status: 201 as const,
          body: {
            ...SEND_RESPONSE,
            source_wallet_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          },
        };
      },
    });
    const ctx = {
      ...sendCtx,
      parsedBody: {
        destination_address: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
        amount_zkz: "5.5",
      },
    };
    const result = await handleCreateExternalSend(ctx, store);
    expect(result.ok).toBe(true);
    expect(seen).toMatchObject({
      destination_address: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
      amount_zkz: "5.5",
    });
    expect(seen).not.toHaveProperty("source_wallet_id");
    if (!result.ok) return;
    const body = JSON.parse(result.body);
    expect(body.source_wallet_id).toBe("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
  });
});

describe("handleGetExternalSend", () => {
  it("returns 200 with the send representation", async () => {
    const result = await handleGetExternalSend(makeCtx(), makeStore(), OP_BASE.operation_id);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.operation.operation_type).toBe("SEND_EXTERNAL");
  });

  it("returns 404 when not found", async () => {
    const store = makeStore({ getExternalSend: async () => null });
    const result = await handleGetExternalSend(makeCtx(), store, "nonexistent");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(404);
  });
});

describe("CreateReceiveBody schema (unknown_field)", () => {
  const VALID_RECEIVE_BODY = {
    amount_zkz: "5.5",
    anchor: "ord_01J2",
    after_landing: { kind: "HOLD", destination_id: null },
  } as const;

  it("accepts a valid receive body (control)", () => {
    expect(CreateReceiveBody.safeParse(VALID_RECEIVE_BODY).success).toBe(true);
  });

  it("rejects callback_url as an unknown field (the node has no callback surface)", () => {
    const result = CreateReceiveBody.safeParse({
      ...VALID_RECEIVE_BODY,
      callback_url: "https://merchant.example/webhook",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      // .strict() emits an unrecognized_keys issue, which the pipeline maps to 400 unknown_field.
      expect(result.error.issues.some((i) => i.code === "unrecognized_keys")).toBe(true);
    }
  });

  it("rejects non-positive amounts, including the zero-form bypass (frozen validateOperationAmount)", () => {
    // "0.0"/"0.00"/… clear the decimal grammar but are rejected by the frozen numeric-positive
    // validator (isNumericallyPositive + canonical re-emit) — the zero-form bypass guard.
    for (const badAmount of ["0", "0.0", "0.00", "0.000000", "0.", "-5", "abc", ""]) {
      const result = CreateReceiveBody.safeParse({ ...VALID_RECEIVE_BODY, amount_zkz: badAmount });
      expect(result.success, `amount_zkz=${JSON.stringify(badAmount)} must be rejected`).toBe(false);
    }
  });

  it("accepts a boundary-valid positive amount below the ceiling", () => {
    const result = CreateReceiveBody.safeParse({ ...VALID_RECEIVE_BODY, amount_zkz: "99999999.99999999" });
    expect(result.success).toBe(true);
  });
});
