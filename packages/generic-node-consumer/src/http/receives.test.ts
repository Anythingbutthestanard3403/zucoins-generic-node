import { describe, expect, it, vi } from "vitest";

import { createReceive, generateIdempotencyKey, getReceive } from "./receives.js";
import { NodeApiError } from "./errors.js";
import type { FetchLike } from "./client-types.js";

const CONFIG = { baseUrl: "https://node.example.com" };
const OP_ID = "55555555-5555-4555-8555-555555555501";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("createReceive", () => {
  it("POSTs to /v1/receives with the bearer key and idempotency header", async () => {
    const responseBody = {
      operation: {
        operation_id: OP_ID,
        operation_type: "RECEIVE_EXTERNAL",
        state: "READY",
        amount_zkz: "5.5",
        row_version: 2,
        attention_required: false,
        attention_reason: null,
        created_at: "2026-07-18T12:00:00.000Z",
        updated_at: "2026-07-18T12:00:00.000Z",
        terminal_at: null,
        verification_material_available_until: null,
      },
      receiver_pubkey: "padded-base64url",
      discriminator: OP_ID,
      expires_at: "2026-07-18T12:05:00.000Z",
      after_landing: { kind: "HOLD", destination_id: null },
      code_status: "AWAITING_ARM",
      transfer_code: null,
      expected_artifact: {
        key_id: "k1",
        preimage_text: "text",
        preimage_sha256: "a".repeat(64),
        signature: "sig",
      },
      t0: { observation_id: "obs1", projection: { s: "", p: "", b_zkz: "0" } },
      subscription_handle: "sh_secret",
    };
    const fetchImpl = vi.fn<FetchLike>(async () => jsonResponse(201, responseBody));

    const result = await createReceive({
      config: { ...CONFIG, fetchImpl },
      bearerKey: "ik_test",
      idempotencyKey: "idem-1",
      request: {
        amount_zkz: "5.5",
        anchor: "ord_01J2",
        after_landing: { kind: "HOLD", destination_id: null },
      },
    });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://node.example.com/v1/receives");
    expect(init?.method).toBe("POST");
    const headers = init?.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer ik_test");
    expect(headers["idempotency-key"]).toBe("idem-1");
    expect(JSON.parse(init!.body as string)).toEqual({
      amount_zkz: "5.5",
      anchor: "ord_01J2",
      after_landing: { kind: "HOLD", destination_id: null },
    });

    expect(result.subscription_handle).toBe("sh_secret");
    expect(result.operation.state).toBe("READY");
    expect(result.code_status).toBe("AWAITING_ARM");
  });

  it("surfaces a 503 receive_queue_full as NodeApiError", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(503, {
        error: { code: "receive_queue_full", message: "full", request_id: "r1", details: {} },
      }),
    );
    await expect(
      createReceive({
        config: { ...CONFIG, fetchImpl },
        bearerKey: "ik_test",
        idempotencyKey: "idem-2",
        request: { amount_zkz: "1", anchor: "a", after_landing: { kind: "HOLD", destination_id: null } },
      }),
    ).rejects.toMatchObject({ code: "receive_queue_full" } satisfies Partial<NodeApiError>);
  });
});

describe("getReceive", () => {
  it("GETs /v1/receives/:operation_id with the bearer key and no body", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(200, {
        operation: {
          operation_id: OP_ID,
          operation_type: "RECEIVE_EXTERNAL",
          state: "RECEIVE_LANDED",
          amount_zkz: "5.5",
          row_version: 4,
          attention_required: false,
          attention_reason: null,
          created_at: "2026-07-18T12:00:00.000Z",
          updated_at: "2026-07-18T12:00:01.000Z",
          terminal_at: "2026-07-18T12:00:01.000Z",
          verification_material_available_until: "2026-07-25T12:00:01.000Z",
        },
        receiver_pubkey: "padded-base64url",
        discriminator: OP_ID,
        expires_at: "2026-07-18T12:05:00.000Z",
        after_landing: { kind: "HOLD", destination_id: null },
        code_status: "RELEASED",
        transfer_code: null,
        expected_artifact: null,
        t0: null,
      }),
    );

    const result = await getReceive({
      config: { ...CONFIG, fetchImpl },
      bearerKey: "ik_test",
      operationId: OP_ID,
    });

    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(`https://node.example.com/v1/receives/${OP_ID}`);
    expect(init?.method).toBe("GET");
    expect(init?.body).toBeUndefined();
    expect(result.transfer_code).toBeNull();
    expect(result.operation.state).toBe("RECEIVE_LANDED");
  });
});

describe("generateIdempotencyKey", () => {
  it("returns a fresh value on every call", () => {
    expect(generateIdempotencyKey()).not.toBe(generateIdempotencyKey());
  });
});
