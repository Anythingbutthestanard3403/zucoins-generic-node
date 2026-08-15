import { describe, expect, it, vi } from "vitest";

import { createExternalSend } from "./sends.js";
import type { FetchLike } from "./client-types.js";
import { assignCapacityReason, NodeApiError } from "./errors.js";

describe("createExternalSend", () => {
  it("POSTs /v1/external-sends with bearer auth", async () => {
    const body = {
      operation: {
        operation_id: "55555555-5555-4555-8555-555555555560",
        operation_type: "SEND_EXTERNAL",
        state: "CREATED",
        amount_zkz: "1.0",
        row_version: 1,
        attention_required: false,
        attention_reason: null,
        created_at: "2026-07-15T10:00:00.000Z",
        updated_at: "2026-07-15T10:00:00.000Z",
        terminal_at: null,
        verification_material_available_until: null,
      },
      source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      destination_address: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      approval_status: "PENDING",
      transfer_code: null,
      transfer_code_sha256: null,
      available_until: null,
      expected_artifact: null,
    };
    const fetchImpl = vi.fn<FetchLike>(async () =>
      new Response(JSON.stringify(body), { status: 201, headers: { "content-type": "application/json" } }),
    );
    const request = {
      source_wallet_id: body.source_wallet_id,
      destination_address: body.destination_address,
      amount_zkz: "1.0",
      client_reference: "payout-9",
    };
    await createExternalSend({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      bearerKey: "ik_test",
      request,
      idempotencyKey: "idem-send-1",
    });
    expect(fetchImpl.mock.calls[0]![0]).toBe("https://node.example.com/v1/external-sends");
    expect(JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string)).toEqual(request);
  });

  it("forwards verification_mode NODE_VERIFIED on create", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      new Response(JSON.stringify({
        operation: {
          operation_id: "55555555-5555-4555-8555-555555555560",
          operation_type: "SEND_EXTERNAL",
          state: "CREATED",
          amount_zkz: "1.0",
          row_version: 1,
          attention_required: false,
          attention_reason: null,
          created_at: "2026-07-15T10:00:00.000Z",
          updated_at: "2026-07-15T10:00:00.000Z",
          terminal_at: null,
          verification_material_available_until: null,
          verification_mode: "NODE_VERIFIED",
        },
        source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
        destination_address: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
        approval_status: "PENDING",
        transfer_code: null,
        transfer_code_sha256: null,
        available_until: null,
        expected_artifact: null,
      }), { status: 201, headers: { "content-type": "application/json" } }),
    );
    const request = {
      destination_address: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      amount_zkz: "1.0",
      verification_mode: "NODE_VERIFIED" as const,
    };
    const result = await createExternalSend({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      bearerKey: "ik_test",
      request,
      idempotencyKey: "idem-send-mode-1",
    });
    expect(JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string)).toEqual(request);
    expect(result.operation.verification_mode).toBe("NODE_VERIFIED");
  });

  it("POSTs without source_wallet_id when omitted (ZTR-1271 assign path)", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      new Response(
        JSON.stringify({
          operation: {
            operation_id: "55555555-5555-4555-8555-555555555561",
            operation_type: "SEND_EXTERNAL",
            state: "CREATED",
            amount_zkz: "1.0",
            row_version: 1,
            attention_required: false,
            attention_reason: null,
            created_at: "2026-07-15T10:00:00.000Z",
            updated_at: "2026-07-15T10:00:00.000Z",
            terminal_at: null,
            verification_material_available_until: null,
          },
          source_wallet_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          destination_address: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
          approval_status: "PENDING",
          transfer_code: null,
          transfer_code_sha256: null,
          available_until: null,
          expected_artifact: null,
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      ),
    );
    const request = {
      destination_address: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      amount_zkz: "1.0",
    };
    await createExternalSend({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      bearerKey: "ik_test",
      request,
      idempotencyKey: "idem-send-assign-1",
    });
    expect(JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string)).toEqual(request);
    expect(JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string)).not.toHaveProperty(
      "source_wallet_id",
    );
  });

  it("surfaces 503 no_free_send_worker as assign-capacity (ZTR-1309)", async () => {
    const fetchImpl = vi.fn<FetchLike>(
      async () =>
        new Response(
          JSON.stringify({
            error: {
              code: "service_unavailable",
              message: "The service is temporarily unavailable.",
              request_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
              details: { reason: "no_free_send_worker" },
            },
          }),
          { status: 503, headers: { "content-type": "application/json" } },
        ),
    );
    try {
      await createExternalSend({
        config: { baseUrl: "https://node.example.com", fetchImpl },
        bearerKey: "ik_test",
        request: {
          destination_address: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
          amount_zkz: "1.0",
        },
        idempotencyKey: "idem-send-503-1",
      });
      throw new Error("expected NodeApiError");
    } catch (err) {
      expect(err).toBeInstanceOf(NodeApiError);
      expect(err).toMatchObject({ status: 503, code: "service_unavailable" });
      expect(assignCapacityReason(err as NodeApiError)).toBe("no_free_send_worker");
    }
  });
});
