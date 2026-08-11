import { describe, expect, it, vi } from "vitest";

import { createInternalMove, getInternalMove } from "./moves.js";
import type { FetchLike } from "./client-types.js";

const OP = {
  operation: {
    operation_id: "55555555-5555-4555-8555-555555555560",
    operation_type: "MOVE_INTERNAL",
    state: "CREATED",
    amount_zkz: "1.25",
    row_version: 1,
    attention_required: false,
    attention_reason: null,
    created_at: "2026-07-15T10:00:00.000Z",
    updated_at: "2026-07-15T10:00:00.000Z",
    terminal_at: null,
    verification_material_available_until: null,
  },
  source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
  destination_id: "8b8bb326-0f2b-4dad-a8e7-40115b375ec4",
  spawned_from_operation_id: null,
  lease_status: "WAITING",
  execution_phase: "NOT_STARTED",
  expected_artifact: null,
  source_terminal_observation_id: null,
  destination_terminal_observation_id: null,
};

describe("createInternalMove", () => {
  it("POSTs body including optional client_reference", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      new Response(JSON.stringify(OP), { status: 201, headers: { "content-type": "application/json" } }),
    );
    const request = {
      source_wallet_id: OP.source_wallet_id,
      destination_id: OP.destination_id,
      amount_zkz: "1.25",
      client_reference: "order-42",
    };
    await createInternalMove({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      bearerKey: "ik_test",
      request,
      idempotencyKey: "idem-move-1",
    });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://node.example.com/v1/internal-moves");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>)["idempotency-key"]).toBe("idem-move-1");
    expect(JSON.parse(init!.body as string)).toEqual(request);
  });
});

describe("getInternalMove", () => {
  it("GETs the point-read route", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      new Response(JSON.stringify(OP), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const result = await getInternalMove({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      bearerKey: "ik_test",
      operationId: OP.operation.operation_id,
    });
    expect(fetchImpl.mock.calls[0]![0]).toBe(
      `https://node.example.com/v1/internal-moves/${OP.operation.operation_id}`,
    );
    expect(result.operation.operation_id).toBe(OP.operation.operation_id);
  });
});
