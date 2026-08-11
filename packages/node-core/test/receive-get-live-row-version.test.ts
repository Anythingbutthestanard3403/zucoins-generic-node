/**
 * GET /v1/receives must surface live operations.row_version/status after land so
 * verification-complete CAS does not 409 on the frozen READY response_body version.
 */
import { describe, expect, it } from "vitest";
import { createSqlOperationRouteStore } from "../src/operation-route-store.js";
import type { StoredReceiveOperation } from "../src/receive/admission.js";

const OP_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const IMPL = "11111111-2222-4333-8444-555555555555";
const NODE = "99999999-8888-4777-8666-555555555555";

function frozenReadyBody(rowVersion: number, state: string): string {
  return JSON.stringify({
    operation: {
      operation_id: OP_ID,
      operation_type: "RECEIVE_EXTERNAL",
      state,
      amount_zkz: "0.000001",
      row_version: rowVersion,
      attention_required: false,
      attention_reason: null,
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-01T00:00:01.000Z",
      terminal_at: null,
      verification_material_available_until: null,
    },
    receiver_pubkey: "pub",
    discriminator: OP_ID,
    expires_at: "2026-01-02T00:00:00.000Z",
    after_landing: { kind: "HOLD", destination_id: null },
    code_status: "AWAITING_ARM",
    transfer_code: null,
    expected_artifact: null,
    t0: {
      observation_id: "obs-t0",
      projection: { s: "s", p: "p", b_zkz: "0" },
    },
    subscription_handle: "sh_test_live_row",
  });
}

function baseRow(over: Partial<StoredReceiveOperation> = {}): StoredReceiveOperation {
  return {
    operationId: OP_ID,
    implementerId: IMPL,
    nodeId: NODE,
    kind: "RECEIVE_EXTERNAL",
    status: "READY",
    httpMethod: "POST",
    route: "/v1/receives",
    amountZkz: "0.000001",
    anchor: "a",
    ttlMs: 60_000,
    afterLanding: { kind: "HOLD", destinationId: null },
    idempotencyKey: "idem-key-1234567890",
    requestSha256: "a".repeat(64),
    destinationWalletId: null,
    walletId: "w".repeat(36).replace(/w/g, "1").slice(0, 36),
    createdAt: Date.parse("2026-01-01T00:00:00.000Z"),
    responseStatus: 201,
    responseBody: frozenReadyBody(2, "READY"),
    ...over,
  };
}

function storeWithRow(row: StoredReceiveOperation | null) {
  return createSqlOperationRouteStore({
    nodeId: NODE,
    queueCap: 8,
    receive: {
      findDestination: async () => null,
      insertInProgress: async () => ({
        kind: "INSERTED" as const,
        subscriptionHandlePlaintext: "sh_test_live_row",
      }),
      insertQueuedIfCapAllows: async () => ({
        kind: "INSERTED" as const,
        subscriptionHandlePlaintext: "sh_test_live_row",
      }),
      findByIdempotency: async () => null,
      completeOperation: async () => true,
      findByOperationId: async () => row,
      countQueuedReceives: async () => 0,
    },
    move: {} as never,
    send: {} as never,
    sendSigner: { sign: () => ({ keyId: "k", preimageText: "", preimageSha256: "", signature: "" }) },
  });
}

describe("GET receive live row_version overlay", () => {
  it("overlays live RECEIVE_LANDED status and row_version over frozen READY body", async () => {
    const ops = storeWithRow(
      baseRow({
        liveStatus: "RECEIVE_LANDED",
        liveRowVersion: 4,
        liveUpdatedAt: "2026-01-01T00:00:05.000Z",
        liveTerminalAt: "2026-01-01T00:00:05.000Z",
        liveVerificationMaterialAvailableUntil: "2026-02-01T00:00:05.000Z",
        liveAttentionRequired: false,
        liveAttentionReason: null,
      }),
    );
    const got = await ops.getReceive(OP_ID, IMPL);
    expect(got).not.toBeNull();
    expect(got!.operation.state).toBe("RECEIVE_LANDED");
    expect(got!.operation.row_version).toBe(4);
    expect(got!.operation.terminal_at).toBe("2026-01-01T00:00:05.000Z");
    expect(got!.t0?.observation_id).toBe("obs-t0");
    expect(got!.code_status).toBe("AWAITING_ARM");
  });

  it("keeps frozen READY body when no live overlay is present", async () => {
    const ops = storeWithRow(baseRow());
    const got = await ops.getReceive(OP_ID, IMPL);
    expect(got!.operation.state).toBe("READY");
    expect(got!.operation.row_version).toBe(2);
  });
});
