import { describe, expect, it } from "vitest";

import { OPERATION_KINDS, type OperationKind } from "../operations/operations.contract.ts";
import { PUBLIC_ROUTES } from "../operations/routes.contract.ts";
import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { MoveInternalRequestSchema, MoveInternalResponseSchema } from "./move-internal.ts";
import {
  PUBLIC_OPERATION_SCHEMAS,
  PUBLIC_OPERATION_SCHEMA_SURFACE,
} from "./operation-schema-surface.ts";
import {
  ReceiveExternalQueuedResponseSchema,
  ReceiveExternalReadyResponseSchema,
  ReceiveExternalRequestSchema,
  ReceiveExternalResponseSchema,
} from "./receive-external.ts";
import { SendExternalRequestSchema, SendExternalResponseSchema } from "./send-external.ts";

const UUID_A = "7b8bb326-0f2b-4dad-a8e7-40115b375ec4";
const UUID_B = "8c9cc437-1f3c-4ebe-b9f8-51226c486fd5";
const TIMESTAMP = "2026-07-18T12:00:00.000Z";
const WALLET_PUBLIC_KEY = `${"A".repeat(43)}=`;
const ED25519_SIGNATURE = `${"A".repeat(86)}==`;
const SHA256_HEX = "a".repeat(64);
const AMOUNT = "99999999.12345678901234567890123456789012";

const EXPECTED_ARTIFACT = {
  key_id: UUID_A,
  preimage_text: "zp-example-v1\nexact bytes",
  preimage_sha256: SHA256_HEX,
  signature: ED25519_SIGNATURE,
};

const T0 = {
  observation_id: UUID_A,
  projection: {
    s: "",
    p: "",
    b_zkz: "0",
  },
};

function operation(operationType: OperationKind) {
  return {
    operation_id: UUID_A,
    operation_type: operationType,
    state:
      operationType === "RECEIVE_EXTERNAL"
        ? "READY"
        : "CREATED",
    amount_zkz: AMOUNT,
    row_version: 1,
    attention_required: false,
    attention_reason: null,
    created_at: TIMESTAMP,
    updated_at: TIMESTAMP,
    terminal_at: null,
    verification_material_available_until: null,
  };
}

const RECEIVE_REQUEST = {
  amount_zkz: AMOUNT,
  anchor: "ord_01J2",
  expires_in_seconds: 300,
  after_landing: { kind: "HOLD", destination_id: null },
} as const;

const RECEIVE_REQUEST_WITHOUT_EXPIRY = {
  amount_zkz: RECEIVE_REQUEST.amount_zkz,
  anchor: RECEIVE_REQUEST.anchor,
  after_landing: RECEIVE_REQUEST.after_landing,
} as const;

const RECEIVE_READY_RESPONSE = {
  operation: operation("RECEIVE_EXTERNAL"),
  receiver_pubkey: WALLET_PUBLIC_KEY,
  discriminator: UUID_A,
  expires_at: "2026-07-18T12:05:00.000Z",
  after_landing: { kind: "HOLD", destination_id: null },
  code_status: "AWAITING_ARM",
  transfer_code: null,
  expected_artifact: EXPECTED_ARTIFACT,
  t0: T0,
  subscription_handle: "sh_secret",
};

const RECEIVE_QUEUED_RESPONSE = {
  operation: {
    ...operation("RECEIVE_EXTERNAL"),
    state: "CREATED",
  },
  receiver_pubkey: null,
  discriminator: UUID_A,
  expires_at: null,
  after_landing: { kind: "HOLD", destination_id: null },
  code_status: "NOT_CREATED",
  transfer_code: null,
  expected_artifact: null,
  t0: null,
  subscription_handle: "sh_secret",
};

const MOVE_REQUEST = {
  source_wallet_id: UUID_A,
  destination_id: UUID_B,
  amount_zkz: AMOUNT,
};

const MOVE_RESPONSE = {
  operation: {
    ...operation("MOVE_INTERNAL"),
    state: "INTERNAL_MOVE_LANDED",
    terminal_at: TIMESTAMP,
    verification_material_available_until: TIMESTAMP,
  },
  source_wallet_id: UUID_A,
  destination_id: UUID_B,
  spawned_from_operation_id: null,
  lease_status: "RELEASED",
  execution_phase: "LANDED_VERIFIED",
  expected_artifact: EXPECTED_ARTIFACT,
  source_terminal_observation_id: UUID_A,
  destination_terminal_observation_id: UUID_B,
};

const SEND_REQUEST = {
  source_wallet_id: UUID_A,
  destination_address: WALLET_PUBLIC_KEY,
  amount_zkz: AMOUNT,
  references_operation_id: UUID_B,
  client_reference: "opaque-reference",
  description: "Operator-visible context",
};

const SEND_RESPONSE = {
  operation: operation("SEND_EXTERNAL"),
  source_wallet_id: UUID_A,
  destination_address: WALLET_PUBLIC_KEY,
  references_operation_id: UUID_B,
  approval_status: "PENDING",
  transfer_code: null,
  transfer_code_sha256: null,
  available_until: null,
  expected_artifact: EXPECTED_ARTIFACT,
};

describe("the named concern RECEIVE_EXTERNAL strict schemas", () => {
  it("accepts the documented request and both documented response variants", () => {
    expect(ReceiveExternalRequestSchema.safeParse(RECEIVE_REQUEST).success).toBe(true);
    expect(ReceiveExternalReadyResponseSchema.safeParse(RECEIVE_READY_RESPONSE).success).toBe(true);
    expect(ReceiveExternalQueuedResponseSchema.safeParse(RECEIVE_QUEUED_RESPONSE).success).toBe(true);
    expect(ReceiveExternalResponseSchema.safeParse(RECEIVE_READY_RESPONSE).success).toBe(true);
    expect(ReceiveExternalResponseSchema.safeParse(RECEIVE_QUEUED_RESPONSE).success).toBe(true);
  });

  it("rejects callback_url and every other unknown request field (the no-callback rule)", () => {
    const result = ReceiveExternalRequestSchema.safeParse({
      ...RECEIVE_REQUEST,
      callback_url: "forbidden-callback-value",
    });
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.error.issues[0]?.code).toBe("unrecognized_keys");
  });

  it("rejects non-canonical request scalars and unknown response fields", () => {
    expect(
      ReceiveExternalRequestSchema.safeParse({
        ...RECEIVE_REQUEST,
        amount_zkz: "2.50",
      }).success,
    ).toBe(false);
    expect(
      ReceiveExternalResponseSchema.safeParse({
        ...RECEIVE_READY_RESPONSE,
        undocumented: true,
      }).success,
    ).toBe(false);
  });

  it("rejects null/empty subscription_handle on READY and QUEUED (ZTR-1142 frozen minLength:1)", () => {
    for (const bad of [null, "", undefined] as const) {
      expect(
        ReceiveExternalReadyResponseSchema.safeParse({
          ...RECEIVE_READY_RESPONSE,
          subscription_handle: bad,
        }).success,
      ).toBe(false);
      expect(
        ReceiveExternalQueuedResponseSchema.safeParse({
          ...RECEIVE_QUEUED_RESPONSE,
          subscription_handle: bad,
        }).success,
      ).toBe(false);
    }
  });

  it.each([
    ["omitted", RECEIVE_REQUEST_WITHOUT_EXPIRY, undefined],
    ["one second", { ...RECEIVE_REQUEST, expires_in_seconds: 1 }, 1],
    ["documented value", RECEIVE_REQUEST, 300],
    ["above the former fixed maximum", { ...RECEIVE_REQUEST, expires_in_seconds: 86_401 }, 86_401],
    [
      "maximum safe integer",
      { ...RECEIVE_REQUEST, expires_in_seconds: Number.MAX_SAFE_INTEGER },
      Number.MAX_SAFE_INTEGER,
    ],
  ] as const)("accepts %s expiry unchanged", (_label, request, expectedExpiry) => {
    const result = ReceiveExternalRequestSchema.safeParse(request);
    expect(result.success).toBe(true);
    if (!result.success) return;

    if (expectedExpiry === undefined) {
      expect(result.data).not.toHaveProperty("expires_in_seconds");
      return;
    }
    expect(result.data.expires_in_seconds).toBe(expectedExpiry);
  });

  it.each([
    ["zero", 0],
    ["negative integer", -1],
    ["fraction", 1.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["above maximum safe integer", Number.MAX_SAFE_INTEGER + 1],
    ["string", "300"],
  ] as const)("rejects %s expiry", (_label, expiresInSeconds) => {
    expect(
      ReceiveExternalRequestSchema.safeParse({
        ...RECEIVE_REQUEST,
        expires_in_seconds: expiresInSeconds,
      }).success,
    ).toBe(false);
  });
});

describe("the named concern MOVE_INTERNAL strict schemas", () => {
  it("accepts the documented request and response", () => {
    expect(MoveInternalRequestSchema.safeParse(MOVE_REQUEST).success).toBe(true);
    expect(
      MoveInternalRequestSchema.safeParse({ ...MOVE_REQUEST, client_reference: "ref-42" }).success,
    ).toBe(true);
    expect(MoveInternalResponseSchema.safeParse(MOVE_RESPONSE).success).toBe(true);
  });

  it("rejects unknown request and response fields", () => {
    expect(
      MoveInternalRequestSchema.safeParse({
        ...MOVE_REQUEST,
        spawned_from_operation_id: UUID_A,
      }).success,
    ).toBe(false);
    expect(
      MoveInternalResponseSchema.safeParse({
        ...MOVE_RESPONSE,
        raw_transaction: "forbidden",
      }).success,
    ).toBe(false);
  });

  it("rejects alternate UUID spelling and numeric amounts", () => {
    expect(
      MoveInternalRequestSchema.safeParse({
        ...MOVE_REQUEST,
        source_wallet_id: UUID_A.toUpperCase(),
      }).success,
    ).toBe(false);
    expect(
      MoveInternalRequestSchema.safeParse({
        ...MOVE_REQUEST,
        amount_zkz: 5.5,
      }).success,
    ).toBe(false);
  });
});

describe("the named concern SEND_EXTERNAL strict schemas", () => {
  it("accepts the documented request and response", () => {
    expect(SendExternalRequestSchema.safeParse(SEND_REQUEST).success).toBe(true);
    expect(SendExternalResponseSchema.safeParse(SEND_RESPONSE).success).toBe(true);
  });

  it("accepts request without source_wallet_id (ZTR-1271 assign path)", () => {
    const { source_wallet_id: _omit, ...withoutSource } = SEND_REQUEST;
    expect(SendExternalRequestSchema.safeParse(withoutSource).success).toBe(true);
    // Response still requires resolved source_wallet_id once bound.
    expect(
      SendExternalResponseSchema.safeParse({
        ...SEND_RESPONSE,
        source_wallet_id: UUID_A,
      }).success,
    ).toBe(true);
  });

  it("rejects unknown request and response fields", () => {
    expect(
      SendExternalRequestSchema.safeParse({
        ...SEND_REQUEST,
        recipient_note: "unknown",
      }).success,
    ).toBe(false);
    expect(
      SendExternalResponseSchema.safeParse({
        ...SEND_RESPONSE,
        client_reference: "not a documented response field",
      }).success,
    ).toBe(false);
  });

  it("rejects non-canonical destination and amount scalars", () => {
    expect(
      SendExternalRequestSchema.safeParse({
        ...SEND_REQUEST,
        destination_address: WALLET_PUBLIC_KEY.slice(0, -1),
      }).success,
    ).toBe(false);
    expect(
      SendExternalRequestSchema.safeParse({
        ...SEND_REQUEST,
        amount_zkz: "0",
      }).success,
    ).toBe(false);
  });
});

describe("the named concern frozen public operation schema surface", () => {
  it("contains exactly the three public create operations in frozen route sequence", () => {
    expect(PUBLIC_OPERATION_SCHEMA_SURFACE).toHaveLength(3);
    assertFieldOrder(
      PUBLIC_OPERATION_SCHEMA_SURFACE.map((entry) => entry.operationType),
      OPERATION_KINDS,
    );
    assertFieldOrder(
      PUBLIC_OPERATION_SCHEMA_SURFACE.map((entry) => entry.path),
      ["/v1/receives", "/v1/internal-moves", "/v1/external-sends"],
    );
  });

  it("derives every entry from the existing frozen public route inventory", () => {
    for (const entry of PUBLIC_OPERATION_SCHEMA_SURFACE) {
      expect(PUBLIC_ROUTES).toContainEqual({
        method: entry.method,
        path: entry.path,
        authMode: "implementer_bearer",
      });
    }
  });

  it("binds one strict request and response schema to every frozen surface entry", () => {
    expect(PUBLIC_OPERATION_SCHEMAS).toHaveLength(3);
    expect(PUBLIC_OPERATION_SCHEMAS[0]?.request.safeParse(RECEIVE_REQUEST).success).toBe(true);
    expect(PUBLIC_OPERATION_SCHEMAS[0]?.response.safeParse(RECEIVE_READY_RESPONSE).success).toBe(true);
    expect(PUBLIC_OPERATION_SCHEMAS[1]?.request.safeParse(MOVE_REQUEST).success).toBe(true);
    expect(PUBLIC_OPERATION_SCHEMAS[1]?.response.safeParse(MOVE_RESPONSE).success).toBe(true);
    expect(PUBLIC_OPERATION_SCHEMAS[2]?.request.safeParse(SEND_REQUEST).success).toBe(true);
    expect(PUBLIC_OPERATION_SCHEMAS[2]?.response.safeParse(SEND_RESPONSE).success).toBe(true);
  });

  it("rejects a fourth operation in the frozen census", () => {
    expectRejects(
      () => [...PUBLIC_OPERATION_SCHEMA_SURFACE, PUBLIC_OPERATION_SCHEMA_SURFACE[0]],
      (mutated) => expect(mutated).toHaveLength(3),
    );
  });
});

describe("verification_mode defaults (ZTR-1299)", () => {
  it("omitted verification_mode on create requests defaults to INDEPENDENT", () => {
    const receive = ReceiveExternalRequestSchema.safeParse(RECEIVE_REQUEST);
    expect(receive.success).toBe(true);
    if (receive.success) expect(receive.data.verification_mode).toBe("INDEPENDENT");

    const move = MoveInternalRequestSchema.safeParse(MOVE_REQUEST);
    expect(move.success).toBe(true);
    if (move.success) expect(move.data.verification_mode).toBe("INDEPENDENT");

    const send = SendExternalRequestSchema.safeParse(SEND_REQUEST);
    expect(send.success).toBe(true);
    if (send.success) expect(send.data.verification_mode).toBe("INDEPENDENT");
  });

  it("accepts explicit NODE_VERIFIED on create requests", () => {
    expect(
      ReceiveExternalRequestSchema.safeParse({
        ...RECEIVE_REQUEST,
        verification_mode: "NODE_VERIFIED",
      }).success,
    ).toBe(true);
    expect(
      MoveInternalRequestSchema.safeParse({
        ...MOVE_REQUEST,
        verification_mode: "NODE_VERIFIED",
      }).success,
    ).toBe(true);
    expect(
      SendExternalRequestSchema.safeParse({
        ...SEND_REQUEST,
        verification_mode: "NODE_VERIFIED",
      }).success,
    ).toBe(true);
  });

  it("rejects unknown verification_mode values", () => {
    expect(
      ReceiveExternalRequestSchema.safeParse({
        ...RECEIVE_REQUEST,
        verification_mode: "HYBRID",
      }).success,
    ).toBe(false);
  });

  it("operation responses accept omitted verification_mode (defaults to INDEPENDENT)", () => {
    expect(ReceiveExternalReadyResponseSchema.safeParse(RECEIVE_READY_RESPONSE).success).toBe(true);
    expect(MoveInternalResponseSchema.safeParse(MOVE_RESPONSE).success).toBe(true);
    expect(SendExternalResponseSchema.safeParse(SEND_RESPONSE).success).toBe(true);
  });
});
