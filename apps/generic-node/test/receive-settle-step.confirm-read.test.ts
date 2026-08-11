// The pre-submit confirm-read (receive-settle-step.ts's createReceiverHeadReader)
// sent a noncanonical get_transaction__v1 field: `public_key_base64urlsafe` instead of the
// canonical `key_public__base64urlsafe` every other wallet-head reader uses. After a crash at
// STEP2_SIGNATURE_PERSISTED this could make the gateway reject the confirm read, leaving
// OBSERVED_AT_HEAD recovery unreachable (the durable submit claim still prevented a second
// submit — the never-blind-retry rule held throughout).
//
// This suite drives createReceiverHeadReader directly against a scripted, EXACT-FORM exchange
// transport — one that decodes the real byte-exact wire body and runs the canonical shape assertion
// (assertCanonicalGetTransactionActionData) against the decoded action data — rather than
// through the whole runReceiveSettleStep loop, which needs a live PostgreSQL server
// (test/receive-settle-step.pg.test.ts already covers the full STEP2_SIGNATURE_PERSISTED
// crash-resume path end to end when TEST_DATABASE_URL is set). No database is required here:
// this is the unit-level proof that the exact function which carried the defect now sends the
// canonical field, and that an exact-form fake would have caught the regression.
//
// Governing: the byte-exact signing rule (byte-exact wire form).
import { describe, expect, it } from "vitest";

import {
  GetTransactionActionDataShapeError,
  assertCanonicalGetTransactionActionData,
  buildGatewayActionRequest,
  type EncryptedWalletKeyStore,
  type GatewayExchangeTransport,
  type GatewayRequest,
} from "@zucoins/node-core";

import {
  createReceiverHeadReader,
  type ReceiveSettleStepDeps,
} from "../src/money-workers/receive-settle-step.js";

const RECEIVER_PUBLIC_KEY = "receiver-wallet-public-key-base64url";
const HEAD_STEP_2_SIGNATURE = "the-head-step-2-signature";

// Decodes request bytes exactly as the real gateway would: one urlencoded form field
// whose value is encodeURIComponent(JSON.stringify({action_name, action_data})).
function decodeGatewayFormBody(bodyBytes: Uint8Array): { actionName: string; actionData: unknown } {
  const text = new TextDecoder().decode(bodyBytes);
  const encoded = new URLSearchParams(text).get("v");
  if (encoded === null) throw new Error("gateway request body carries no v= form field");
  const parsed = JSON.parse(encoded) as { action_name: string; action_data: unknown };
  return { actionName: parsed.action_name, actionData: parsed.action_data };
}

/**
 * An exact-form integration fake: every get_transaction__v1 exchange is decoded off the real
 * wire bytes and run through the canonical shape assertion BEFORE a response is served. A
 * request built with the legacy `public_key_base64urlsafe` field — or any other noncanonical
 * shape — throws here rather than silently getting a scripted answer, exactly the gap that let
 * the codec defect ship unnoticed (the pg suite's earlier fake only checked the rpc name).
 */
function exactFormExchange(headStep2Signature: string | null): {
  readonly transport: GatewayExchangeTransport;
  readonly calls: GatewayRequest[];
} {
  const calls: GatewayRequest[] = [];
  const headBody =
    headStep2Signature === null
      ? JSON.stringify({ status: false, code: "account_not_found", message: "no account", data: null })
      : JSON.stringify({
          status: true,
          code: "ok",
          message: "OK",
          data: [{ inner: { version: "2" }, step_1_signature: "s1", step_2_signature: headStep2Signature }],
        });
  const transport: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      calls.push(request);
      const { actionName, actionData } = decodeGatewayFormBody(request.bodyBytes);
      expect(actionName).toBe("get_transaction__v1");
      // The load-bearing assertion: fail closed on anything but the canonical shape.
      assertCanonicalGetTransactionActionData(actionData);
      const responseBytes = new TextEncoder().encode(headBody);
      return {
        endpoint,
        endpointFingerprint: "offline-fp",
        requestBytes: request.bodyBytes,
        requestSha256: "unused",
        responseBytes,
        responseSha256: "unused",
        statusCode: 200,
      };
    },
  };
  return { transport, calls };
}

function makeDeps(exchange: GatewayExchangeTransport): ReceiveSettleStepDeps {
  const vault: ReceiveSettleStepDeps["vault"] = {
    open: (() => {
      throw new Error("vault.open must not be called by createReceiverHeadReader");
    }) as unknown as EncryptedWalletKeyStore["open"],
  };
  return {
    query: async () => {
      throw new Error("query must not be called by createReceiverHeadReader");
    },
    // Successful confirm-read never opens the pool; transport-ambiguous path would.
    pool: { connect: async () => { throw new Error("pool unused on success path"); } } as never,
    vault,
    nodeId: "00000000-0000-4000-8000-00000000000a",
    leadership: { held: true },
    moneyPathGates: {
      assertMoneyAdmitted: () => {
        throw new Error("assertMoneyAdmitted must not be called by createReceiverHeadReader");
      },
      assertCanOperate: () => {
        throw new Error("assertCanOperate must not be called by createReceiverHeadReader");
      },
      assertWalletMaySign: async () => {
        throw new Error("assertWalletMaySign must not be called by createReceiverHeadReader");
      },
    },
    gateway: {
      endpoint: "https://gateway.offline.test",
      limits: { readTimeoutMs: 1000, maxRequestBytes: 65536, maxResponseBytes: 65536 },
      exchange,
    },
    logger: { info: () => {}, error: () => {} },
  };
}

describe("receive-settle-step confirm-read sends the canonical wallet-head field", () => {
  it("reads the receiver head through the canonical key_public__base64urlsafe field and returns the head signature", async () => {
    const { transport, calls } = exactFormExchange(HEAD_STEP_2_SIGNATURE);
    const readReceiverHead = createReceiverHeadReader(makeDeps(transport));

    const signature = await readReceiverHead(RECEIVER_PUBLIC_KEY);

    expect(signature).toBe(HEAD_STEP_2_SIGNATURE);
    expect(calls).toHaveLength(1);
    const { actionData } = decodeGatewayFormBody(calls[0]!.bodyBytes);
    expect(actionData).toEqual({ key_public__base64urlsafe: RECEIVER_PUBLIC_KEY });
  });

  it("returns null (no head) on genesis, still through the canonical field", async () => {
    const { transport } = exactFormExchange(null);
    const readReceiverHead = createReceiverHeadReader(makeDeps(transport));

    expect(await readReceiverHead(RECEIVER_PUBLIC_KEY)).toBeNull();
  });

  it("regression guard: the exact-form fake rejects the legacy public_key_base64urlsafe form", () => {
    // The exact defect that shipped: a hand-built request using the old, noncanonical field
    // name. buildGatewayActionRequest never reorders or renames action-data keys (the byte-exact signing rule
    // 3), so this reproduces the literal bytes the pre-fix confirm-read sent.
    const legacyRequest = buildGatewayActionRequest("get_transaction__v1", {
      public_key_base64urlsafe: RECEIVER_PUBLIC_KEY,
    });
    const { actionData } = decodeGatewayFormBody(legacyRequest.bodyBytes);
    expect(() => assertCanonicalGetTransactionActionData(actionData)).toThrow(
      GetTransactionActionDataShapeError,
    );
  });
});
