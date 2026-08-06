import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  CANDIDATE_INTAKE_IS_PUBLIC_OPERATION_ENDPOINT,
  CANDIDATE_RAW_CAPTURE_FIELDS,
  CANDIDATE_LOCATE_KEYS,
  REFUSE_CANDIDATE_WHEN_UNARMED,
  SINGLE_CANDIDATE_WINS_RECEIVE_ATTEMPT,
  RECEIVER_CHANNEL_ACTION_NAME,
  RECEIVER_CHANNEL_ACTION_DATA_FIELD,
  GATEWAY_FORM_BODY_PARAM,
  GATEWAY_ACTION_FIELDS,
  GATEWAY_FORM_BODY_TEMPLATE,
  GATEWAY_RESPONSE_FIELDS,
  GATEWAY_RESPONSE_CAPTURED_RAW_BEFORE_DECODE,
  SUBMIT_ACTION_NAME,
  SUBMIT_IS_SINGLE_SHOT,
  SUBMIT_BLIND_RETRY_ALLOWED,
  SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED,
  SUBMIT_OUTCOME_CATEGORIES,
  SUBMIT_LANDED_OUTCOME_CATEGORIES,
  INTAKE_EXPIRY_FIELD,
  INTAKE_EXPIRY_UNIT,
} from "./candidate-intake.contract.ts";
import { buildGatewayRequestBody } from "./gateway-transport-codec.ts";

/**
 * the receive-golden transfer-code concern.2 census: freezes the candidate-intake surface and the official gateway form transport
 * submit action, and receipt-only acknowledgement semantics. Every frozen fact carries a negative.
 */
describe("candidate-intake + gateway transport census (the receive-golden transfer-code concern.2, the frozen rule/the frozen rule/the frozen rule/C-09)", () => {
  it("keeps candidate intake an internal adapter, not a public operation endpoint", () => {
    expect(CANDIDATE_INTAKE_IS_PUBLIC_OPERATION_ENDPOINT).toBe(false);
  });

  it("freezes raw-capture fields and locate keys", () => {
    assertFieldOrder(CANDIDATE_RAW_CAPTURE_FIELDS, ["inner_preimage_text", "step_1_signature"]);
    assertFieldOrder(CANDIDATE_LOCATE_KEYS, [
      "receiver_pubkey",
      "discriminator",
      "expiry",
      "active_lease",
    ]);
    expect(REFUSE_CANDIDATE_WHEN_UNARMED).toBe(true);
    expect(SINGLE_CANDIDATE_WINS_RECEIVE_ATTEMPT).toBe(true);
  });

  it("freezes the wallet-compatible receiver-channel action literals", () => {
    expect(RECEIVER_CHANNEL_ACTION_NAME).toBe("zucoin_wallet_sender_partial_transfer_code__v1");
    expect(RECEIVER_CHANNEL_ACTION_DATA_FIELD).toBe("sender_transfer_code_encoded");
  });

  it("freezes the gateway form transport", () => {
    expect(GATEWAY_FORM_BODY_PARAM).toBe("v");
    assertFieldOrder(GATEWAY_ACTION_FIELDS, ["action_name", "action_data"]);
    expect(GATEWAY_FORM_BODY_TEMPLATE).toBe(
      "v=<encodeURIComponent(JSON.stringify({action_name,action_data}))>",
    );
  });

  it("builds the exact gateway request body from the frozen transport", () => {
    const body = buildGatewayRequestBody("submit_transaction__v1", { a: "1" });
    expect(body).toBe(
      `v=${encodeURIComponent('{"action_name":"submit_transaction__v1","action_data":{"a":"1"}}')}`,
    );
  });

  it("rejects a resequenced action-field tuple (negative)", () => {
    expectRejects(
      () => ["action_data", "action_name"] as const,
      (mutated) => assertFieldOrder(mutated, GATEWAY_ACTION_FIELDS),
    );
  });

  it("freezes the gateway response envelope and raw-before-decode capture", () => {
    assertFieldOrder(GATEWAY_RESPONSE_FIELDS, ["status", "code", "message", "data"]);
    expect(GATEWAY_RESPONSE_CAPTURED_RAW_BEFORE_DECODE).toBe(true);
  });

  it("freezes single-shot submit with no blind retry", () => {
    expect(SUBMIT_ACTION_NAME).toBe("submit_transaction__v1");
    expect(SUBMIT_IS_SINGLE_SHOT).toBe(true);
    expect(SUBMIT_BLIND_RETRY_ALLOWED).toBe(false);
  });

  it("freezes receipt-only acknowledgement: status:true is NEVER settlement", () => {
    expect(SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED).toBe(false);
  });

  it("freezes the closed submit outcome category set and its landing subset", () => {
    assertClosedSet(SUBMIT_OUTCOME_CATEGORIES, [
      "deterministic_rejection",
      "receipt_acknowledgement",
      "indeterminate_transport",
      "verified_exact_landing",
      "verified_complete_path_landing",
      "incomplete_or_conflicting_or_resource_exhausted",
      "regression_or_gap_or_unrelated_or_unverifiable",
    ]);
    assertClosedSet(SUBMIT_LANDED_OUTCOME_CATEGORIES, [
      "verified_exact_landing",
      "verified_complete_path_landing",
    ]);
  });

  it("rejects a receipt acknowledgement being treated as a landing (negative)", () => {
    expectRejects(
      () => "receipt_acknowledgement",
      (category) => {
        if (!SUBMIT_LANDED_OUTCOME_CATEGORIES.includes(category as never)) {
          throw new Error(`${category} is not a landing outcome`);
        }
      },
    );
  });

  it("freezes intake expiry units as seconds (never ms)", () => {
    expect(INTAKE_EXPIRY_FIELD).toBe("expiry__unix_time_secs");
    expect(INTAKE_EXPIRY_UNIT).toBe("seconds");
  });
});
