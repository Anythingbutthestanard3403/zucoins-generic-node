import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  TRANSFER_CODE_WIRE_VERSION,
  TRANSFER_CODE_TOP_LEVEL_FIELDS,
  TRANSFER_CODE_TYPES,
  RECEIVE_CODE_TYPE,
  RECEIVE_CODE_TYPE_EXPLICIT,
  SEND_CODE_TYPE,
  SENDER_CREATE_REQUIRED_FIELDS,
  SENDER_CREATE_OPTIONAL_FIELDS,
  SENDER_CREATE_EXPLICIT_PREFIX_FIELD,
  RECEIVER_CONFIRM_INCOMING_DATA_FIELDS,
  TRANSFER_CODE_ENCODE_PIPELINE,
  TRANSFER_CODE_DECODE_PIPELINE,
  EXPIRY_FIELD,
  EXPIRY_UNIT,
  EXPIRY_MAX_SECONDS_AHEAD_OF_BLOCK,
  EXPIRED_CODE_GATEWAY_DISPOSITION,
  RECEIVE_MESSAGE_PREFIX,
  RECEIVE_MESSAGE_MAX_LENGTH,
  USER_SHARE_MESSAGE_MAX_LENGTH,
  USER_SHARE_MESSAGE_IS_SIGNED,
} from "./transfer-code.contract.ts";
import { assertWireVersion, objectKeySequence } from "./transfer-code-codec.ts";

/**
 * the receive-golden transfer-code concern.1 census: freezes the two transfer-code envelope versions, types, field sequences, padded
 * base64url pipeline, and expiry units. Every frozen sequence carries at least one negative.
 */
describe("transfer-code census (the receive-golden transfer-code concern.1, the frozen rule/the code-matching rule/the frozen rule/the frozen rule)", () => {
  it("freezes the single wire version literal '1'", () => {
    expect(TRANSFER_CODE_WIRE_VERSION).toBe("1");
  });

  it("freezes the top-level field sequence", () => {
    assertFieldOrder(TRANSFER_CODE_TOP_LEVEL_FIELDS, ["version", "type", "incoming_data"]);
  });

  it("rejects a resequenced top-level field tuple (negative)", () => {
    expectRejects(
      () => ["type", "version", "incoming_data"] as const,
      (mutated) => assertFieldOrder(mutated, TRANSFER_CODE_TOP_LEVEL_FIELDS),
    );
  });

  it("freezes the envelope type discriminators", () => {
    assertClosedSet(TRANSFER_CODE_TYPES, [
      "sender_create_transaction",
      "sender_create_transaction_explicit",
      "receiver_confirm_partial_transaction",
    ]);
    expect(RECEIVE_CODE_TYPE).toBe("sender_create_transaction");
    expect(RECEIVE_CODE_TYPE_EXPLICIT).toBe("sender_create_transaction_explicit");
    expect(SEND_CODE_TYPE).toBe("receiver_confirm_partial_transaction");
  });

  it("rejects a fourth envelope type (negative)", () => {
    const fourthType = "sender_create_transaction_v2";
    expectRejects(
      () => [...TRANSFER_CODE_TYPES, fourthType],
      (mutated) => assertClosedSet(mutated, TRANSFER_CODE_TYPES),
    );
  });

  it("freezes sender_create_transaction incoming_data field sequences", () => {
    assertFieldOrder(SENDER_CREATE_REQUIRED_FIELDS, [
      "receiver_key_public__base64urlsafe",
      "inner_state_amount",
    ]);
    assertFieldOrder(SENDER_CREATE_OPTIONAL_FIELDS, [
      "expiry__unix_time_secs",
      "message",
      "inner_state_metadata",
      "user_share_message",
    ]);
    expect(SENDER_CREATE_EXPLICIT_PREFIX_FIELD).toBe("sender_key_public__base64urlsafe");
  });

  it("rejects a resequenced optional-field tuple (negative)", () => {
    expectRejects(
      () => ["message", "expiry__unix_time_secs", "inner_state_metadata", "user_share_message"] as const,
      (mutated) => assertFieldOrder(mutated, SENDER_CREATE_OPTIONAL_FIELDS),
    );
  });

  it("freezes receiver_confirm_partial_transaction incoming_data", () => {
    assertFieldOrder(RECEIVER_CONFIRM_INCOMING_DATA_FIELDS, ["partial_transaction"]);
  });

  it("freezes the encode and decode pipelines", () => {
    assertFieldOrder(TRANSFER_CODE_ENCODE_PIPELINE, [
      "JSON.stringify",
      "encodeURIComponent",
      "base64url",
      "strip-padding",
    ]);
    assertFieldOrder(TRANSFER_CODE_DECODE_PIPELINE, [
      "base64url-decode-tolerant-padding",
      "decodeURIComponent",
      "JSON.parse",
    ]);
  });

  it("rejects a resequenced encode pipeline (negative)", () => {
    expectRejects(
      () => ["encodeURIComponent", "JSON.stringify", "base64url", "strip-padding"] as const,
      (mutated) => assertFieldOrder(mutated, TRANSFER_CODE_ENCODE_PIPELINE),
    );
  });

  it("freezes expiry byte units and bounds (seconds, never ms)", () => {
    expect(EXPIRY_FIELD).toBe("expiry__unix_time_secs");
    expect(EXPIRY_UNIT).toBe("seconds");
    expect(EXPIRY_MAX_SECONDS_AHEAD_OF_BLOCK).toBe(59999880);
    expect(EXPIRED_CODE_GATEWAY_DISPOSITION).toBe("hard_reject");
  });

  it("rejects milliseconds as the expiry unit (negative)", () => {
    expectRejects(
      () => "milliseconds",
      (mutated) => expect(mutated).toBe(EXPIRY_UNIT),
    );
  });

  it("freezes receive-message and user-share-message contracts", () => {
    expect(RECEIVE_MESSAGE_PREFIX).toBe("zp1:");
    expect(RECEIVE_MESSAGE_MAX_LENGTH).toBe(256);
    expect(USER_SHARE_MESSAGE_MAX_LENGTH).toBe(300);
    expect(USER_SHARE_MESSAGE_IS_SIGNED).toBe(false);
  });

  it("version verifier accepts '1' and rejects '2'/'3' (negative)", () => {
    expect(() => assertWireVersion({ version: "1" })).not.toThrow();
    expect(() => assertWireVersion({ version: "3" })).toThrow();
    expect(() => assertWireVersion({ version: "2" })).toThrow();
  });

  it("objectKeySequence reflects insertion sequence", () => {
    assertFieldOrder(objectKeySequence({ version: "1", type: "x", incoming_data: {} }), [
      "version",
      "type",
      "incoming_data",
    ]);
  });
});
