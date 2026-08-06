import { describe, it, expect } from "vitest";
import {
  AMOUNT_FIELD_ROLES,
  AMOUNT_LAYERS,
  AMOUNT_AUTHORSHIP,
  amountFieldRole,
  type AmountFieldRole,
} from "./field-roles.js";

const ROLE_NAMES = Object.keys(AMOUNT_FIELD_ROLES) as AmountFieldRole[];

describe("amount field-role map — census", () => {
  it("freezes exactly the amount-bearing roles across requests/operations/states/approvals/artifacts/derived balances", () => {
    expect(ROLE_NAMES.sort()).toEqual(
      [
        "approval_amount",
        "derived_balance",
        "expected_artifact_amount",
        "genesis_amount",
        "node_head_amount",
        "node_post_transfer_state",
        "observed_onchain_step_state",
        "operation_amount_zkz",
        "payer_signed_step_amount",
        "recipient_signed_step_amount",
        "request_transfer_amount",
      ].sort(),
    );
  });
});

describe("amount field-role map — layer/authorship invariants", () => {
  it("node roles carry a real layer; foreign roles carry null", () => {
    for (const name of ROLE_NAMES) {
      const spec = amountFieldRole(name);
      if (spec.authorship === AMOUNT_AUTHORSHIP.node) {
        expect([AMOUNT_LAYERS.balance, AMOUNT_LAYERS.operation]).toContain(spec.layer);
      } else {
        expect(spec.authorship).toBe(AMOUNT_AUTHORSHIP.foreign);
        expect(spec.layer).toBeNull();
      }
    }
  });
  it("requests / operations / approvals / artifacts are the strictly-positive operation layer", () => {
    for (const name of [
      "request_transfer_amount",
      "operation_amount_zkz",
      "approval_amount",
      "expected_artifact_amount",
    ] as const) {
      expect(AMOUNT_FIELD_ROLES[name]).toEqual({ authorship: "node", layer: "operation" });
    }
  });
  it("states / derived balances / heads / genesis are the inclusive-zero balance layer", () => {
    for (const name of [
      "node_post_transfer_state",
      "derived_balance",
      "node_head_amount",
      "genesis_amount",
    ] as const) {
      expect(AMOUNT_FIELD_ROLES[name]).toEqual({ authorship: "node", layer: "balance" });
    }
  });
  it("payer / recipient / observed step amounts are foreign (byte-exact, the byte-exact signing rule)", () => {
    for (const name of [
      "payer_signed_step_amount",
      "recipient_signed_step_amount",
      "observed_onchain_step_state",
    ] as const) {
      expect(AMOUNT_FIELD_ROLES[name]).toEqual({ authorship: "foreign", layer: null });
    }
  });
});
