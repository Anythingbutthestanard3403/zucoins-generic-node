import { describe, expect, it } from "vitest";

import { ATTENTION_REASONS } from "../../generic-node-contracts/src/operations/events.contract.ts";

import { toAttentionReason } from "../src/protocol/reconcile/types.js";

describe("toAttentionReason — ZTR-1147 closed-set extensions", () => {
  it("maps DESTINATION_NO_LONGER_BLESSED", () => {
    expect(toAttentionReason({ source: "DESTINATION_NO_LONGER_BLESSED" })).toBe(
      "DESTINATION_NO_LONGER_BLESSED",
    );
  });

  it("maps OPERATOR_PARKED", () => {
    expect(toAttentionReason({ source: "OPERATOR_PARKED" })).toBe("OPERATOR_PARKED");
  });

  it("maps gateway deferred sources onto the frozen vocabulary", () => {
    expect(toAttentionReason({ source: "GATEWAY_RESPONSE_INVALID" })).toBe(
      "GATEWAY_RESPONSE_INVALID",
    );
    expect(toAttentionReason({ source: "GATEWAY_UNAVAILABLE_BEYOND_BUDGET" })).toBe(
      "GATEWAY_UNAVAILABLE_BEYOND_BUDGET",
    );
  });

  it("every mapped value is a member of ATTENTION_REASONS", () => {
    const samples = [
      toAttentionReason({ source: "DESTINATION_NO_LONGER_BLESSED" }),
      toAttentionReason({ source: "OPERATOR_PARKED" }),
      toAttentionReason({ source: "GATEWAY_RESPONSE_INVALID" }),
      toAttentionReason({ source: "GATEWAY_UNAVAILABLE_BEYOND_BUDGET" }),
      toAttentionReason({ source: "SUBMIT_OUTCOME_UNKNOWN" }),
    ] as const;
    for (const v of samples) {
      expect(ATTENTION_REASONS).toContain(v);
    }
  });
});
