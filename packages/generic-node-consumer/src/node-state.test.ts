import { describe, expect, it } from "vitest";

import {
  NodeStateDriftError,
  isKnownNodeClaimState,
  parseNodeClaimState,
} from "./node-state.js";

describe("parseNodeClaimState", () => {
  it("accepts closed Layer-1 states", () => {
    expect(parseNodeClaimState("RECEIVE_LANDED")).toBe("RECEIVE_LANDED");
    expect(parseNodeClaimState("INTERNAL_MOVE_LANDED")).toBe("INTERNAL_MOVE_LANDED");
    expect(parseNodeClaimState("CREATED")).toBe("CREATED");
    expect(isKnownNodeClaimState("EXTERNAL_SEND_LANDED")).toBe(true);
  });

  it("rejects unknown states with typed drift error", () => {
    expect(() => parseNodeClaimState("TOTALLY_MADE_UP")).toThrow(NodeStateDriftError);
    try {
      parseNodeClaimState("TOTALLY_MADE_UP");
    } catch (err) {
      expect(err).toMatchObject({ code: "NODE_STATE_DRIFT", reason: "unknown_state" });
    }
  });

  it("rejects forbidden product-projection aliases", () => {
    expect(() => parseNodeClaimState("PAID")).toThrow(NodeStateDriftError);
    try {
      parseNodeClaimState("SETTLED");
    } catch (err) {
      expect(err).toMatchObject({ code: "NODE_STATE_DRIFT", reason: "forbidden_alias" });
    }
  });
});
