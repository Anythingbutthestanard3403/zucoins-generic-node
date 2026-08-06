import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  RECEIVE_EXTERNAL_STATES,
  MOVE_INTERNAL_STATES,
  SEND_EXTERNAL_STATES,
  FORBIDDEN_STATE_ALIASES,
  RECEIVE_EXTERNAL_TRANSITIONS,
  MOVE_INTERNAL_TRANSITIONS,
  SEND_EXTERNAL_TRANSITIONS,
} from "./states.contract.ts";

describe("states census", () => {
  it("freezes RECEIVE_EXTERNAL states, in sequence", () => {
    assertFieldOrder(RECEIVE_EXTERNAL_STATES, ["CREATED", "READY", "RECEIVE_LANDED", "EXPIRED"]);
  });

  it("freezes MOVE_INTERNAL states, in sequence", () => {
    assertFieldOrder(MOVE_INTERNAL_STATES, ["CREATED", "INTERNAL_MOVE_LANDED", "NEEDS_ATTENTION"]);
  });

  it("freezes SEND_EXTERNAL states, in sequence", () => {
    assertFieldOrder(SEND_EXTERNAL_STATES, [
      "CREATED",
      "APPROVED",
      "AWAITING_REDEMPTION",
      "EXTERNAL_SEND_LANDED",
      "REJECTED",
      "NEEDS_ATTENTION",
    ]);
  });

  it("freezes the forbidden state alias list", () => {
    assertFieldOrder(FORBIDDEN_STATE_ALIASES, [
      "RESERVED",
      "OBSERVED",
      "CONFIRMED",
      "FINALISED", // contract-allow:forbidden-alias-citation
      "PAID",
      "HELD",
      "REFUNDED", // contract-allow:forbidden-alias-citation
      "SUBMITTED",
      "FAILED",
      "SETTLED",
    ]);
  });

  it("freezes the exact transition count per operation", () => {
    expect(RECEIVE_EXTERNAL_TRANSITIONS).toHaveLength(5);
    expect(MOVE_INTERNAL_TRANSITIONS).toHaveLength(5);
    expect(SEND_EXTERNAL_TRANSITIONS).toHaveLength(11);
  });

  it("rejects a reordered state list (negative path)", () => {
    expectRejects(
      () => [...RECEIVE_EXTERNAL_STATES].reverse(),
      (mutated) => assertFieldOrder(mutated, RECEIVE_EXTERNAL_STATES),
    );
  });
});
