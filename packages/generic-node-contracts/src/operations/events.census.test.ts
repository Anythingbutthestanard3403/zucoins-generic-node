import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  DURABLE_EVENTS,
  ATTENTION_REASONS,
  FORBIDDEN_EVENT_ALIASES,
} from "./events.contract.ts";

describe("events census", () => {
  it("freezes the durable public event set at exactly nine values, in sequence", () => {
    assertFieldOrder(DURABLE_EVENTS, [
      "receive.ready",
      "receive.landed",
      "internal_move.created",
      "internal_move.landed",
      "external_send.created",
      "external_send.awaiting_redemption",
      "external_send.landed",
      "operation.needs_attention",
      "operation.expired",
    ]);
    expect(DURABLE_EVENTS).toHaveLength(9);
  });

  it("freezes the attention-reason vocabulary", () => {
    expect(ATTENTION_REASONS).toHaveLength(15);
    expect(new Set(ATTENTION_REASONS).size).toBe(ATTENTION_REASONS.length);
    expect(ATTENTION_REASONS).toContain("POST_EXPIRY_RECONCILING");
  });

  it("freezes the forbidden event-alias list", () => {
    assertFieldOrder(FORBIDDEN_EVENT_ALIASES, [
      "transfer.confirmed",
      "transfer.finalised", // contract-allow:forbidden-alias-citation
      "sweep.settled", // contract-allow:forbidden-alias-citation
      "outbound.settled", // contract-allow:forbidden-alias-citation
    ]);
  });

  it("rejects a tenth event (negative path)", () => {
    expectRejects(
      () => [...DURABLE_EVENTS, "transfer.confirmed"],
      (mutated) => assertFieldOrder(mutated, DURABLE_EVENTS),
    );
  });
});
