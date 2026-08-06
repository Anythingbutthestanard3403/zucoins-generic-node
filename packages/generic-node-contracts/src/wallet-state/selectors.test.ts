import { describe, it, expect } from "vitest";
import {
  WALLET_SELECTORS,
  PROJECTION_BOUND_SELECTORS,
  isSelectorConsistent,
  type WalletSelectorName,
} from "./selectors.js";

describe("selector registry — census", () => {
  it("names every selector that consumes wallet state", () => {
    expect(Object.keys(WALLET_SELECTORS).sort()).toEqual([
      "move_destination_selection",
      "pool_receive_selection",
      "recovery_flow",
      "release_path",
      "send_source_selection",
      "signer_eligibility",
    ]);
  });
  it("five selectors are projection-bound; recovery_flow (ceremony/observation) is not", () => {
    expect(PROJECTION_BOUND_SELECTORS).toHaveLength(5);
    expect(PROJECTION_BOUND_SELECTORS).not.toContain("recovery_flow");
    expect(WALLET_SELECTORS.recovery_flow.requiresProjection).toBe(false);
  });
});

describe("isSelectorConsistent — a projection-bound selector must consume the projection", () => {
  it("accepts a projection-bound selector that uses the projection", () => {
    for (const selector of PROJECTION_BOUND_SELECTORS) {
      expect(isSelectorConsistent(selector, true)).toBe(true);
    }
  });
  it("NEGATIVE: a projection-bound selector that bypasses the projection is rejected", () => {
    for (const selector of PROJECTION_BOUND_SELECTORS) {
      expect(isSelectorConsistent(selector, false)).toBe(false);
    }
  });
  it("recovery_flow is consistent either way (not projection-bound)", () => {
    expect(isSelectorConsistent("recovery_flow" as WalletSelectorName, false)).toBe(true);
    expect(isSelectorConsistent("recovery_flow" as WalletSelectorName, true)).toBe(true);
  });
});
