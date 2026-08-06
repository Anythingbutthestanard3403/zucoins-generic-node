import { describe, it, expect } from "vitest";
import {
  POOL_WALLET_STATES,
  POOL_WALLET_TRANSITIONS,
  POOL_KEY_DELETION_ALLOWED,
  isValidPoolTransition,
  countsTowardCap,
  type PoolWalletState,
} from "./states.js";

describe("pool wallet state machine — census", () => {
  it("freezes exactly the four lifecycle states (no DELETED state)", () => {
    expect([...POOL_WALLET_STATES]).toEqual(["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"]);
    expect(POOL_WALLET_STATES as readonly string[]).not.toContain("DELETED");
  });
  it("allows exactly the frozen transitions", () => {
    expect(POOL_WALLET_TRANSITIONS.map(([f, t]) => `${f}->${t}`)).toEqual([
      "AVAILABLE->PINNED",
      "PINNED->AVAILABLE",
      "AVAILABLE->QUARANTINED",
      "QUARANTINED->AVAILABLE",
      "AVAILABLE->RETIRED",
    ]);
  });
});

describe("isValidPoolTransition — allowed transitions", () => {
  it("permits lease, quarantine/re-verify, and AVAILABLE->RETIRED", () => {
    expect(isValidPoolTransition("AVAILABLE", "PINNED")).toBe(true);
    expect(isValidPoolTransition("PINNED", "AVAILABLE")).toBe(true);
    expect(isValidPoolTransition("AVAILABLE", "RETIRED")).toBe(true);
  });
});

describe("isValidPoolTransition — forbidden transitions (NEGATIVES)", () => {
  it("cannot retire a live-leased (PINNED) wallet", () => {
    expect(isValidPoolTransition("PINNED", "RETIRED")).toBe(false);
  });
  it("cannot un-retire (no path that skips re-verification, the recovery-gated eligibility rule)", () => {
    expect(isValidPoolTransition("RETIRED", "AVAILABLE")).toBe(false);
    expect(isValidPoolTransition("RETIRED", "PINNED")).toBe(false);
  });
});

describe("permanent key retention — physical delete is rejected (NEGATIVE, the key-custody rule / the frozen rule)", () => {
  it("key deletion is structurally forbidden and there is no delete transition", () => {
    expect(POOL_KEY_DELETION_ALLOWED).toBe(false);
    for (const [, to] of POOL_WALLET_TRANSITIONS) {
      expect(to).not.toBe("DELETED");
    }
  });
});

describe("countsTowardCap — cap counts ALL states incl. RETIRED (the receive-queue backpressure rule 2)", () => {
  it("every lifecycle state counts toward pool_cap", () => {
    for (const state of POOL_WALLET_STATES) {
      expect(countsTowardCap(state)).toBe(true);
    }
    expect(countsTowardCap("RETIRED")).toBe(true);
  });
  it("an unknown/deleted state does not count (there is no such wallet)", () => {
    expect(countsTowardCap("DELETED" as PoolWalletState)).toBe(false);
  });
});
