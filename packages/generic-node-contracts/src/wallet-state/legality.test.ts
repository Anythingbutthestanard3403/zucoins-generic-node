import { describe, it, expect } from "vitest";
import {
  isLegalWalletTransition,
  requiredLeaseEvent,
  canExpiryReleaseReceiveLease,
} from "./legality.js";

describe("isLegalWalletTransition — transitions grounded in lease events (C-02)", () => {
  it("permits each the named concern transition under its required event", () => {
    expect(isLegalWalletTransition("AVAILABLE", "PINNED", "LEASE_ACQUIRED")).toBe(true);
    expect(isLegalWalletTransition("PINNED", "AVAILABLE", "LEASE_RELEASED")).toBe(true);
    expect(isLegalWalletTransition("AVAILABLE", "QUARANTINED", "QUARANTINE_FLAGGED")).toBe(true);
    expect(isLegalWalletTransition("QUARANTINED", "AVAILABLE", "QUARANTINE_CLEARED")).toBe(true);
    expect(isLegalWalletTransition("AVAILABLE", "RETIRED", "RETIRED_FLAGGED")).toBe(true);
  });
});

describe("isLegalWalletTransition — no state change without the right lease event (NEGATIVES)", () => {
  it("rejects a legal transition driven by the wrong event", () => {
    expect(isLegalWalletTransition("AVAILABLE", "PINNED", "LEASE_RELEASED")).toBe(false);
    expect(isLegalWalletTransition("AVAILABLE", "RETIRED", "LEASE_ACQUIRED")).toBe(false);
  });
  it("rejects a transition absent from the named concern set (cannot retire a leased wallet)", () => {
    expect(isLegalWalletTransition("PINNED", "RETIRED", "RETIRED_FLAGGED")).toBe(false);
    expect(requiredLeaseEvent("PINNED", "RETIRED")).toBeNull();
  });
  it("rejects a spontaneous self-transition", () => {
    expect(isLegalWalletTransition("AVAILABLE", "AVAILABLE", "LEASE_ACQUIRED")).toBe(false);
  });
});

describe("canExpiryReleaseReceiveLease — the receive-expiry rule lease-hold precedence over expiry", () => {
  it("pre-candidate expiry may release the receive lease", () => {
    expect(canExpiryReleaseReceiveLease(false)).toBe(true);
  });
  it("NEGATIVE: post-candidate expiry must NOT release the lease (wallet stays PINNED, held)", () => {
    expect(canExpiryReleaseReceiveLease(true)).toBe(false);
  });
});
