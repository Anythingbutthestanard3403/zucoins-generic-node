import { describe, it, expect } from "vitest";
import {
  isAvailableForReceive,
  availableWalletCount,
  capCount,
  type PoolWalletDescriptor,
} from "./eligibility.js";

const verifiedAvailable: PoolWalletDescriptor = {
  keyOrigin: "node_generated",
  recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
  state: "AVAILABLE",
};

describe("isAvailableForReceive — recovery-gated receive-eligibility", () => {
  it("accepts a node-generated, recovery-verified, AVAILABLE wallet", () => {
    expect(isAvailableForReceive(verifiedAvailable)).toBe(true);
  });
  it("REJECTS a recovery-unverified AVAILABLE wallet (the core recovery-gated-eligibility fact — NEGATIVE)", () => {
    expect(isAvailableForReceive({ ...verifiedAvailable, recoveryVerifiedAt: null })).toBe(false);
  });
  it("rejects non-AVAILABLE states even when verified", () => {
    for (const state of ["PINNED", "QUARANTINED", "RETIRED"] as const) {
      expect(isAvailableForReceive({ ...verifiedAvailable, state })).toBe(false);
    }
  });
  it("rejects a non-node-generated wallet", () => {
    expect(isAvailableForReceive({ ...verifiedAvailable, keyOrigin: "imported" })).toBe(false);
  });
});

describe("availableWalletCount vs capCount — two distinct counts (recovery-gated eligibility + backpressure rule 2)", () => {
  const pool: PoolWalletDescriptor[] = [
    verifiedAvailable,
    verifiedAvailable,
    verifiedAvailable,
    { ...verifiedAvailable, recoveryVerifiedAt: null }, // minted-unverified
    { ...verifiedAvailable, recoveryVerifiedAt: null }, // minted-unverified
    { ...verifiedAvailable, state: "PINNED" },
    { ...verifiedAvailable, state: "RETIRED" },
  ];
  it("available counts ONLY recovery-verified AVAILABLE wallets", () => {
    expect(availableWalletCount(pool)).toBe(3);
  });
  it("cap counts ALL non-deleted wallets incl. unverified / PINNED / RETIRED", () => {
    expect(capCount(pool)).toBe(7);
  });
  it("minting-unverified wallets raise the cap but never the available count", () => {
    // Two more minted-unverified wallets: cap +2, available unchanged (replenishment is the
    // recovery ceremony, not the mint loop).
    const grown = [
      ...pool,
      { ...verifiedAvailable, recoveryVerifiedAt: null },
      { ...verifiedAvailable, recoveryVerifiedAt: null },
    ];
    expect(availableWalletCount(grown)).toBe(3);
    expect(capCount(grown)).toBe(9);
  });
});
