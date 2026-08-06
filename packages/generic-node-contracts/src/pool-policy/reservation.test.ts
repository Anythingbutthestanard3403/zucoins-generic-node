import { describe, it, expect } from "vitest";
import {
  reserveWallet,
  isAssignable,
  RESERVE_WALLET_CAS_SQL,
  POOL_CAS_COLUMN,
  REPLENISHMENT_CRASH_SAFETY,
} from "./reservation.js"; // contract-allow:reservation-module-path
import { type PoolWalletDescriptor } from "./eligibility.js";

const verifiedAvailable: PoolWalletDescriptor = {
  keyOrigin: "node_generated",
  recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
  state: "AVAILABLE",
};

describe("reserveWallet — optimistic row_version CAS", () => {
  it("reserves when version matches and state is AVAILABLE, bumping the version", () => {
    expect(reserveWallet({ expectedRowVersion: 4, actualRowVersion: 4, state: "AVAILABLE" })).toEqual({
      kind: "reserved",
      nextRowVersion: 5,
    });
  });
  it("loses on a stale row_version (another txn moved the row) — NEGATIVE", () => {
    expect(reserveWallet({ expectedRowVersion: 4, actualRowVersion: 5, state: "AVAILABLE" })).toEqual({
      kind: "lost",
    });
  });
  it("loses when the row is no longer AVAILABLE — NEGATIVE", () => {
    expect(reserveWallet({ expectedRowVersion: 4, actualRowVersion: 4, state: "PINNED" })).toEqual({
      kind: "lost",
    });
    expect(reserveWallet({ expectedRowVersion: 4, actualRowVersion: 4, state: "RETIRED" })).toEqual({
      kind: "lost",
    });
  });
});

describe("isAssignable — boot secret-probe + eligibility, resurrected-wallet block (the recovery-gated eligibility rule)", () => {
  it("is assignable only with a decryptable secret and receive-eligibility", () => {
    expect(isAssignable(verifiedAvailable, true)).toBe(true);
  });
  it("blocks a wallet whose secret is not decryptable (boot probe fail) — NEGATIVE", () => {
    expect(isAssignable(verifiedAvailable, false)).toBe(false);
  });
  it("blocks a resurrected/un-retired wallet (recovery_verified_at null) — NEGATIVE", () => {
    const resurrected: PoolWalletDescriptor = { ...verifiedAvailable, recoveryVerifiedAt: null };
    expect(isAssignable(resurrected, true)).toBe(false);
  });
});

describe("hold — frozen SQL + crash-safety invariant", () => {
  it("the CAS UPDATE guards on id, row_version, and AVAILABLE", () => {
    expect(RESERVE_WALLET_CAS_SQL).toContain("row_version = row_version + 1");
    expect(RESERVE_WALLET_CAS_SQL).toContain("WHERE id = $1 AND row_version = $2 AND state = 'AVAILABLE'");
    expect(POOL_CAS_COLUMN).toBe("row_version");
  });
  it("freezes the crash-atomic replenishment invariant", () => {
    expect(REPLENISHMENT_CRASH_SAFETY).toEqual({
      walletAndVaultInOneTransaction: true,
      bootVerifiesSecretOneToOne: true,
      quarantineUndecryptableBeforeSelection: true,
    });
  });
});
