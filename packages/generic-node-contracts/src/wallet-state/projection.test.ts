import { describe, it, expect } from "vitest";
import { projectWalletState, isSelectableForReceive } from "./projection.js";
import { type WalletLease } from "./leases.js";

const receiveLease: WalletLease = { role: "RECEIVE_WINDOW", lifecycle: "ACTIVE" };
const sendLease: WalletLease = { role: "SEND_SOURCE", lifecycle: "ACTIVE" };
const reconLease: WalletLease = { role: "RECONCILIATION", lifecycle: "ACTIVE" };
const releasedReceive: WalletLease = { role: "RECEIVE_WINDOW", lifecycle: "RELEASED" };

const clean = { leases: [], quarantined: false, retired: false };

describe("projectWalletState — lease truth takes precedence (the core invariant)", () => {
  it("a wallet with an active operation lease projects PINNED, never AVAILABLE", () => {
    expect(projectWalletState({ ...clean, leases: [receiveLease] })).toEqual({
      state: "PINNED",
      activeRole: "RECEIVE_WINDOW",
      reconciliationActive: false,
      breach: null,
    });
    expect(projectWalletState({ ...clean, leases: [sendLease] }).state).toBe("PINNED");
  });
  it("a clean wallet with no active operation lease projects AVAILABLE", () => {
    expect(projectWalletState(clean).state).toBe("AVAILABLE");
  });
  it("a RELEASED lease does not pin (does not keep the wallet PINNED)", () => {
    expect(projectWalletState({ ...clean, leases: [releasedReceive] }).state).toBe("AVAILABLE");
  });
  it("a RECONCILIATION lease never pins — observation does not exclude from selection", () => {
    expect(projectWalletState({ ...clean, leases: [reconLease] })).toEqual({
      state: "AVAILABLE",
      activeRole: null,
      reconciliationActive: true,
      breach: null,
    });
  });
});

describe("projectWalletState — the one-in-flight-per-wallet rule (one in-flight per wallet)", () => {
  it("NEGATIVE: more than one active operation lease is a breach", () => {
    const result = projectWalletState({ ...clean, leases: [receiveLease, sendLease] });
    expect(result.state).toBe("PINNED");
    expect(result.breach).toBe("multiple_active_operation_leases");
  });
});

describe("projectWalletState — quarantine / retirement precedence", () => {
  it("quarantine and retirement project their state when unleased", () => {
    expect(projectWalletState({ ...clean, quarantined: true }).state).toBe("QUARANTINED");
    expect(projectWalletState({ ...clean, retired: true }).state).toBe("RETIRED");
  });
  it("quarantine is honoured on the active-lease path (never understates as PINNED)", () => {
    // Live shape: QUARANTINED wallet holding RECEIVE_WINDOW. Quarantine is strictly more
    // restricted than PINNED; projecting PINNED would make boot-audit ask to "repair" the
    // quarantine away. activeRole still surfaces the lease.
    expect(
      projectWalletState({ leases: [receiveLease], quarantined: true, retired: false }),
    ).toEqual({
      state: "QUARANTINED",
      activeRole: "RECEIVE_WINDOW",
      reconciliationActive: false,
      breach: null,
    });
  });
  it("NEGATIVE: a quarantined leased wallet must not project PINNED (ordering regression)", () => {
    const result = projectWalletState({
      leases: [receiveLease],
      quarantined: true,
      retired: false,
    });
    expect(result.state).not.toBe("PINNED");
    expect(result.state).not.toBe("AVAILABLE");
  });
});

describe("isSelectableForReceive — projection AND recovery gate meet here (the named concern exit criterion)", () => {
  const verified = { keyOrigin: "node_generated", recoveryVerifiedAt: "2026-07-19T00:00:00.000Z" };
  it("selectable when projected AVAILABLE and recovery-verified", () => {
    expect(isSelectableForReceive({ ...clean, ...verified })).toBe(true);
  });
  it("NEGATIVE: recovery-unverified projected-AVAILABLE wallet is not selectable (the recovery-gate rule)", () => {
    expect(isSelectableForReceive({ ...clean, ...verified, recoveryVerifiedAt: null })).toBe(false);
  });
  it("NEGATIVE: a leased (PINNED) wallet is not selectable even if recovery-verified", () => {
    expect(isSelectableForReceive({ leases: [receiveLease], quarantined: false, retired: false, ...verified })).toBe(false);
  });
});
