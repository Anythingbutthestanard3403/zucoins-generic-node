import { describe, it, expect } from "vitest";
import { auditPersistedWallet } from "./boot-audit.js";
import { projectWalletState } from "./projection.js";
import { type WalletLease } from "./leases.js";

const receiveLease: WalletLease = { role: "RECEIVE_WINDOW", lifecycle: "ACTIVE" };
const sendLease: WalletLease = { role: "SEND_SOURCE", lifecycle: "ACTIVE" };

const projClean = projectWalletState({ leases: [], quarantined: false, retired: false });
const projLeased = projectWalletState({ leases: [receiveLease], quarantined: false, retired: false });
const projBreach = projectWalletState({ leases: [receiveLease, sendLease], quarantined: false, retired: false });

describe("auditPersistedWallet — consistent state", () => {
  it("no contradiction when stored equals projected; no audit", () => {
    expect(auditPersistedWallet("AVAILABLE", projClean)).toEqual({
      contradictionClass: "none",
      disposition: "CONSISTENT",
      auditRequired: false,
    });
  });
});

describe("auditPersistedWallet — understated restriction (the boot expectation)", () => {
  it("a leased wallet stored AVAILABLE is repaired to the projected PINNED + audit", () => {
    expect(auditPersistedWallet("AVAILABLE", projLeased)).toEqual({
      contradictionClass: "understated_restriction",
      disposition: "REPAIR_TO_PROJECTION",
      auditRequired: true,
    });
  });
});

describe("auditPersistedWallet — stored QUARANTINED is never repaired away", () => {
  it("QUARANTINED + active lease projects QUARANTINED → CONSISTENT, no repair", () => {
    const proj = projectWalletState({
      leases: [receiveLease],
      quarantined: true,
      retired: false,
    });
    expect(proj.state).toBe("QUARANTINED");
    expect(auditPersistedWallet("QUARANTINED", proj)).toEqual({
      contradictionClass: "none",
      disposition: "CONSISTENT",
      auditRequired: false,
    });
  });
  it("NEGATIVE: stored QUARANTINED never yields understated_restriction / REPAIR_TO_PROJECTION", () => {
    // Defensive: even if a caller under-feeds quarantined=false while stored is QUARANTINED,
    // boot must not classify operator quarantine as "insufficiently restrictive".
    const result = auditPersistedWallet("QUARANTINED", projLeased);
    expect(result.contradictionClass).not.toBe("understated_restriction");
    expect(result.disposition).not.toBe("REPAIR_TO_PROJECTION");
    expect(result.disposition).toBe("CONSISTENT");
  });
});

describe("auditPersistedWallet — overstated restriction fails closed (NEGATIVE)", () => {
  it("stored PINNED with no lease quarantines for reconciliation, never repaired to AVAILABLE", () => {
    const result = auditPersistedWallet("PINNED", projClean);
    expect(result.disposition).toBe("QUARANTINE_FOR_RECONCILIATION");
    expect(result.disposition).not.toBe("REPAIR_TO_PROJECTION");
    expect(result.auditRequired).toBe(true);
  });
  it("stored RETIRED projecting AVAILABLE also fails closed (guards a silent un-retire)", () => {
    expect(auditPersistedWallet("RETIRED", projClean).disposition).toBe("QUARANTINE_FOR_RECONCILIATION");
  });
});

describe("auditPersistedWallet — persisted invariant breach", () => {
  it("more than one active operation lease quarantines as an invariant breach", () => {
    expect(auditPersistedWallet("PINNED", projBreach)).toEqual({
      contradictionClass: "persisted_invariant_breach",
      disposition: "INVARIANT_BREACH_QUARANTINE",
      auditRequired: true,
    });
  });
});

describe("auditPersistedWallet — a boot never silently accepts a contradiction (NEGATIVE)", () => {
  it("every mismatch yields a non-CONSISTENT disposition and requires an audit event", () => {
    for (const [stored, projection] of [
      ["AVAILABLE", projLeased],
      ["PINNED", projClean],
      ["RETIRED", projClean],
      ["PINNED", projBreach],
    ] as const) {
      const result = auditPersistedWallet(stored, projection);
      expect(result.disposition).not.toBe("CONSISTENT");
      expect(result.auditRequired).toBe(true);
    }
  });
});
