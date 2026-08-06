import { describe, it, expect } from "vitest";
import {
  LEASE_ROLES,
  OPERATION_LEASE_ROLES,
  isOperationRole,
  isLeaseActive,
  activeOperationLeases,
  type WalletLease,
} from "./leases.js";

describe("lease vocabulary — census", () => {
  it("freezes the five lease roles", () => {
    expect([...LEASE_ROLES]).toEqual([
      "RECEIVE_WINDOW",
      "MOVE_DESTINATION",
      "SEND_SOURCE",
      "MOVE_SOURCE",
      "RECONCILIATION",
    ]);
  });
  it("the four operation roles pin; RECONCILIATION does not (observation-only)", () => {
    for (const role of OPERATION_LEASE_ROLES) expect(isOperationRole(role)).toBe(true);
    expect(isOperationRole("RECONCILIATION")).toBe(false);
  });
});

describe("isLeaseActive — the receive-expiry rule held-past-expiry stays ACTIVE", () => {
  it("an ACTIVE lease is active (a post-candidate held receive lease is modeled ACTIVE)", () => {
    expect(isLeaseActive({ role: "RECEIVE_WINDOW", lifecycle: "ACTIVE" })).toBe(true);
  });
  it("NEGATIVE: a RELEASED lease is not active", () => {
    expect(isLeaseActive({ role: "RECEIVE_WINDOW", lifecycle: "RELEASED" })).toBe(false);
  });
});

describe("activeOperationLeases — filters released and reconciliation", () => {
  it("keeps only active operation leases", () => {
    const leases: WalletLease[] = [
      { role: "RECEIVE_WINDOW", lifecycle: "ACTIVE" },
      { role: "RECONCILIATION", lifecycle: "ACTIVE" },
      { role: "SEND_SOURCE", lifecycle: "RELEASED" },
    ];
    expect(activeOperationLeases(leases)).toEqual([{ role: "RECEIVE_WINDOW", lifecycle: "ACTIVE" }]);
  });
});
