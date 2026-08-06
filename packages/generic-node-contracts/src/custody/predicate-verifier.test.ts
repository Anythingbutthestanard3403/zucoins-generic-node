import { describe, expect, it } from "vitest";
import { verifyAutomaticSinkEligibility, verifyInternalCustody } from "./predicate-verifier.ts";

const eligible = {
  keyOrigin: "node_generated",
  destinationState: "BLESSED",
  recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
  walletState: "AVAILABLE",
} as const;

describe("custody predicate verifier (the custody concern)", () => {
  it("accepts internal custody without requiring recovery", () => {
    expect(verifyInternalCustody({ ...eligible, recoveryVerifiedAt: null })).toEqual({ eligible: true, denialReason: null });
  });
  it.each(["AVAILABLE", "PINNED"])("accepts automatic sink wallet state %s", (walletState) => {
    expect(verifyAutomaticSinkEligibility({ ...eligible, walletState }).eligible).toBe(true);
  });
  it.each(["imported", null, "future_origin", 1])("denies imported, missing, future, and malformed origin %j", (keyOrigin) => {
    expect(verifyInternalCustody({ ...eligible, keyOrigin }).eligible).toBe(false);
    expect(verifyAutomaticSinkEligibility({ ...eligible, keyOrigin }).eligible).toBe(false);
  });
  it.each(["PENDING", "RETIRED", null, "FUTURE", {}])("denies unblessed, retired, missing, future, and malformed destination %j", (destinationState) => {
    expect(verifyInternalCustody({ ...eligible, destinationState }).eligible).toBe(false);
  });
  it.each([null, "", "not-a-time", 0, {}, "2026-99-99T00:00:00Z", "2026-02-30T00:00:00Z", "2026-07-19"])("denies absent or malformed recovery evidence %j", (recoveryVerifiedAt) => {
    expect(verifyAutomaticSinkEligibility({ ...eligible, recoveryVerifiedAt }).eligible).toBe(false);
  });
  it.each(["QUARANTINED", "RETIRED", null, "FUTURE", 1])("denies disabled, missing, future, and malformed wallet state %j", (walletState) => {
    expect(verifyAutomaticSinkEligibility({ ...eligible, walletState }).eligible).toBe(false);
  });
  it("recovery never upgrades imported origin", () => {
    expect(verifyAutomaticSinkEligibility({ ...eligible, keyOrigin: "imported" })).toEqual({
      eligible: false,
      denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED",
    });
  });
});
