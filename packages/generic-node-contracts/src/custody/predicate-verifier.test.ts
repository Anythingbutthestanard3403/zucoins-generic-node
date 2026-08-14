import { describe, expect, it } from "vitest";
import {
  verifyAutomaticSinkEligibility,
  verifyCompositionSinkEligibility,
  verifyInternalCustody,
  verifyWorkerSinkEligibility,
} from "./predicate-verifier.ts";

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
  it("WORKER is not internal custody and not an automatic sink", () => {
    expect(verifyInternalCustody({ ...eligible, destinationState: "WORKER" })).toEqual({
      eligible: false,
      denialReason: "DESTINATION_NOT_BLESSED",
    });
    expect(verifyAutomaticSinkEligibility({ ...eligible, destinationState: "WORKER" })).toEqual({
      eligible: false,
      denialReason: "DESTINATION_NOT_BLESSED",
    });
  });
  it("accepts a worker sink without recovery evidence", () => {
    expect(
      verifyWorkerSinkEligibility({
        ...eligible,
        destinationState: "WORKER",
        recoveryVerifiedAt: null,
      }),
    ).toEqual({ eligible: true, denialReason: null });
  });
  it("composition top-up accepts blessed automatic sinks and worker sinks", () => {
    expect(verifyCompositionSinkEligibility(eligible).eligible).toBe(true);
    expect(
      verifyCompositionSinkEligibility({
        ...eligible,
        destinationState: "WORKER",
        recoveryVerifiedAt: null,
      }).eligible,
    ).toBe(true);
    expect(
      verifyCompositionSinkEligibility({ ...eligible, destinationState: "PENDING" }).eligible,
    ).toBe(false);
  });
});
