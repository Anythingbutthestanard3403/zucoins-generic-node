import { describe, it, expect } from "vitest";
import {
  EXPIRY_RECONCILE_RELEASE_ORDER,
  postBoundaryExpiryDisposition,
  leaseDropAllowed,
} from "./ordering.js"; // contract-allow:ordering-module-path

const proof = { reconcileCompleted: true, t0Unchanged: true, groupAcknowledgementsComplete: true };

describe("EXPIRY_RECONCILE_RELEASE_ORDER — reconcile precedes resolution", () => {
  it("freezes the sequenced steps", () => {
    expect([...EXPIRY_RECONCILE_RELEASE_ORDER]).toEqual([
      "hold_lease",
      "retain_evidence",
      "reconcile_first",
      "resolve_or_release",
    ]);
  });
});

describe("postBoundaryExpiryDisposition — wired to .1's resolution contract", () => {
  const base = { ...proof, landingObserved: false, durablyInconclusive: false };
  it("stays held until reconcile completes", () => {
    expect(postBoundaryExpiryDisposition({ ...base, reconcileCompleted: false })).toEqual({
      kind: "held",
      attentionReason: "POST_EXPIRY_RECONCILING",
    });
  });
  it("a landing resolves to RECEIVE_LANDED", () => {
    expect(postBoundaryExpiryDisposition({ ...base, landingObserved: true })).toEqual({
      kind: "resolved",
      resolution: "RECEIVE_LANDED",
    });
  });
  it("MONEY-LOSS (the receive-expiry rule): exact no-landing proof + acks does NOT release — there is no post-boundary release; it stays held while not yet durably inconclusive", () => {
    expect(postBoundaryExpiryDisposition(base)).toEqual({
      kind: "held",
      attentionReason: "POST_EXPIRY_RECONCILING",
    });
  });
  it("a durably inconclusive reconcile resolves to INDETERMINATE (held indefinitely), even with full head-unchanged proof + acks", () => {
    expect(
      postBoundaryExpiryDisposition({ ...base, durablyInconclusive: true }),
    ).toEqual({ kind: "resolved", resolution: "INDETERMINATE" });
  });
  it("a durably inconclusive reconcile resolves to INDETERMINATE regardless of t0Unchanged/acks", () => {
    expect(
      postBoundaryExpiryDisposition({ ...base, t0Unchanged: false, durablyInconclusive: true }),
    ).toEqual({ kind: "resolved", resolution: "INDETERMINATE" });
  });
  it("otherwise stays held and keeps reconciling", () => {
    expect(postBoundaryExpiryDisposition({ ...base, t0Unchanged: false }).kind).toBe("held");
  });
});

describe("leaseDropAllowed — never before a terminal disposition", () => {
  it("permits a lease drop only on a landing", () => {
    expect(leaseDropAllowed({ kind: "resolved", resolution: "RECEIVE_LANDED" })).toBe(true);
  });
  it("NEGATIVE: never drops while held or INDETERMINATE — there is no release disposition to drop on", () => {
    expect(leaseDropAllowed({ kind: "held", attentionReason: "POST_EXPIRY_RECONCILING" })).toBe(false);
    expect(leaseDropAllowed({ kind: "resolved", resolution: "INDETERMINATE" })).toBe(false);
  });
});
