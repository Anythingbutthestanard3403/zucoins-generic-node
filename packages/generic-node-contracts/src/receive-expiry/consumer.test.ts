import { describe, it, expect } from "vitest";
import {
  isTerminalPaymentFailure,
  releasedWalletDisposition,
  isEligibleAsT0Baseline,
  SAFE_TERMINAL_RELEASE_STATUS,
} from "./consumer.js";

describe("isTerminalPaymentFailure — EXPIRED is terminal ONLY with the safe release proof", () => {
  it("is terminal when expired AND release_status == RELEASED_T0_UNCHANGED", () => {
    expect(isTerminalPaymentFailure({ receiveExpired: true, releaseStatus: SAFE_TERMINAL_RELEASE_STATUS })).toBe(true);
  });
  it("NEGATIVE: EXPIRED without the safe release proof is NOT terminal", () => {
    expect(isTerminalPaymentFailure({ receiveExpired: true, releaseStatus: "POST_EXPIRY_RECONCILING" })).toBe(false);
    expect(isTerminalPaymentFailure({ receiveExpired: true, releaseStatus: "UNKNOWN" })).toBe(false);
  });
  it("a non-expired receive is not a terminal failure", () => {
    expect(isTerminalPaymentFailure({ receiveExpired: false, releaseStatus: SAFE_TERMINAL_RELEASE_STATUS })).toBe(false);
  });
});

describe("released-wallet safety — head movement quarantines, never a new T0 baseline", () => {
  it("quarantines on head movement, retires otherwise (never reassigns)", () => {
    expect(releasedWalletDisposition(true)).toBe("QUARANTINE");
    expect(releasedWalletDisposition(false)).toBe("RETIRE");
    expect(releasedWalletDisposition(true)).not.toBe("RETIRE");
  });
  it("NEGATIVE: a released wallet is never eligible as a new op's T0 baseline", () => {
    expect(isEligibleAsT0Baseline()).toBe(false);
  });
});
