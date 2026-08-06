// The platform consumer-terminality contract and released-wallet safety. Data +
// pure predicates; no DB code.

// A consumer MUST NOT treat a receive EXPIRED / operation.expired as a terminal landing FAILURE
// unless it positively proves the safe-terminal branch: release_status == RELEASED_T0_UNCHANGED
// (symmetric with the consumer success predicate).
export const SAFE_TERMINAL_RELEASE_STATUS = "RELEASED_T0_UNCHANGED" as const;

export function isTerminalPaymentFailure(input: {
  readonly receiveExpired: boolean;
  readonly releaseStatus: string;
}): boolean {
  return input.receiveExpired && input.releaseStatus === SAFE_TERMINAL_RELEASE_STATUS;
}

// Released-wallet safety: a wallet released to AVAILABLE must be observed; ANY head movement
// quarantines it; it is NEVER adopted as a new op's T0 baseline (release-then-retire, not
// release-then-reassign).
export const RELEASED_WALLET_SAFETY = {
  observedPostRelease: true,
  headMovementQuarantines: true,
  neverNewT0Baseline: true,
  releaseThenRetireNotReassign: true,
} as const;

export function releasedWalletDisposition(headMoved: boolean): "QUARANTINE" | "RETIRE" {
  return headMoved ? "QUARANTINE" : "RETIRE";
}

// A released wallet is never eligible as a new operation's T0 baseline.
export function isEligibleAsT0Baseline(): boolean {
  return false;
}
