import { isValidPoolTransition, type PoolWalletState } from "../pool-policy/states.js";

// the named concern — wallet-state transition legality vs the lease lifecycle. A wallet-state change is
// ONLY ever caused by a lease/flag event (C-02) — there is no spontaneous transition. Each legal
// transition (the named concern pool-transition set) is grounded in exactly one event.
export const WALLET_LEASE_EVENTS = [
  "LEASE_ACQUIRED",
  "LEASE_RELEASED",
  "QUARANTINE_FLAGGED",
  "QUARANTINE_CLEARED",
  "RETIRED_FLAGGED",
] as const;
export type WalletLeaseEvent = (typeof WALLET_LEASE_EVENTS)[number];

const TRANSITION_EVENT = {
  "AVAILABLE->PINNED": "LEASE_ACQUIRED",
  "PINNED->AVAILABLE": "LEASE_RELEASED",
  "AVAILABLE->QUARANTINED": "QUARANTINE_FLAGGED",
  "QUARANTINED->AVAILABLE": "QUARANTINE_CLEARED",
  "AVAILABLE->RETIRED": "RETIRED_FLAGGED",
} as const satisfies Record<string, WalletLeaseEvent>;

export function requiredLeaseEvent(from: PoolWalletState, to: PoolWalletState): WalletLeaseEvent | null {
  const key = `${from}->${to}`;
  if (key in TRANSITION_EVENT) return TRANSITION_EVENT[key as keyof typeof TRANSITION_EVENT];
  return null;
}

// Legal iff the transition is in the named concern pool-transition set AND driven by its required lease
// event. Requiring the event is how "no state change without a lease event" is enforced.
export function isLegalWalletTransition(
  from: PoolWalletState,
  to: PoolWalletState,
  event: WalletLeaseEvent,
): boolean {
  if (!isValidPoolTransition(from, to)) return false;
  return requiredLeaseEvent(from, to) === event;
}

// the receive-expiry rule lease-hold precedence over expiry: a RECEIVE_WINDOW lease is released by expiry ONLY
// before the durable-candidate boundary. Post-candidate, expiry MUST NOT release it — the wallet
// stays PINNED (held, the one-in-flight-per-wallet rule); release then comes only via a T0 expiry proof.
export function canExpiryReleaseReceiveLease(postCandidate: boolean): boolean {
  return !postCandidate;
}
