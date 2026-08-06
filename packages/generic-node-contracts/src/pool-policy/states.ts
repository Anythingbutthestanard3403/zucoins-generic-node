// Pool wallet lifecycle (the receive-queue backpressure rule rules 5-6). There is NO deleted state: vault/secret rows are
// never deleted in any state (the key-custody rule / the frozen rule), enforced structurally at the DB grant level
// by the DB-domains concern, not by convention. `RETIRED` is a logical pool-membership flag bound to
// logical-only semantics — this binding is how the frozen rule "keys are never retired/deleted"
// collision is resolved (a retired wallet keeps its keys and stays a sweepable send-side source);
// see CONTRACT.md.
export const POOL_WALLET_STATES = ["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"] as const;
export type PoolWalletState = (typeof POOL_WALLET_STATES)[number];

// Allowed transitions. AVAILABLE<->PINNED (lease acquire / release); AVAILABLE<->QUARANTINED
// (probe fail / re-verify); AVAILABLE->RETIRED ONLY, via row_version CAS — never from PINNED
// (cannot retire a live-leased wallet), and there is no un-retire path (a resurrected wallet must
// re-run recovery verification, the recovery-gated eligibility rule). No transition deletes keys. This predicate is the POLICY
// layer; the AVAILABLE->RETIRED WRITE mechanism (RETIRE_WALLET_CAS_SQL + pure retireWallet) is
// frozen in retirement.ts, symmetric with the sibling hold module's AVAILABLE->PINNED reserve.
export const POOL_WALLET_TRANSITIONS = [
  ["AVAILABLE", "PINNED"],
  ["PINNED", "AVAILABLE"],
  ["AVAILABLE", "QUARANTINED"],
  ["QUARANTINED", "AVAILABLE"],
  ["AVAILABLE", "RETIRED"],
] as const;

export function isValidPoolTransition(from: PoolWalletState, to: PoolWalletState): boolean {
  return POOL_WALLET_TRANSITIONS.some(([f, t]) => f === from && t === to);
}

// Structural invariant: keys are never deleted in any state (the key-custody rule / the frozen rule). Retirement
// is logical membership only; there is no physical-delete transition or state.
export const POOL_KEY_DELETION_ALLOWED = false;

// Does a wallet in this state count toward pool_cap? YES for every state — nothing is ever
// deleted, so ALL wallets (incl. PINNED / QUARANTINED / RETIRED) count (the receive-queue backpressure rule 2). This is
// the reversal of the v2 draft's non-retired counting; retirement never restores capacity.
export function countsTowardCap(state: PoolWalletState): boolean {
  return (POOL_WALLET_STATES as readonly string[]).includes(state);
}
