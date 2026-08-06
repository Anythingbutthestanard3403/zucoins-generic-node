import { type PoolWalletState } from "./states.js";

// the named concern — logical-retirement WRITE contract (the receive-queue backpressure rule 5). Frozen data + a pure CAS model; no DB
// code. states.ts declares AVAILABLE->RETIRED legal at the policy level (isValidPoolTransition);
// this freezes the retirement WRITE mechanism, symmetric with the sibling hold module's reserve
// write. The transition flips AVAILABLE->RETIRED under the SAME optimistic row_version CAS
// (POOL_CAS_COLUMN) as the hold, so retirement can NEVER win against a live lease: a wallet already PINNED
// (leased) fails the state guard, and a wallet reserved concurrently fails the row_version guard.

// Contract-level SQL text (frozen DATA; bindable). Retirement succeeds ONLY when the row is still
// AVAILABLE at the expected row_version — the `state = 'AVAILABLE'` guard is what forbids retiring
// a PINNED (live-leased) wallet (the receive-queue backpressure rule 5 "never from PINNED"), closing the fund-stranding
// footgun of a naked `UPDATE wallets SET state='RETIRED' WHERE id=$1`. There is no un-retire
// (RETIRED->AVAILABLE is not a legal transition), so a wallet must never be retired mid-lease.
export const RETIRE_WALLET_CAS_SQL =
  "UPDATE wallets SET state = 'RETIRED', row_version = row_version + 1 " +
  "WHERE id = $1 AND row_version = $2 AND state = 'AVAILABLE'";

export type RetirementOutcome =
  | { readonly kind: "retired"; readonly nextRowVersion: number }
  | { readonly kind: "lost" };

// Pure model of the CAS: retire iff the row is still AVAILABLE AND the observed row_version equals
// the expected one. A non-AVAILABLE state (PINNED live lease, or already RETIRED) or a stale
// version loses (matches a 0-row UPDATE) — identical shape to reserveWallet. Because reserve and
// retire share the AVAILABLE + expected-row_version guard on the same row, at most one of the two
// can win a given (id, row_version); the loser always loses and re-reads.
export function retireWallet(input: {
  readonly expectedRowVersion: number;
  readonly actualRowVersion: number;
  readonly state: PoolWalletState;
}): RetirementOutcome {
  if (input.state !== "AVAILABLE" || input.actualRowVersion !== input.expectedRowVersion) {
    return { kind: "lost" };
  }
  return { kind: "retired", nextRowVersion: input.actualRowVersion + 1 };
}
