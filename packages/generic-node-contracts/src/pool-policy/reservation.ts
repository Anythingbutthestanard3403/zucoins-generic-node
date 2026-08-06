import { isAvailableForReceive, type PoolWalletDescriptor } from "./eligibility.js";
import { type PoolWalletState } from "./states.js";

// the named concern — hold / crash-safe state-change contract. Frozen data + pure CAS models; no DB
// code. A hold claims a selected AVAILABLE wallet into a RECEIVE_WINDOW lease, flipping
// state AVAILABLE->PINNED under an optimistic row_version CAS so concurrent claims are safe.

// The optimistic-concurrency column (the frozen rule CAS). the DB-domains concern binds it to the wallets table.
export const POOL_CAS_COLUMN = "row_version" as const;

// Contract-level SQL text (frozen DATA; bindable). Only the txn whose expected row_version and the
// still-AVAILABLE state both hold wins; the loser (0 rows updated) re-runs selection.
export const RESERVE_WALLET_CAS_SQL =
  "UPDATE wallets SET state = 'PINNED', row_version = row_version + 1 " +
  "WHERE id = $1 AND row_version = $2 AND state = 'AVAILABLE'";

export type ReservationOutcome =
  | { readonly kind: "reserved"; readonly nextRowVersion: number }
  | { readonly kind: "lost" };

// Pure model of the CAS: reserve iff the row is still AVAILABLE AND the observed row_version equals
// the expected one. A stale version or a non-AVAILABLE state loses (matches a 0-row UPDATE).
export function reserveWallet(input: {
  readonly expectedRowVersion: number;
  readonly actualRowVersion: number;
  readonly state: PoolWalletState;
}): ReservationOutcome {
  if (input.state !== "AVAILABLE" || input.actualRowVersion !== input.expectedRowVersion) {
    return { kind: "lost" };
  }
  return { kind: "reserved", nextRowVersion: input.actualRowVersion + 1 };
}

// Crash-atomic replenishment invariant (the receive-queue backpressure rule addendum, contingent on B-02/the vault-storage rule): a minted wallet
// row and its vault envelope are written in ONE transaction; on boot the node verifies 1:1 and
// quarantines any wallet lacking a decryptable secret BEFORE it can be selected. Frozen as data.
export const REPLENISHMENT_CRASH_SAFETY = {
  walletAndVaultInOneTransaction: true,
  bootVerifiesSecretOneToOne: true,
  quarantineUndecryptableBeforeSelection: true,
} as const;

// Assignment-time defence-in-depth (the recovery-gated eligibility rule): even past selection, a wallet is assignable only if it
// passed the boot secret-probe AND is receive-eligible. This blocks a resurrected wallet — a
// resurrected/un-retired wallet carries recovery_verified_at = null (there is no un-retire that
// re-stamps it), so it fails eligibility and is never assigned.
export function isAssignable(
  wallet: PoolWalletDescriptor,
  hasDecryptableSecret: boolean,
): boolean {
  return hasDecryptableSecret && isAvailableForReceive(wallet);
}
