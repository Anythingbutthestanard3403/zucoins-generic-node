import { type PoolWalletState } from "./states.js";

export const KEY_ORIGIN_NODE_GENERATED = "node_generated";

export type PoolWalletDescriptor = {
  readonly keyOrigin: string;
  // ISO timestamp the audited-recovery ceremony (the recovery-drill concern) stamped; null = not recovery-verified.
  readonly recoveryVerifiedAt: string | null;
  readonly state: PoolWalletState;
};

// the recovery-gated eligibility rule receive-eligibility — the AVAILABLE-count input to headroom. A wallet is eligible for a
// NEW receive ONLY if node-generated, recovery-verified, and AVAILABLE. Excludes PINNED /
// QUARANTINED / RETIRED and every recovery-UNVERIFIED wallet: a minted-unverified wallet is never
// assigned (a node-internal ciphertext round-trip is not recovery — real ZKZ into an unverified
// receiver is a self-custody failure, the key-custody rule). This is the custody selection rule recovery conjunct MINUS
// blessing (a pool receiver is not a move destination and is never blessed).
export function isAvailableForReceive(wallet: PoolWalletDescriptor): boolean {
  return (
    wallet.keyOrigin === KEY_ORIGIN_NODE_GENERATED &&
    wallet.recoveryVerifiedAt !== null &&
    wallet.state === "AVAILABLE"
  );
}

// Headroom AVAILABLE input (the recovery-gated eligibility rule): counts ONLY recovery-verified AVAILABLE wallets.
export function availableWalletCount(wallets: readonly PoolWalletDescriptor[]): number {
  return wallets.reduce((n, wallet) => (isAvailableForReceive(wallet) ? n + 1 : n), 0);
}

// pool_cap input (the receive-queue backpressure rule 2): counts ALL non-deleted wallets, including unverified / PINNED
// QUARANTINED / RETIRED, to bound permanent key growth. Nothing is ever deleted, so this is the
// full wallet count.
export function capCount(wallets: readonly PoolWalletDescriptor[]): number {
  return wallets.length;
}
