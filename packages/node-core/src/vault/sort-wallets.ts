// Canonical wallet-id ordering for multi-wallet acquisition (guard 4).
// Duplicated from leases/sort-wallets.ts so the vault leaf never imports leases
// (boundary gate: vault: []). Byte-identical comparison: lowercase-hyphenated UUID text.

/**
 * Ascending raw-UUID-byte comparison on the canonical lowercase-hyphenated text form.
 * Returns a new array; does not mutate the input.
 */
export function sortWalletIdsAscending(walletIds: readonly string[]): string[] {
  return [...walletIds].sort((a, b) => {
    const la = a.toLowerCase();
    const lb = b.toLowerCase();
    return la < lb ? -1 : la > lb ? 1 : 0;
  });
}
