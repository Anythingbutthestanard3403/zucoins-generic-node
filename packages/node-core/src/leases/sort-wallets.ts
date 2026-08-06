// Sort required wallet UUID bytes ascending
// before multi-wallet acquisition so two workers never take locks in opposite sequences
// (deadlock) and so a mixed batch either commits all rows or none.

/**
 * Ascending raw-UUID-byte comparison on the canonical lowercase-hyphenated text form.
 * Hyphens sit at fixed positions, so plain lowercase string comparison visits the same
 * hex-digit pairs left-to-right as a 16-byte comparison and matches Postgres uuid sort.
 * Returns a new array; does not mutate the input.
 */
export function sortWalletIdsAscending(walletIds: readonly string[]): string[] {
  return [...walletIds].sort((a, b) => {
    const la = a.toLowerCase();
    const lb = b.toLowerCase();
    return la < lb ? -1 : la > lb ? 1 : 0;
  });
}
