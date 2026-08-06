import { isAvailableForReceive, type PoolWalletDescriptor } from "./eligibility.js";

// the named concern — available-wallet SELECTION contract. Frozen data + a pure model of the query's
// row-visibility semantics; NO SQL is executed here. the DB-domains concern/the named concern bind the SQL text below to the
// final 04-data-model schema (identifier names are the ones the receive-queue backpressure rule/the recovery-gated eligibility rule rules use).

// Selection sequence: oldest-created first, tie-broken by id — deterministic, even wallet wear.
export const WALLET_SELECTION_ORDER = ["created_at ASC", "id ASC"] as const;

// Lock mode: FOR UPDATE SKIP LOCKED — concurrent selectors skip a row another txn holds (never
// block, never double-claim). the frozen rule concurrency.
export const WALLET_SELECTION_LOCK = "FOR UPDATE SKIP LOCKED" as const;

// Contract-level SQL text (frozen DATA; bindable by the DB-domains concern/the named concern). The WHERE clause is the recovery-gated eligibility rule
// receive-eligibility conjunction; a receiver is never blessed, so no destinations.state predicate.
export const SELECT_ASSIGNABLE_WALLET_SQL =
  "SELECT id FROM wallets " +
  "WHERE key_origin = 'node_generated' AND recovery_verified_at IS NOT NULL AND state = 'AVAILABLE' " +
  "ORDER BY created_at ASC, id ASC " + // contract-allow:frozen-sql-text
  "FOR UPDATE SKIP LOCKED LIMIT 1";

export type SelectableWallet = PoolWalletDescriptor & {
  readonly id: string;
  readonly createdAt: string;
};

function bySelectionOrder(a: SelectableWallet, b: SelectableWallet): number {
  if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? -1 : 1;
  if (a.id !== b.id) return a.id < b.id ? -1 : 1;
  return 0;
}

// Pure model of the SELECT's semantics: a row is visible to this selector iff it is receive-
// eligible (the recovery-gated eligibility rule) AND not currently locked by another txn (SKIP LOCKED). The first row by
// selection sequence is claimed. Deterministic — this is the testable contract for the query.
export function selectAssignableWallet(
  candidates: readonly SelectableWallet[],
  lockedIds: ReadonlySet<string>,
): SelectableWallet | null {
  const visible = candidates
    .filter((wallet) => isAvailableForReceive(wallet) && !lockedIds.has(wallet.id))
    .sort(bySelectionOrder);
  return visible[0] ?? null;
}
