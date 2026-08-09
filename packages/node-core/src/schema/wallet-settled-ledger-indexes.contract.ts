// Per-wallet index on the canonical settled ledger.
//
// Frozen inventory of the structural invariants carried by
// wallet-settled-ledger-indexes.sql — the single wallet_settled_ledger index that keeps the
// wallet_id foreign key's referencing side off a sequential scan, and that per-wallet
// derivation will read when it is written.

export const WALLET_SETTLED_LEDGER_INDEXES_SCHEMA_FILE =
  "wallet-settled-ledger-indexes.sql" as const;

export interface WalletSettledLedgerIndexInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const WALLET_SETTLED_LEDGER_INDEX_INVARIANTS: readonly WalletSettledLedgerIndexInvariant[] =
  [
    {
      id: "WALLET_ID_INDEX",
      sqlAnchor:
        "CREATE INDEX wallet_settled_ledger_wallet_id_idx\n  ON wallet_settled_ledger(wallet_id);",
      rule:
        "wallet_id leads a real index, so `WHERE wallet_id = $1` over an append-only ledger is a keyed lookup whose cost tracks the queried wallet's own history rather than every wallet's.",
    },
    {
      id: "WALLET_ID_INDEX_NOT_PARTIAL",
      sqlAnchor: "ON wallet_settled_ledger(wallet_id);",
      rule:
        "unqualified, not partial: wallet_id is NOT NULL and foreign-key enforcement must see every referencing row, so a WHERE clause here would let a row escape the check.",
    },
    {
      id: "WALLET_ID_INDEX_SINGLE_COLUMN",
      sqlAnchor: "(wallet_id);",
      rule:
        "one column, from the query census rather than the column list: the only live wallet_id predicate is the foreign key's RI check, an equality on wallet_id alone that no suffix column narrows. A settled_at or operation_role suffix would index a query no production code issues and be paid for on every append.",
    },
    {
      id: "PURE_INDEX_EXTENSION",
      // Named, not the bare "CREATE INDEX" verb: that phrase also appears in this file's
      // prose, so a bare anchor would stay satisfied after the DDL itself was deleted.
      sqlAnchor: "CREATE INDEX wallet_settled_ledger_wallet_id_idx",
      rule:
        "applies after wallet-settled-ledger.sql (wallet_settled_ledger must already exist) and creates no table, column, trigger or domain, so the ledger's append-only and verbatim invariants are untouched.",
    },
  ] as const;

export const WALLET_SETTLED_LEDGER_INDEXES_EXECUTION_OBLIGATIONS: readonly string[] = [
  "wallet-settled-ledger-indexes.sql applies after wallet-settled-ledger.sql and is a pure index extension: it creates no table, no column, no trigger, no domain.",
  "The index ships as its own money-pack slice appended to MONEY_SCHEMA_PACK_ORDER; wallet-settled-ledger.sql is already applied and its schema_migrations sql_sha256 must not change.",
  "CREATE INDEX is deliberately not CONCURRENTLY: db/migrate.ts applies migrations inside a transaction block, which CONCURRENTLY cannot join.",
  "EXPLAIN confirms wallet_settled_ledger_wallet_id_idx serves a wallet_id equality lookup — the shape of the wallet_id foreign key's RI check when a wallets row is deleted.",
] as const;

export const WALLET_SETTLED_LEDGER_INDEXES_SOURCE =
  "data-model: canonical wallet ledger; per-wallet settled derivation" as const;
