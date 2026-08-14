/**
 * Implementer funding-wallet pin (ZTR-1287).
 *
 * Frozen inventory of the structural invariants carried by
 * implementer-funding-wallet.sql. Funding wallet = reserve/proof pubkey for an
 * integration — never a forced send/source pin.
 */

export const IMPLEMENTER_FUNDING_WALLET_SCHEMA_FILE =
  "implementer-funding-wallet.sql" as const;

/** node_settings key for the node-wide default funding wallet id (uuid text). */
export const DEFAULT_FUNDING_WALLET_SETTING_KEY =
  "integration.default_funding_wallet_id" as const;

export interface ImplementerFundingWalletInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const IMPLEMENTER_FUNDING_WALLET_INVARIANTS: readonly ImplementerFundingWalletInvariant[] =
  [
    {
      id: "REQUIRES_IMPLEMENTERS",
      sqlAnchor: "implementer-funding-wallet requires implementers",
      rule: "Pack apply fails closed if implementers is missing.",
    },
    {
      id: "REQUIRES_WALLETS",
      sqlAnchor: "implementer-funding-wallet requires wallets (custody-eligibility)",
      rule: "Pack apply fails closed if wallets is missing — funding pin FK target.",
    },
    {
      id: "COLUMN_NULLABLE_UUID",
      sqlAnchor: "ADD COLUMN IF NOT EXISTS funding_wallet_id uuid NULL",
      rule: "funding_wallet_id is nullable: NULL means resolve via node default setting.",
    },
    {
      id: "FK_WALLETS_RESTRICT",
      sqlAnchor: "implementers_funding_wallet_id_fkey",
      rule: "FK to wallets(id) ON DELETE RESTRICT — fail closed; clear pin before wallet drop.",
    },
    {
      id: "ON_DELETE_RESTRICT",
      sqlAnchor: "ON DELETE RESTRICT",
      rule: "Wallet delete while referenced as funding pin is refused.",
    },
    {
      id: "PARTIAL_INDEX",
      sqlAnchor: "implementers_funding_wallet_id_idx",
      rule: "Partial index on non-null funding_wallet_id for reverse lookups.",
    },
  ] as const;

export const IMPLEMENTER_FUNDING_WALLET_EXECUTION_OBLIGATIONS: readonly string[] = [
  "implementer-funding-wallet.sql applies after custody-eligibility (wallets) and after implementers exists (reporting 0000 / node-implementer-registry); pure ALTER — creates no table.",
  "NULL funding_wallet_id means use node_settings key integration.default_funding_wallet_id; never confuses with send/source wallet fields.",
  "Runtime setFundingWallet writes implementers.funding_wallet_id + audit_log; default setting uses node_settings row_version bump + audit.",
] as const;

export const IMPLEMENTER_FUNDING_WALLET_SOURCE =
  "ZTR-1287 schema+admin funding wallet; epic ZTR-1286 SplitChain-verifiable funding wallet" as const;
