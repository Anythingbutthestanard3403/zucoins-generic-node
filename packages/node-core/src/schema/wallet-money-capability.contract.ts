/**
 * Wallet money-capability columns (ZTR-1267).
 *
 * Frozen inventory of the structural invariants carried by wallet-money-capability.sql.
 */

export const WALLET_MONEY_CAPABILITY_SCHEMA_FILE = "wallet-money-capability.sql" as const;

export const WALLET_MONEY_MODES = [
  "RECEIVE_ONLY",
  "SEND_ONLY",
  "INTERNAL_ONLY",
  "FULL",
] as const;

export type WalletMoneyModeSql = (typeof WALLET_MONEY_MODES)[number];

/** New-mint and backfill default: preserve pre-capability behaviour. */
export const WALLET_MONEY_CAPABILITY_DEFAULT_MODE = "FULL" as const;

export interface WalletMoneyCapabilityInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const WALLET_MONEY_CAPABILITY_INVARIANTS: readonly WalletMoneyCapabilityInvariant[] = [
  {
    id: "ALLOW_EXTERNAL_RECEIVE_DEFAULT_TRUE",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS allow_external_receive boolean NOT NULL DEFAULT true",
    rule: "allow_external_receive defaults true (FULL) so pre-existing and new rows stay unrestricted until operator reconfiguration.",
  },
  {
    id: "ALLOW_EXTERNAL_SEND_DEFAULT_TRUE",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS allow_external_send boolean NOT NULL DEFAULT true",
    rule: "allow_external_send defaults true (FULL).",
  },
  {
    id: "ALLOW_INTERNAL_MOVE_DEFAULT_TRUE",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS allow_internal_move boolean NOT NULL DEFAULT true",
    rule: "allow_internal_move defaults true (FULL).",
  },
  {
    id: "MONEY_MODE_DEFAULT_FULL",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS money_mode text NOT NULL DEFAULT 'FULL'",
    rule: "money_mode defaults FULL — the only preset that matches all-three-true.",
  },
  {
    id: "ROW_VERSION_DEFAULT_ONE",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS row_version bigint NOT NULL DEFAULT 1",
    rule: "row_version is the house CAS counter for admin mode mutations (ZTR-1269).",
  },
  {
    id: "BACKFILL_FULL",
    sqlAnchor: "money_mode = 'FULL'",
    rule: "explicit UPDATE converges already-applied rows to FULL flags + mode.",
  },
  {
    id: "MODE_CLOSED",
    sqlAnchor: "wallets_money_mode_closed",
    rule: "money_mode is closed to RECEIVE_ONLY | SEND_ONLY | INTERNAL_ONLY | FULL.",
  },
  {
    id: "MODE_FLAGS_CONSISTENT",
    sqlAnchor: "wallets_money_mode_flags_consistent",
    rule: "money_mode must match the three allow flags exactly; illegal triples (including all-false) are structurally impossible.",
  },
  {
    id: "ROW_VERSION_POSITIVE",
    sqlAnchor: "wallets_row_version_positive",
    rule: "row_version > 0.",
  },
] as const;

export const WALLET_MONEY_CAPABILITY_EXECUTION_OBLIGATIONS: readonly string[] = [
  "wallet-money-capability.sql applies after custody-eligibility.sql (wallets must already exist) and is a pure column extension: it creates no table.",
  "New-mint default is FULL (all three allows true); recorded in WALLET_MONEY_CAPABILITY_DEFAULT_MODE and enforced by column defaults + mint INSERT.",
  "Illegal triples are rejected by wallets_money_mode_flags_consistent; all-three-false is not a legal preset.",
] as const;

export const WALLET_MONEY_CAPABILITY_SOURCE =
  "ZTR-1267 per-wallet money capabilities; epic ZTR-1266" as const;
