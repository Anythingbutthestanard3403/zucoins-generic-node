/**
 * Connector reserve wallets (ZTR-1324 / GN-101).
 *
 * Frozen inventory of the structural invariants carried by
 * connector-reserve-wallets.sql. A reserve wallet is a named custody wallet a
 * connector may consolidate into. It is not a send-source pin.
 */

export const CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE =
  "connector-reserve-wallets.sql" as const;

export interface ConnectorReserveWalletsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const CONNECTOR_RESERVE_WALLETS_INVARIANTS: readonly ConnectorReserveWalletsInvariant[] =
  [
    {
      id: "REQUIRES_WALLETS",
      sqlAnchor: "connector-reserve-wallets requires wallets",
      rule: "Pack apply fails closed when wallets is missing.",
    },
    {
      id: "REQUIRES_IMPLEMENTERS",
      sqlAnchor: "connector-reserve-wallets requires implementers",
      rule: "Pack apply fails closed when implementers is missing.",
    },
    {
      id: "DISPLAY_LABEL",
      sqlAnchor: "ADD COLUMN IF NOT EXISTS display_label text NULL",
      rule: "wallets.display_label is nullable text. Blank labels are refused by CHECK.",
    },
    {
      id: "DISPLAY_LABEL_CHECK",
      sqlAnchor: "wallets_display_label_len_chk",
      rule: "Label is null or 1-128 characters after trim.",
    },
    {
      id: "ALLOW_CUSTOM_ROUTING",
      sqlAnchor: "ADD COLUMN IF NOT EXISTS allow_custom_routing boolean NOT NULL DEFAULT false",
      rule: "Custom routing defaults off. Connectors cannot override consolidation until an operator opts in.",
    },
    {
      id: "JUNCTION_TABLE",
      sqlAnchor: "CREATE TABLE implementer_reserve_wallets",
      rule: "Junction binds one connector to many reserve wallets.",
    },
    {
      id: "FK_IMPLEMENTER_CASCADE",
      sqlAnchor: "REFERENCES implementers (id) ON DELETE CASCADE",
      rule: "Deleting a connector removes its reserve bindings.",
    },
    {
      id: "FK_WALLET_RESTRICT",
      sqlAnchor: "REFERENCES wallets (id) ON DELETE RESTRICT",
      rule: "A wallet referenced as a reserve binding cannot be deleted.",
    },
    {
      id: "ONE_DEFAULT",
      sqlAnchor: "implementer_reserve_wallets_one_default_uidx",
      rule: "At most one is_default row per connector.",
    },
    {
      id: "WALLET_INDEX",
      sqlAnchor: "implementer_reserve_wallets_wallet_id_idx",
      rule: "Reverse lookup from wallet to connectors that bind it.",
    },
    {
      id: "BACKFILL",
      sqlAnchor: "i.funding_wallet_id IS NOT NULL",
      rule: "Existing funding pins become the default reserve row. Re-apply does not add a second default.",
    },
  ] as const;

export const CONNECTOR_RESERVE_WALLETS_EXECUTION_OBLIGATIONS: readonly string[] = [
  "connector-reserve-wallets.sql applies after custody-eligibility (wallets) and after implementers exists; appended so earlier pack versions stay stable.",
  "setReserveWallets writes the junction and implementers.funding_wallet_id in one statement, plus an audit_log row with actor_kind OPERATOR_SESSION.",
  "An empty wallet list clears the junction and sets funding_wallet_id NULL so resolution falls through to the node default setting.",
  "Wallet inventory exposes display_label. Label changes ride the money-capability CAS (expected row version) and the same operator audit path.",
] as const;

export const CONNECTOR_RESERVE_WALLETS_SOURCE =
  "ZTR-1324 GN-101 reserve wallet labels, junction, and custom routing flag" as const;
