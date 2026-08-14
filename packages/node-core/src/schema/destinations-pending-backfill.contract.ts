/**
 * ZTR-1306 backfill: PENDING destinations row for every node_generated wallet
 * that is missing one.
 *
 * Frozen inventory of the structural invariants carried by
 * destinations-pending-backfill.sql.
 */

export const DESTINATIONS_PENDING_BACKFILL_SCHEMA_FILE =
  "destinations-pending-backfill.sql" as const;

export interface DestinationsPendingBackfillInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const DESTINATIONS_PENDING_BACKFILL_INVARIANTS: readonly DestinationsPendingBackfillInvariant[] =
  [
    {
      id: "BACKFILL_NODE_GENERATED_MISSING_DEST",
      sqlAnchor:
        "WHERE w.key_origin = 'node_generated'\n     AND NOT EXISTS (\n           SELECT 1 FROM destinations d WHERE d.wallet_id = w.id\n         )",
      rule:
        "only node_generated wallets without a destinations row are inserted; imported origin never enters destination history.",
    },
    {
      id: "PENDING_ONLY",
      sqlAnchor: "SELECT gen_random_uuid(), w.node_id, w.id, '', 'PENDING'",
      rule:
        "backfill writes state PENDING and an empty label; never BLESSED and never stamps blessing columns.",
    },
    {
      id: "IDEMPOTENT_NOT_EXISTS",
      sqlAnchor: "AND NOT EXISTS (\n           SELECT 1 FROM destinations d WHERE d.wallet_id = w.id",
      rule:
        "re-applying the slice is a no-op on wallets that already have a destinations row (wallet_id UNIQUE).",
    },
    {
      id: "FAIL_CLOSED_WITHOUT_WALLETS",
      sqlAnchor: "RAISE EXCEPTION\n      'destinations-pending-backfill requires wallets'",
      rule:
        "standalone apply without the wallets table fails closed with a named exception rather than silently no-oping.",
    },
    {
      id: "FAIL_CLOSED_WITHOUT_DESTINATIONS",
      sqlAnchor: "RAISE EXCEPTION\n      'destinations-pending-backfill requires destinations'",
      rule:
        "standalone apply without the destinations table fails closed with a named exception rather than silently no-oping.",
    },
    {
      id: "PURE_DATA_FIX_FORWARD",
      sqlAnchor: "INSERT INTO destinations (id, node_id, wallet_id, label, state)",
      rule:
        "creates no table, column, index, trigger, or domain — data-only fix-forward on the already-created destinations table.",
    },
  ] as const;

export const DESTINATIONS_PENDING_BACKFILL_EXECUTION_OBLIGATIONS: readonly string[] =
  [
    "destinations-pending-backfill.sql applies after custody-eligibility.sql (wallets and destinations must already exist) and is a pure data fix-forward.",
    "The INSERT ships as its own money-pack slice appended to MONEY_SCHEMA_PACK_ORDER; custody-eligibility.sql is already applied and its schema_migrations sql_sha256 must not change.",
    "Blessing remains dual-control. This slice never writes BLESSED and never stamps blessed_at / device / artifact columns.",
  ] as const;

export const DESTINATIONS_PENDING_BACKFILL_SOURCE =
  "ZTR-1306: every node_generated mint must leave a PENDING destinations row so operators can bless without minting another wallet" as const;
