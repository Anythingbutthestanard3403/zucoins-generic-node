/**
 * destinations.idempotency_key column (ZTR-1310).
 *
 * Frozen inventory of the structural invariants carried by
 * destinations-idempotency-key.sql.
 */

export const DESTINATIONS_IDEMPOTENCY_KEY_SCHEMA_FILE =
  "destinations-idempotency-key.sql" as const;

export interface DestinationsIdempotencyKeyInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const DESTINATIONS_IDEMPOTENCY_KEY_INVARIANTS: readonly DestinationsIdempotencyKeyInvariant[] =
  [
    {
      id: "FAIL_CLOSED_WITHOUT_DESTINATIONS",
      sqlAnchor: "RAISE EXCEPTION\n      'destinations-idempotency-key requires destinations'",
      rule:
        "standalone apply without the destinations table fails closed with a named exception rather than silently no-oping.",
    },
    {
      id: "COLUMN_NULLABLE_TEXT",
      sqlAnchor: "ADD COLUMN IF NOT EXISTS idempotency_key text",
      rule:
        "idempotency_key is nullable text so mint / pool / backfill rows (no register key) stay valid; register writes the key.",
    },
    {
      id: "KEY_FORM_CHECK",
      sqlAnchor: "idempotency_key ~ '^[!-~]{16,255}$'",
      rule:
        "a non-null key must be 16-255 visible ASCII (0x21-0x7e), matching the implementer-API Idempotency-Key grammar.",
    },
    {
      id: "UNIQUE_NODE_AND_KEY",
      sqlAnchor:
        "ON destinations (node_id, idempotency_key)\n  WHERE idempotency_key IS NOT NULL",
      rule:
        "DestinationStore port scope: at most one destinations row per (node_id, idempotency_key). Partial UNIQUE so many NULL keys may coexist.",
    },
  ] as const;

export const DESTINATIONS_IDEMPOTENCY_KEY_EXECUTION_OBLIGATIONS: readonly string[] =
  [
    "destinations-idempotency-key.sql applies after custody-eligibility.sql (destinations must already exist) and is a pure column + index extension: it creates no table and no trigger.",
    "The DestinationStore port keys findByIdempotencyKey on (node_id, idempotency_key). Do not invent a second (implementer_id, http_method, route, idempotency_key) ledger for destinations.",
    "The slice ships appended to MONEY_SCHEMA_PACK_ORDER; custody-eligibility.sql is already applied and its schema_migrations sql_sha256 must not change.",
  ] as const;

export const DESTINATIONS_IDEMPOTENCY_KEY_SOURCE =
  "ZTR-1310: persist destinations register Idempotency-Key so a client retry does not mint another wallet" as const;
