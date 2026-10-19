/**
 * webhook_deliveries (ZTR-1333).
 *
 * Frozen inventory of the structural invariants carried by webhook-deliveries.sql.
 */

export const WEBHOOK_DELIVERIES_SCHEMA_FILE = "webhook-deliveries.sql" as const;

export interface WebhookDeliveriesInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const WEBHOOK_DELIVERIES_INVARIANTS: readonly WebhookDeliveriesInvariant[] = [
  {
    id: "FAIL_CLOSED_WITHOUT_IMPLEMENTERS",
    sqlAnchor: "RAISE EXCEPTION\n      'webhook-deliveries requires implementers'",
    rule:
      "standalone apply without implementers fails closed with a named exception rather than creating an unbound table.",
  },
  {
    id: "WEBHOOK_DELIVERIES_TABLE",
    sqlAnchor: "CREATE TABLE webhook_deliveries (",
    rule: "webhook_deliveries is created only by this appended slice.",
  },
  {
    id: "STATUS_DEFAULT_PENDING",
    sqlAnchor: "status text NOT NULL DEFAULT 'PENDING'",
    rule: "a new delivery stays pending until a tick posts it or the attempt budget ends.",
  },
  {
    id: "SOURCE_UNIQUE",
    sqlAnchor: "CONSTRAINT webhook_deliveries_source_uidx UNIQUE (source_kind, source_id)",
    rule: "one delivery row exists for each source event or rule decision.",
  },
] as const;

export const WEBHOOK_DELIVERIES_EXECUTION_OBLIGATIONS: readonly string[] = [
  "webhook-deliveries.sql applies after implementers exist and is appended to MONEY_SCHEMA_PACK_ORDER.",
  "webhook_deliveries.implementer_id references implementers(id) ON DELETE CASCADE.",
  "The signed body is stored as text. The connector target address is not copied onto the row.",
] as const;

export const WEBHOOK_DELIVERIES_SOURCE =
  "ZTR-1333: signed hook deliveries that a background tick posts" as const;
