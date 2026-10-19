/**
 * connector_configs plus integration_requests proposal columns (ZTR-1330).
 *
 * Frozen inventory of the structural invariants carried by connector-configs.sql.
 */

export const CONNECTOR_CONFIGS_SCHEMA_FILE = "connector-configs.sql" as const;

export interface ConnectorConfigsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const CONNECTOR_CONFIGS_INVARIANTS: readonly ConnectorConfigsInvariant[] = [
  {
    id: "FAIL_CLOSED_WITHOUT_IMPLEMENTERS",
    sqlAnchor: "RAISE EXCEPTION\n      'connector-configs requires implementers'",
    rule:
      "standalone apply without implementers fails closed with a named exception rather than creating an unbound table.",
  },
  {
    id: "FAIL_CLOSED_WITHOUT_INTEGRATION_REQUESTS",
    sqlAnchor: "RAISE EXCEPTION\n      'connector-configs requires integration_requests'",
    rule:
      "standalone apply without integration_requests fails closed before the proposal columns are added.",
  },
  {
    id: "CONNECTOR_CONFIGS_TABLE",
    sqlAnchor: "CREATE TABLE connector_configs (",
    rule:
      "connector_configs is one row per implementer and is created only by this appended slice.",
  },
  {
    id: "POLICY_MODE_DEFAULT",
    sqlAnchor: "policy_mode text NOT NULL DEFAULT 'NODE_VERIFIED'",
    rule:
      "a new connector records NODE_VERIFIED unless the operator later selects LEGACY.",
  },
  {
    id: "REQUESTED_RULES_COLUMN",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS requested_rules jsonb NOT NULL DEFAULT '[]'::jsonb",
    rule:
      "integration_requests.requested_rules stores the platform rule proposal without editing the frozen table body.",
  },
  {
    id: "REQUESTED_WEBHOOK_COLUMN",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS requested_webhook_url text NULL",
    rule:
      "integration_requests.requested_webhook_url stores an optional hook target. The node does not fetch it.",
  },
] as const;

export const CONNECTOR_CONFIGS_EXECUTION_OBLIGATIONS: readonly string[] = [
  "connector-configs.sql applies after implementers and integration_requests exist and is appended to MONEY_SCHEMA_PACK_ORDER.",
  "connector_configs.implementer_id references implementers(id) ON DELETE CASCADE. Capability labels live in scopes and are not bearer-key scopes.",
  "The slice does not edit integration-requests.sql. Proposal columns are added with IF NOT EXISTS. The connector table itself is created once, when the journal applies this slice.",
] as const;

export const CONNECTOR_CONFIGS_SOURCE =
  "ZTR-1330: one connector row per implementer, plus the platform rule and hook proposal columns" as const;
