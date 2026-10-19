/**
 * connector_rule_requests (ZTR-1331).
 *
 * Frozen inventory of the structural invariants carried by connector-rule-requests.sql.
 */

export const CONNECTOR_RULE_REQUESTS_SCHEMA_FILE = "connector-rule-requests.sql" as const;

export interface ConnectorRuleRequestsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const CONNECTOR_RULE_REQUESTS_INVARIANTS: readonly ConnectorRuleRequestsInvariant[] = [
  {
    id: "FAIL_CLOSED_WITHOUT_IMPLEMENTERS",
    sqlAnchor: "RAISE EXCEPTION\n      'connector-rule-requests requires implementers'",
    rule:
      "standalone apply without implementers fails closed with a named exception rather than creating an unbound table.",
  },
  {
    id: "FAIL_CLOSED_WITHOUT_WALLETS",
    sqlAnchor: "RAISE EXCEPTION\n      'connector-rule-requests requires wallets'",
    rule:
      "standalone apply without wallets fails closed before the reserve wallet reference is declared.",
  },
  {
    id: "CONNECTOR_RULE_REQUESTS_TABLE",
    sqlAnchor: "CREATE TABLE connector_rule_requests (",
    rule:
      "connector_rule_requests is created only by this appended slice.",
  },
  {
    id: "STATUS_DEFAULT_PENDING",
    sqlAnchor: "status text NOT NULL DEFAULT 'PENDING'",
    rule:
      "a new request stays pending until an operator admits or declines it.",
  },
  {
    id: "WINDOW_HOURS_BOUND",
    sqlAnchor: "CONSTRAINT connector_rule_requests_window_hours_chk CHECK (",
    rule:
      "window_hours is an integer from 1 through 720.",
  },
] as const;

export const CONNECTOR_RULE_REQUESTS_EXECUTION_OBLIGATIONS: readonly string[] = [
  "connector-rule-requests.sql applies after implementers and wallets exist and is appended to MONEY_SCHEMA_PACK_ORDER.",
  "connector_rule_requests.implementer_id references implementers(id) ON DELETE CASCADE. reserve_wallet_id references wallets(id) and may be null.",
  "Amounts are canonical text. The slice does not fetch a hook target. webhook_enabled is a boolean flag only.",
] as const;

export const CONNECTOR_RULE_REQUESTS_SOURCE =
  "ZTR-1331: platform spend-rule requests that stay pending until an operator admits them" as const;
