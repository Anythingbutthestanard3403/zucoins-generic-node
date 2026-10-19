/**
 * send_operations.rule_id and operations.rule_id (ZTR-1329).
 *
 * Frozen inventory of the structural invariants carried by
 * send-operations-rule-id.sql.
 */

export const SEND_OPERATIONS_RULE_ID_SCHEMA_FILE =
  "send-operations-rule-id.sql" as const;

export interface SendOperationsRuleIdInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const SEND_OPERATIONS_RULE_ID_INVARIANTS: readonly SendOperationsRuleIdInvariant[] =
  [
    {
      id: "FAIL_CLOSED_WITHOUT_SEND_OPERATIONS",
      sqlAnchor: "RAISE EXCEPTION\n      'send-operations-rule-id requires send_operations'",
      rule:
        "standalone apply without send_operations fails closed with a named exception rather than silently no-oping.",
    },
    {
      id: "FAIL_CLOSED_WITHOUT_OPERATIONS",
      sqlAnchor: "RAISE EXCEPTION\n      'send-operations-rule-id requires operations'",
      rule:
        "standalone apply without the operations inventory table fails closed with a named exception.",
    },
    {
      id: "SEND_COLUMN_NULLABLE_TEXT",
      sqlAnchor: "ALTER TABLE send_operations\n  ADD COLUMN IF NOT EXISTS rule_id text",
      rule:
        "send_operations.rule_id is nullable text so a send that omits a spend rule stays valid.",
    },
    {
      id: "OPERATIONS_COLUMN_NULLABLE_TEXT",
      sqlAnchor: "ALTER TABLE operations\n    ADD COLUMN IF NOT EXISTS rule_id text",
      rule:
        "operations.rule_id mirrors the send column and is nullable text.",
    },
    {
      id: "RULE_ID_FORM_CHECK",
      sqlAnchor: "rule_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'",
      rule:
        "a non-null rule_id must match the auto-approve rule id grammar.",
    },
  ] as const;

export const SEND_OPERATIONS_RULE_ID_EXECUTION_OBLIGATIONS: readonly string[] =
  [
    "send-operations-rule-id.sql applies after send-external-create.sql and operations.sql and is a pure column extension: it creates no table and no trigger.",
    "NULL rule_id means the client omitted a spend rule. Auto-approve then matches the connector default rule, or the sole rule, and otherwise leaves the send CREATED.",
    "The slice ships appended to MONEY_SCHEMA_PACK_ORDER; send-external-create.sql and operations.sql are already applied and their schema_migrations sql_sha256 must not change.",
  ] as const;

export const SEND_OPERATIONS_RULE_ID_SOURCE =
  "ZTR-1329: persist optional external-send rule_id so a connector can target one spend rule" as const;
