/**
 * ZTR-1250 backfill: clear sticky attention on already-landed operations.
 *
 * Frozen inventory of the structural invariants carried by
 * operations-landed-attention-clear-backfill.sql.
 */

export const OPERATIONS_LANDED_ATTENTION_CLEAR_BACKFILL_SCHEMA_FILE =
  "operations-landed-attention-clear-backfill.sql" as const;

export interface OperationsLandedAttentionClearBackfillInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OPERATIONS_LANDED_ATTENTION_CLEAR_BACKFILL_INVARIANTS: readonly OperationsLandedAttentionClearBackfillInvariant[] =
  [
    {
      id: "CLEAR_ONLY_LANDED_TERMINALS",
      sqlAnchor:
        "AND status IN (\n           'RECEIVE_LANDED',\n           'INTERNAL_MOVE_LANDED',\n           'EXTERNAL_SEND_LANDED'\n         )",
      rule:
        "only positive land statuses are cleared; EXPIRED / NEEDS_ATTENTION / in-flight rows keep their attention flag so operator doctrine is intact.",
    },
    {
      id: "CO_PRESENCE_CLEAR",
      sqlAnchor:
        "SET attention_required = false,\n         attention_reason = NULL,\n         attention_detail = NULL",
      rule:
        "attention_required, attention_reason, and attention_detail clear together so the operations co-presence CHECK cannot be violated.",
    },
    {
      id: "FAIL_CLOSED_WITHOUT_OPERATIONS",
      sqlAnchor:
        "RAISE EXCEPTION\n      'operations-landed-attention-clear-backfill requires operations'",
      rule:
        "standalone apply without the operations table fails closed with a named exception.",
    },
  ] as const;

export const OPERATIONS_LANDED_ATTENTION_CLEAR_BACKFILL_EXECUTION_OBLIGATIONS: readonly string[] =
  [
    "operations-landed-attention-clear-backfill.sql applies after operations.sql and is a pure data fix-forward.",
    "The UPDATE ships as its own money-pack slice appended to MONEY_SCHEMA_PACK_ORDER.",
  ] as const;

export const OPERATIONS_LANDED_ATTENTION_CLEAR_BACKFILL_SOURCE =
  "ZTR-1250: sticky attention on landed ops; SPA needs-attention inbox" as const;
