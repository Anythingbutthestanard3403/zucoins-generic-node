// Operations response columns (migration-pack ownership).
//
// Frozen inventory of the structural invariants carried by
// operations-response-columns.sql — the two nullable operations columns that record the
// last synchronous gateway response observed for an operation, previously written by a
// runtime `ALTER TABLE IF NOT EXISTS` in start-money-workers.ts.

export const OPERATIONS_RESPONSE_COLUMNS_SCHEMA_FILE =
  "operations-response-columns.sql" as const;

export interface OperationsResponseColumnsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OPERATIONS_RESPONSE_COLUMNS_INVARIANTS: readonly OperationsResponseColumnsInvariant[] =
  [
    {
      id: "RESPONSE_STATUS_NULLABLE",
      sqlAnchor: "ADD COLUMN IF NOT EXISTS response_status integer",
      rule:
        "response_status is nullable: an operation has no recorded gateway response until one is observed, and historical rows predating this column have none.",
    },
    {
      id: "RESPONSE_BODY_NULLABLE",
      sqlAnchor: "ADD COLUMN IF NOT EXISTS response_body text",
      rule:
        "response_body is nullable for the same reason as response_status; the two columns are always written together by the operation worker, never independently.",
    },
  ] as const;

export const OPERATIONS_RESPONSE_COLUMNS_EXECUTION_OBLIGATIONS: readonly string[] = [
  "operations-response-columns.sql applies after operations.sql (operations must already exist) and is a pure column extension: it creates no table, no index, no trigger.",
] as const;

export const OPERATIONS_RESPONSE_COLUMNS_SOURCE = "data-model: operations" as const;
