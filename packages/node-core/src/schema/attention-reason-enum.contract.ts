/**
 * operations.attention_reason (+ send_operations) → attention_reason enum
 * (migration-pack ownership). ZTR-1147.
 */

export const ATTENTION_REASON_ENUM_SCHEMA_FILE = "attention-reason-enum.sql" as const;

export interface AttentionReasonEnumInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const ATTENTION_REASON_ENUM_INVARIANTS: readonly AttentionReasonEnumInvariant[] = [
  {
    id: "ATTENTION_REASON_TYPE",
    sqlAnchor: "CREATE TYPE attention_reason AS ENUM (",
    rule:
      "attention_reason is a real Postgres ENUM closed at the fifteen frozen ATTENTION_REASONS values (Appendix B §4 / events.contract.ts).",
  },
  {
    id: "OPERATIONS_COLUMN_ENUM",
    sqlAnchor: "ALTER COLUMN attention_reason TYPE attention_reason",
    rule:
      "operations.attention_reason and send_operations.attention_reason become the real attention_reason enum (value-preserving USING cast after free-text purge) when still text.",
  },
  {
    id: "FREE_TEXT_PURGE",
    sqlAnchor: "AND attention_reason NOT IN (",
    rule:
      "Pre-existing free-text values are moved into attention_detail (operations) or nulled (send_operations) before the enum cast, so the migration cannot fail on production-shaped prose.",
  },
  {
    id: "TEXT_ONLY_GUARD",
    sqlAnchor: "AND udt_name = 'text'",
    rule:
      "Conversion is gated on udt_name = text so cold applies that already created the enum column (or re-runs) are no-ops.",
  },
] as const;

export const ATTENTION_REASON_ENUM_EXECUTION_OBLIGATIONS: readonly string[] = [
  "attention-reason-enum.sql applies after operations.sql and send-external-expiry.sql so both attention_reason columns exist.",
  "Idempotent: skips columns already typed as attention_reason.",
  "Writing a value outside the fifteen frozen members is rejected by Postgres (invalid input value for enum attention_reason).",
] as const;

export const ATTENTION_REASON_ENUM_SOURCE =
  "state-event reference: attention reasons; CONVENTIONS.md §6; ZTR-1147" as const;
