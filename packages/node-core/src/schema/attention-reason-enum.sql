-- operations.attention_reason → attention_reason enum (CONVENTIONS.md §6 closed enumerations).
--
-- Appendix B §4 / events.contract.ts freezes exactly fifteen attention_reason values.
-- operations.sql historically stored the column as plain text with no enum and no CHECK,
-- so both production writers could (and did) emit free-form prose. send_operations already
-- carried a CHECK closed set (send-external-expiry.sql); this slice promotes both live
-- columns onto one real Postgres ENUM so the database rejects a 16th value.
--
-- Free-text rows that are not already one of the fifteen values are preserved in
-- attention_detail (when empty) and then nulled with attention_required cleared, so the
-- USING cast cannot fail on production-shaped data. A failed money-DB migration is not an
-- acceptable discovery path (ZTR-1147).
--
-- Pack position: after operations + send-external-expiry (both columns exist). Appended only.

DO $attention_reason_enum$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = 'attention_reason'
  ) THEN
    CREATE TYPE attention_reason AS ENUM (
      'GATEWAY_RESPONSE_INVALID',
      'GATEWAY_UNAVAILABLE_BEYOND_BUDGET',
      'UNEXPECTED_HEAD_CHANGE',
      'LINEAGE_GAP',
      'SUBMIT_OUTCOME_AMBIGUOUS',
      'SIGNING_OUTCOME_AMBIGUOUS',
      'DESTINATION_NO_LONGER_BLESSED',
      'T0_RELEASE_MISMATCH',
      'VERIFICATION_REJECTED',
      'VERIFICATION_INDETERMINATE',
      'VERIFICATION_RESOURCE_EXHAUSTED',
      'LEASE_INVARIANT_VIOLATION',
      'EXACT_BYTES_UNAVAILABLE',
      'OPERATOR_PARKED',
      'POST_EXPIRY_RECONCILING'
    );
  END IF;
END
$attention_reason_enum$;

-- Preserve free-text prose into attention_detail before the enum cast rejects it.
DO $attention_reason_migrate_ops$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'operations'
       AND column_name = 'attention_reason'
       AND udt_name = 'text'
  ) THEN
    UPDATE operations
       SET attention_detail = CASE
             WHEN attention_detail IS NULL OR btrim(attention_detail) = ''
               THEN attention_reason
             ELSE attention_detail
           END,
           attention_required = false,
           attention_reason = NULL
     WHERE attention_reason IS NOT NULL
       AND attention_reason NOT IN (
         'GATEWAY_RESPONSE_INVALID',
         'GATEWAY_UNAVAILABLE_BEYOND_BUDGET',
         'UNEXPECTED_HEAD_CHANGE',
         'LINEAGE_GAP',
         'SUBMIT_OUTCOME_AMBIGUOUS',
         'SIGNING_OUTCOME_AMBIGUOUS',
         'DESTINATION_NO_LONGER_BLESSED',
         'T0_RELEASE_MISMATCH',
         'VERIFICATION_REJECTED',
         'VERIFICATION_INDETERMINATE',
         'VERIFICATION_RESOURCE_EXHAUSTED',
         'LEASE_INVARIANT_VIOLATION',
         'EXACT_BYTES_UNAVAILABLE',
         'OPERATOR_PARKED',
         'POST_EXPIRY_RECONCILING'
       );

    ALTER TABLE operations
      ALTER COLUMN attention_reason TYPE attention_reason
      USING attention_reason::attention_reason;
  END IF;
END
$attention_reason_migrate_ops$;

DO $attention_reason_migrate_send$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'send_operations'
       AND column_name = 'attention_reason'
       AND udt_name = 'text'
  ) THEN
    -- send_operations already CHECKed the closed set; free-text should not exist.
    -- Still fail-closed: null any residual that is not in the vocabulary.
    UPDATE send_operations
       SET attention_required = false,
           attention_reason = NULL
     WHERE attention_reason IS NOT NULL
       AND attention_reason NOT IN (
         'GATEWAY_RESPONSE_INVALID',
         'GATEWAY_UNAVAILABLE_BEYOND_BUDGET',
         'UNEXPECTED_HEAD_CHANGE',
         'LINEAGE_GAP',
         'SUBMIT_OUTCOME_AMBIGUOUS',
         'SIGNING_OUTCOME_AMBIGUOUS',
         'DESTINATION_NO_LONGER_BLESSED',
         'T0_RELEASE_MISMATCH',
         'VERIFICATION_REJECTED',
         'VERIFICATION_INDETERMINATE',
         'VERIFICATION_RESOURCE_EXHAUSTED',
         'LEASE_INVARIANT_VIOLATION',
         'EXACT_BYTES_UNAVAILABLE',
         'OPERATOR_PARKED',
         'POST_EXPIRY_RECONCILING'
       );

    -- Drop the decorative CHECK before the type change (enum supersedes it).
    ALTER TABLE send_operations
      DROP CONSTRAINT IF EXISTS send_operations_attention_reason_closed;

    ALTER TABLE send_operations
      ALTER COLUMN attention_reason TYPE attention_reason
      USING attention_reason::attention_reason;
  END IF;
END
$attention_reason_migrate_send$;
