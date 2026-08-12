-- approval_method += AUTO_POLICY (ZTR-1233).
--
-- Own pack slice so ALTER TYPE ... ADD VALUE commits before any later slice
-- references the new label in a CHECK (PG forbids using a newly-added enum
-- label until the adding transaction commits).
--
-- Greenfield base-enums-domains.sql already creates the 3-value enum; this
-- slice is a no-op there. Appended only.

DO $approval_method_auto_policy_enum$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_type
     WHERE typname = 'approval_method'
  ) THEN
    RAISE EXCEPTION 'approval-method-auto-policy-enum requires approval_method';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_enum e
      JOIN pg_type t ON t.oid = e.enumtypid
     WHERE t.typname = 'approval_method'
       AND e.enumlabel = 'AUTO_POLICY'
  ) THEN
    ALTER TYPE approval_method ADD VALUE 'AUTO_POLICY';
  END IF;
END
$approval_method_auto_policy_enum$;
