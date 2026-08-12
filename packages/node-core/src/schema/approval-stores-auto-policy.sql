-- approval-stores AUTO_POLICY method arm (ZTR-1233).
--
-- Greenfield CREATE in approval-stores.sql already carries the three-arm method
-- CHECK, nullable challenge_id / totp_timestep, and the partial TOTP single-use
-- index. This appended slice converges databases that already journaled the
-- pre-AUTO_POLICY approval-stores body without renumbering prior pack versions
-- (sql_sha256 of approval-stores must not change for already-applied DBs).
--
-- Pack position: after approval-stores (table exists). Appended only.

DO $approval_auto_policy$
BEGIN
  IF to_regclass('public.operation_approvals') IS NULL THEN
    RAISE EXCEPTION 'approval-stores-auto-policy requires operation_approvals';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_enum e
      JOIN pg_type t ON t.oid = e.enumtypid
     WHERE t.typname = 'approval_method'
       AND e.enumlabel = 'AUTO_POLICY'
  ) THEN
    RAISE EXCEPTION 'approval-stores-auto-policy requires approval_method.AUTO_POLICY (apply approval-method-auto-policy-enum first)';
  END IF;
END
$approval_auto_policy$;

-- Nullable factor columns for machine-committed approvals.
ALTER TABLE operation_approvals
  ALTER COLUMN challenge_id DROP NOT NULL,
  ALTER COLUMN totp_timestep DROP NOT NULL;

-- Replace two-arm device biconditional CHECK with three-arm method CHECK.
DO $approval_method_check$
DECLARE
  con_name text;
BEGIN
  FOR con_name IN
    SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'operation_approvals'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%TOTP_AND_DEVICE%'
       AND pg_get_constraintdef(c.oid) LIKE '%device_key_id%'
  LOOP
    EXECUTE format(
      'ALTER TABLE operation_approvals DROP CONSTRAINT %I',
      con_name
    );
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'operation_approvals'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%AUTO_POLICY%'
  ) THEN
    ALTER TABLE operation_approvals
      ADD CONSTRAINT operation_approvals_method_arms_check
      CHECK (
        (method = 'TOTP_AND_DEVICE'
          AND challenge_id IS NOT NULL
          AND totp_timestep IS NOT NULL
          AND device_key_id IS NOT NULL
          AND device_signature IS NOT NULL)
        OR
        (method = 'TOTP_ONLY'
          AND challenge_id IS NOT NULL
          AND totp_timestep IS NOT NULL
          AND device_key_id IS NULL
          AND device_signature IS NULL)
        OR
        (method = 'AUTO_POLICY'
          AND challenge_id IS NULL
          AND totp_timestep IS NULL
          AND device_key_id IS NULL
          AND device_signature IS NULL)
      );
  END IF;
END
$approval_method_check$;

-- Partial unique index: exclude null totp_timestep (AUTO_POLICY).
DROP INDEX IF EXISTS operation_approvals_totp_single_use;
CREATE UNIQUE INDEX IF NOT EXISTS operation_approvals_totp_single_use
  ON operation_approvals (node_id, totp_timestep)
  WHERE totp_timestep IS NOT NULL;
