-- Nullable rule_id on send_operations and the operations mirror (ZTR-1329).
--
-- Frozen schema contract. Pure column extension. send-external-create.sql owns
-- CREATE TABLE send_operations and operations.sql owns CREATE TABLE operations.
-- Those slices' schema_migrations sql_sha256 must not change, so the column
-- ships here as an appended ALTER.
--
-- NULL means the client omitted a spend rule. A non-null value matches the
-- auto-approve rule_id grammar. Pack position: appended so earlier money-pack
-- versions stay stable.

DO $send_operations_rule_id_prereq$
BEGIN
  IF to_regclass('send_operations') IS NULL THEN
    RAISE EXCEPTION
      'send-operations-rule-id requires send_operations';
  END IF;
END
$send_operations_rule_id_prereq$;

ALTER TABLE send_operations
  ADD COLUMN IF NOT EXISTS rule_id text;

DO $send_operations_rule_id_check$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'send_operations_rule_id_form'
  ) THEN
    ALTER TABLE send_operations
      ADD CONSTRAINT send_operations_rule_id_form
      CHECK (
        rule_id IS NULL
        OR rule_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
      );
  END IF;
END
$send_operations_rule_id_check$;

DO $operations_rule_id_column$
BEGIN
  IF to_regclass('operations') IS NULL THEN
    RAISE EXCEPTION
      'send-operations-rule-id requires operations';
  END IF;
  ALTER TABLE operations
    ADD COLUMN IF NOT EXISTS rule_id text;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'operations_rule_id_form'
  ) THEN
    ALTER TABLE operations
      ADD CONSTRAINT operations_rule_id_form
      CHECK (
        rule_id IS NULL
        OR rule_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
      );
  END IF;
END
$operations_rule_id_column$;
