-- Per-operation verification_mode + RELEASED_NODE_VERIFIED release status + policy home (ZTR-1300).
--
-- Mode is chosen at admission and immutable thereafter. DEFAULT 'INDEPENDENT' backfills every
-- existing row (pre-mode ops are independent by definition). CLOSED CHECK admits only the two
-- frozen labels from generic-node-contracts verification-mode.contract.ts.
--
-- Tables that hold lease-bearing operation rows:
--   * operations          - universal mirror (receive / move / send)
--   * receive_operations  - RECEIVE_EXTERNAL projection
--   * send_operations     - SEND_EXTERNAL projection
-- MOVE_INTERNAL has no separate projection table; it lives only on operations.
--
-- RELEASED_NODE_VERIFIED widens operations.receive_release_status so node-verified custody
-- close is durably distinct from expiry releases and operator-accepted-risk. Not an expiry
-- predicate token; audit/forensic only until ZTR-1301+ writers land.
--
-- Policy: ops.allow_node_verified lives in node_settings (parallel to ops.auto_approve_sends /
-- ops.dual_control_mode). This slice does NOT seed a row - fail-closed absent document.
--
-- Pack position: after operator-accepted-risk-release (receive_release_status CHECK owner),
-- operational-stores (node_settings), audit-log, receive-admission, send-external-create.
-- Appended only - prior pack slice sql_sha256 values must not change.

-- -- prerequisites ----------------------------------------------------------
DO $verification_mode_prereq$
BEGIN
  IF to_regclass('operations') IS NULL THEN
    RAISE EXCEPTION 'verification-mode requires operations';
  END IF;
  IF to_regclass('receive_operations') IS NULL THEN
    RAISE EXCEPTION 'verification-mode requires receive_operations';
  END IF;
  IF to_regclass('send_operations') IS NULL THEN
    RAISE EXCEPTION 'verification-mode requires send_operations';
  END IF;
  IF to_regclass('node_settings') IS NULL THEN
    RAISE EXCEPTION 'verification-mode requires node_settings (operational-stores)';
  END IF;
  IF to_regclass('audit_log') IS NULL THEN
    RAISE EXCEPTION 'verification-mode requires audit_log';
  END IF;
END
$verification_mode_prereq$;

-- -- operations.verification_mode -------------------------------------------
ALTER TABLE operations
  ADD COLUMN IF NOT EXISTS verification_mode text NOT NULL DEFAULT 'INDEPENDENT';

DO $vm_ops_check$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_operations_verification_mode'
  ) THEN
    ALTER TABLE operations
      ADD CONSTRAINT chk_operations_verification_mode
      CHECK (verification_mode IN ('INDEPENDENT', 'NODE_VERIFIED'));
  END IF;
END
$vm_ops_check$;

-- -- receive_operations.verification_mode -----------------------------------
ALTER TABLE receive_operations
  ADD COLUMN IF NOT EXISTS verification_mode text NOT NULL DEFAULT 'INDEPENDENT';

DO $vm_recv_check$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_receive_verification_mode'
  ) THEN
    ALTER TABLE receive_operations
      ADD CONSTRAINT chk_receive_verification_mode
      CHECK (verification_mode IN ('INDEPENDENT', 'NODE_VERIFIED'));
  END IF;
END
$vm_recv_check$;

-- -- send_operations.verification_mode --------------------------------------
ALTER TABLE send_operations
  ADD COLUMN IF NOT EXISTS verification_mode text NOT NULL DEFAULT 'INDEPENDENT';

DO $vm_send_check$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_send_verification_mode'
  ) THEN
    ALTER TABLE send_operations
      ADD CONSTRAINT chk_send_verification_mode
      CHECK (verification_mode IN ('INDEPENDENT', 'NODE_VERIFIED'));
  END IF;
END
$vm_send_check$;

-- -- immutability: verification_mode cannot change after insert -------------
CREATE OR REPLACE FUNCTION verification_mode_reject_mutation() RETURNS trigger AS $$
BEGIN
  IF NEW.verification_mode IS DISTINCT FROM OLD.verification_mode THEN
    RAISE EXCEPTION 'VERIFICATION_MODE_IMMUTABLE';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS operations_verification_mode_immutable ON operations;
CREATE TRIGGER operations_verification_mode_immutable
  BEFORE UPDATE ON operations
  FOR EACH ROW EXECUTE FUNCTION verification_mode_reject_mutation();

DROP TRIGGER IF EXISTS receive_operations_verification_mode_immutable ON receive_operations;
CREATE TRIGGER receive_operations_verification_mode_immutable
  BEFORE UPDATE ON receive_operations
  FOR EACH ROW EXECUTE FUNCTION verification_mode_reject_mutation();

DROP TRIGGER IF EXISTS send_operations_verification_mode_immutable ON send_operations;
CREATE TRIGGER send_operations_verification_mode_immutable
  BEFORE UPDATE ON send_operations
  FOR EACH ROW EXECUTE FUNCTION verification_mode_reject_mutation();

-- -- operations.receive_release_status: admit RELEASED_NODE_VERIFIED --------
-- Replaces the CHECK installed by receive-expiry-release / operator-accepted-risk-release.
DO $vm_release_status$
DECLARE
  con_name text;
BEGIN
  FOR con_name IN
    SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'operations'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%receive_release_status%'
       AND (
         pg_get_constraintdef(c.oid) LIKE '%RELEASED_T0_UNCHANGED%'
         OR pg_get_constraintdef(c.oid) LIKE '%RELEASED_OPERATOR_ACCEPTED_RISK%'
       )
       AND pg_get_constraintdef(c.oid) NOT LIKE '%RELEASED_NODE_VERIFIED%'
  LOOP
    EXECUTE format('ALTER TABLE operations DROP CONSTRAINT %I', con_name);
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'operations'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%RELEASED_NODE_VERIFIED%'
       AND pg_get_constraintdef(c.oid) LIKE '%receive_release_status%'
  ) THEN
    ALTER TABLE operations
      ADD CONSTRAINT operations_receive_release_status_check
      CHECK (
        receive_release_status IS NULL
        OR receive_release_status IN (
          'RELEASED_T0_UNCHANGED',
          'RELEASED_PROVEN_NOT_STARTED',
          'RELEASED_OPERATOR_ACCEPTED_RISK',
          'RELEASED_NODE_VERIFIED'
        )
      );
  END IF;
END
$vm_release_status$;
