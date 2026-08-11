-- Dual-control approval policy home (ZTR-1214).
--
-- Frozen schema contract. The durable row lives in node_settings under
-- ops.dual_control_mode (see dual-control-policy.ts / DUAL_CONTROL_SETTING_KEY).
-- Mutations also append audit_log with action ops.dual_control_mode_changed.
--
-- This slice does NOT seed a default value: the validated boot env
-- (DUAL_CONTROL_MODE) remains the pre-mutation source of truth so a two_human
-- deployment is not silently rewritten to single_operator by cold apply. The
-- first guarded POST (fresh TOTP) writes the durable row; thereafter the DB
-- survives restart.
--
-- Pack position: after operational-stores (node_settings) and audit-log.
-- Appended so earlier money-pack version numbers stay stable.

DO $dual_control_policy$
BEGIN
  IF to_regclass('public.node_settings') IS NULL THEN
    RAISE EXCEPTION 'dual-control-policy requires node_settings (operational-stores)';
  END IF;
  IF to_regclass('public.audit_log') IS NULL THEN
    RAISE EXCEPTION 'dual-control-policy requires audit_log';
  END IF;
END
$dual_control_policy$;
