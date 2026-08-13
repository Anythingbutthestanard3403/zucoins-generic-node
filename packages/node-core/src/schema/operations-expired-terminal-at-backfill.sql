-- ZTR-1249: backfill terminal_at on walletless EXPIRED operations left NULL by
-- EXPIRE_QUEUE_AGED_RECEIVE (which historically stamped status only).
--
-- SPA Overview treats terminal_at IS NULL as "in flight", so EXPIRED rows with a
-- null terminal_at render as in-flight forever. updated_at is the closest durable
-- clock we have for the flip moment on already-applied rows.
--
-- Idempotent: only touches EXPIRED + terminal_at IS NULL. Pure data fix-forward;
-- creates no table, column, index, or trigger. Appended pack slice so earlier
-- money-pack version numbers and their sql_sha256 journal entries stay stable.
-- Wrapped in DO so standalone apply fails closed when operations is absent
-- (migration-integrity NO_TABLE shape) and so already-applied DBs stay green.

DO $operations_expired_terminal_at_backfill$
BEGIN
  IF to_regclass('operations') IS NULL THEN
    RAISE EXCEPTION
      'operations-expired-terminal-at-backfill requires operations';
  END IF;

  UPDATE operations
     SET terminal_at = COALESCE(terminal_at, updated_at)
   WHERE status = 'EXPIRED'
     AND terminal_at IS NULL;
END
$operations_expired_terminal_at_backfill$;
