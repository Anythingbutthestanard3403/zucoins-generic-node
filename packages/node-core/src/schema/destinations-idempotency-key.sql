-- destinations.idempotency_key: durable register replay key (ZTR-1310).
--
-- Frozen schema contract. Pure column extension on the already-created
-- destinations table (custody-eligibility.sql). That early pack slice's
-- schema_migrations sql_sha256 must not change, so the column ships here as
-- an appended ALTER -- never by editing the CREATE TABLE.
--
-- DestinationStore.findByIdempotencyKey is keyed (node_id, idempotency_key).
-- Destinations are not implementer-API operations, so this is not the
-- (implementer_id, http_method, route, idempotency_key) ledger. NULL is
-- allowed: mint / pool / backfill rows have no register key. UNIQUE is
-- partial so many NULL keys may coexist.
--
-- Pack position: appended so earlier money-pack versions stay stable.

DO $destinations_idempotency_key_prereq$
BEGIN
  IF to_regclass('destinations') IS NULL THEN
    RAISE EXCEPTION
      'destinations-idempotency-key requires destinations';
  END IF;
END
$destinations_idempotency_key_prereq$;

ALTER TABLE destinations
  ADD COLUMN IF NOT EXISTS idempotency_key text;

DO $destinations_idempotency_key_check$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'destinations_idempotency_key_form'
  ) THEN
    ALTER TABLE destinations
      ADD CONSTRAINT destinations_idempotency_key_form
      CHECK (
        idempotency_key IS NULL
        OR idempotency_key ~ '^[!-~]{16,255}$'
      );
  END IF;
END
$destinations_idempotency_key_check$;

CREATE UNIQUE INDEX IF NOT EXISTS destinations_node_idempotency_key_uidx
  ON destinations (node_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
