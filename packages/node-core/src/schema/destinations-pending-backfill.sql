-- ZTR-1306: backfill a PENDING destinations row for every node_generated
-- wallet that was minted without one. Pool scale-up and funding mint
-- historically wrote wallets only; POST /v1/destinations was the sole dest
-- insert. Assign then preferred older send-capable wallets with dest_id
-- null and failed closed (worker_destination_missing).
--
-- PENDING only -- never BLESSED. Blessing stays dual-control (device + TOTP).
-- Imported-origin wallets are excluded (custody insert trigger would reject).
-- Idempotent: NOT EXISTS on destinations.wallet_id (UNIQUE).
-- Pure data fix-forward; creates no table, column, index, or trigger.
-- Appended pack slice so earlier money-pack version numbers stay stable.

DO $destinations_pending_backfill$
BEGIN
  IF to_regclass('wallets') IS NULL THEN
    RAISE EXCEPTION
      'destinations-pending-backfill requires wallets';
  END IF;
  IF to_regclass('destinations') IS NULL THEN
    RAISE EXCEPTION
      'destinations-pending-backfill requires destinations';
  END IF;

  INSERT INTO destinations (id, node_id, wallet_id, label, state)
  SELECT gen_random_uuid(), w.node_id, w.id, '', 'PENDING'
    FROM wallets w
   WHERE w.key_origin = 'node_generated'
     AND NOT EXISTS (
           SELECT 1 FROM destinations d WHERE d.wallet_id = w.id
         );
END
$destinations_pending_backfill$;
