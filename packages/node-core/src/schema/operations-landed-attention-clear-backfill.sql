-- ZTR-1250: clear sticky attention on operations that already reached a landed
-- terminal status. Receive land (ZTR-1245) and move land already clear the pair
-- going forward; send land mirror (this ticket) does too. Staging still holds
-- rows that parked LINEAGE_GAP / POST_EXPIRY_RECONCILING then settled without
-- the clear — they render as red "Attention required" with zero actions.
--
-- Doctrine: only positive land clears attention. This slice touches only
-- RECEIVE_LANDED / INTERNAL_MOVE_LANDED / EXTERNAL_SEND_LANDED. EXPIRED and
-- NEEDS_ATTENTION are left alone (operator or expiry-release owns those).
-- Co-presence CHECK: required + reason + detail move together.
-- Appended pack slice; prior sql_sha256 journal entries stay stable.

DO $operations_landed_attention_clear_backfill$
BEGIN
  IF to_regclass('operations') IS NULL THEN
    RAISE EXCEPTION
      'operations-landed-attention-clear-backfill requires operations';
  END IF;

  UPDATE operations
     SET attention_required = false,
         attention_reason = NULL,
         attention_detail = NULL
   WHERE attention_required = true
     AND status IN (
           'RECEIVE_LANDED',
           'INTERNAL_MOVE_LANDED',
           'EXTERNAL_SEND_LANDED'
         );
END
$operations_landed_attention_clear_backfill$;
