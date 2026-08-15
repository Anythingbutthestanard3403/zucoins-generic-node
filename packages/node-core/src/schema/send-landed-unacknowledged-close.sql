-- Distinct lease-release proof kind for CLOSE_LANDED_UNACKNOWLEDGED (ZTR-1316).
--
-- Extends lease-foundation + send-proven-not-landed-close so an INDEPENDENT
-- EXTERNAL_SEND_LANDED send whose verification-complete is overdue never mints
-- EXTERNAL_SEND_LANDED (or SEND_PROVEN_NOT_LANDED_CLOSE) into lease_release_proofs.
-- Pure CHECK-constraint ALTER on already-owned lease_release_proofs.
-- Appended only -- prior pack slice sql_sha256 values must not change.
--
-- Pack position: after send-proven-not-landed-close (the last prior
-- rewrite of lease_release_proofs.proof_kind).

-- lease_release_proofs.proof_kind: admit SEND_LANDED_UNACKNOWLEDGED_CLOSE
DO $sluc_lease_proof$
DECLARE
  con_name text;
BEGIN
  IF to_regclass('lease_release_proofs') IS NULL THEN
    RAISE EXCEPTION 'send-landed-unacknowledged-close requires lease_release_proofs';
  END IF;

  FOR con_name IN
    SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'lease_release_proofs'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%proof_kind%'
       AND pg_get_constraintdef(c.oid) LIKE '%SEND_PROVEN_NOT_LANDED_CLOSE%'
       AND pg_get_constraintdef(c.oid) NOT LIKE '%SEND_LANDED_UNACKNOWLEDGED_CLOSE%'
  LOOP
    EXECUTE format('ALTER TABLE lease_release_proofs DROP CONSTRAINT %I', con_name);
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'lease_release_proofs'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%SEND_LANDED_UNACKNOWLEDGED_CLOSE%'
  ) THEN
    ALTER TABLE lease_release_proofs
      ADD CONSTRAINT lease_release_proofs_proof_kind_check
      CHECK (proof_kind IN (
        'RECEIVE_LANDED',
        'INTERNAL_MOVE_LANDED',
        'EXTERNAL_SEND_LANDED',
        'RECEIVE_EXPIRED_T0',
        'OPERATOR_QUARANTINE_RELEASE',
        'RECEIVE_OPERATOR_ACCEPTED_RISK',
        'SEND_PROVEN_NOT_LANDED_CLOSE',
        'SEND_LANDED_UNACKNOWLEDGED_CLOSE'
      ));
  END IF;
END
$sluc_lease_proof$;
