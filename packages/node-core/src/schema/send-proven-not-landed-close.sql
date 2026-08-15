-- Distinct lease-release proof kind for CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED (ZTR-1318).
--
-- Extends lease-foundation + operator-accepted-risk-release so a send proven
-- NOT landed never mints EXTERNAL_SEND_LANDED into lease_release_proofs.
-- Pure CHECK-constraint ALTER on already-owned lease_release_proofs.
-- Appended only -- prior pack slice sql_sha256 values must not change.
--
-- Pack position: after operator-accepted-risk-release (the last prior
-- rewrite of lease_release_proofs.proof_kind).

-- lease_release_proofs.proof_kind: admit SEND_PROVEN_NOT_LANDED_CLOSE
DO $spnlc_lease_proof$
DECLARE
  con_name text;
BEGIN
  IF to_regclass('lease_release_proofs') IS NULL THEN
    RAISE EXCEPTION 'send-proven-not-landed-close requires lease_release_proofs';
  END IF;

  FOR con_name IN
    SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'lease_release_proofs'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%proof_kind%'
       AND pg_get_constraintdef(c.oid) LIKE '%EXTERNAL_SEND_LANDED%'
       AND pg_get_constraintdef(c.oid) NOT LIKE '%SEND_PROVEN_NOT_LANDED_CLOSE%'
  LOOP
    EXECUTE format('ALTER TABLE lease_release_proofs DROP CONSTRAINT %I', con_name);
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'lease_release_proofs'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%SEND_PROVEN_NOT_LANDED_CLOSE%'
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
        'SEND_PROVEN_NOT_LANDED_CLOSE'
      ));
  END IF;
END
$spnlc_lease_proof$;
