-- Operator-accepted-risk receive release (ZTR-1280).
--
-- Extends receive-expiry-release + lease-foundation so an audited last-resort
-- recovery path can mint a distinct release kind that is never EXPIRED_T0_UNCHANGED.
-- Pure CHECK/column-constraint ALTER on already-owned tables. Appended only —
-- prior pack slice sql_sha256 values must not change.
--
-- Pack position: after receive-expiry-release and lease-foundation.

-- ── operations.receive_release_status: admit RELEASED_OPERATOR_ACCEPTED_RISK ──
DO $oar_ops_status$
DECLARE
  con_name text;
BEGIN
  IF to_regclass('operations') IS NULL THEN
    RAISE EXCEPTION 'operator-accepted-risk-release requires operations';
  END IF;

  FOR con_name IN
    SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'operations'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%RELEASED_T0_UNCHANGED%'
       AND pg_get_constraintdef(c.oid) LIKE '%receive_release_status%'
  LOOP
    EXECUTE format('ALTER TABLE operations DROP CONSTRAINT %I', con_name);
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'operations'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%RELEASED_OPERATOR_ACCEPTED_RISK%'
  ) THEN
    ALTER TABLE operations
      ADD CONSTRAINT operations_receive_release_status_check
      CHECK (
        receive_release_status IS NULL
        OR receive_release_status IN (
          'RELEASED_T0_UNCHANGED',
          'RELEASED_PROVEN_NOT_STARTED',
          'RELEASED_OPERATOR_ACCEPTED_RISK'
        )
      );
  END IF;
END
$oar_ops_status$;

-- ── receive_release_proofs.release_kind: admit OPERATOR_ACCEPTED_RISK ──
-- Observations optional (override is not a T0-unchanged proof). Ack always null.
DO $oar_recv_proof$
DECLARE
  con_name text;
BEGIN
  IF to_regclass('receive_release_proofs') IS NULL THEN
    RAISE EXCEPTION 'operator-accepted-risk-release requires receive_release_proofs';
  END IF;

  FOR con_name IN
    SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'receive_release_proofs'
       AND c.contype = 'c'
       AND (
         pg_get_constraintdef(c.oid) LIKE '%EXPIRED_T0_UNCHANGED%'
         OR pg_get_constraintdef(c.oid) LIKE '%EXPIRED_PROVEN_NOT_STARTED%'
         OR pg_get_constraintdef(c.oid) LIKE '%VERIFICATION_COMPLETE%'
       )
  LOOP
    EXECUTE format('ALTER TABLE receive_release_proofs DROP CONSTRAINT %I', con_name);
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'receive_release_proofs'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%OPERATOR_ACCEPTED_RISK%'
  ) THEN
    ALTER TABLE receive_release_proofs
      ADD CONSTRAINT receive_release_proofs_release_kind_check
      CHECK (release_kind IN (
        'VERIFICATION_COMPLETE',
        'EXPIRED_T0_UNCHANGED',
        'EXPIRED_PROVEN_NOT_STARTED',
        'OPERATOR_ACCEPTED_RISK'
      ));

    ALTER TABLE receive_release_proofs
      ADD CONSTRAINT receive_release_proofs_kind_biconditional_check
      CHECK (
        (release_kind = 'VERIFICATION_COMPLETE'
          AND verification_acknowledgement_id IS NOT NULL
          AND t0_observation_id IS NOT NULL AND fresh_observation_id IS NOT NULL)
        OR
        (release_kind = 'EXPIRED_T0_UNCHANGED'
          AND verification_acknowledgement_id IS NULL
          AND t0_observation_id IS NOT NULL AND fresh_observation_id IS NOT NULL)
        OR
        (release_kind = 'EXPIRED_PROVEN_NOT_STARTED'
          AND verification_acknowledgement_id IS NULL
          AND t0_observation_id IS NULL AND fresh_observation_id IS NULL)
        OR
        (release_kind = 'OPERATOR_ACCEPTED_RISK'
          AND verification_acknowledgement_id IS NULL)
      );
  END IF;
END
$oar_recv_proof$;

-- ── lease_release_proofs.proof_kind: admit RECEIVE_OPERATOR_ACCEPTED_RISK ──
DO $oar_lease_proof$
DECLARE
  con_name text;
BEGIN
  IF to_regclass('lease_release_proofs') IS NULL THEN
    RAISE EXCEPTION 'operator-accepted-risk-release requires lease_release_proofs';
  END IF;

  FOR con_name IN
    SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'lease_release_proofs'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%RECEIVE_EXPIRED_T0%'
  LOOP
    EXECUTE format('ALTER TABLE lease_release_proofs DROP CONSTRAINT %I', con_name);
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
     WHERE rel.relname = 'lease_release_proofs'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%RECEIVE_OPERATOR_ACCEPTED_RISK%'
  ) THEN
    ALTER TABLE lease_release_proofs
      ADD CONSTRAINT lease_release_proofs_proof_kind_check
      CHECK (proof_kind IN (
        'RECEIVE_LANDED',
        'INTERNAL_MOVE_LANDED',
        'EXTERNAL_SEND_LANDED',
        'RECEIVE_EXPIRED_T0',
        'OPERATOR_QUARANTINE_RELEASE',
        'RECEIVE_OPERATOR_ACCEPTED_RISK'
      ));
  END IF;
END
$oar_lease_proof$;
