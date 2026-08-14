-- Worker-sink destination + G2 overlay (send-worker auto-scale).
--
-- Requires destination-state-worker (WORKER enum label committed).
-- Does not rewrite custody-eligibility.sql (pack sql_sha256 frozen).
-- Rewrites destinations_blessed_iff so WORKER may exist with null blessing
-- columns, and replaces custody_reject_ineligible_lease so MOVE_DESTINATION
-- admits BLESSED (recovery required) or WORKER (recovery not required).
--
-- WORKER → BLESSED remains structurally impossible: bless still requires the
-- artifact columns, and the service CAS only accepts PENDING.

DO $destination_worker_sink_prereq$
BEGIN
  IF to_regclass('destinations') IS NULL THEN
    RAISE EXCEPTION 'destination-worker-sink requires destinations';
  END IF;
  IF to_regtype('destination_state') IS NULL THEN
    RAISE EXCEPTION 'destination-worker-sink requires destination_state';
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM pg_enum e
     WHERE e.enumtypid = to_regtype('destination_state')
       AND e.enumlabel = 'WORKER'
  ) THEN
    RAISE EXCEPTION 'destination-worker-sink requires destination_state WORKER';
  END IF;
END
$destination_worker_sink_prereq$;

-- destinations_blessed_iff historically: (BLESSED|RETIRED) iff blessed_at.
-- WORKER is a node-owned sink with no ceremony, so blessed_at stays NULL.
ALTER TABLE destinations DROP CONSTRAINT IF EXISTS destinations_blessed_iff;
ALTER TABLE destinations
  ADD CONSTRAINT destinations_blessed_iff
  CHECK (
    (state IN ('BLESSED', 'RETIRED')) = (blessed_at IS NOT NULL)
    AND (
      state <> 'WORKER'
      OR (
        blessed_at IS NULL
        AND blessed_by_device_key_id IS NULL
        AND blessing_artifact_id IS NULL
      )
    )
  );

-- Overlay the live eligibility function (wallet-money-capability-lease-guard
-- already replaced the custody-eligibility body). Keep money-capability
-- conjuncts; split the MOVE_DESTINATION sink gate.
CREATE OR REPLACE FUNCTION custody_reject_ineligible_lease() RETURNS trigger AS $$
DECLARE
  wallet_row wallets%ROWTYPE;
  destination_row destinations%ROWTYPE;
BEGIN
  SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id FOR UPDATE;
  IF wallet_row.key_origin IS DISTINCT FROM 'node_generated' THEN
    RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED';
  END IF;
  IF NEW.lease_role IS DISTINCT FROM 'RECONCILIATION'
     AND wallet_row.state NOT IN ('AVAILABLE', 'PINNED') THEN
    RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED';
  END IF;
  IF NEW.lease_role = 'RECONCILIATION' THEN
    NULL;
  ELSIF NEW.lease_role = 'RECEIVE_WINDOW' THEN
    IF wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    IF wallet_row.state IS DISTINCT FROM 'AVAILABLE' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED';
    END IF;
    IF wallet_row.allow_external_receive IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECEIVE_CAPABILITY_REJECTED';
    END IF;
  ELSIF NEW.lease_role = 'MOVE_DESTINATION' THEN
    SELECT * INTO destination_row FROM destinations WHERE wallet_id = NEW.wallet_id FOR UPDATE;
    IF destination_row.state IS DISTINCT FROM 'BLESSED'
       AND destination_row.state IS DISTINCT FROM 'WORKER' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_DESTINATION_NOT_BLESSED';
    END IF;
    IF destination_row.state = 'BLESSED'
       AND wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    IF wallet_row.allow_internal_move IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED';
    END IF;
  ELSIF NEW.lease_role = 'MOVE_SOURCE' THEN
    IF wallet_row.allow_internal_move IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED';
    END IF;
  ELSIF NEW.lease_role = 'SEND_SOURCE' THEN
    IF wallet_row.allow_external_send IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_SEND_CAPABILITY_REJECTED';
    END IF;
  ELSE
    RAISE EXCEPTION 'CUSTODY_LEASE_ROLE_UNKNOWN';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
