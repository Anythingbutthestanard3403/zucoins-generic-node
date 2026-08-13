-- Wallet money-capability lease eligibility overlay (ZTR-1268).
--
-- Replaces custody_reject_ineligible_lease so lease claim re-checks money
-- capability flags in the same TX as the wallet-row FOR UPDATE (no TOCTOU).
-- Column surface lands in wallet-money-capability.sql; this slice must apply
-- after that ALTER. custody-eligibility.sql stays frozen (its pack sql_sha256
-- must not change); the function body is upgraded here via CREATE OR REPLACE.
--
-- Role map:
--   RECEIVE_WINDOW  -> allow_external_receive
--   SEND_SOURCE     -> allow_external_send
--   MOVE_SOURCE / MOVE_DESTINATION -> allow_internal_move
--   RECONCILIATION  -> exempt (recovery lane; no money verb)

CREATE OR REPLACE FUNCTION custody_reject_ineligible_lease() RETURNS trigger AS $$
DECLARE
  wallet_row wallets%ROWTYPE;
  destination_row destinations%ROWTYPE;
BEGIN
  -- Lock the wallet row. An unlocked read on the path that exists to catch
  -- concurrent quarantine is not a backstop - quarantine mutates wallets.state.
  -- The wallets primary key is `id`.
  SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id FOR UPDATE;
  -- Origin conjunct holds at EVERY claim boundary: an imported-origin wallet
  -- never carries any lease role.
  IF wallet_row.key_origin IS DISTINCT FROM 'node_generated' THEN
    RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED';
  END IF;
  -- Acquisition rule 3 (role-agnostic for non-recovery signing): reject
  -- quarantined/retired wallets - allowlist-positive on {AVAILABLE, PINNED}.
  -- RECONCILIATION is the recovery-lane exemption: backup export and
  -- recovery ceremony must cover every wallet regardless of state. A state added to the
  -- enum without a matching allowlist update is denied by default (fail-closed).
  -- Hoisted above the role switch so RECEIVE_WINDOW / MOVE_SOURCE / SEND_SOURCE /
  -- MOVE_DESTINATION share one structural gate; sink-only conjuncts stay
  -- in the MOVE_DESTINATION branch below.
  IF NEW.lease_role IS DISTINCT FROM 'RECONCILIATION'
     AND wallet_row.state NOT IN ('AVAILABLE', 'PINNED') THEN
    RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED';
  END IF;
  -- Single terminal RETURN NEW below so every RAISE stays reachable (body-structure pins).
  IF NEW.lease_role = 'RECONCILIATION' THEN
    -- G0 EXEMPT: observation must never block on recovery standing.
    NULL;
  ELSIF NEW.lease_role = 'RECEIVE_WINDOW' THEN
    -- G1: recovery-verified + state=AVAILABLE at lease insert (pin follows insert).
    -- State allowlist above already denied QUARANTINED/RETIRED; AVAILABLE-only is stricter.
    IF wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    IF wallet_row.state IS DISTINCT FROM 'AVAILABLE' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED';
    END IF;
    -- Money capability (ZTR-1268): external receive assign/arm requires allow_external_receive.
    IF wallet_row.allow_external_receive IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECEIVE_CAPABILITY_REJECTED';
    END IF;
  ELSIF NEW.lease_role = 'MOVE_DESTINATION' THEN
    SELECT * INTO destination_row FROM destinations WHERE wallet_id = NEW.wallet_id FOR UPDATE;
    IF destination_row.state IS DISTINCT FROM 'BLESSED' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_DESTINATION_NOT_BLESSED';
    END IF;
    IF wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    -- Money capability (ZTR-1268): MOVE party requires allow_internal_move.
    IF wallet_row.allow_internal_move IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED';
    END IF;
    -- Acquisition rule 3 state allowlist already enforced above for every
    -- non-RECONCILIATION role (wallet_row.state NOT IN ('AVAILABLE', 'PINNED')).
  ELSIF NEW.lease_role = 'MOVE_SOURCE' THEN
    -- G3 origin + state allowlist above; money capability for internal move source.
    IF wallet_row.allow_internal_move IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED';
    END IF;
  ELSIF NEW.lease_role = 'SEND_SOURCE' THEN
    -- G3 origin + state allowlist above; money capability for external send source.
    IF wallet_row.allow_external_send IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_SEND_CAPABILITY_REJECTED';
    END IF;
  ELSE
    -- Unknown role fails closed so a wallet_lease_role member added (ALTER TYPE ADD VALUE)
    -- without a matching branch is DENIED. Unreachable for the closed five-value enum at
    -- CREATE time; load-bearing when the enum grows (04:1409).
    RAISE EXCEPTION 'CUSTODY_LEASE_ROLE_UNKNOWN';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
