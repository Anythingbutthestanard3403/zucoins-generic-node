-- Custody eligibility: wallets, destinations, recovery verifications, and the universal
-- one-active-lease projection, with the eligibility guard that fences lease acquisition.
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package runs it. Every invariant
-- below is inventoried in custody-eligibility.contract.ts and censused by
-- test/custody-eligibility.census.test.ts.
--
-- This file is deliberately PREREQUISITE-BOUND rather than a self-contained executable
-- excerpt. Self-containment would force `nodes` out (taking the tenant FKs with it), force
-- the reference domains out (collapsing `public_key` and `export_sha256` to bare `text` and
-- dropping the schema-level public_key CHECK the vault AAD injectivity proof rests on), and
-- force the primary keys to be renamed (`wallets.id` -> `wallet_id`, `destinations.id` ->
-- `destination_id`, `wallet_recovery_verifications.id` -> `recovery_verification_id`),
-- leaving every sibling contract's `REFERENCES wallets(id)` unresolvable at apply time.
--
-- The schema-apply phase applies, in sequence: base-enums-domains.sql (reference domains
-- and enums),
-- node-implementer-registry.sql (`nodes`), then this file. Applied alone against an empty
-- schema it fails on its first missing prerequisite, which is the documented and asserted
-- outcome (test/migration-integrity.test.ts), not a defect.

CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes (id),
  public_key padded_base64url_pubkey NOT NULL,
  key_origin wallet_key_origin NOT NULL,
  state wallet_state NOT NULL DEFAULT 'AVAILABLE',
  -- NO column default here, ever. The v1 grandfather pattern
  -- (a timestamp column added with DEFAULT now()) silently nulled the gate.
  recovery_verified_at timestamptz,
  recovery_verification_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  quarantine_reason text,
  UNIQUE (node_id, public_key),
  CONSTRAINT wallets_quarantine_reason_iff
    CHECK ((state = 'QUARANTINED') = (quarantine_reason IS NOT NULL)),
  CONSTRAINT wallets_retired_at_iff
    CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL)),
  -- Custody rule 5: both recovery fields are set together or not at all.
  CONSTRAINT wallets_recovery_fields_together
    CHECK ((recovery_verified_at IS NULL) = (recovery_verification_id IS NULL))
);

CREATE TABLE wallet_recovery_verifications (
  id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL REFERENCES wallets (id),
  method text NOT NULL CHECK (method IN ('AUDITED_EXPORT')),
  public_key padded_base64url_pubkey NOT NULL,
  export_sha256 sha256_hex NOT NULL,
  audit_event_id uuid NOT NULL,
  verified_at timestamptz NOT NULL,
  verifier_identity text NOT NULL,
  UNIQUE (wallet_id, export_sha256)
);

ALTER TABLE wallets
  ADD CONSTRAINT wallets_recovery_verification_fk
  FOREIGN KEY (recovery_verification_id)
  REFERENCES wallet_recovery_verifications (id);

CREATE TABLE destinations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes (id),
  wallet_id uuid NOT NULL UNIQUE REFERENCES wallets (id),
  -- Operator-facing display name (GN-025.2). Advisory and unsigned. The
  -- destinations-label pack slice also ALTERs this column onto already-applied DBs.
  label text NOT NULL DEFAULT '',
  state destination_state NOT NULL DEFAULT 'PENDING',
  blessed_at timestamptz,
  blessed_by_device_key_id uuid,
  blessing_artifact_id uuid,
  retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT destinations_blessed_iff
    CHECK ((state IN ('BLESSED', 'RETIRED')) = (blessed_at IS NOT NULL)),
  -- Custody rule 6: a destination is never blessed by TOTP alone; blessing binds an
  -- enrolled device key and the exact blessing artifact.
  CONSTRAINT destinations_blessing_requires_device_artifact
    CHECK ((blessed_at IS NULL) OR (blessed_by_device_key_id IS NOT NULL AND blessing_artifact_id IS NOT NULL)),
  CONSTRAINT destinations_retired_at_iff
    CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL))
);

-- At most one active lease per wallet, structurally (primary key).
-- lease_role is the real wallet_lease_role enum (base-enums-domains.sql); value set
-- is pinned to LEASE_ROLES by test/lease-role-parity.test.ts. The lease-role-enum
-- pack slice value-preserves text columns on already-applied DBs.
-- The lease-fencing columns and both UNIQUEs are required: without them lease liveness,
-- ownership and epoch fencing have no structural carrier.
CREATE TABLE wallet_active_leases (
  wallet_id uuid PRIMARY KEY REFERENCES wallets (id),
  membership_id uuid NOT NULL UNIQUE,
  lease_group_id uuid NOT NULL,
  root_operation_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_role wallet_lease_role NOT NULL,
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL,
  owner_instance_id uuid NOT NULL,
  release_not_before timestamptz,
  UNIQUE (operation_id, wallet_id),
  UNIQUE (lease_group_id, wallet_id)
);

-- Custody rule 1: wallets.key_origin, wallets.node_id, wallets.public_key are immutable.
-- Custody rule 5 (second half): recovery fields, once set, are never cleared or changed.
CREATE FUNCTION custody_reject_wallet_mutation() RETURNS trigger AS $$
BEGIN
  IF NEW.key_origin IS DISTINCT FROM OLD.key_origin
     OR NEW.node_id IS DISTINCT FROM OLD.node_id
     OR NEW.public_key IS DISTINCT FROM OLD.public_key THEN
    RAISE EXCEPTION 'CUSTODY_IMMUTABLE_FIELD_REJECTED';
  END IF;
  IF OLD.recovery_verified_at IS NOT NULL
     AND (NEW.recovery_verified_at IS DISTINCT FROM OLD.recovery_verified_at
          OR NEW.recovery_verification_id IS DISTINCT FROM OLD.recovery_verification_id) THEN
    RAISE EXCEPTION 'CUSTODY_RECOVERY_NEVER_CLEARED';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER wallets_custody_mutation_guard
  BEFORE UPDATE ON wallets
  FOR EACH ROW EXECUTE FUNCTION custody_reject_wallet_mutation();

-- Custody rule 2: a destinations insert is rejected unless the referenced
-- wallet has key_origin = 'node_generated'. Tenant isolation is structural at the same
-- boundary: the destination row's node_id must equal the wallet's node_id.
CREATE FUNCTION custody_reject_destination_insert() RETURNS trigger AS $$
DECLARE
  wallet_row wallets%ROWTYPE;
BEGIN
  SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id;
  IF wallet_row.key_origin IS DISTINCT FROM 'node_generated' THEN
    RAISE EXCEPTION 'CUSTODY_DESTINATION_ORIGIN_REJECTED';
  END IF;
  IF NEW.node_id IS DISTINCT FROM wallet_row.node_id THEN
    RAISE EXCEPTION 'CUSTODY_TENANT_MISMATCH_REJECTED';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER destinations_custody_insert_guard
  BEFORE INSERT ON destinations
  FOR EACH ROW EXECUTE FUNCTION custody_reject_destination_insert();

-- Structural mechanism plus the origin conjunct at the claim boundary: a BEFORE INSERT
-- trigger on wallet_active_leases, keyed by lease_role, re-checks eligibility at
-- lease/arm/assign time. No code path can acquire a lease for an ineligible wallet
-- regardless of which query reached it.
CREATE FUNCTION custody_reject_ineligible_lease() RETURNS trigger AS $$
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
  ELSIF NEW.lease_role = 'MOVE_DESTINATION' THEN
    SELECT * INTO destination_row FROM destinations WHERE wallet_id = NEW.wallet_id FOR UPDATE;
    IF destination_row.state IS DISTINCT FROM 'BLESSED' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_DESTINATION_NOT_BLESSED';
    END IF;
    IF wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    -- Acquisition rule 3 state allowlist already enforced above for every
    -- non-RECONCILIATION role (wallet_row.state NOT IN ('AVAILABLE', 'PINNED')).
  ELSIF NEW.lease_role IN ('MOVE_SOURCE', 'SEND_SOURCE') THEN
    -- G3: origin + acquisition rule 3 state allowlist (both enforced above).
    NULL;
  ELSE
    -- Unknown role fails closed so a wallet_lease_role member added (ALTER TYPE ADD VALUE)
    -- without a matching branch is DENIED. Unreachable for the closed five-value enum at
    -- CREATE time; load-bearing when the enum grows (04:1409).
    RAISE EXCEPTION 'CUSTODY_LEASE_ROLE_UNKNOWN';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER wallet_active_leases_eligibility_guard
  BEFORE INSERT ON wallet_active_leases
  FOR EACH ROW EXECUTE FUNCTION custody_reject_ineligible_lease();
