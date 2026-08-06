-- Lease foundation: lease groups, memberships, group operations, the exclusive
-- wallet_active_leases projection, and the lease forensic trail. The one-in-flight-per-wallet and key-custody rules.
-- Frozen schema contract. This file is the TARGET lease-foundation DDL: executed
-- by the lease migrator / schema-apply phase against a live database; nothing in this package
-- runs it blindly. Every invariant is inventoried in lease-foundation.contract.ts and
-- censused by test/lease-foundation.census.test.ts.
--
-- Scope: the universal wallet-level active-operation lease projection, permanent lease
-- groups / memberships / group-operations, typed terminal-positive release
-- proofs, monotonic epoch high-water, and a schema-version fence. The three-column legacy
-- wallet_active_leases projection that ships in custody-eligibility.sql cannot be truthfully
-- backfilled; the migrator expands only an EMPTY legacy table and refuses a populated one
-- until verified evacuation / quarantine (never fabricated defaults, never silent DELETE).
--
-- RECONCILIATION never occupies this exclusive table: acquisition
-- rejects it at the service boundary; the role remains in the CHECK so the G0 branch
-- stays expressible for any future observation-only surface that does NOT write here.
--
-- Operations FKs are bare uuid (operations.sql is not yet on main) -- same deferred-FK pattern
-- as the closed lease bundle. wallets(id) is the live custody key; the
-- lease row's own column remains wallet_id and joins wallets.id.

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE TABLE lease_groups (
  id uuid PRIMARY KEY,
  root_operation_id uuid NOT NULL UNIQUE,
  created_at timestamptz NOT NULL,
  -- Durable child disposition closes the pre-formation unpin window.
  -- NONE  = HOLD / no automatic child (releasable when joined ops are terminal).
  -- PENDING = automatic child expected but not yet joined (release must refuse).
  -- JOINED = child op row exists in lease_group_operations.
  child_disposition text NOT NULL DEFAULT 'NONE',
  released_at timestamptz,
  release_proof_id uuid,
  CONSTRAINT lease_groups_child_disposition_check
    CHECK (child_disposition IN ('NONE', 'PENDING', 'JOINED')),
  CONSTRAINT lease_groups_released_check
    CHECK ((released_at IS NULL) = (release_proof_id IS NULL))
);

-- Additive for foundations applied before child_disposition existed (idempotent).
ALTER TABLE lease_groups
  ADD COLUMN IF NOT EXISTS child_disposition text NOT NULL DEFAULT 'NONE';

DO $lease_child_disp$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'lease_groups_child_disposition_check'
  ) THEN
    ALTER TABLE lease_groups
      ADD CONSTRAINT lease_groups_child_disposition_check
      CHECK (child_disposition IN ('NONE', 'PENDING', 'JOINED'));
  END IF;
END
$lease_child_disp$;

CREATE TABLE lease_group_operations (
  lease_group_id uuid NOT NULL REFERENCES lease_groups (id),
  operation_id uuid NOT NULL UNIQUE,
  joined_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (lease_group_id, operation_id),
  CONSTRAINT lease_group_operations_completed_at_check
    CHECK (completed_at IS NULL OR completed_at >= joined_at)
);

CREATE TABLE wallet_lease_memberships (
  id uuid PRIMARY KEY,
  lease_group_id uuid NOT NULL REFERENCES lease_groups (id),
  wallet_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_role text NOT NULL
    CHECK (lease_role IN (
      'RECEIVE_WINDOW',
      'MOVE_SOURCE',
      'MOVE_DESTINATION',
      'SEND_SOURCE',
      'RECONCILIATION'
    )),
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL,
  released_at timestamptz,
  release_reason text,
  release_proof_id uuid,
  UNIQUE (lease_group_id, wallet_id, operation_id, lease_epoch),
  CONSTRAINT wallet_lease_memberships_release_check
    CHECK (
      (released_at IS NULL AND release_reason IS NULL AND release_proof_id IS NULL)
      OR
      (released_at IS NOT NULL AND release_reason IS NOT NULL AND release_proof_id IS NOT NULL)
    )
);

-- Monotonic never-reset epoch high-water per wallet. Survives active-row DELETE and process
-- restart so a successor lease always gets a strictly greater epoch (ABA safety).
CREATE TABLE wallet_lease_epoch_highwater (
  wallet_id uuid PRIMARY KEY,
  highwater bigint NOT NULL CHECK (highwater > 0)
);

-- Trusted-verifier-created, immutable, operation-specific terminal-positive release proofs.
-- Standalone owner IDs, random UUIDs, digests, or caller-supplied bearer tokens are NOT
-- release authority: only a row minted with issuer = 'TRUSTED_VERIFIER' that still has
-- consumed_at IS NULL can authorize a matching exact-tuple release.
CREATE TABLE lease_release_proofs (
  proof_id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  membership_id uuid NOT NULL,
  lease_group_id uuid NOT NULL,
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  proof_kind text NOT NULL
    CHECK (proof_kind IN (
      'RECEIVE_LANDED',
      'INTERNAL_MOVE_LANDED',
      'EXTERNAL_SEND_LANDED',
      'RECEIVE_EXPIRED_T0',
      'OPERATOR_QUARANTINE_RELEASE'
    )),
  proof_digest sha256_hex NOT NULL,
  issuer text NOT NULL CHECK (issuer = 'TRUSTED_VERIFIER'),
  created_at timestamptz NOT NULL,
  consumed_at timestamptz
);

CREATE UNIQUE INDEX lease_release_proofs_unconsumed_tuple_uidx
  ON lease_release_proofs (
    wallet_id,
    operation_id,
    membership_id,
    lease_group_id,
    lease_epoch
  )
  WHERE consumed_at IS NULL;

-- Append-only lease forensic trail (an audit-log-shaped subset; does not require nodes/operations
-- tables so the foundation slice stays loadable without the full audit_log assembly).
CREATE TABLE lease_audit_events (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL UNIQUE,
  action text NOT NULL
    CHECK (action IN (
      'LEASE_ACQUIRED',
      'LEASE_RELEASED',
      'LEASE_TRANSFERRED',
      'LEASE_HEARTBEAT',
      'LEASE_SIGN_CLAIM',
      'LEASE_PROOF_CONSUMED',
      'LEASE_MIGRATE_EXPAND',
      'LEASE_MIGRATE_REFUSED'
    )),
  wallet_id uuid,
  operation_id uuid,
  membership_id uuid,
  lease_group_id uuid,
  lease_epoch bigint,
  owner_instance_id uuid,
  details_text text NOT NULL,
  details_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE lease_schema_fence (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  schema_version integer NOT NULL CHECK (schema_version > 0),
  applied_at timestamptz NOT NULL
);

-- Full exclusive projection. wallet_id is the structural one-active-row authority.
CREATE TABLE wallet_active_leases (
  wallet_id uuid PRIMARY KEY,
  membership_id uuid NOT NULL UNIQUE
    REFERENCES wallet_lease_memberships (id),
  lease_group_id uuid NOT NULL
    REFERENCES lease_groups (id),
  root_operation_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_role text NOT NULL
    CHECK (lease_role IN (
      'RECEIVE_WINDOW',
      'MOVE_SOURCE',
      'MOVE_DESTINATION',
      'SEND_SOURCE',
      'RECONCILIATION'
    )),
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL,
  owner_instance_id uuid NOT NULL,
  release_not_before timestamptz,
  UNIQUE (operation_id, wallet_id),
  UNIQUE (lease_group_id, wallet_id)
);

CREATE INDEX wallet_active_leases_operation_idx
  ON wallet_active_leases (operation_id);

-- Structural receive-gate (disposition branches). Requires wallets/destinations
-- relations at INSERT time (custody-eligibility.sql supplies them in assembled schemas).
CREATE FUNCTION lease_foundation_reject_ineligible_lease() RETURNS trigger AS $$
DECLARE
  wallet_row wallets%ROWTYPE;
  destination_row destinations%ROWTYPE;
BEGIN
  -- Lock the wallet row. An unlocked read on the path that exists to catch
  -- concurrent quarantine is not a backstop - quarantine mutates wallets.state.
  -- The wallets primary key is `id`.
  SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id FOR UPDATE;

  IF wallet_row.key_origin IS DISTINCT FROM 'node_generated' THEN
    RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED';
  END IF;

  IF NEW.lease_role = 'RECONCILIATION' THEN
    RETURN NEW;
  END IF;

  IF NEW.lease_role = 'RECEIVE_WINDOW' THEN
    IF wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    IF wallet_row.state IS DISTINCT FROM 'AVAILABLE' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.lease_role = 'MOVE_DESTINATION' THEN
    SELECT * INTO destination_row FROM destinations WHERE wallet_id = NEW.wallet_id FOR UPDATE;
    IF destination_row.state IS DISTINCT FROM 'BLESSED' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_DESTINATION_NOT_BLESSED';
    END IF;
    IF wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    IF wallet_row.state NOT IN ('AVAILABLE', 'PINNED') THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.lease_role IN ('MOVE_SOURCE', 'SEND_SOURCE') THEN
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'CUSTODY_LEASE_ROLE_UNKNOWN';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER wallet_active_leases_eligibility_guard
  BEFORE INSERT ON wallet_active_leases
  FOR EACH ROW EXECUTE FUNCTION lease_foundation_reject_ineligible_lease();
