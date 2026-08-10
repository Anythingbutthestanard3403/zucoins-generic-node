-- ZTR-1139 fix-forward: lease ownership rows must reference durable operations.
--
-- custody-eligibility creates wallet_active_leases before operations and lease-foundation
-- exist, so its authoritative CREATE TABLE cannot express these circular/deferred FKs inline.
-- This append-only production-pack slice runs after all targets exist. It checks every
-- existing row before adding ANY constraint: a dangling row is a stuck-wallet incident that
-- requires operator disposition, never an automatic delete or cascade.

DO $lease_operation_foreign_keys$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM wallet_active_leases l
      LEFT JOIN operations o ON o.id = l.operation_id
     WHERE o.id IS NULL
  ) OR EXISTS (
    SELECT 1
      FROM wallet_active_leases l
      LEFT JOIN operations o ON o.id = l.root_operation_id
     WHERE o.id IS NULL
  ) OR EXISTS (
    SELECT 1
      FROM lease_groups g
      LEFT JOIN operations o ON o.id = g.root_operation_id
     WHERE o.id IS NULL
  ) OR EXISTS (
    SELECT 1
      FROM lease_group_operations g
      LEFT JOIN operations o ON o.id = g.operation_id
     WHERE o.id IS NULL
  ) OR EXISTS (
    SELECT 1
      FROM wallet_active_leases l
      LEFT JOIN wallet_lease_memberships m ON m.id = l.membership_id
     WHERE m.id IS NULL
  ) OR EXISTS (
    SELECT 1
      FROM wallet_active_leases l
      LEFT JOIN lease_groups g ON g.id = l.lease_group_id
     WHERE g.id IS NULL
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '23503',
      MESSAGE = 'lease foreign-key upgrade refused: dangling lease ownership rows require operator disposition';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'wallet_active_leases'::regclass
       AND conname = 'wallet_active_leases_membership_id_fkey'
  ) THEN
    ALTER TABLE wallet_active_leases
      ADD CONSTRAINT wallet_active_leases_membership_id_fkey
      FOREIGN KEY (membership_id) REFERENCES wallet_lease_memberships (id)
      ON DELETE NO ACTION;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'wallet_active_leases'::regclass
       AND conname = 'wallet_active_leases_lease_group_id_fkey'
  ) THEN
    ALTER TABLE wallet_active_leases
      ADD CONSTRAINT wallet_active_leases_lease_group_id_fkey
      FOREIGN KEY (lease_group_id) REFERENCES lease_groups (id)
      ON DELETE NO ACTION;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'wallet_active_leases'::regclass
       AND conname = 'wallet_active_leases_root_operation_id_fkey'
  ) THEN
    ALTER TABLE wallet_active_leases
      ADD CONSTRAINT wallet_active_leases_root_operation_id_fkey
      FOREIGN KEY (root_operation_id) REFERENCES operations (id)
      ON DELETE NO ACTION;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'wallet_active_leases'::regclass
       AND conname = 'wallet_active_leases_operation_id_fkey'
  ) THEN
    ALTER TABLE wallet_active_leases
      ADD CONSTRAINT wallet_active_leases_operation_id_fkey
      FOREIGN KEY (operation_id) REFERENCES operations (id)
      ON DELETE NO ACTION;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'lease_groups'::regclass
       AND conname = 'lease_groups_root_operation_id_fkey'
  ) THEN
    ALTER TABLE lease_groups
      ADD CONSTRAINT lease_groups_root_operation_id_fkey
      FOREIGN KEY (root_operation_id) REFERENCES operations (id)
      ON DELETE NO ACTION;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'lease_group_operations'::regclass
       AND conname = 'lease_group_operations_operation_id_fkey'
  ) THEN
    ALTER TABLE lease_group_operations
      ADD CONSTRAINT lease_group_operations_operation_id_fkey
      FOREIGN KEY (operation_id) REFERENCES operations (id)
      ON DELETE NO ACTION;
  END IF;
END
$lease_operation_foreign_keys$;
