-- lease_role → wallet_lease_role enum (CONVENTIONS.md §6 closed enumerations).
--
-- wallet_lease_role already exists in base-enums-domains.sql. Early pack slices
-- (custody-eligibility, lease-foundation) historically stored lease_role as
-- text + CHECK with the same five values. This appended slice value-preserves
-- both live columns onto the real enum so already-applied databases converge
-- without renumbering prior pack versions.
--
-- CUSTODY_LEASE_ROLE_UNKNOWN in custody_reject_ineligible_lease stays load-bearing:
-- ALTER TYPE ... ADD VALUE can admit a new member without a matching trigger
-- branch; the ELSE fail-closed path is what denies it (04:1409).
--
-- Pack position: after lease-foundation (both columns exist). Appended only.

DO $lease_role_enum$
BEGIN
  -- wallet_active_leases.lease_role
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'wallet_active_leases'
       AND column_name = 'lease_role'
       AND udt_name = 'text'
  ) THEN
    ALTER TABLE wallet_active_leases
      ALTER COLUMN lease_role TYPE wallet_lease_role
      USING lease_role::wallet_lease_role;
  END IF;

  -- wallet_lease_memberships.lease_role
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'wallet_lease_memberships'
       AND column_name = 'lease_role'
       AND udt_name = 'text'
  ) THEN
    ALTER TABLE wallet_lease_memberships
      ALTER COLUMN lease_role TYPE wallet_lease_role
      USING lease_role::wallet_lease_role;
  END IF;
END
$lease_role_enum$;
