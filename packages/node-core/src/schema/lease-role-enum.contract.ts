/**
 * lease_role columns → wallet_lease_role enum (migration-pack ownership).
 */

export const LEASE_ROLE_ENUM_SCHEMA_FILE = "lease-role-enum.sql" as const;

export interface LeaseRoleEnumInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const LEASE_ROLE_ENUM_INVARIANTS: readonly LeaseRoleEnumInvariant[] = [
  {
    id: "ACTIVE_LEASE_ROLE_ENUM",
    sqlAnchor: "ALTER COLUMN lease_role TYPE wallet_lease_role",
    rule:
      "wallet_active_leases.lease_role and wallet_lease_memberships.lease_role become the real wallet_lease_role enum (value-preserving USING cast) when still text.",
  },
  {
    id: "TEXT_ONLY_GUARD",
    sqlAnchor: "AND udt_name = 'text'",
    rule:
      "Conversion is gated on udt_name = text so cold applies that already created the enum column are no-ops (idempotent).",
  },
] as const;

export const LEASE_ROLE_ENUM_EXECUTION_OBLIGATIONS: readonly string[] = [
  "lease-role-enum.sql applies after custody-eligibility.sql and lease-foundation.sql so both lease_role columns exist.",
  "Idempotent: skips columns already typed as wallet_lease_role (cold apply after CREATE already uses the enum, or re-run).",
  "CUSTODY_LEASE_ROLE_UNKNOWN remains load-bearing in custody_reject_ineligible_lease for ALTER TYPE ADD VALUE without a trigger branch (04:1409).",
] as const;

export const LEASE_ROLE_ENUM_SOURCE =
  "data-model: wallet_lease_role; CONVENTIONS.md §6; ZTR-1169" as const;
