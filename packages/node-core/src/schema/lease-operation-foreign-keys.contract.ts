/**
 * Deferred lease-ownership foreign keys for the append-only production money pack.
 */

export const LEASE_OPERATION_FOREIGN_KEYS_SCHEMA_FILE =
  "lease-operation-foreign-keys.sql" as const;

export interface LeaseOperationForeignKeyInvariant {
  readonly id: string;
  readonly rule: string;
}

export const LEASE_OPERATION_FOREIGN_KEY_INVARIANTS: readonly LeaseOperationForeignKeyInvariant[] =
  [
    {
      id: "ALL_OWNERS_EXIST",
      rule: "The upgrade audits every lease ownership edge before adding any constraint and refuses dangling rows with SQLSTATE 23503.",
    },
    {
      id: "ATOMIC_FIX_FORWARD",
      rule: "All six deferred constraints are installed only after the complete preflight succeeds.",
    },
    {
      id: "NO_ACTION_RELEASE",
      rule: "Every deferred foreign key uses ON DELETE NO ACTION; deleting an operation can never release a wallet lease.",
    },
  ] as const;

export const LEASE_OPERATION_FOREIGN_KEY_EXECUTION_OBLIGATIONS: readonly string[] = [
  "Apply after operations, wallet_lease_memberships, lease_groups, lease_group_operations, and wallet_active_leases exist.",
  "Treat any dangling row as an operator-disposition incident; never repair it by deletion or fabrication.",
  "Keep the slice append-only so databases that journaled the earlier lease schema receive the constraints.",
] as const;

export const LEASE_OPERATION_FOREIGN_KEYS_SOURCE =
  "Doc 04 §6; ZTR-1139" as const;
