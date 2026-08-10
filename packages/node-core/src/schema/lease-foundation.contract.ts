/**
 * Lease foundation: lease groups, memberships, group operations, the exclusive
 * wallet_active_leases projection, and the lease forensic trail. The one-in-flight-per-wallet and key-custody rules.
 *
 * Frozen inventory of the persisted lease foundation. The census binds every
 * entry here to the literal SQL text so the inventory and the schema contract cannot drift.
 * Live-database execution is discharged by test/lease-foundation.pg.test.ts and by the
 * fail-closed migrator in src/leases/migrate.ts. Eligibility trigger ownership is
 * custody-eligibility.sql (ZTR-1169 removed the shadowed lease-foundation copy).
 */

export const LEASE_FOUNDATION_SCHEMA_FILE = "lease-foundation.sql" as const;

export const LEASE_FOUNDATION_SCHEMA_SOURCE =
  "data-model: universal wallet lease, lease groups, and the lease audit trail" as const;

/** Required schema_version written into lease_schema_fence by a successful migrate. */
export const LEASE_FOUNDATION_SCHEMA_VERSION = 2 as const;

export interface LeaseFoundationInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const LEASE_FOUNDATION_INVARIANTS: readonly LeaseFoundationInvariant[] = [
  {
    id: "ONE_ACTIVE_ROW_PER_WALLET",
    sqlAnchor: "wallet_id uuid PRIMARY KEY,",
    rule: "wallet_active_leases is keyed by wallet_id: at most one active lease per wallet (the one-in-flight-per-wallet rule).",
  },
  {
    id: "ACTIVE_BINDS_MEMBERSHIP_GROUP_OPS_EPOCH_OWNER",
    sqlAnchor: "membership_id uuid NOT NULL UNIQUE",
    rule: "Active rows bind membership, group, root/current operation, role, epoch, heartbeat, and owner instance.",
  },
  {
    id: "EPOCH_STRICTLY_POSITIVE",
    sqlAnchor: "lease_epoch bigint NOT NULL CHECK (lease_epoch > 0)",
    rule: "lease_epoch is strictly positive and never zero.",
  },
  {
    id: "LEASE_GROUPS_RELEASE_COUPLED",
    sqlAnchor: "CONSTRAINT lease_groups_released_check",
    rule: "lease_groups released_at and release_proof_id are set together or not at all.",
  },
  {
    id: "LEASE_GROUPS_CHILD_DISPOSITION",
    sqlAnchor: "CONSTRAINT lease_groups_child_disposition_check",
    rule: "lease_groups.child_disposition is NONE | PENDING | JOINED so release can refuse the pre-formation window.",
  },
  {
    id: "MEMBERSHIP_RELEASE_COUPLED",
    sqlAnchor: "CONSTRAINT wallet_lease_memberships_release_check",
    rule: "Membership release fields are all-null or all-set — no partial close.",
  },
  {
    id: "MEMBERSHIP_EPOCH_UNIQUE",
    sqlAnchor: "UNIQUE (lease_group_id, wallet_id, operation_id, lease_epoch)",
    rule: "A (group, wallet, operation, epoch) membership tuple is unique and permanent.",
  },
  {
    id: "EPOCH_HIGHWATER_PERSISTS",
    sqlAnchor: "CREATE TABLE wallet_lease_epoch_highwater (",
    rule: "Epoch high-water persists across active-row DELETE and restart (ABA safety).",
  },
  {
    id: "PROOF_TRUSTED_ISSUER_ONLY",
    sqlAnchor: "issuer text NOT NULL CHECK (issuer = 'TRUSTED_VERIFIER')",
    rule: "Only trusted-verifier-minted proofs are release authority; bearer tokens cannot forge rows.",
  },
  {
    id: "PROOF_TERMINAL_POSITIVE_KINDS",
    sqlAnchor: "'RECEIVE_LANDED'",
    rule: "Release proofs are operation-specific terminal-positive kinds only.",
  },
  {
    id: "SCHEMA_VERSION_FENCE",
    sqlAnchor: "CREATE TABLE lease_schema_fence (",
    rule: "Schema-version fence fails closed when the required version is absent.",
  },
  {
    id: "NO_SHADOWED_ELIGIBILITY_TRIGGER",
    sqlAnchor: "no shadowed second copy here (ZTR-1169)",
    rule: "Eligibility trigger is owned solely by custody-eligibility.sql; this slice must not re-declare wallet_active_leases_eligibility_guard or a second reject function.",
  },
  {
    id: "ACTIVE_OPERATION_INDEX",
    sqlAnchor: "CREATE INDEX wallet_active_leases_operation_idx",
    rule: "Active leases are indexed by operation_id for operation-scoped lookup.",
  },
  {
    id: "LEASE_ROLE_IS_ENUM",
    sqlAnchor: "lease_role wallet_lease_role NOT NULL",
    rule: "Membership and active-lease roles use the real wallet_lease_role enum, not text+CHECK.",
  },
] as const;

export const LEASE_FOUNDATION_TABLES = [
  "lease_groups",
  "lease_group_operations",
  "wallet_lease_memberships",
  "wallet_lease_epoch_highwater",
  "lease_release_proofs",
  "lease_audit_events",
  "lease_schema_fence",
  "wallet_active_leases",
] as const;

export const LEASE_FOUNDATION_MUTABILITY_REGIMES = [
  "wallet_active_leases: current exclusivity projection; DELETE only via guarded release",
  "wallet_lease_memberships: permanent; one-way release fields only",
  "lease_groups / lease_group_operations: permanent; one-way completion/release fields only",
  "wallet_lease_epoch_highwater: monotonic high-water only (never decreases)",
  "lease_release_proofs: insert then one-way consume (consumed_at)",
  "lease_audit_events: append-only",
  "lease_schema_fence: singleton version row",
] as const;

export const SCHEMA_LEASE_FOUNDATION_OBLIGATIONS: readonly string[] = [
  "Apply lease-foundation.sql only through the fail-closed migrator (src/leases/migrate.ts) or an equivalent schema-apply assembly that preserves the empty-legacy-only expand rule.",
  "Populated three-column legacy wallet_active_leases rows require verified evacuation/quarantine before foundation apply — never fabricate membership/epoch defaults and never silent-DELETE live exclusivity rows.",
  "Acquisition sorts wallet UUID bytes ascending and writes memberships + active rows + pins + high-water in one SERIALIZABLE transaction; any conflict rolls the whole batch back.",
  "RECONCILIATION must never be inserted into wallet_active_leases by the acquisition service (the one-in-flight-per-wallet rule).",
  "Release locks the lease group, all group operations, open memberships, and active rows FOR UPDATE first; refuses membership close, proof consume, active-row DELETE, or unpin while child_disposition is PENDING (pre-formation) or any lease_group_operations.completed_at is null (the hold is continuous through child formation and terminal ops); then requires owner_instance_id + exact (wallet, operation, membership, group, epoch) + an unconsumed TRUSTED_VERIFIER proof, closes membership, consumes proof, audits, un-pins, DELETEs the active row, and stamps lease_groups.released_at only when no open memberships remain; exact-tuple DELETE must affect one row. HOLD/no-child groups create with child_disposition=NONE so root-terminal release remains valid.",
  "Foreign, stale, or replayed proofs mutate nothing (zero row counts on membership/active/proof).",
  "Epoch high-water survives DELETE and restart; a stale capability cannot release or sign under a successor lease (ABA).",
  "Signer validation takes the active lease row lock (or durable sign-claim) before any private-key use; private keys remain outside the hosted platform (the key-custody rule).",
  "Boot refuses money-path work when lease_schema_fence.schema_version < LEASE_FOUNDATION_SCHEMA_VERSION.",
  "Direct SQL that attempts to DELETE wallet_active_leases outside the guarded service is rejected by process discipline and covered by real-PG reconciliation tests.",
] as const;
