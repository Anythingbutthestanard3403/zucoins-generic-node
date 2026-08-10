/**
 * Custody eligibility: wallets, destinations, recovery verifications, and the universal
 * one-active-lease projection.
 *
 * Frozen inventory of the structural custody-eligibility invariants carried by
 * custody-eligibility.sql. The census test binds every entry here to the
 * literal SQL text, so the inventory and the schema contract cannot drift apart.
 * Execution against a live database belongs to the schema-apply phase, recorded below
 * as obligations rather than silently omitted.
 */

export const CUSTODY_SCHEMA_FILE = "custody-eligibility.sql" as const;

export interface CustodySchemaInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const CUSTODY_SCHEMA_INVARIANTS: readonly CustodySchemaInvariant[] = [
  {
    id: "NO_RECOVERY_DEFAULT",
    sqlAnchor: "recovery_verified_at timestamptz,",
    rule: "recovery_verified_at carries NO column default; the v1 grandfather pattern (DEFAULT now()) is forbidden on a gate timestamp.",
  },
  {
    id: "QUARANTINE_REASON_IFF",
    sqlAnchor: "wallets_quarantine_reason_iff",
    rule: "(state = 'QUARANTINED') = (quarantine_reason IS NOT NULL).",
  },
  {
    id: "RETIRED_AT_IFF",
    sqlAnchor: "wallets_retired_at_iff",
    rule: "(state = 'RETIRED') = (retired_at IS NOT NULL) on wallets.",
  },
  {
    id: "RECOVERY_FIELDS_TOGETHER",
    sqlAnchor: "wallets_recovery_fields_together",
    rule: "recovery_verified_at and recovery_verification_id are set together or not at all.",
  },
  {
    id: "RECOVERY_METHOD_AUDITED_EXPORT",
    sqlAnchor: "CHECK (method IN ('AUDITED_EXPORT'))",
    rule: "recovery verification rows exist only for audited exports, unique per wallet/export digest.",
  },
  {
    id: "DESTINATION_LABEL",
    sqlAnchor: "label text NOT NULL DEFAULT ''",
    rule: "destinations.label is the operator-facing display name (GN-025.2); advisory and unsigned.",
  },
  {
    id: "BLESSED_IFF_AT",
    sqlAnchor: "destinations_blessed_iff",
    rule: "(state IN ('BLESSED','RETIRED')) = (blessed_at IS NOT NULL) on destinations.",
  },
  {
    id: "BLESS_REQUIRES_DEVICE_AND_ARTIFACT",
    sqlAnchor: "destinations_blessing_requires_device_artifact",
    rule: "blessing binds an enrolled device key and the blessing artifact; never TOTP alone.",
  },
  {
    id: "DESTINATION_RETIRED_AT_IFF",
    sqlAnchor: "destinations_retired_at_iff",
    rule: "(state = 'RETIRED') = (retired_at IS NOT NULL) on destinations.",
  },
  {
    id: "IMMUTABLE_WALLET_FIELDS",
    sqlAnchor: "CUSTODY_IMMUTABLE_FIELD_REJECTED",
    rule: "wallets.key_origin, wallets.node_id, wallets.public_key are immutable (BEFORE UPDATE guard).",
  },
  {
    id: "RECOVERY_NEVER_CLEARED",
    sqlAnchor: "CUSTODY_RECOVERY_NEVER_CLEARED",
    rule: "once set, recovery fields are never cleared or changed (monotonic).",
  },
  {
    id: "DESTINATION_ORIGIN_REJECT",
    sqlAnchor: "CUSTODY_DESTINATION_ORIGIN_REJECTED",
    rule: "a destinations insert referencing a wallet whose key_origin is not node_generated is rejected before it exists.",
  },
  {
    id: "TENANT_MATCH_AT_DESTINATION_INSERT",
    sqlAnchor: "CUSTODY_TENANT_MISMATCH_REJECTED",
    rule: "the destination row's node_id must equal the referenced wallet's node_id — cross-tenant destination rows are structurally impossible.",
  },
  {
    id: "ONE_ACTIVE_LEASE_PER_WALLET",
    sqlAnchor: "wallet_id uuid PRIMARY KEY REFERENCES wallets (id)",
    rule: "wallet_active_leases is keyed by wallet_id: at most one active lease per wallet, structurally.",
  },
  {
    id: "LEASE_ROLE_IS_ENUM",
    sqlAnchor: "lease_role wallet_lease_role NOT NULL",
    rule: "lease_role is the real wallet_lease_role Postgres ENUM (not text + CHECK).",
  },
  {
    id: "LEASE_ORIGIN_CONJUNCT_AT_CLAIM",
    sqlAnchor: "CUSTODY_LEASE_ORIGIN_REJECTED",
    rule: "every lease acquisition re-checks key_origin = node_generated at the claim boundary.",
  },
  {
    id: "SINK_LEASE_FULL_PREDICATE",
    sqlAnchor: "CUSTODY_LEASE_DESTINATION_NOT_BLESSED",
    rule: "a MOVE_DESTINATION lease additionally requires BLESSED destination and recovery verified — the sink conjuncts beyond the role-agnostic state allowlist, re-checked structurally at lease time.",
  },
  {
    id: "NON_RECOVERY_LEASE_STATE_ALLOWLIST",
    sqlAnchor: "CUSTODY_LEASE_WALLET_STATE_REJECTED",
    rule: "Acquisition rule 3: every non-RECONCILIATION lease role requires wallet state in the positive allowlist {AVAILABLE, PINNED}. RECONCILIATION is the recovery-path exemption.",
  },
  {
    id: "ELIGIBILITY_WALLET_FOR_UPDATE",
    sqlAnchor: "SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id FOR UPDATE",
    rule: "The eligibility trigger locks the wallet row FOR UPDATE — an unlocked read cannot catch concurrent quarantine.",
  },
  {
    id: "RECEIVE_WINDOW_BRANCH",
    sqlAnchor: "IF NEW.lease_role = 'RECEIVE_WINDOW' THEN",
    rule: "RECEIVE_WINDOW (G1): recovery_verified_at IS NOT NULL and state='AVAILABLE' at lease insert.",
  },
  {
    id: "RECONCILIATION_EXEMPT",
    sqlAnchor: "IF NEW.lease_role = 'RECONCILIATION' THEN",
    rule: "RECONCILIATION (G0) is exempt — observation must never block on recovery standing.",
  },
  {
    id: "UNKNOWN_ROLE_FAIL_CLOSED",
    sqlAnchor: "CUSTODY_LEASE_ROLE_UNKNOWN",
    rule: "Unknown lease_role fails closed rather than being silently admitted.",
  },
] as const;

/**
 * Live-database proofs this package cannot run (no database harness lands in this package). The schema-apply phase MUST discharge each of these against a
 * real Postgres before the schema contract is considered enforced.
 */
export const SCHEMA_EXECUTION_OBLIGATIONS = [
  "information_schema introspection: wallets.recovery_verified_at has column_default IS NULL.",
  "trigger existence: wallet_active_leases_eligibility_guard exists, BEFORE INSERT, keyed by lease_role.",
  "negative: destinations insert for an imported-origin wallet raises CUSTODY_DESTINATION_ORIGIN_REJECTED.",
  "negative: blessed but recovery-unverified wallet is excluded from every automatic-sink query and its MOVE_DESTINATION lease raises CUSTODY_LEASE_RECOVERY_UNVERIFIED.",
  "negative: clearing a previously-set recovery_verified_at raises CUSTODY_RECOVERY_NEVER_CLEARED.",
  "negative: cross-tenant destinations insert raises CUSTODY_TENANT_MISMATCH_REJECTED.",
  "negative: the two breaking inputs at the claim boundary raise CUSTODY_LEASE_ORIGIN_REJECTED.",
  "negative: a non-RECONCILIATION lease (RECEIVE_WINDOW / MOVE_SOURCE / SEND_SOURCE / MOVE_DESTINATION) for a QUARANTINED or RETIRED wallet raises CUSTODY_LEASE_WALLET_STATE_REJECTED; RECONCILIATION remains the recovery-lane exemption.",
  "negative: a duplicate ACTIVE wallet_active_leases insert for the same wallet_id is rejected by the DB with unique_violation (23505) — the ONE_ACTIVE_LEASE_PER_WALLET wallet_id PRIMARY KEY, proven by a real-PG integration test.",
  "negative: a RECEIVE_WINDOW lease for a QUARANTINED or recovery-unverified wallet raises CUSTODY_LEASE_WALLET_STATE_REJECTED / CUSTODY_LEASE_RECOVERY_UNVERIFIED under FOR UPDATE.",
  "concurrency: quarantine-vs-lease-insert race serializes on the wallet-row FOR UPDATE taken by custody_reject_ineligible_lease.",
] as const;

export const CUSTODY_SCHEMA_SOURCE =
  "data-model: wallets, destinations, custody eligibility, and the one-active-lease projection" as const;
