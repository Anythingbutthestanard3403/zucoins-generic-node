/**
 * Wallet money-capability lease eligibility overlay (ZTR-1268).
 *
 * Frozen inventory of the structural invariants carried by
 * wallet-money-capability-lease-guard.sql. Replaces the body of
 * custody_reject_ineligible_lease after wallet-money-capability columns exist.
 */

export const WALLET_MONEY_CAPABILITY_LEASE_GUARD_SCHEMA_FILE =
  "wallet-money-capability-lease-guard.sql" as const;

export interface WalletMoneyCapabilityLeaseGuardInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const WALLET_MONEY_CAPABILITY_LEASE_GUARD_INVARIANTS: readonly WalletMoneyCapabilityLeaseGuardInvariant[] =
  [
    {
      id: "REPLACE_ELIGIBILITY_FUNCTION",
      sqlAnchor:
        "CREATE OR REPLACE FUNCTION custody_reject_ineligible_lease() RETURNS trigger AS $$",
      rule: "Overlay replaces the custody eligibility function body; custody-eligibility.sql remains frozen for pack sql_sha256.",
    },
    {
      id: "RECEIVE_WINDOW_CAPABILITY",
      sqlAnchor: "CUSTODY_LEASE_RECEIVE_CAPABILITY_REJECTED",
      rule: "RECEIVE_WINDOW lease requires allow_external_receive IS TRUE (in-TX under wallet FOR UPDATE).",
    },
    {
      id: "SEND_SOURCE_CAPABILITY",
      sqlAnchor: "CUSTODY_LEASE_SEND_CAPABILITY_REJECTED",
      rule: "SEND_SOURCE lease requires allow_external_send IS TRUE.",
    },
    {
      id: "MOVE_PARTY_CAPABILITY",
      sqlAnchor: "CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED",
      rule: "MOVE_SOURCE and MOVE_DESTINATION leases require allow_internal_move IS TRUE.",
    },
    {
      id: "RECONCILIATION_STILL_EXEMPT",
      sqlAnchor: "IF NEW.lease_role = 'RECONCILIATION' THEN",
      rule: "RECONCILIATION remains exempt from money-capability checks (recovery lane).",
    },
    {
      id: "WALLET_FOR_UPDATE_RETAINED",
      sqlAnchor: "SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id FOR UPDATE",
      rule: "Capability recheck runs under the same wallet-row FOR UPDATE as origin/state gates (no TOCTOU).",
    },
  ] as const;

export const WALLET_MONEY_CAPABILITY_LEASE_GUARD_PACK_NOTES = [
  "wallet-money-capability-lease-guard.sql applies after wallet-money-capability.sql (allow_* columns must exist).",
  "Does not CREATE TABLE; pure function body replace of custody_reject_ineligible_lease.",
  "Exception codes are role-scoped capability rejects distinct from origin/state/recovery rejects.",
] as const;

export const WALLET_MONEY_CAPABILITY_LEASE_GUARD_SOURCE =
  "ZTR-1268 money-capability lease claim gates; epic ZTR-1266" as const;
