import { type PoolWalletState } from "../pool-policy/states.js";
import { isAvailableForReceive } from "../pool-policy/eligibility.js";
import { activeOperationLeases, isLeaseActive, type WalletLease, type LeaseRole } from "./leases.js";

// the named concern — the ONE wallet-state projection. Public wallet state is DERIVED from lease reality
// (C-02: the lease is the sole wallet-state authority), never an independently mutable column. This
// resolves boot's "every leased wallet is PINNED" against move/send flows that might otherwise
// leave a leased wallet AVAILABLE: lease truth takes precedence.

export type WalletProjectionInput = {
  readonly leases: readonly WalletLease[];
  readonly quarantined: boolean;
  readonly retired: boolean;
};

export type WalletProjection = {
  readonly state: PoolWalletState;
  // The single active operation role, or null. RECONCILIATION never appears here (it does not pin).
  readonly activeRole: LeaseRole | null;
  readonly reconciliationActive: boolean;
  // A one-in-flight-per-wallet violation (more than one active operation lease) — a contradictory reality.
  readonly breach: string | null;
};

export function projectWalletState(input: WalletProjectionInput): WalletProjection {
  const operationLeases = activeOperationLeases(input.leases);
  const reconciliationActive = input.leases.some(
    (lease) => isLeaseActive(lease) && lease.role === "RECONCILIATION",
  );

  // One-in-flight-per-wallet breach first: more than one active operation lease is contradictory reality.
  // State is still never AVAILABLE; quarantine/retirement flags do not clear the breach.
  if (operationLeases.length > 1) {
    return { state: "PINNED", activeRole: null, reconciliationActive, breach: "multiple_active_operation_leases" };
  }

  // One active operation lease pins the wallet for selection (never AVAILABLE). Quarantine is
  // operator state and strictly more restricted than PINNED — honour it even while the lease
  // remains. activeRole still surfaces the lease so callers see lease truth.
  if (operationLeases.length === 1) {
    const activeRole = operationLeases[0].role;
    if (input.quarantined) {
      return { state: "QUARANTINED", activeRole, reconciliationActive, breach: null };
    }
    return { state: "PINNED", activeRole, reconciliationActive, breach: null };
  }

  // No active operation lease: quarantine over retirement over available. A RECONCILIATION lease
  // does not change any of these (observation must never exclude a wallet from selection).
  if (input.quarantined) return { state: "QUARANTINED", activeRole: null, reconciliationActive, breach: null };
  if (input.retired) return { state: "RETIRED", activeRole: null, reconciliationActive, breach: null };
  return { state: "AVAILABLE", activeRole: null, reconciliationActive, breach: null };
}

// The single point where projection, receive-pool exclusion, and recovery meet (the named concern exit
// criterion). A wallet is receive-selectable iff it PROJECTS to AVAILABLE (no active operation
// lease, not quarantined, not retired) AND passes the recovery-gate rule recovery gate (the named concern eligibility
// the named concern owns that predicate).
export function isSelectableForReceive(
  input: WalletProjectionInput & { readonly keyOrigin: string; readonly recoveryVerifiedAt: string | null },
): boolean {
  if (projectWalletState(input).state !== "AVAILABLE") return false;
  return isAvailableForReceive({
    keyOrigin: input.keyOrigin,
    recoveryVerifiedAt: input.recoveryVerifiedAt,
    state: "AVAILABLE",
  });
}
