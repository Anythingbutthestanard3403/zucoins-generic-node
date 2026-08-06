// the named concern — the universal wallet-lease vocabulary. Under C-02 the wallet lease
// (wallet_active_leases) is the SOLE wallet-state authority; public wallet state is a
// projection of lease reality (projection.ts). Frozen data + pure predicates; no DB code.

export const LEASE_ROLES = [
  "RECEIVE_WINDOW",
  "MOVE_DESTINATION",
  "SEND_SOURCE",
  "MOVE_SOURCE",
  "RECONCILIATION",
] as const;
export type LeaseRole = (typeof LEASE_ROLES)[number];

// Operation roles hold an in-flight operation and pin the wallet (the one-in-flight-per-wallet rule: at most one
// per wallet). RECONCILIATION is observation-only — it never pins and never counts toward the
// one-in-flight bound (the recovery-gate rule exempts it from the recovery gate; observation must never block).
export const OPERATION_LEASE_ROLES = [
  "RECEIVE_WINDOW",
  "MOVE_DESTINATION",
  "SEND_SOURCE",
  "MOVE_SOURCE",
] as const;

export function isOperationRole(role: LeaseRole): boolean {
  return (OPERATION_LEASE_ROLES as readonly string[]).includes(role);
}

// A lease is ACTIVE until it is RELEASED. Per the receive-expiry rule, a RECEIVE_WINDOW lease that has passed the
// durable-candidate boundary is NOT released by expiry — it stays ACTIVE (held) until a T0
// T0-proof release, so an expired-held receive lease is still active here.
export const LEASE_LIFECYCLE_STATES = ["ACTIVE", "RELEASED"] as const;
export type LeaseLifecycleState = (typeof LEASE_LIFECYCLE_STATES)[number];

export type WalletLease = {
  readonly role: LeaseRole;
  readonly lifecycle: LeaseLifecycleState;
};

export function isLeaseActive(lease: WalletLease): boolean {
  return lease.lifecycle === "ACTIVE";
}

export function activeOperationLeases(leases: readonly WalletLease[]): readonly WalletLease[] {
  return leases.filter((lease) => isLeaseActive(lease) && isOperationRole(lease.role));
}
