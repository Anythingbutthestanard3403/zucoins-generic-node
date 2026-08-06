import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { LEASE_ROLES, OPERATION_LEASE_ROLES, LEASE_LIFECYCLE_STATES } from "./leases.js";
import { WALLET_LEASE_EVENTS } from "./legality.js";
import { POOL_WALLET_STATES } from "../pool-policy/states.js";

// the named concern — the single invariant set for wallet-state projection, recorded as frozen data.
export const WALLET_STATE_INVARIANTS = {
  projectionIsSoleSource:
    "Public wallet state is a projection of lease reality (C-02); it is never an independently mutable column.",
  leasedIsNeverAvailable:
    "Any wallet with an active operation lease projects PINNED, never AVAILABLE (resolves the boot vs move/send tension).",
  oneInFlightPerWallet:
    "At most one active operation lease per wallet (the one-in-flight-per-wallet rule); more than one is a breach.",
  noStateChangeWithoutLeaseEvent:
    "Every wallet-state transition is caused by a lease/flag event; there is no spontaneous transition.",
  leaseHoldPrecedenceOverExpiry:
    "A post-candidate RECEIVE_WINDOW lease is not released by expiry; the wallet stays PINNED, held (the receive-expiry rule).",
} as const;

export const walletStateContract = {
  // Derived-state domain (the named concern owns the set; wallet-state derives it from leases).
  states: POOL_WALLET_STATES,
  leaseRoles: LEASE_ROLES,
  operationLeaseRoles: OPERATION_LEASE_ROLES,
  leaseLifecycleStates: LEASE_LIFECYCLE_STATES,
  leaseEvents: WALLET_LEASE_EVENTS,
  invariants: WALLET_STATE_INVARIANTS,
} as const;

export const walletStateConcernManifest = {
  concern: "wallet-state",
  frozenBy: "wallet-state-freeze",
  governedBy: ["C-02", "receive-expiry-prevention-rule", "recovery-gate-rule"],
  contract: walletStateContract,
} as const;

/**
 * the named concern's self-registered ConcernManifest. Wraps `walletStateContract`
 * byte-identically under the canonical shape; `walletStateConcernManifest` above is the
 * provisional form it supersedes. Registration export only — the concern-manifest registry
 * assembles `src/registry.ts`.
 */
export const WALLET_STATE_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "wallet-state",
  decisionRefs: ["receive-expiry-prevention-rule", "recovery-gate-rule"],
  frozenValues: { walletStateContract },
  goldenRefs: [{ path: "gen/wallet-state.json", sha256: "2189d02e18f0e29ea64586f57a4533c99db9fca80fe35a12a332078592e3d5ab" }],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "the C-02 lease invariant: public wallet state is a projection of lease reality",
    "data model: wallet, lease, and destination tables",
    "operation flows: lease acquisition and release per operation kind",
    "operations-recovery: boot recovery",
    "receive-expiry-prevention-rule",
    "recovery-gate-rule",
  ],
});
