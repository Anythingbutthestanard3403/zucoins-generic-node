// Concern barrel for the frozen wallet-state projection (the named concern). Lives inside the exclusive
// wallet-state/ concern dir. NOT the package root src/index.ts (the concern-manifest registry-owned). Consumes the named concern's
// pool-policy concern (state set + recovery eligibility); the named concern wins on conflict.
export {
  LEASE_ROLES,
  OPERATION_LEASE_ROLES,
  LEASE_LIFECYCLE_STATES,
  isOperationRole,
  isLeaseActive,
  activeOperationLeases,
  type LeaseRole,
  type LeaseLifecycleState,
  type WalletLease,
} from "./leases.js";
export {
  projectWalletState,
  isSelectableForReceive,
  type WalletProjectionInput,
  type WalletProjection,
} from "./projection.js";
export {
  WALLET_LEASE_EVENTS,
  requiredLeaseEvent,
  isLegalWalletTransition,
  canExpiryReleaseReceiveLease,
  type WalletLeaseEvent,
} from "./legality.js";
export {
  WALLET_STATE_INVARIANTS,
  walletStateContract,
  walletStateConcernManifest,
} from "./manifest.js";

// the named concern — selector consistency + boot-audit alignment.
export {
  WALLET_SELECTORS,
  PROJECTION_BOUND_SELECTORS,
  isSelectorConsistent,
  type WalletSelectorName,
} from "./selectors.js";
export {
  BOOT_AUDIT_DISPOSITIONS,
  BOOT_AUDIT_CONTRADICTION_CLASSES,
  auditPersistedWallet,
  type BootAuditDisposition,
  type BootAuditContradictionClass,
  type BootAuditResult,
} from "./boot-audit.js";
export { walletStateAlignmentContract } from "./alignment-manifest.js";

// the named concern — exhaustive matrix dimensions + invariants.
export {
  OPERATION_ROLE_DIMENSION,
  LEASE_LIFECYCLE_DIMENSION,
  STORED_STATE_DIMENSION,
  MATRIX_INVARIANTS,
  walletStateMatrixContract,
} from "./matrix.js";
