import { WALLET_SELECTORS, PROJECTION_BOUND_SELECTORS } from "./selectors.js";
import { BOOT_AUDIT_DISPOSITIONS, BOOT_AUDIT_CONTRADICTION_CLASSES } from "./boot-audit.js";

// the named concern aggregate: the selector-consistency + boot-audit alignment contract, frozen as data.
// Snapshotted to gen/wallet-state-alignment.json (sync test). Separate from .1's manifest so the
// the named concern snapshot stays byte-stable.
export const walletStateAlignmentContract = {
  selectors: WALLET_SELECTORS,
  projectionBoundSelectors: PROJECTION_BOUND_SELECTORS,
  bootAuditDispositions: BOOT_AUDIT_DISPOSITIONS,
  bootAuditContradictionClasses: BOOT_AUDIT_CONTRADICTION_CLASSES,
} as const;
