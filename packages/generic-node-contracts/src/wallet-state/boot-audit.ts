import { type PoolWalletState } from "../pool-policy/states.js";
import { type WalletProjection } from "./projection.js";

// the named concern — boot-audit contract. At boot every persisted wallet-state column is re-projected from
// lease reality and reconciled against the projection. Frozen data + a pure disposition verifier;
// no DB code.

export const BOOT_AUDIT_DISPOSITIONS = {
  consistent: "CONSISTENT",
  repairToProjection: "REPAIR_TO_PROJECTION",
  quarantineForReconciliation: "QUARANTINE_FOR_RECONCILIATION",
  invariantBreachQuarantine: "INVARIANT_BREACH_QUARANTINE",
} as const;
export type BootAuditDisposition =
  (typeof BOOT_AUDIT_DISPOSITIONS)[keyof typeof BOOT_AUDIT_DISPOSITIONS];

export const BOOT_AUDIT_CONTRADICTION_CLASSES = {
  none: { when: "stored === projected", disposition: "CONSISTENT", auditRequired: false },
  persisted_invariant_breach: {
    when: "projection carries a breach (more than one active operation lease)",
    disposition: "INVARIANT_BREACH_QUARANTINE",
    auditRequired: true,
  },
  understated_restriction: {
    when: "projection is more restricted than stored (e.g. a leased wallet stored AVAILABLE)",
    disposition: "REPAIR_TO_PROJECTION",
    auditRequired: true,
  },
  overstated_restriction_to_available: {
    when: "projection is AVAILABLE but stored is more restricted (phantom PIN / lost lease / would-be un-retire)",
    disposition: "QUARANTINE_FOR_RECONCILIATION",
    auditRequired: true,
  },
} as const;

export type BootAuditContradictionClass = keyof typeof BOOT_AUDIT_CONTRADICTION_CLASSES;

export type BootAuditResult = {
  readonly contradictionClass: BootAuditContradictionClass;
  readonly disposition: BootAuditDisposition;
  readonly auditRequired: boolean;
};

function classify(name: BootAuditContradictionClass): BootAuditResult {
  const entry = BOOT_AUDIT_CONTRADICTION_CLASSES[name];
  return { contradictionClass: name, disposition: entry.disposition, auditRequired: entry.auditRequired };
}

// Safety principle: it is always safe to repair a stored state toward a MORE-restricted projection
// (a leased wallet stored AVAILABLE -> repair to PINNED), but a stored non-AVAILABLE wallet must
// NEVER be silently made AVAILABLE (a lost lease or an un-retire) — that fails closed to quarantine
// for operator reconciliation. A stored QUARANTINED wallet is operator state and is never repaired
// away — even when a lease would otherwise project PINNED. A persisted one-in-flight-per-wallet
// breach always quarantines. A contradiction is never silently accepted (auditRequired holds for
// every non-`none` class).
export function auditPersistedWallet(
  stored: PoolWalletState,
  projection: WalletProjection,
): BootAuditResult {
  if (projection.breach !== null) return classify("persisted_invariant_breach");
  if (stored === projection.state) return classify("none");
  if (projection.state === "AVAILABLE") return classify("overstated_restriction_to_available");
  // Quarantine is strictly more restricted than PINNED. Never classify it as understated, and
  // never yield REPAIR_TO_PROJECTION that would clear an operator quarantine.
  if (stored === "QUARANTINED") return classify("none");
  return classify("understated_restriction");
}
