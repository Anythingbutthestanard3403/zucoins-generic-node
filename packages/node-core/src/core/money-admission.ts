// composition-root money-admission gate.
//
// While validated reads are unavailable, no new leased operation advances past the point
// requiring T0, and readiness reports degraded once the failure budget is exceeded.
// Reconcile posture gates readiness on schema ∧ database ∧ vault ∧
// observation_read_capable; leadership is non-gating for readiness but required at the
// signUnderLease chokepoint.
//
// Production call sites (not test-only):
// - createMoneyPathAdmissionPorts / createMoneySignerBoundaryDeps (root composition)
// - apps/generic-node main.ts wires live readiness + BP into moneyPathPorts
// signUnderLease requires money gates
// - captureReceiveT0 requires assertMoneyAdmitted (omit throws)
// - apps/generic-node boot-lane shouldStartMoneyWorkersAfterRecovery
//
// The predicate itself is pure: callers inject live DB reachability and the
// stamped readiness snapshot. Storage CRITICAL / operator halt refuse via the
// injected assert ports (assertCanOperate / halt-gate) so those surfaces stay
// authoritative.
//
// The predicate itself is pure: callers inject live DB reachability and the
// stamped readiness snapshot. Storage CRITICAL / operator halt refuse via the
// injected assert ports (assertCanOperate / halt-gate) so those surfaces stay
// authoritative.

import type { ReadinessStateInputs } from "./readiness-state.js";

/** Closed refusal codes — no free-text, no secrets. */
export const MONEY_ADMISSION_REFUSAL_CODES = [
  "schema_not_migrated",
  "database_unreachable",
  "vault_unavailable",
  "observation_not_read_capable",
  "restore_hold_active",
  "event_signer_unavailable",
  "stopping",
] as const;

export type MoneyAdmissionRefusalCode = (typeof MONEY_ADMISSION_REFUSAL_CODES)[number];

export class MoneyAdmissionRefusedError extends Error {
  readonly code: MoneyAdmissionRefusalCode;

  constructor(code: MoneyAdmissionRefusalCode) {
    super(`money admission refused: ${code}`);
    this.name = "MoneyAdmissionRefusedError";
    this.code = code;
  }
}

/**
 * Pure gating conjunction for money engines. Lives in core/ so money engines
 * never import api/.
 *
 * Matches {@link evaluateReadinessFromProbes}'s deploy-ready verdict PLUS the
 * EVENT_SIGNING conjunct (ZTR-1179). Leadership, halt, and storage_pressure
 * stay excluded (leadership is non-gating for deploy readiness); EVENT_SIGNING
 * is money-only so an overlap-deploy follower can answer `/health/ready` 200
 * without holding leadership or arming the event signer (ZPAY-252).
 */
export function isGatingReadyForMoney(
  state: ReadinessStateInputs,
  databaseReachable: boolean,
): boolean {
  if (state.stopping) return false;
  if (!state.schemaMigrated) return false;
  if (!databaseReachable) return false;
  if (!(state.vaultKeyRingLoaded && state.vaultCensusVerified)) return false;
  if (!state.observationReadCapable) return false;
  // ZTR-1172: held restore refuses money work (matches deploy-ready gate).
  if (!state.restoreHoldClear) return false;
  // Runtime EVENT_SIGNING authority loss quiesces the money surface (ZTR-1179).
  // Not part of the /health/ready verdict (ZPAY-252).
  if (!state.eventSignerAvailable) return false;
  return true;
}

/** First failing gate, or null when admission is open. */
export function moneyAdmissionRefusal(
  state: ReadinessStateInputs,
  databaseReachable: boolean,
): MoneyAdmissionRefusalCode | null {
  if (state.stopping) return "stopping";
  if (!state.schemaMigrated) return "schema_not_migrated";
  if (!databaseReachable) return "database_unreachable";
  if (!(state.vaultKeyRingLoaded && state.vaultCensusVerified)) return "vault_unavailable";
  if (!state.observationReadCapable) return "observation_not_read_capable";
  if (!state.restoreHoldClear) return "restore_hold_active";
  if (!state.eventSignerAvailable) return "event_signer_unavailable";
  return null;
}

/**
 * Throw {@link MoneyAdmissionRefusedError} when new money work must not advance
 * past the T0-requiring point. Call before captureReceiveT0 / arm /
 * pre_sign admission.
 */
export function assertNewMoneyWorkAdmitted(
  state: ReadinessStateInputs,
  databaseReachable: boolean,
): void {
  const code = moneyAdmissionRefusal(state, databaseReachable);
  if (code !== null) {
    throw new MoneyAdmissionRefusedError(code);
  }
}

/**
 * Boot-recovery → money-worker start gate (step 8).
 * Money engines start only on explicit ready AND no invariant breach.
 * Wired from apps/generic-node boot-lane before startMoneyWorkers.
 */
export function shouldStartMoneyWorkersAfterRecovery(bootRecovery: {
  readonly ready: boolean;
  readonly invariantBreach: boolean;
}): boolean {
  // Fail-closed: missing/undefined ready never opens engines. Explicit
  // invariantBreach===true also refuses even if a buggy adapter reports ready.
  return bootRecovery.ready === true && bootRecovery.invariantBreach !== true;
}
