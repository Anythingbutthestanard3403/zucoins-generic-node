// MOVE_INTERNAL live-run abort criteria (the never-blind-retry rule).
//
// On ambiguity the runner holds both leases and reconciles by observation. Rebuild is
// possible only under the positive non-landing evidence cases
// (there is no generic PROVEN_NOT_LANDED oracle; silence never authorizes rebuild).
// A second submit for the same attempt is never licensed.

export const MOVE_ABORT_POLICY_ID = "zp-move-internal-live-abort-v1" as const;

export type MoveAbortAction =
  /** Park both wallets; continue observation. Never resubmit. */
  | "HOLD_BOTH_LEASES_AND_RECONCILE"
  /** Page operator; freeze wallets. No release, no rebuild, no second submit. */
  | "ESCALATE_INVARIANT_BREACH"
  /** Definitive pre-submit failure; nothing crossed the boundary. Safe to abandon. */
  | "FAIL_PROVEN_NOT_STARTED"
  /** Clean verified landing; proceed to evidence bundle + disposition. */
  | "COMPLETE_LANDED_VERIFIED";

export type MoveAbortTrigger =
  | "SUBMIT_REJECTED"
  | "SUBMIT_AMBIGUOUS_OR_UNOBSERVED"
  | "INVARIANT_BREACH"
  | "LANDED_VERIFIED"
  | "OPERATOR_HALT";

export interface MoveAbortRule {
  readonly trigger: MoveAbortTrigger;
  readonly action: MoveAbortAction;
  readonly mayResubmit: false;
  readonly mayRebuildWithoutPositiveOracle: false;
  readonly detail: string;
}

export interface MoveAbortCriteria {
  readonly policyId: typeof MOVE_ABORT_POLICY_ID;
  readonly rules: readonly MoveAbortRule[];
  /**
   * Explicit negative: a halted or ambiguous live run is never license to rebuild
   * without the positive non-landing evidence cases.
   */
  readonly rebuildRequiresPositiveNonLandingOracle: true;
  /** Explicit negative: never blind-retry a submit (the never-blind-retry rule). */
  readonly blindRetryForbidden: true;
}

const RULES: readonly MoveAbortRule[] = [
  {
    trigger: "SUBMIT_REJECTED",
    action: "FAIL_PROVEN_NOT_STARTED",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Gateway rejected before any chain write; classify PROVEN_NOT_STARTED. Do not resubmit the same attempt.",
  },
  {
    trigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
    action: "HOLD_BOTH_LEASES_AND_RECONCILE",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Submit outcome unknown or no independent landing proof. Hold source + destination leases and reconcile by observation. Rebuild only after positive non-landing evidence — silence is not non-landing proof.",
  },
  {
    trigger: "INVARIANT_BREACH",
    action: "ESCALATE_INVARIANT_BREACH",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Unattributed or contradictory successor under an active lease. Quarantine both wallets; no FORCE_RELEASE, no rebuild, no second submit.",
  },
  {
    trigger: "LANDED_VERIFIED",
    action: "COMPLETE_LANDED_VERIFIED",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Independent dual-path landing proof satisfied. Collect evidence bundle; do not submit again.",
  },
  {
    trigger: "OPERATOR_HALT",
    action: "HOLD_BOTH_LEASES_AND_RECONCILE",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Operator halt mid-run. Hold both leases; never treat halt as license to rebuild or resubmit.",
  },
] as const;

export function moveInternalAbortCriteria(): MoveAbortCriteria {
  return {
    policyId: MOVE_ABORT_POLICY_ID,
    rules: RULES,
    rebuildRequiresPositiveNonLandingOracle: true,
    blindRetryForbidden: true,
  };
}

/** Look up the fixed action for a trigger. Always forbids resubmit. */
export function abortActionFor(trigger: MoveAbortTrigger): MoveAbortRule {
  const rule = RULES.find((r) => r.trigger === trigger);
  if (rule === undefined) {
    throw new Error(`unknown MOVE abort trigger: ${String(trigger)}`);
  }
  return rule;
}
