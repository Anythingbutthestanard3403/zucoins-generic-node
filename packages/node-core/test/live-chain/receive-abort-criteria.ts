// RECEIVE_EXTERNAL live-run abort criteria (the one-in-flight-per-wallet and never-blind-retry rules).
//
// Unlike SEND_EXTERNAL, the node DOES submit step_2 for RECEIVE_EXTERNAL.
// Stop conditions therefore include post-submit ambiguity. The never-blind-retry rule still
// applies: never blind-retry a submit — reconcile by observation; rebuild only under the
// positive non-landing evidence cases.
//
// Expiry uses the payer-code TTL window (defaults: 60..3600, default 300s). A.8.1's
// 3600s fixture delta is the MAX operating margin, not a stop timer identity for SEND's
// T2=300. Post-boundary expiry never releases the receiver lease without the
// positive T0-unchanged non-landing oracle.

/** default payer-code TTL — the stop-conditions schedule against this window. */
export const RECEIVE_CODE_TTL_DEFAULT_SECS = 300 as const;

/** max payer-code TTL (A.8.1 golden margin). */
export const RECEIVE_CODE_TTL_MAX_SECS = 3600 as const;

/** min payer-code TTL. */
export const RECEIVE_CODE_TTL_MIN_SECS = 60 as const;

export const RECEIVE_ABORT_POLICY_ID = "zp-receive-external-live-abort-v1" as const;

export type ReceiveAbortAction =
  /** Park receiver; continue observation. Never resubmit. */
  | "HOLD_RECEIVER_LEASE_AND_RECONCILE"
  /** Page operator; freeze receiver. No release, no rebuild, no second submit. */
  | "ESCALATE_INVARIANT_BREACH"
  /** Definitive pre-submit failure; nothing crossed the boundary. Safe to abandon. */
  | "FAIL_PROVEN_NOT_STARTED"
  /** Clean verified landing; proceed to evidence bundle + disposition. */
  | "COMPLETE_LANDED_VERIFIED"
  /**
   * Payer-code TTL elapsed without verified landing. Park + reconcile — expiry alone
   * never releases the receiver lease and never authorizes a second submit.
   */
  | "HOLD_RECEIVER_ON_CODE_EXPIRY";

export type ReceiveAbortTrigger =
  | "SUBMIT_REJECTED"
  | "SUBMIT_AMBIGUOUS_OR_UNOBSERVED"
  | "INVARIANT_BREACH"
  | "LANDED_VERIFIED"
  | "OPERATOR_HALT"
  | "CODE_TTL_ELAPSED";

export interface ReceiveAbortRule {
  readonly trigger: ReceiveAbortTrigger;
  readonly action: ReceiveAbortAction;
  /** Never resubmit the same attempt (the never-blind-retry rule). */
  readonly mayResubmit: false;
  /** Never rebuild without the positive non-landing oracle. */
  readonly mayRebuildWithoutPositiveOracle: false;
  readonly detail: string;
}

export interface ReceiveAbortCriteria {
  readonly policyId: typeof RECEIVE_ABORT_POLICY_ID;
  readonly rules: readonly ReceiveAbortRule[];
  /** Explicit: stop timer is the default payer-code TTL (not SEND T2). */
  readonly codeTtlDefaultSecs: typeof RECEIVE_CODE_TTL_DEFAULT_SECS;
  readonly codeTtlMinSecs: typeof RECEIVE_CODE_TTL_MIN_SECS;
  readonly codeTtlMaxSecs: typeof RECEIVE_CODE_TTL_MAX_SECS;
  /** Explicit negative: never blind-retry a submit (the never-blind-retry rule). */
  readonly blindRetryForbidden: true;
  /**
   * Explicit negative: a halted or ambiguous live run is never license to rebuild
   * without the positive non-landing evidence cases.
   */
  readonly rebuildRequiresPositiveNonLandingOracle: true;
  /**
   * The node may submit step_2 for RECEIVE_EXTERNAL — unlike SEND_EXTERNAL — but only
   * once per attempt. A second submit is never licensed by any abort rule.
   */
  readonly singleSubmitOnly: true;
}

const RULES: readonly ReceiveAbortRule[] = [
  {
    trigger: "SUBMIT_REJECTED",
    action: "FAIL_PROVEN_NOT_STARTED",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Gateway rejected step_2 before any chain write; classify PROVEN_NOT_STARTED. Do not resubmit the same attempt.",
  },
  {
    trigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
    action: "HOLD_RECEIVER_LEASE_AND_RECONCILE",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Submit outcome unknown or no independent landing proof. Hold receiver lease and reconcile by observation. Rebuild only after positive non-landing evidence — silence is not non-landing proof. Leave READY with lease held or NEEDS_ATTENTION; never silently retry.",
  },
  {
    trigger: "INVARIANT_BREACH",
    action: "ESCALATE_INVARIANT_BREACH",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Unattributed or contradictory successor under an active receiver lease. Quarantine receiver; no FORCE_RELEASE, no rebuild, no second submit.",
  },
  {
    trigger: "LANDED_VERIFIED",
    action: "COMPLETE_LANDED_VERIFIED",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Independent receiver landing proof satisfied. Collect evidence bundle; do not submit again.",
  },
  {
    trigger: "OPERATOR_HALT",
    action: "HOLD_RECEIVER_LEASE_AND_RECONCILE",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      "Operator halt mid-run. Hold receiver lease; never treat halt as license to rebuild or resubmit. Fail-closed to READY (lease held) or NEEDS_ATTENTION per classification — never a silent retry.",
  },
  {
    trigger: "CODE_TTL_ELAPSED",
    action: "HOLD_RECEIVER_ON_CODE_EXPIRY",
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    detail:
      `Payer-code TTL elapsed (default=${RECEIVE_CODE_TTL_DEFAULT_SECS}s, max=${RECEIVE_CODE_TTL_MAX_SECS}s margin) without verified landing. Hold receiver lease and reconcile. Expiry alone never releases the lease and never authorizes a second submit. Do not derive this window from the SEND redemption window of 300s — they are distinct timers that happen to share the default numeric value.`,
  },
] as const;

export function receiveExternalAbortCriteria(): ReceiveAbortCriteria {
  return {
    policyId: RECEIVE_ABORT_POLICY_ID,
    rules: RULES,
    codeTtlDefaultSecs: RECEIVE_CODE_TTL_DEFAULT_SECS,
    codeTtlMinSecs: RECEIVE_CODE_TTL_MIN_SECS,
    codeTtlMaxSecs: RECEIVE_CODE_TTL_MAX_SECS,
    blindRetryForbidden: true,
    rebuildRequiresPositiveNonLandingOracle: true,
    singleSubmitOnly: true,
  };
}

/** Look up the fixed action for a trigger. Always forbids resubmit / rebuild-without-oracle. */
export function receiveAbortActionFor(trigger: ReceiveAbortTrigger): ReceiveAbortRule {
  const rule = RULES.find((r) => r.trigger === trigger);
  if (rule === undefined) {
    throw new Error(`unknown RECEIVE_EXTERNAL abort trigger: ${String(trigger)}`);
  }
  return rule;
}
