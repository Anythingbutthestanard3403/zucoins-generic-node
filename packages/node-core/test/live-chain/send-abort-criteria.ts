// SEND_EXTERNAL live-run abort criteria (the one-in-flight-per-wallet and never-blind-retry rules).
//
// The node NEVER submits for SEND_EXTERNAL. Stop conditions are timed against
// SEND_REDEMPTION_WINDOW_SECS=300 (T2), not the unrelated A.8.1 RECEIVE payer-chosen
// 3600s expiry. Ambiguity holds the source lease and reconciles by observation — silence
// never authorizes a replacement partial or a second approval consumption.

/** T2 redemption window the stop-conditions schedule against. */
export const SEND_REDEMPTION_WINDOW_SECS = 300 as const;

export const SEND_ABORT_POLICY_ID = "zp-send-external-live-abort-v1" as const;

export type SendAbortAction =
  /** Park source; continue observation. Never mint a replacement partial. */
  | "HOLD_SOURCE_LEASE_AND_RECONCILE"
  /** Page operator; freeze source. No release, no rebuild, no second approval. */
  | "ESCALATE_INVARIANT_BREACH"
  /** Definitive pre-formation failure; nothing crossed the boundary. Safe to abandon. */
  | "FAIL_PROVEN_NOT_STARTED"
  /** Clean verified landing; proceed to evidence bundle + disposition. */
  | "COMPLETE_LANDED_VERIFIED"
  /**
   * T2 redemption window elapsed without verified landing. Park + reconcile — expiry alone
   * never terminally rejects, never releases the source lease, never authorizes a
   * replacement partial (no AWAITING_REDEMPTION→EXPIRED transition).
   */
  | "HOLD_SOURCE_ON_REDEMPTION_WINDOW";

export type SendAbortTrigger =
  | "FORMATION_REJECTED"
  | "PARTIAL_DELIVERED_UNOBSERVED"
  | "INVARIANT_BREACH"
  | "LANDED_VERIFIED"
  | "OPERATOR_HALT"
  | "REDEMPTION_WINDOW_ELAPSED";

export interface SendAbortRule {
  readonly trigger: SendAbortTrigger;
  readonly action: SendAbortAction;
  /** Node never submits; always false. */
  readonly maySubmit: false;
  /** Never mint a second partial for the same approval / operation. */
  readonly mayMintReplacementPartial: false;
  /** Never consume a second TOTP for the same attempt. */
  readonly mayReconsumeApproval: false;
  readonly detail: string;
}

export interface SendAbortCriteria {
  readonly policyId: typeof SEND_ABORT_POLICY_ID;
  readonly rules: readonly SendAbortRule[];
  /** Explicit: T2 stop timer is SEND_REDEMPTION_WINDOW_SECS, never A.8.1's 3600s. */
  readonly redemptionWindowSecs: typeof SEND_REDEMPTION_WINDOW_SECS;
  /** Explicit negative: node has no submit route for SEND_EXTERNAL. */
  readonly nodeSubmitForbidden: true;
  /** Explicit negative: never blind-retry a submit (the never-blind-retry rule) — N/A path, still frozen. */
  readonly blindRetryForbidden: true;
  /**
   * Explicit negative: a halted or ambiguous live run is never license to rebuild a
   * partial without the positive non-landing evidence cases.
   */
  readonly rebuildRequiresPositiveNonLandingOracle: true;
}

const RULES: readonly SendAbortRule[] = [
  {
    trigger: "FORMATION_REJECTED",
    action: "FAIL_PROVEN_NOT_STARTED",
    maySubmit: false,
    mayMintReplacementPartial: false,
    mayReconsumeApproval: false,
    detail:
      "Formation rejected before durable sign intent (source busy after approval, insufficient balance, or observation failure). Classify PROVEN_NOT_STARTED. Do not consume another approval or mint a replacement partial.",
  },
  {
    trigger: "PARTIAL_DELIVERED_UNOBSERVED",
    action: "HOLD_SOURCE_LEASE_AND_RECONCILE",
    maySubmit: false,
    mayMintReplacementPartial: false,
    mayReconsumeApproval: false,
    detail:
      "Sender partial delivered but landing unobserved. Hold source lease and reconcile by observation. Node never submits. Rebuild only after positive non-landing evidence — silence is not non-landing proof.",
  },
  {
    trigger: "INVARIANT_BREACH",
    action: "ESCALATE_INVARIANT_BREACH",
    maySubmit: false,
    mayMintReplacementPartial: false,
    mayReconsumeApproval: false,
    detail:
      "Unattributed or contradictory successor under an active source lease. Quarantine source; no FORCE_RELEASE, no replacement partial, no second approval consumption.",
  },
  {
    trigger: "LANDED_VERIFIED",
    action: "COMPLETE_LANDED_VERIFIED",
    maySubmit: false,
    mayMintReplacementPartial: false,
    mayReconsumeApproval: false,
    detail:
      "Independent source landing proof satisfied against the exact persisted partial. Collect evidence bundle; do not mint again.",
  },
  {
    trigger: "OPERATOR_HALT",
    action: "HOLD_SOURCE_LEASE_AND_RECONCILE",
    maySubmit: false,
    mayMintReplacementPartial: false,
    mayReconsumeApproval: false,
    detail:
      "Operator halt mid-run. Hold source lease; never treat halt as license to rebuild, resubmit, or reconsume approval.",
  },
  {
    trigger: "REDEMPTION_WINDOW_ELAPSED",
    action: "HOLD_SOURCE_ON_REDEMPTION_WINDOW",
    maySubmit: false,
    mayMintReplacementPartial: false,
    mayReconsumeApproval: false,
    detail:
      `T2 SEND_REDEMPTION_WINDOW_SECS=${SEND_REDEMPTION_WINDOW_SECS} elapsed without verified landing. Hold source lease and reconcile. Expiry alone never terminally rejects, never releases the lease, never authorizes a replacement partial. Do not derive this window from the payer-chosen 3600s RECEIVE golden.`,
  },
] as const;

export function sendExternalAbortCriteria(): SendAbortCriteria {
  return {
    policyId: SEND_ABORT_POLICY_ID,
    rules: RULES,
    redemptionWindowSecs: SEND_REDEMPTION_WINDOW_SECS,
    nodeSubmitForbidden: true,
    blindRetryForbidden: true,
    rebuildRequiresPositiveNonLandingOracle: true,
  };
}

/** Look up the fixed action for a trigger. Always forbids submit / replacement / reconsume. */
export function sendAbortActionFor(trigger: SendAbortTrigger): SendAbortRule {
  const rule = RULES.find((r) => r.trigger === trigger);
  if (rule === undefined) {
    throw new Error(`unknown SEND_EXTERNAL abort trigger: ${String(trigger)}`);
  }
  return rule;
}
