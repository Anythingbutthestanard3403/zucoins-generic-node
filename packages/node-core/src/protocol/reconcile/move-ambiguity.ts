// permanent MOVE_INTERNAL ambiguity handling after a single exact
// submit may have started.
// 1. There is no generic PROVEN_NOT_LANDED oracle (canonical).
// 2. Read retry is not submit retry; expiry alone is not non-landing proof.
// 3. The post-submit classification rows govern once a submit call may have occurred.
// 4. Submit is single-shot; there is no rebuild boundary.
// 5. The lease is retained across the ambiguity.
//
// Conflicting older wording (flagged, not papered over): REBUILD_INTERNAL_MOVE and a
// "positive non-landing proof" release condition describe a rebuild path. The landing-path
// oracle plus the attempt_no CHECK = 1 supersede those passages. This module deliberately
// does not implement REBUILD_INTERNAL_MOVE, SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING,
// PROVEN_NOT_LANDED, archive-old-attempt, or any second-attempt constructor. A future
// reader must not "helpfully" add them back without a new decision that amends the
// landing-path oracle.
//
// Scope: pure classification at the reconciler boundary. Consumes
// verification/observation evidence already on hand; never calls SUBMIT; never releases a
// lease; never invents a second operation_transactions / submit_decisions /
// gateway_submit_attempts row. Sibling owns dedicated INVARIANT_BREACH quarantine
// machinery; this module only surfaces the classification.

import {
  type LeaseLifecycleState,
} from "@zucoins/generic-node-contracts/wallet-state";

import {
  classifyMoveReconcile,
  type MoveFormationEvidence,
  type MoveObservationEvidence,
  type MoveReconcileOutcome,
  type MoveResumeAction,
} from "./move.js";
import { type PathObservation } from "./observation-input.js";
import {
  type ReconcileIndeterminateReason,
  type ReconcileInvariantBreachReason,
  assertUnreachable,
  toAttentionReason,
} from "./types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Evidence taxonomy (every post-submit evidence kind)
// ─────────────────────────────────────────────────────────────────────────────

// Transport / gateway surface after the one authorized submit call (table;
// gateway/submit.ts classifySubmitHttpStatus). ACK is receipt-only, never settlement.
export type MoveSubmitTransportEvidence =
  | { readonly kind: "TIMEOUT" }
  | { readonly kind: "TRANSPORT_ERROR"; readonly detail?: string }
  | { readonly kind: "ACK"; readonly gatewayCode?: string }
  | { readonly kind: "REJECT"; readonly gatewayCode?: string }
  | { readonly kind: "UNREADABLE_RESPONSE" }
  | { readonly kind: "NO_RESPONSE_CAPTURED" };

// Named post-submit evidence kinds. Each folds into WAITING /
// INDETERMINATE / INVARIANT_BREACH / LANDED_VERIFIED — never into a second attempt.
export type MoveAmbiguityEvidenceKind =
  | "TIMEOUT"
  | "ACK"
  | "REJECT"
  | "TRANSPORT_ERROR"
  | "UNREADABLE_RESPONSE"
  | "EXPIRY"
  | "UNCHANGED_HEAD"
  | "CHANGED_HEAD"
  | "INCOMPLETE_LINEAGE"
  | "ANOMALY"
  | "OPERATOR_ACTION"
  | "RESOURCE_EXHAUSTION"
  | "PATH_DISAGREEMENT"
  | "DUAL_PATH_LANDED"
  | "LEASE_NOT_ACTIVE"
  | "SUBMIT_OUTCOME_UNKNOWN";

// ─────────────────────────────────────────────────────────────────────────────
// Closed outcome union — permanent pin after submit may have started
// ─────────────────────────────────────────────────────────────────────────────

// Automatic effects after classification. Structurally excludes:
// - secondAttempt / rebuild / archiveOldAttempt / PROVEN_NOT_LANDED
// - releaseSourceLease / releaseDestinationLease / releaseEitherLease
// - retrySubmit / resubmit / callSubmitAgain
// The only authorized side-effects are: retain both leases, continue bounded reads,
// park/attention, or (for INVARIANT_BREACH) surface quarantine-required to.
export type MoveAmbiguityAutomaticEffect =
  | "CONTINUE_FIRST_FORMATION_OR_SUBMIT" // PRE_SUBMIT / PROVEN_NOT_STARTED only
  | "CONTINUE_BOUNDED_READ_RECONCILIATION"
  | "PARK_NEEDS_ATTENTION_RETAIN_LEASES"
  | "SURFACE_INVARIANT_BREACH_QUARANTINE"
  | "ADVANCE_LANDED_VERIFIED";

export type MoveAmbiguityOutcome =
  | {
      readonly kind: "PROVEN_NOT_STARTED";
      readonly moveAttemptId: string;
      readonly resumeAction: MoveResumeAction;
      readonly permitsSubmitCall: true;
      readonly retainSourceLease: true;
      readonly retainDestinationLease: true;
      readonly automaticEffect: "CONTINUE_FIRST_FORMATION_OR_SUBMIT";
      // False always: PROVEN_NOT_STARTED authorizes the FIRST call of the still-unsubmitted
      // original attempt only — never a rebuild of a prior attempt.
      readonly isRebuild: false;
    }
  | {
      readonly kind: "WAITING";
      readonly moveAttemptId: string;
      readonly evidenceKind: MoveAmbiguityEvidenceKind;
      readonly retainSourceLease: true;
      readonly retainDestinationLease: true;
      readonly permitsSubmitCall: false;
      readonly permitsSecondAttempt: false;
      readonly automaticEffect: "CONTINUE_BOUNDED_READ_RECONCILIATION";
    }
  | {
      readonly kind: "INDETERMINATE";
      readonly moveAttemptId: string;
      readonly evidenceKind: MoveAmbiguityEvidenceKind;
      readonly reason: ReconcileIndeterminateReason;
      readonly retainSourceLease: true;
      readonly retainDestinationLease: true;
      readonly permitsSubmitCall: false;
      readonly permitsSecondAttempt: false;
      readonly automaticEffect: "PARK_NEEDS_ATTENTION_RETAIN_LEASES";
      readonly attentionReason: ReturnType<typeof toAttentionReason>;
    }
  | {
      readonly kind: "INVARIANT_BREACH";
      readonly moveAttemptId: string;
      readonly evidenceKind: MoveAmbiguityEvidenceKind;
      readonly reason: ReconcileInvariantBreachReason;
      readonly affectedWalletIds: readonly string[];
      readonly retainSourceLease: true;
      readonly retainDestinationLease: true;
      readonly permitsSubmitCall: false;
      readonly permitsSecondAttempt: false;
      readonly automaticEffect: "SURFACE_INVARIANT_BREACH_QUARANTINE";
      readonly attentionReason: ReturnType<typeof toAttentionReason>;
    }
  | {
      readonly kind: "LANDED_VERIFIED";
      readonly moveAttemptId: string;
      readonly evidenceKind: "DUAL_PATH_LANDED";
      readonly retainSourceLease: true; // release is a separate guarded transition, not this classifier
      readonly retainDestinationLease: true;
      readonly permitsSubmitCall: false;
      readonly permitsSecondAttempt: false;
      readonly automaticEffect: "ADVANCE_LANDED_VERIFIED";
      readonly reconcile: Extract<MoveReconcileOutcome, { kind: "LANDED_VERIFIED" }>;
    };

// ─────────────────────────────────────────────────────────────────────────────
// Inputs
// ─────────────────────────────────────────────────────────────────────────────

// Durable evidence that the submit boundary was never crossed (rows 2–4). The only
// path that may authorize a signer/submit call — and only for the original attempt.
export interface MoveAmbiguityPreSubmitInput {
  readonly phase: "PRE_SUBMIT";
  readonly formation: MoveFormationEvidence;
}

// Post-submit: a submit claim/call may have occurred ("Submit call may have occurred |
// Reconcile; never call submit for that attempt again."). Observation evidence is required;
// transport evidence is optional additional context that can only deepen parking, never unlock
// a second attempt.
export interface MoveAmbiguityPostSubmitInput {
  readonly phase: "POST_SUBMIT";
  readonly observation: MoveObservationEvidence;
  readonly transport?: MoveSubmitTransportEvidence;
  // "operator action" is evidence, not authority to rebuild/release. Presence parks.
  readonly operatorActionRecorded?: boolean;
  // "expiry" alone is not non-landing proof (axiom 2).
  readonly transactionExpired?: boolean;
}

export type MoveAmbiguityInput = MoveAmbiguityPreSubmitInput | MoveAmbiguityPostSubmitInput;

// ─────────────────────────────────────────────────────────────────────────────
// Forbidden action surface — compile-time + runtime pin that rebuild is absent
// ─────────────────────────────────────────────────────────────────────────────

// Tokens that / / name but landing-path oracle forbids for launch MOVE_INTERNAL.
// Kept as a named const so a code-search / lint / future reader finds the deliberate omission
// with the landing-path oracle citation rather than concluding the rebuild path was "forgotten."
export const MOVE_AMBIGUITY_FORBIDDEN_ACTIONS = [
  "REBUILD_INTERNAL_MOVE",
  "SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING",
  "PROVEN_NOT_LANDED",
  "ARCHIVE_OLD_ATTEMPT",
  "CREATE_ATTEMPT_2",
  "RETRY_SUBMIT",
  "RESUBMIT",
  "FORCE_RELEASE_SOURCE_LEASE",
  "FORCE_RELEASE_DESTINATION_LEASE",
  "FORCE_RELEASE_EITHER_LEASE",
  "FORCE_LANDED",
  "ASSUME_NOT_LANDED_FROM_TIMEOUT",
  "ASSUME_NOT_LANDED_FROM_UNCHANGED_HEAD",
  "ASSUME_NOT_LANDED_FROM_EXPIRY",
  "ASSUME_NOT_LANDED_FROM_ACK",
  "ASSUME_NOT_LANDED_FROM_REJECT",
] as const;

export type MoveAmbiguityForbiddenAction = (typeof MOVE_AMBIGUITY_FORBIDDEN_ACTIONS)[number];

// Always false. Exists so call sites and tests can assert the permanent pin without reaching
// for a rebuild API that must not exist.
export function isMoveAmbiguityActionPermitted(
  action: MoveAmbiguityForbiddenAction,
): false {
  void action;
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Classifier
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Classify MOVE_INTERNAL recovery after (or before) the single exact submit.
 *
 * - PRE_SUBMIT → only PROVEN_NOT_STARTED (first formation/sign/submit of attempt 1) or
 * INVARIANT_BREACH. Never a second attempt; never LANDED from this phase.
 * - POST_SUBMIT → WAITING | INDETERMINATE | INVARIANT_BREACH | LANDED_VERIFIED.
 * Both leases retained on every branch. permitsSubmitCall and permitsSecondAttempt are
 * literally `false` on every POST_SUBMIT branch (type-level + runtime).
 *
 * Indefinite reconciliation is the caller's loop: this function is pure and side-effect free.
 * Re-invoking it with fresh PathObservation evidence is the only authorized progress path
 * after submit may have started (axiom 1: read retry is not submit retry).
 */
export function classifyMoveAmbiguity(input: MoveAmbiguityInput): MoveAmbiguityOutcome {
  if (input.phase === "PRE_SUBMIT") {
    return classifyPreSubmit(input.formation);
  }
  return classifyPostSubmit(input);
}

function classifyPreSubmit(formation: MoveFormationEvidence): MoveAmbiguityOutcome {
  const outcome = classifyMoveReconcile(formation);
  switch (outcome.kind) {
    case "PROVEN_NOT_STARTED":
      return {
        kind: "PROVEN_NOT_STARTED",
        moveAttemptId: outcome.moveAttemptId,
        resumeAction: outcome.resumeAction,
        permitsSubmitCall: true,
        retainSourceLease: true,
        retainDestinationLease: true,
        automaticEffect: "CONTINUE_FIRST_FORMATION_OR_SUBMIT",
        isRebuild: false,
      };
    case "INVARIANT_BREACH":
      return {
        kind: "INVARIANT_BREACH",
        moveAttemptId: formation.moveAttemptId,
        evidenceKind: "ANOMALY",
        reason: outcome.reason,
        affectedWalletIds: outcome.affectedWalletIds,
        retainSourceLease: true,
        retainDestinationLease: true,
        permitsSubmitCall: false,
        permitsSecondAttempt: false,
        automaticEffect: "SURFACE_INVARIANT_BREACH_QUARANTINE",
        attentionReason: toAttentionReason(outcome.reason),
      };
    case "LANDED_VERIFIED":
    case "INDETERMINATE":
      // PRE_SUBMIT formation evidence cannot produce these (move.ts); if it ever did, park.
      return {
        kind: "INDETERMINATE",
        moveAttemptId: formation.moveAttemptId,
        evidenceKind: "SUBMIT_OUTCOME_UNKNOWN",
        reason: { source: "SUBMIT_OUTCOME_UNKNOWN" },
        retainSourceLease: true,
        retainDestinationLease: true,
        permitsSubmitCall: false,
        permitsSecondAttempt: false,
        automaticEffect: "PARK_NEEDS_ATTENTION_RETAIN_LEASES",
        attentionReason: toAttentionReason({ source: "SUBMIT_OUTCOME_UNKNOWN" }),
      };
    default:
      return assertUnreachable(outcome);
  }
}

function classifyPostSubmit(input: MoveAmbiguityPostSubmitInput): MoveAmbiguityOutcome {
  const { observation, transport, operatorActionRecorded, transactionExpired } = input;
  const moveAttemptId = observation.moveAttemptId;

  // Lease axis first (same as classifyMoveReconcile): a non-ACTIVE lease during reconcile is
  // already an invariant breach — still retain (quarantine path holds custody; never "release
  // because lease looks wrong").
  const reconcile = classifyMoveReconcile(observation);

  if (reconcile.kind === "LANDED_VERIFIED") {
    // Dual complete-path landing is the only positive terminal this classifier emits.
    // Transport ACK is never required and never sufficient; operator action is irrelevant.
    return {
      kind: "LANDED_VERIFIED",
      moveAttemptId,
      evidenceKind: "DUAL_PATH_LANDED",
      retainSourceLease: true,
      retainDestinationLease: true,
      permitsSubmitCall: false,
      permitsSecondAttempt: false,
      automaticEffect: "ADVANCE_LANDED_VERIFIED",
      reconcile,
    };
  }

  if (reconcile.kind === "INVARIANT_BREACH") {
    return {
      kind: "INVARIANT_BREACH",
      moveAttemptId,
      evidenceKind: evidenceKindForBreach(observation, transport),
      reason: reconcile.reason,
      affectedWalletIds: reconcile.affectedWalletIds,
      retainSourceLease: true,
      retainDestinationLease: true,
      permitsSubmitCall: false,
      permitsSecondAttempt: false,
      automaticEffect: "SURFACE_INVARIANT_BREACH_QUARANTINE",
      attentionReason: toAttentionReason(reconcile.reason),
    };
  }

  if (reconcile.kind === "PROVEN_NOT_STARTED") {
    // Unreachable from POST_SUBMIT MoveObservationEvidence (move.matrix.test.ts proves it).
    // If a caller forces the shape, park rather than authorize any submit.
    return parkIndeterminate(moveAttemptId, "SUBMIT_OUTCOME_UNKNOWN", {
      source: "SUBMIT_OUTCOME_UNKNOWN",
    });
  }

  // reconcile.kind === "INDETERMINATE"
  const evidenceKind = pickEvidenceKind({
    reason: reconcile.reason,
    observation,
    transport,
    operatorActionRecorded: operatorActionRecorded === true,
    transactionExpired: transactionExpired === true,
  });

  // WAITING: exact external-style "no contradictory evidence, keep reading" — for MOVE the
  // only clean non-contradiction signal is dual NO_SUCCESSOR (unchanged heads) or a bare
  // transport-timeout/ACK with dual NO_SUCCESSOR. Every positive fault stays INDETERMINATE
  // (landing-path oracle: unchanged head alone is insufficient for non-landing, but is WAITING for
  // continued read reconciliation — never rebuild authority).
  if (evidenceKind === "UNCHANGED_HEAD" || isCleanTransportWaiting(evidenceKind, reconcile.reason)) {
    return {
      kind: "WAITING",
      moveAttemptId,
      evidenceKind,
      retainSourceLease: true,
      retainDestinationLease: true,
      permitsSubmitCall: false,
      permitsSecondAttempt: false,
      automaticEffect: "CONTINUE_BOUNDED_READ_RECONCILIATION",
    };
  }

  return parkIndeterminate(moveAttemptId, evidenceKind, reconcile.reason);
}

function parkIndeterminate(
  moveAttemptId: string,
  evidenceKind: MoveAmbiguityEvidenceKind,
  reason: ReconcileIndeterminateReason,
): MoveAmbiguityOutcome {
  return {
    kind: "INDETERMINATE",
    moveAttemptId,
    evidenceKind,
    reason,
    retainSourceLease: true,
    retainDestinationLease: true,
    permitsSubmitCall: false,
    permitsSecondAttempt: false,
    automaticEffect: "PARK_NEEDS_ATTENTION_RETAIN_LEASES",
    attentionReason: toAttentionReason(reason),
  };
}

function isCleanTransportWaiting(
  evidenceKind: MoveAmbiguityEvidenceKind,
  reason: ReconcileIndeterminateReason,
): boolean {
  // Transport ACK/timeout/etc. with only NO_SUCCESSOR_OBSERVED on the observation side is
  // still "keep reading" — never non-landing, never second attempt (axiom 2).
  if (reason.source !== "NO_SUCCESSOR_OBSERVED") return false;
  return (
    evidenceKind === "TIMEOUT" ||
    evidenceKind === "ACK" ||
    evidenceKind === "REJECT" ||
    evidenceKind === "TRANSPORT_ERROR" ||
    evidenceKind === "UNREADABLE_RESPONSE" ||
    evidenceKind === "SUBMIT_OUTCOME_UNKNOWN" ||
    evidenceKind === "EXPIRY"
  );
}

function pickEvidenceKind(args: {
  readonly reason: ReconcileIndeterminateReason;
  readonly observation: MoveObservationEvidence;
  readonly transport: MoveSubmitTransportEvidence | undefined;
  readonly operatorActionRecorded: boolean;
  readonly transactionExpired: boolean;
}): MoveAmbiguityEvidenceKind {
  // Operator action and expiry are named evidence kinds; they deepen park/wait but
  // never unlock rebuild. Prefer the most specific observation-derived kind when present.
  if (args.operatorActionRecorded) return "OPERATOR_ACTION";

  switch (args.reason.source) {
    case "PATH_DISAGREEMENT":
      return "PATH_DISAGREEMENT";
    case "LANDING_PROOF_INCOMPLETE":
      return args.reason.fault === "BUDGET_EXHAUSTED"
        ? "RESOURCE_EXHAUSTION"
        : "INCOMPLETE_LINEAGE";
    case "OBSERVATION_ANOMALY":
      return "ANOMALY";
    case "NO_SUCCESSOR_OBSERVED":
      if (args.transactionExpired) return "EXPIRY";
      if (args.transport !== undefined) return transportToEvidenceKind(args.transport);
      return "UNCHANGED_HEAD";
    case "SUBMIT_OUTCOME_UNKNOWN":
      if (args.transport !== undefined) return transportToEvidenceKind(args.transport);
      return "SUBMIT_OUTCOME_UNKNOWN";
    case "RELEASE_PREDICATE_UNSATISFIED":
    case "PROOF_INTAKE_REJECTED":
      return "CHANGED_HEAD";
    default:
      return assertUnreachable(args.reason);
  }
}

function transportToEvidenceKind(
  transport: MoveSubmitTransportEvidence,
): MoveAmbiguityEvidenceKind {
  switch (transport.kind) {
    case "TIMEOUT":
      return "TIMEOUT";
    case "TRANSPORT_ERROR":
      return "TRANSPORT_ERROR";
    case "ACK":
      return "ACK";
    case "REJECT":
      return "REJECT";
    case "UNREADABLE_RESPONSE":
      return "UNREADABLE_RESPONSE";
    case "NO_RESPONSE_CAPTURED":
      return "SUBMIT_OUTCOME_UNKNOWN";
    default:
      return assertUnreachable(transport);
  }
}

function evidenceKindForBreach(
  observation: MoveObservationEvidence,
  transport: MoveSubmitTransportEvidence | undefined,
): MoveAmbiguityEvidenceKind {
  if (observation.sourceLeaseState !== "ACTIVE" || observation.destinationLeaseState !== "ACTIVE") {
    return "LEASE_NOT_ACTIVE";
  }
  const src = observation.sourceObservation;
  const dst = observation.destinationObservation;
  if (isChangedHeadObservation(src) || isChangedHeadObservation(dst)) {
    return "CHANGED_HEAD";
  }
  if (src.result === "ANOMALY" || dst.result === "ANOMALY") {
    return "ANOMALY";
  }
  if (transport !== undefined) return transportToEvidenceKind(transport);
  return "ANOMALY";
}

function isChangedHeadObservation(obs: PathObservation): boolean {
  return obs.result === "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE";
}

// ─────────────────────────────────────────────────────────────────────────────
// Permanent-pin helpers (lease retention + no-second-attempt assertions)
// ─────────────────────────────────────────────────────────────────────────────

/** True when both leases must stay held. Always true for every outcome this module emits. */
export function moveAmbiguityRetainsBothLeases(outcome: MoveAmbiguityOutcome): true {
  void outcome.retainSourceLease;
  void outcome.retainDestinationLease;
  return true;
}

/**
 * True only for PRE_SUBMIT PROVEN_NOT_STARTED. POST_SUBMIT never authorizes a submit call —
 * including when transport was TIMEOUT/ACK/REJECT and heads are unchanged.
 */
export function moveAmbiguityPermitsSubmitCall(outcome: MoveAmbiguityOutcome): boolean {
  return outcome.kind === "PROVEN_NOT_STARTED" && outcome.permitsSubmitCall === true;
}

/** Always false. A second MOVE attempt is unrepresentable after this classifier runs. */
export function moveAmbiguityPermitsSecondAttempt(_outcome: MoveAmbiguityOutcome): false {
  return false;
}

/**
 * Indefinite reconciliation directive: given a prior non-terminal outcome and a fresh
 * observation pass, re-classify. Never escalates to submit/rebuild regardless of pass count.
 * The `passCount` argument exists so tests can simulate extended reconciliation periods;
 * it is intentionally unused by the decision (no attempt budget, no auto-release timer).
 */
export function continueMoveAmbiguityReconciliation(
  prior: Exclude<MoveAmbiguityOutcome, { kind: "LANDED_VERIFIED" | "PROVEN_NOT_STARTED" }>,
  freshObservation: MoveObservationEvidence,
  extras?: {
    readonly transport?: MoveSubmitTransportEvidence;
    readonly operatorActionRecorded?: boolean;
    readonly transactionExpired?: boolean;
    readonly passCount?: number;
  },
): MoveAmbiguityOutcome {
  void prior;
  void extras?.passCount;
  return classifyMoveAmbiguity({
    phase: "POST_SUBMIT",
    observation: freshObservation,
    transport: extras?.transport,
    operatorActionRecorded: extras?.operatorActionRecorded,
    transactionExpired: extras?.transactionExpired,
  });
}

/** Lease states the permanent pin requires on every non-breach POST_SUBMIT park/wait. */
export function assertMoveAmbiguityLeasesHeld(
  sourceLeaseState: LeaseLifecycleState,
  destinationLeaseState: LeaseLifecycleState,
): { readonly bothHeld: true } | { readonly bothHeld: false; readonly kind: "INVARIANT_BREACH" } {
  if (sourceLeaseState === "ACTIVE" && destinationLeaseState === "ACTIVE") {
    return { bothHeld: true };
  }
  return { bothHeld: false, kind: "INVARIANT_BREACH" };
}
