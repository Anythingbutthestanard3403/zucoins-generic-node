// closed recovery-action evaluator and guarded mutation.
//
// POST /admin/v1/operations/:operation_id/recovery-actions re-evaluates every
// predicate under locks with expected_row_version, single-use recovery_nonce,
// fresh TOTP, CSRF, and idempotency. Classification + permitted-action facts come
// from recovery-inspection; this module never trustsn the client's
// view of what was permitted on a prior GET.
//
// Structural closure:
// * The action discriminator is the closed OPERATOR_RECOVERY_ACTIONS set.
// * FORBIDDEN_RECOVERY_ACTIONS and every non-action are unreachable as
// typed branches — there is no switch arm, no factory key, no submit call.
// * REBUILD_INTERNAL_MOVE is the only action that authorizes a *new* attempt
// number (archive old unchanged, create next). It never resubmits the old
// attempt (the never-blind-retry rule). Formation/submit of the new attempt is a later
// worker step, not this POST body.
// * RETRY_OBSERVATION and ACKNOWLEDGE_KEEP_PINNED bump row_version for CAS
// single-winner semantics but never change public protocol status or leases.

import {
  FORBIDDEN_RECOVERY_ACTIONS,
  OPERATOR_RECOVERY_ACTIONS,
  classifyRecovery,
  derivePermittedActions,
  type OperatorRecoveryAction,
  type RecoveryClassification,
  type RecoveryFacts,
} from "./recovery-inspection.js";

/**
 * halt.contract: only REBUILD_INTERNAL_MOVE re-authorizes a fund-moving
 * first formation and is halt-gated. All other actions stay available.
 */
function isActionAdmittedUnderHalt(
  action: OperatorRecoveryAction,
  haltEngaged: boolean,
): boolean {
  if (!haltEngaged) return true;
  return action !== "REBUILD_INTERNAL_MOVE";
}

export { FORBIDDEN_RECOVERY_ACTIONS, OPERATOR_RECOVERY_ACTIONS };

/** Token gate — rejects free strings before any store write. */
export function isOperatorRecoveryAction(value: string): value is OperatorRecoveryAction {
  return (OPERATOR_RECOVERY_ACTIONS as readonly string[]).includes(value);
}

/** Defence-in-depth: forbidden tokens can never be admitted. */
export function isForbiddenRecoveryAction(value: string): boolean {
  return (FORBIDDEN_RECOVERY_ACTIONS as readonly string[]).includes(value);
}

/**
 * Effects that each admitted action is allowed to request from the store.
 * Forbidden effects (SUBMIT_ATTEMPT, FORCE_LANDED, RELEASE_WITHOUT_PROOF, …)
 * are deliberately absent from this closed union.
 */
export type RecoveryActionEffect =
  | { readonly kind: "RETRY_OBSERVATION" }
  | {
      readonly kind: "REDELIVER_EXACT_PARTIAL";
    }
  | {
      readonly kind: "CONTINUE_EXTERNAL_WAIT";
      readonly nextStatus: "AWAITING_REDEMPTION";
      /** Clear attention; keep source lease. */
      readonly clearAttention: true;
      readonly keepLease: true;
    }
  | {
      readonly kind: "CLOSE_NEVER_STARTED_EXTERNAL_SEND";
      readonly nextStatus: "REJECTED";
      readonly releaseSourceLease: true;
    }
  | {
      readonly kind: "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED";
      readonly nextStatus: "REJECTED";
      readonly releaseSourceLease: true;
    }
  | {
      readonly kind: "REBUILD_INTERNAL_MOVE";
      readonly nextStatus: "CREATED";
      readonly clearAttention: true;
      readonly decision: "SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING";
      readonly proofId: string;
      /** Archive old attempt unchanged; never resubmit it. */
      readonly archiveOldAttemptUnchanged: true;
      readonly createNextAttemptNumber: true;
      readonly submitOldAttempt: false;
    }
  | {
      readonly kind: "RELEASE_EXPIRED_RECEIVE";
      readonly releaseStatus: "RELEASED_T0_UNCHANGED";
      readonly walletPinnedToAvailable: true;
    }
  | {
      readonly kind: "QUARANTINE_WALLETS";
      readonly walletIds: readonly string[];
    }
  | {
      readonly kind: "ACKNOWLEDGE_KEEP_PINNED";
      readonly protocolStateUnchanged: true;
      readonly leasesUnchanged: true;
    };

export interface RecoveryActionRequest {
  readonly action: string;
  readonly expectedRowVersion: number;
  readonly recoveryNonce: string;
  readonly proofId: string | null;
  readonly operatorNote: string | null;
  readonly idempotencyKey: string;
  /** Operator principal from the session (audit attribution). */
  readonly operatorId: string;
  /**
   * Timestep already verified by the operator_session_totp chain.
   * Burned under purpose RECOVERY_ACTION inside the commitment TX.
   */
  readonly totpTimestep: number;
  /**
   * CSRF double-submit already validated by the admin mutation chain.
   * The evaluator refuses when this is not affirmatively true.
   */
  readonly csrfValidated: true;
}

export type RecoveryActionRejectReason =
  | "action_not_in_catalog"
  | "action_forbidden"
  | "csrf_required"
  | "operation_not_found"
  | "operation_version_conflict"
  | "recovery_nonce_invalid"
  | "action_not_permitted"
  | "proof_id_required"
  | "proof_id_mismatch"
  | "halt_engaged"
  | "predicate_failed"
  | "idempotency_conflict";

export interface RecoveryActionSuccessBody {
  readonly operation_id: string;
  readonly action: OperatorRecoveryAction;
  readonly classification: RecoveryClassification;
  readonly status: string;
  readonly row_version: number;
  readonly release_status: "RELEASED_T0_UNCHANGED" | null;
  readonly transfer_code_text: string | null;
  readonly transfer_code_sha256: string | null;
  readonly effect: RecoveryActionEffect["kind"];
}

export type RecoveryActionOutcome =
  | {
      readonly status: "ok";
      readonly body: RecoveryActionSuccessBody;
      readonly idempotentReplay?: boolean;
    }
  | {
      readonly status: "rejected";
      readonly reason: RecoveryActionRejectReason;
      readonly detail?: string;
    };

export interface RecoveryActionCommitInput {
  readonly operationId: string;
  readonly action: OperatorRecoveryAction;
  readonly expectedRowVersion: number;
  readonly recoveryNonce: string;
  readonly proofId: string | null;
  readonly operatorNote: string | null;
  readonly operatorId: string;
  readonly totpTimestep: number;
  readonly effect: RecoveryActionEffect;
  readonly classification: RecoveryClassification;
  readonly priorStatus: string;
  readonly idempotencyKey: string;
}

export type RecoveryActionCommitResult =
  | {
      readonly ok: true;
      readonly rowVersion: number;
      readonly status: string;
      readonly releaseStatus: "RELEASED_T0_UNCHANGED" | null;
      readonly transferCodeText: string | null;
      readonly transferCodeSha256: string | null;
    }
  | {
      readonly ok: false;
      readonly reason:
        | "operation_version_conflict"
        | "recovery_nonce_invalid"
        | "predicate_failed"
        | "operation_not_found";
      readonly detail?: string;
    };

/**
 * Persistence port. The store owns the SERIALIZABLE / lock-under-row work:
 * * load fresh RecoveryFacts (same predicates as GET /recovery)
 * * consume ISSUED recovery_nonce under the operation lock
 * * burn totp_timestep under purpose RECOVERY_ACTION
 * * apply the typed effect (CAS on expected_row_version)
 * * append audit_log
 * * complete idempotency with exact response bytes
 *
 * Handlers never open SQL. No method on this port submits a gateway call,
 * regenerates partial bytes, edits economics, or deletes evidence.
 */
export interface RecoveryActionStore {
  lookupIdempotency(
    operationId: string,
    idempotencyKey: string,
  ): Promise<
    | { readonly kind: "miss" }
    | { readonly kind: "hit"; readonly body: RecoveryActionSuccessBody }
    | { readonly kind: "conflict" }
  >;

  /** Fresh durable snapshot under the operation lock (or null if absent). */
  loadRecoveryFactsLocked(operationId: string): Promise<RecoveryFacts | null>;

  /**
   * Atomically: consume nonce + burn TOTP + apply effect + CAS + audit.
   * Must refuse child writes when CAS or nonce fails.
   */
  commitRecoveryAction(input: RecoveryActionCommitInput): Promise<RecoveryActionCommitResult>;

  storeIdempotency(
    operationId: string,
    idempotencyKey: string,
    body: RecoveryActionSuccessBody,
  ): Promise<void>;
}

/**
 * Pure gate: map a permitted action + facts into a typed effect, or reject.
 * No I/O. Callers re-derive permitted set before invoking this.
 */
export function planRecoveryEffect(
  action: OperatorRecoveryAction,
  facts: RecoveryFacts,
  proofId: string | null,
):
  | { readonly ok: true; readonly effect: RecoveryActionEffect }
  | { readonly ok: false; readonly reason: RecoveryActionRejectReason; readonly detail?: string } {
  if (!isActionAdmittedUnderHalt(action, facts.haltEngaged)) {
    return { ok: false, reason: "halt_engaged", detail: action };
  }

  switch (action) {
    case "RETRY_OBSERVATION": {
      // Defence-in-depth mirror of derivePermittedActions (ZTR-1283): expiry-parked
      // receives cannot usefully retry — effect is row_version-only and the sweep
      // will not re-pick attention_required rows.
      if (
        facts.kind === "RECEIVE_EXTERNAL" &&
        facts.status === "EXPIRED" &&
        facts.attentionRequired
      ) {
        return {
          ok: false,
          reason: "predicate_failed",
          detail: "expiry_parked_receive_no_retry",
        };
      }
      return { ok: true, effect: { kind: "RETRY_OBSERVATION" } };
    }

    case "REDELIVER_EXACT_PARTIAL": {
      if (facts.kind !== "SEND_EXTERNAL" || facts.send === null || !facts.send.hasDurablePartial) {
        return { ok: false, reason: "predicate_failed", detail: "no_durable_partial" };
      }
      return { ok: true, effect: { kind: "REDELIVER_EXACT_PARTIAL" } };
    }

    case "CONTINUE_EXTERNAL_WAIT": {
      const s = facts.send;
      if (
        facts.kind !== "SEND_EXTERNAL" ||
        s === null ||
        facts.status !== "NEEDS_ATTENTION" ||
        !s.hasDurablePartial ||
        s.protocolExpiredPlusMargin
      ) {
        return { ok: false, reason: "predicate_failed", detail: "continue_wait_guards" };
      }
      return {
        ok: true,
        effect: {
          kind: "CONTINUE_EXTERNAL_WAIT",
          nextStatus: "AWAITING_REDEMPTION",
          clearAttention: true,
          keepLease: true,
        },
      };
    }

    case "CLOSE_NEVER_STARTED_EXTERNAL_SEND": {
      const s = facts.send;
      if (facts.kind !== "SEND_EXTERNAL" || s === null || facts.status !== "APPROVED") {
        return { ok: false, reason: "predicate_failed", detail: "close_never_started_status" };
      }
      // Re-prove the five negatives under the current snapshot.
      if (
        s.hasSignIntent ||
        s.hasSignerCall ||
        s.hasSignature ||
        s.hasDurablePartial ||
        s.hasDelivery
      ) {
        return { ok: false, reason: "predicate_failed", detail: "formation_boundary_crossed" };
      }
      return {
        ok: true,
        effect: {
          kind: "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
          nextStatus: "REJECTED",
          releaseSourceLease: true,
        },
      };
    }

    case "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED": {
      const s = facts.send;
      if (facts.kind !== "SEND_EXTERNAL" || s === null) {
        return { ok: false, reason: "predicate_failed", detail: "not_send" };
      }
      // Two-part oracle — re-evaluate, never trust prior GET.
      const oracle =
        s.protocolExpiredPlusMargin &&
        (s.freshHeadEqualsSourceT0 || s.completePathExclusionProved);
      if (!oracle) {
        return { ok: false, reason: "predicate_failed", detail: "send_not_landed_oracle" };
      }
      return {
        ok: true,
        effect: {
          kind: "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
          nextStatus: "REJECTED",
          releaseSourceLease: true,
        },
      };
    }

    case "REBUILD_INTERNAL_MOVE": {
      // Structural: proof_id is mandatory BEFORE any DB write (negative path).
      if (proofId === null || proofId.length === 0) {
        return { ok: false, reason: "proof_id_required" };
      }
      const m = facts.move;
      if (facts.kind !== "MOVE_INTERNAL" || m === null) {
        return { ok: false, reason: "predicate_failed", detail: "not_move" };
      }
      if (m.positiveNonLandingProofId === null) {
        return { ok: false, reason: "proof_id_required", detail: "no_stored_positive_proof" };
      }
      if (m.positiveNonLandingProofId !== proofId) {
        return { ok: false, reason: "proof_id_mismatch" };
      }
      if (
        !m.deterministicPreAcceptanceRejection &&
        !m.expiredAndBothWalletsUnchangedAtT0
      ) {
        return { ok: false, reason: "predicate_failed", detail: "move_cases_1_2_absent" };
      }
      if (facts.haltEngaged) {
        return { ok: false, reason: "halt_engaged" };
      }
      return {
        ok: true,
        effect: {
          kind: "REBUILD_INTERNAL_MOVE",
          nextStatus: "CREATED",
          clearAttention: true,
          decision: "SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING",
          proofId,
          archiveOldAttemptUnchanged: true,
          createNextAttemptNumber: true,
          submitOldAttempt: false,
        },
      };
    }

    case "RELEASE_EXPIRED_RECEIVE": {
      const r = facts.receive;
      if (facts.kind !== "RECEIVE_EXTERNAL" || r === null) {
        return { ok: false, reason: "predicate_failed", detail: "not_receive" };
      }
      // All five predicates — re-proved here, not cached from GET.
      if (
        !(
          r.codeExpiredPlusMargin &&
          r.noPersistedLandedProof &&
          r.freshObservationEqualsT0 &&
          r.noAnomalyOrSubmitReconcileDebt &&
          r.childAbsentOrTerminal
        )
      ) {
        return { ok: false, reason: "predicate_failed", detail: "receive_five" };
      }
      return {
        ok: true,
        effect: {
          kind: "RELEASE_EXPIRED_RECEIVE",
          releaseStatus: "RELEASED_T0_UNCHANGED",
          walletPinnedToAvailable: true,
        },
      };
    }

    case "QUARANTINE_WALLETS":
      return {
        ok: true,
        effect: {
          kind: "QUARANTINE_WALLETS",
          walletIds: facts.heldLeases.map((l) => l.walletId),
        },
      };

    case "ACKNOWLEDGE_KEEP_PINNED":
      return {
        ok: true,
        effect: {
          kind: "ACKNOWLEDGE_KEEP_PINNED",
          protocolStateUnchanged: true,
          leasesUnchanged: true,
        },
      };

    default: {
      // Exhaustiveness: a new token without a planner arm fails closed.
      const _exhaustive: never = action;
      return {
        ok: false,
        reason: "action_not_in_catalog",
        detail: String(_exhaustive),
      };
    }
  }
}

/**
 * Full recovery-action path. Re-loads facts, re-derives permitted actions,
 * plans effect, commits under the store's locks. Auth (session/CSRF/TOTP) is a
 * prerequisite of the REQUEST shape — csrfValidated must be the literal true.
 */
export async function executeRecoveryAction(
  store: RecoveryActionStore,
  operationId: string,
  request: RecoveryActionRequest,
): Promise<RecoveryActionOutcome> {
  // CSRF must already be proven by the operator_session_totp chain.
  if (request.csrfValidated !== true) {
    return { status: "rejected", reason: "csrf_required" };
  }

  // Idempotency first — no second mutation for a completed key.
  const prior = await store.lookupIdempotency(operationId, request.idempotencyKey);
  if (prior.kind === "hit") {
    return { status: "ok", body: prior.body, idempotentReplay: true };
  }
  if (prior.kind === "conflict") {
    return { status: "rejected", reason: "idempotency_conflict" };
  }

  // Catalog gate before any operation lock work.
  if (isForbiddenRecoveryAction(request.action)) {
    return { status: "rejected", reason: "action_forbidden", detail: request.action };
  }
  if (!isOperatorRecoveryAction(request.action)) {
    return { status: "rejected", reason: "action_not_in_catalog", detail: request.action };
  }
  const action: OperatorRecoveryAction = request.action;

  // REBUILD without proof_id must reject before any DB write (negative-path AC).
  if (action === "REBUILD_INTERNAL_MOVE" && (request.proofId === null || request.proofId === "")) {
    return { status: "rejected", reason: "proof_id_required" };
  }

  const facts = await store.loadRecoveryFactsLocked(operationId);
  if (facts === null) {
    return { status: "rejected", reason: "operation_not_found" };
  }

  if (facts.rowVersion !== request.expectedRowVersion) {
    return {
      status: "rejected",
      reason: "operation_version_conflict",
      detail: `expected=${request.expectedRowVersion} actual=${facts.rowVersion}`,
    };
  }

  const { classification } = classifyRecovery(facts);
  const permitted = derivePermittedActions(facts, classification);
  if (!permitted.permittedActions.includes(action)) {
    return {
      status: "rejected",
      reason: "action_not_permitted",
      detail: `permitted=${permitted.permittedActions.join(",")}`,
    };
  }

  const planned = planRecoveryEffect(action, facts, request.proofId);
  if (!planned.ok) {
    return { status: "rejected", reason: planned.reason, detail: planned.detail };
  }

  const committed = await store.commitRecoveryAction({
    operationId,
    action,
    expectedRowVersion: request.expectedRowVersion,
    recoveryNonce: request.recoveryNonce,
    proofId: request.proofId,
    operatorNote: request.operatorNote,
    operatorId: request.operatorId,
    totpTimestep: request.totpTimestep,
    effect: planned.effect,
    classification,
    priorStatus: facts.status,
    idempotencyKey: request.idempotencyKey,
  });

  if (!committed.ok) {
    return {
      status: "rejected",
      reason: committed.reason,
      detail: committed.detail,
    };
  }

  const body: RecoveryActionSuccessBody = {
    operation_id: operationId,
    action,
    classification,
    status: committed.status,
    row_version: committed.rowVersion,
    release_status: committed.releaseStatus,
    transfer_code_text: committed.transferCodeText,
    transfer_code_sha256: committed.transferCodeSha256,
    effect: planned.effect.kind,
  };

  await store.storeIdempotency(operationId, request.idempotencyKey, body);
  return { status: "ok", body };
}

/**
 * Structural census: effects this module can never emit. Used by tests so a
 * future "helpful" edit that adds FORCE_LANDED as an Effect kind fails closed.
 */
export const STRUCTURALLY_ABSENT_RECOVERY_EFFECTS = [
  "FORCE_LANDED",
  "FORCE_RELEASE",
  "RETRY_SUBMIT",
  "RESUBMIT",
  "EDIT_TRANSACTION",
  "CHANGE_DESTINATION",
  "CHANGE_AMOUNT",
  "REFORM_EXTERNAL_SEND",
  "NODE_SUBMIT_EXTERNAL_SEND",
  "DELETE_EVIDENCE",
  "SKIP_VERIFICATION",
  "SUBMIT_OLD_ATTEMPT",
  "BLIND_SUBMIT",
] as const;
