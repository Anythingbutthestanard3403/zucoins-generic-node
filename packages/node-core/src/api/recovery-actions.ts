// admin recovery-actions route (mutating).
//
// Landing-path oracle.
//
// POST /admin/v1/operations/:operation_id/recovery-actions
// authMode: operator_session_totp (session + CSRF + fresh single-use TOTP)
// Idempotency-Key: required
//
// Body (frozen): {action, expected_row_version, recovery_nonce, proof_id, operator_note}
//
// Pure planning + guarded execution live in `../operator/recovery-actions.js`.
// This module is the request surface: body schema, handler outcome → HTTP map.
// Shells run operator_session_totp (session + CSRF + TOTP) before calling
// handleRecoveryAction; csrfValidated is then the literal true on the request.

import {
  executeRecoveryAction,
  type RecoveryActionOutcome,
  type RecoveryActionRequest,
  type RecoveryActionStore,
  type RecoveryActionSuccessBody,
} from "../operator/recovery-actions.js";
import { apiErrorResponse, type ApiErrorCode } from "./error-envelope.js";
import {
  RecoveryActionsBody,
  type RecoveryActionsBodyInput,
} from "./route-schemas.js";

export type RecoveryActionsBodyParsed = RecoveryActionsBodyInput;
export { RecoveryActionsBody };

export {
  FORBIDDEN_RECOVERY_ACTIONS,
  OPERATOR_RECOVERY_ACTIONS,
  STRUCTURALLY_ABSENT_RECOVERY_EFFECTS,
  executeRecoveryAction,
  isForbiddenRecoveryAction,
  isOperatorRecoveryAction,
  planRecoveryEffect,
  type RecoveryActionCommitInput,
  type RecoveryActionCommitResult,
  type RecoveryActionEffect,
  type RecoveryActionOutcome,
  type RecoveryActionRejectReason,
  type RecoveryActionRequest,
  type RecoveryActionStore,
  type RecoveryActionSuccessBody,
} from "../operator/recovery-actions.js";

export const RECOVERY_ACTIONS_PATH =
  "/admin/v1/operations/:operation_id/recovery-actions" as const;

/** Auth factors already proven by operator_session_totp + CSRF. */
export interface RecoveryActionAuthContext {
  readonly operatorId: string;
  readonly totpTimestep: number;
  readonly csrfValidated: true;
  readonly idempotencyKey: string;
}

export type HandleRecoveryActionResult =
  | {
      readonly ok: true;
      readonly status: 200;
      readonly body: RecoveryActionSuccessBody;
      readonly headers?: Readonly<Record<string, string>>;
    }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: ApiErrorCode;
      readonly reason: string;
    };

const IDEMPOTENT_REPLAY_HEADERS: Readonly<Record<string, string>> = {
  "Idempotency-Replayed": "true",
};

function mapReject(
  outcome: Extract<RecoveryActionOutcome, { status: "rejected" }>,
): HandleRecoveryActionResult {
  switch (outcome.reason) {
    case "operation_not_found":
      return { ok: false, status: 404, code: "not_found", reason: outcome.reason };
    case "operation_version_conflict":
      return {
        ok: false,
        status: 409,
        code: "operation_version_conflict",
        reason: outcome.reason,
      };
    case "idempotency_conflict":
      return {
        ok: false,
        status: 409,
        code: "idempotency_conflict",
        reason: outcome.reason,
      };
    case "action_not_in_catalog":
    case "action_forbidden":
      return { ok: false, status: 400, code: "invalid_scalar", reason: outcome.reason };
    case "csrf_required":
      return { ok: false, status: 401, code: "invalid_api_key", reason: outcome.reason };
    case "recovery_nonce_invalid":
    case "action_not_permitted":
    case "proof_id_required":
    case "proof_id_mismatch":
    case "halt_engaged":
    case "predicate_failed":
      return {
        ok: false,
        status: 422,
        code: "protocol_predicate_failed",
        reason: outcome.reason,
      };
    default: {
      const _e: never = outcome.reason;
      return {
        ok: false,
        status: 503,
        code: "service_unavailable",
        reason: String(_e),
      };
    }
  }
}

/**
 * POST recovery-actions handler. Body must already pass RecoveryActionsBody
 * (unknown_field / invalid action rejected by pipeline before TOTP per step 2).
 */
export async function handleRecoveryAction(
  store: RecoveryActionStore,
  operationId: string,
  body: RecoveryActionsBodyInput,
  auth: RecoveryActionAuthContext,
): Promise<HandleRecoveryActionResult> {
  const request: RecoveryActionRequest = {
    action: body.action,
    expectedRowVersion: body.expected_row_version,
    recoveryNonce: body.recovery_nonce,
    proofId: body.proof_id ?? null,
    operatorNote: body.operator_note ?? null,
    idempotencyKey: auth.idempotencyKey,
    operatorId: auth.operatorId,
    totpTimestep: auth.totpTimestep,
    csrfValidated: true,
  };

  const outcome = await executeRecoveryAction(store, operationId, request);
  if (outcome.status === "rejected") {
    return mapReject(outcome);
  }
  return {
    ok: true,
    status: 200,
    body: outcome.body,
    headers: outcome.idempotentReplay ? IDEMPOTENT_REPLAY_HEADERS : undefined,
  };
}

/** Convenience for shells that want the frozen apiErrorResponse envelope. */
export function recoveryActionErrorEnvelope(
  result: Extract<HandleRecoveryActionResult, { ok: false }>,
  requestId: string,
) {
  return apiErrorResponse(result.code, requestId);
}

