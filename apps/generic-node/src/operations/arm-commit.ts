// Guarded arm commit after pre-open.
//
// Consumes a successful ArmPreopenResult (credential + binding + matching T0 already
// prepared) and runs createArmMutationService under the wallet-lock gate.
// On success returns the arm response body and a persistChild that names the
// receive_arms child for the reporting completed-idempotency parent.
//
// Reporting nonce consumption is owned by the reporting pipeline (burn before handler);
// the SQL ArmStore envelope binds the burned nonce id into receive_arms.reporting_nonce_id.
// Bearer implementer keys and subscription handles never reach this path — the handler
// is only registered under REPORTING_ROUTE_IDS.operationArmed.

import { randomUUID } from "node:crypto";

import {
  apiErrorResponse,
  buildArmSuccessResponse,
  createArmMutationService,
  type ArmAuditLog,
  type ArmClock,
  type ArmMutationService,
  type ArmOperationState,
  type ArmOutcome,
  type ArmPreopenResult,
  type ArmRecord,
  type ArmSignatureVerifier,
  type ArmStore,
  type ArmSuccessResponse,
  type ArmWalletGate,
  type ReportingHandlerResult,
  type ReportingHttpResponse,
  type ReportingMutationTx,
  type SqlArmInsertEnvelope,
} from "@zucoins/node-core";

export type ArmCommitPreopen = Extract<ArmPreopenResult, { ok: true }>;

export interface ArmCommitDeps {
  readonly walletGate: ArmWalletGate;
  readonly armStore: ArmStore;
  readonly operationState: ArmOperationState;
  readonly auditLog: ArmAuditLog;
  readonly clock: ArmClock;
  /** Protocol clock for the unexpired guard (unix ms). */
  readonly nowMs: () => number;
  /**
   * Resolve the assigned receiver wallet id for the operation (tenant-scoped).
   * Required because the pre-open binding does not carry wallet_id on the wire.
   */
  readonly resolveReceiverWalletId: (input: {
    readonly operationId: string;
    readonly nodeId: string;
    readonly implementerId: string;
  }) => Promise<string | null>;
  readonly newRequestId: () => string;
  /**
   * Child id returned to the reporting UoW as receive_arms PK (`id`).
   * Default: randomUUID(). Composition roots that pre-allocate the arm id for the
   * SQL envelope MUST return the same value here so parent/child FKs agree.
   */
  readonly armChildIdFor?: (input: {
    readonly record: ArmRecord;
    readonly preopen: ArmCommitPreopen;
  }) => string;
  /** Optional assigned-signer gate (unit fixtures only; live path uses reporting credential). */
  readonly signatureVerifier?: ArmSignatureVerifier;
}

function apiToReporting(api: {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}): ReportingHttpResponse {
  return {
    status: api.status,
    headers: api.headers,
    bodyBytes: new TextEncoder().encode(api.body),
  };
}

function mapOutcomeToHandlerResult(
  outcome: ArmOutcome,
  requestId: string,
  operationId: string,
  armChildId: string | null,
): ReportingHandlerResult {
  if (outcome.status === "armed" || outcome.status === "already_armed") {
    const body = buildArmSuccessResponse({
      operationId,
      release: outcome.release,
    }) satisfies ArmSuccessResponse;
    const bodyText = JSON.stringify(body);
    return {
      response: {
        status: 200,
        headers: { "content-type": "application/json" },
        bodyBytes: new TextEncoder().encode(bodyText),
      },
      // First-write and same-key already_armed both supply the arm child id so the
      // reporting runtime can complete the idempotency parent.
      // already_armed under a *new* Idempotency-Key is a fingerprint conflict owned by
      // the reporting layer before this handler runs.
      persistChild:
        armChildId === null
          ? null
          : async (_tx: ReportingMutationTx) => armChildId,
    };
  }

  if (outcome.status === "t0_mismatch") {
    return {
      response: apiToReporting(apiErrorResponse("t0_mismatch", requestId)),
      persistChild: null,
    };
  }
  if (outcome.status === "verification_mode_mismatch") {
    // NODE_VERIFIED refuse — no mutation, no attention (ZTR-1302 AC3).
    return {
      response: apiToReporting(apiErrorResponse("verification_mode_mismatch", requestId)),
      persistChild: null,
    };
  }
  if (outcome.status === "operation_version_conflict") {
    return {
      response: apiToReporting(apiErrorResponse("operation_version_conflict", requestId)),
      persistChild: null,
    };
  }
  // operation_not_armable + invalid_signature (unreachable on live reporting path)
  return {
    response: apiToReporting(apiErrorResponse("operation_not_armable", requestId)),
    persistChild: null,
  };
}

/**
 * Build a commitArm hook for createArmRouteHandler from mutation ports.
 * The returned function is the sole place that releases transfer_code bytes on the
 * reporting operation_armed route.
 */
export function createArmCommitHook(deps: ArmCommitDeps): (
  preopen: ArmCommitPreopen,
) => Promise<ReportingHandlerResult> {
  const service: ArmMutationService = createArmMutationService({
    armStore: deps.armStore,
    operationState: deps.operationState,
    auditLog: deps.auditLog,
    clock: deps.clock,
    walletGate: deps.walletGate,
    signatureVerifier: deps.signatureVerifier,
  });

  return async (preopen: ArmCommitPreopen): Promise<ReportingHandlerResult> => {
    const requestId = deps.newRequestId();
    const { binding, reporting } = preopen;

    // Defensive: pre-open already rejects mismatch before calling commitArm.
    if (preopen.mismatchField !== null) {
      return {
        response: apiToReporting(apiErrorResponse("t0_mismatch", requestId)),
        persistChild: null,
      };
    }

    const walletId = await deps.resolveReceiverWalletId({
      operationId: binding.operationId,
      nodeId: reporting.nodeId,
      implementerId: reporting.implementerId,
    });
    if (walletId === null) {
      return {
        response: apiToReporting(apiErrorResponse("operation_not_armable", requestId)),
        persistChild: null,
      };
    }

    const outcome = await service.arm({
      operationId: binding.operationId,
      walletId,
      nodeT0ObservationId: binding.nodeT0ObservationId,
      acknowledgedS: binding.consumerProjection.s,
      acknowledgedP: binding.consumerProjection.p,
      acknowledgedB: binding.consumerProjection.b_zkz,
      openedCursor: binding.openedCursor,
      expectedRowVersion: binding.expectedRowVersion,
      nowMs: deps.nowMs(),
    });

    let armChildId: string | null = null;
    if (outcome.status === "armed" || outcome.status === "already_armed") {
      armChildId =
        deps.armChildIdFor?.({ record: outcome.record, preopen }) ?? randomUUID();
    }

    return mapOutcomeToHandlerResult(outcome, requestId, binding.operationId, armChildId);
  };
}

/**
 * Helper for SQL ArmStore envelope construction from a successful pre-open.
 * `reportingNonceId` must be the durable `reporting_request_nonces.id` (already burned),
 * not the client nonce string. `mutationIdempotencyId` is the completion parent PK the
 * reporting UoW inserts as `draft.id` (randomUUID) and passes into persistChild — child
 * `mutation_idempotency_id` must equal that id. Replay looks up by composite key, not PK.
 */
export function defaultArmInsertEnvelope(input: {
  readonly armId: string;
  readonly preopen: ArmCommitPreopen;
  readonly reportingNonceId: string;
  readonly mutationIdempotencyId: string;
}): SqlArmInsertEnvelope {
  return {
    armId: input.armId,
    nodeId: input.preopen.reporting.nodeId,
    implementerId: input.preopen.reporting.implementerId,
    rawTarget: input.preopen.reporting.rawTarget,
    requestBodySha256: input.preopen.reporting.bodySha256,
    reportingNonceId: input.reportingNonceId,
    mutationIdempotencyId: input.mutationIdempotencyId,
  };
}
