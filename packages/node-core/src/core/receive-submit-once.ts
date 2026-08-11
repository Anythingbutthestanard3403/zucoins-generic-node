// Submit-once service for RECEIVE_EXTERNAL. Governing:
// Formation step 9; landing-path oracle; the never-blind-retry rule.
//
// The at-most-once guarantee is arbitrated by the persistence seam, not by this service.
// The store exposes exactly one operation — claimSubmitOnce — which both writes the claim
// and reports whether THIS call won the mint. There is deliberately no separate
// "does a claim exist?" read: a read followed by a write is two operations with a suspension
// point between them, so two concurrent workers both observe "no claim", both write, and both
// proceed to the gateway. Collapsing the pair into one arbitrated operation makes that race
// unrepresentable at the seam (same discipline as MOVE_INTERNAL's move-submit-claim.ts).

import {
  type SubmitTransportOutcome,
  type GatewaySubmitAttemptRecord,
  type NowIsoFn,
  defaultNowIso,
} from "../gateway/records.js";
import {
  submitGatewayRequestOnce,
  SubmitIndeterminateError,
  type SubmitAuthorization,
  type SubmitGatewayActionOptions,
} from "../gateway/submit.js";
import type { GatewayRequest } from "../protocol/index.js";
import {
  captureSubmitAcknowledgement,
  mintSubmitClaim,
  type SubmitAcknowledgement,
  type SubmitClaim,
} from "../protocol/reconcile/submit-authority.js";
import { type ReconcileIndeterminateReason } from "../protocol/reconcile/types.js";
import type { MetricsHooks } from "./metrics.js";

export type ReceiveSubmitOnceResult =
  | {
      readonly kind: "SUBMITTED";
      readonly transportOutcome: SubmitTransportOutcome;
      readonly claim: ReceiveSubmitClaim;
      readonly acknowledgement: SubmitAcknowledgement;
      readonly recordedAttempt: GatewaySubmitAttemptRecord;
    }
  | {
      readonly kind: "AMBIGUOUS";
      readonly claim: ReceiveSubmitClaim;
      readonly reason: ReconcileIndeterminateReason;
      readonly recordedAttempt: GatewaySubmitAttemptRecord;
    };

// The durable single-shot claim for one receive attempt. `attemptId` is the receive-attempt
// identity; `(operationId, transactionAttemptNo)` is the uniqueness key the store arbitrates
// on — the same pair submit_decisions uses for MOVE.
export interface ReceiveSubmitClaim extends SubmitClaim {
  readonly operationId: string;
  readonly transactionAttemptNo: number;
}

// Outcome of one claimSubmitOnce call. `claim` is always the attempt's one durable claim;
// `minted` is true only for the single call that created it. A loser receives the winner's
// claim with minted=false and must never submit.
export interface ReceiveSubmitClaimMint {
  readonly claim: ReceiveSubmitClaim;
  readonly minted: boolean;
}

// The persistence seam. Implementations MUST arbitrate the mint atomically and MUST NOT
// decide `minted` from a prior read (which cannot be atomic with the write).
export interface SubmitClaimStore {
  claimSubmitOnce(claim: ReceiveSubmitClaim): Promise<ReceiveSubmitClaimMint>;
}

export interface ReceiveSubmitOnceInput {
  readonly receiveAttemptId: string;
  readonly signedRequest: GatewayRequest;
  readonly authorization: SubmitAuthorization;
  readonly submitOptions: SubmitGatewayActionOptions;
  readonly claimStore: SubmitClaimStore;
  readonly metricsHooks?: MetricsHooks;
  readonly nowIso?: NowIsoFn;
}

export async function receiveSubmitOnce(
  input: ReceiveSubmitOnceInput,
): Promise<ReceiveSubmitOnceResult> {
  const nowIso = input.nowIso ?? defaultNowIso;
  const { receiveAttemptId, signedRequest, authorization, submitOptions, claimStore } = input;

  // Claim BEFORE crossing the irreversible boundary: the durable record exists no matter
  // where a crash lands after this point, which is what stops a second call.
  const { claim, minted } = await claimStore.claimSubmitOnce({
    ...mintSubmitClaim(receiveAttemptId, nowIso()),
    operationId: authorization.operationId,
    transactionAttemptNo: authorization.transactionAttemptNo,
  });

  if (!minted) {
    input.metricsHooks?.onDuplicateSubmitRejection();
    return {
      kind: "AMBIGUOUS",
      claim,
      reason: { source: "SUBMIT_OUTCOME_UNKNOWN" },
      recordedAttempt: {
        decisionId: authorization.submitDecisionId,
        operationId: authorization.operationId,
        attemptNo: 1,
        transactionAttemptNo: authorization.transactionAttemptNo,
        requestBytes: signedRequest.bodyBytes,
        requestSha256: "",
        responseBytes: null,
        responseSha256: null,
        transportOutcome: "INDETERMINATE",
        startedAt: nowIso(),
        completedAt: null,
      },
    };
  }

  try {
    const submit = (): ReturnType<typeof submitGatewayRequestOnce> =>
      submitGatewayRequestOnce(signedRequest, authorization, submitOptions);
    const result = input.metricsHooks
      ? await input.metricsHooks.timeGateway("submit_transaction__v1", submit)
      : await submit();

    if (result.transportOutcome === "INDETERMINATE") {
      input.metricsHooks?.onSubmit("ambiguous");
      return {
        kind: "AMBIGUOUS",
        claim,
        reason: { source: "SUBMIT_OUTCOME_UNKNOWN" },
        recordedAttempt: result.recordedAttempt,
      };
    }

    const acknowledgement = captureSubmitAcknowledgement(
      receiveAttemptId,
      result.transportOutcome === "ACK",
      result.transportOutcome === "ACK" ? "ok" : "rejected",
      nowIso(),
    );
    input.metricsHooks?.onSubmit(result.transportOutcome === "ACK" ? "accepted" : "rejected");

    return {
      kind: "SUBMITTED",
      transportOutcome: result.transportOutcome,
      claim,
      acknowledgement,
      recordedAttempt: result.recordedAttempt,
    };
  } catch (error) {
    if (error instanceof SubmitIndeterminateError) {
      input.metricsHooks?.onSubmit("ambiguous");
      return {
        kind: "AMBIGUOUS",
        claim,
        reason: { source: "SUBMIT_OUTCOME_UNKNOWN" },
        recordedAttempt: error.recordedAttempt,
      };
    }
    input.metricsHooks?.onSubmit("error");
    throw error;
  }
}
