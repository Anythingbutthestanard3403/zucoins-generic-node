// Single-shot submit claim and execution for MOVE_INTERNAL.
//
// Step 9 of formation: claim SUBMIT(attempt_1) and invoke once, persist response
// bytes/outcome, never submit this attempt again. A submit call is single-shot for one exact
// authorized attempt; the claim/call is recorded regardless of response, and recovery
// reconciles by receiver observation rather than resubmitting. Landing-path oracle; golden
// rule 4 (never blind-retry a submit).
//
// The at-most-once guarantee is arbitrated by the database, not by this service. The store
// seam exposes exactly one operation — claimSubmitOnce — which both writes the claim and
// reports whether THIS call won the mint. There is deliberately no separate "does a claim
// exist?" read: a read followed by a write is two operations with a suspension point between
// them, so two concurrent workers both observe "no claim", both write, and both proceed to
// the gateway. Collapsing the pair into one arbitrated operation makes that race
// unrepresentable at the seam rather than guarded against at one call site.

import {
  submitGatewayActionOnce,
  SubmitIndeterminateError,
  type SubmitAuthorization,
  type SubmitGatewayActionOptions,
} from "../gateway/submit.js";
import type { GatewayExchangeCapture } from "../gateway/capture.js";
import { defaultNowIso, type GatewaySubmitAttemptRecord } from "../gateway/records.js";
import { mintSubmitClaim, type SubmitClaim } from "../protocol/reconcile/submit-authority.js";

import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";

// The durable single-shot claim for one move attempt ("Exact attempt identity
// survives crashes"). It is a submit_decisions row: `attemptId` is its `id`, and
// `(operationId, transactionAttemptNo)` is the uniqueness key the database arbitrates on.
export interface MoveSubmitClaim extends SubmitClaim {
  readonly operationId: string;
  readonly transactionAttemptNo: number;
}

// The outcome of one claimSubmitOnce call. `claim` is always the attempt's one durable claim;
// `minted` is true only for the single call that created it. A loser receives the winner's
// claim with minted=false and must never submit.
export interface MoveSubmitClaimMint {
  readonly claim: MoveSubmitClaim;
  readonly minted: boolean;
}

// The persistence seam. Implementations MUST arbitrate the mint in the database — the
// backing constraint is submit_decisions UNIQUE (operation_id, transaction_attempt_no)
// — and MUST NOT decide `minted` from a prior read, which cannot be atomic with the
// write. See makeSubmitDecisionClaimStore for the SQL implementation.
export interface MoveSubmitClaimStore {
  claimSubmitOnce(claim: MoveSubmitClaim): Promise<MoveSubmitClaimMint>;
}

// The closed outcome of the one submit exchange, named for the move operation. ACK is
// receipt-only (receipt-only ACK posture / C-09: a gateway acknowledgement is NEVER settlement — landing is
// proven only by a fresh signature-verified observation via the landing-path oracle, which lives
// elsewhere). AMBIGUOUS is the transport-ambiguity / non-2xx/4xx class: reconcile-only — no
// re-attempt, no rebuild, no assumed failure (the never-blind-retry rule).
export type MoveSubmitOutcomeStatus = "ACK" | "REJECT" | "AMBIGUOUS";

// The recorded result of the one shot. `capture` is null exactly when transport ambiguity
// left no complete response; `recordedAttempt` is the append-only gateway_submit_attempts
// evidence the submit primitive persisted for the exchange (or its ambiguous
// attempt).
export interface MoveSubmitRecordedOutcome {
  readonly status: MoveSubmitOutcomeStatus;
  readonly capture: GatewayExchangeCapture | null;
  readonly recordedAttempt: GatewaySubmitAttemptRecord;
}

// The result of executeMoveSubmitClaim. `executed` is true only for the one call that won the
// mint and made the exchange; every other call for the same attempt returns executed=false
// with a null recordedOutcome. A null recordedOutcome is itself the reconcile-only signal:
// this attempt's outcome must be established by observation, never by a second submit.
export interface MoveSubmitExecutionResult {
  readonly claim: MoveSubmitClaim;
  readonly executed: boolean;
  readonly recordedOutcome: MoveSubmitRecordedOutcome | null;
}

// Raised when the one shot is AMBIGUOUS and the attempt evidence could not be persisted: the
// submit primitive surfaces a recorder failure after the exchange as a SubmitIndeterminateError
// with the unpersisted attempt attached. The exchange may have landed with no attempt row to
// evidence it, so the only safe next step is reconcile — never rebuild, never resubmit, never
// assume failed (the never-blind-retry rule).
export class MoveSubmitAmbiguousError extends Error {
  constructor(
    message: string,
    readonly claim: MoveSubmitClaim,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "MoveSubmitAmbiguousError";
  }
}

export interface ExecuteMoveSubmitClaimOptions {
  readonly authorization: SubmitAuthorization;
  // The exact signed transaction submitted as the move's one shot. Its byte-exact
  // JSON.stringify form is the gateway action data; this service never reformats it
  // (the byte-exact signing rule).
  readonly signedTransaction: unknown;
  readonly claimStore: MoveSubmitClaimStore;
  readonly submit: SubmitGatewayActionOptions;
  /** Fired when claimSubmitOnce returns minted=false (uniqueness loser) — ZTR-1144. */
  readonly onDuplicateSubmitRejection?: () => void;
}

// Claim SUBMIT(attempt) and invoke once (step 9). The gateway call is reachable on
// exactly one branch — the one where the database awarded this caller the mint. Losing the
// mint (a concurrent worker, or a claim recovered from a crashed run) yields executed=false
// with no exchange at all.
export async function executeMoveSubmitClaim(
  options: ExecuteMoveSubmitClaimOptions,
): Promise<MoveSubmitExecutionResult> {
  const { authorization, claimStore } = options;
  const nowIso = options.submit.nowIso ?? defaultNowIso;

  // Claim BEFORE crossing the irreversible boundary: the durable record exists no matter
  // where a crash lands after this point, which is what stops a second call.
  const { claim, minted } = await claimStore.claimSubmitOnce({
    ...mintSubmitClaim(authorization.submitDecisionId, nowIso()),
    operationId: authorization.operationId,
    transactionAttemptNo: authorization.transactionAttemptNo,
  });

  if (!minted) {
    options.onDuplicateSubmitRejection?.();
    return { claim, executed: false, recordedOutcome: null };
  }

  let shot;
  try {
    shot = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      options.signedTransaction,
      authorization,
      options.submit,
    );
  } catch (error) {
    if (error instanceof SubmitIndeterminateError) {
      // The exchange completed but its attempt evidence could not be persisted: the outcome is
      // AMBIGUOUS and the only safe next step is reconcile (the never-blind-retry rule).
      throw new MoveSubmitAmbiguousError(
        "move submit outcome is AMBIGUOUS: attempt evidence could not be persisted after the exchange — reconcile is the only safe next step, never resubmit (the never-blind-retry rule)",
        claim,
        { cause: error },
      );
    }
    throw error;
  }

  const status: MoveSubmitOutcomeStatus =
    shot.transportOutcome === "INDETERMINATE" ? "AMBIGUOUS" : shot.transportOutcome;
  return {
    claim,
    executed: true,
    recordedOutcome: { status, capture: shot.capture, recordedAttempt: shot.recordedAttempt },
  };
}
