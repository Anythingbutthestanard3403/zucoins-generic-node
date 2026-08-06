// SEND_EXTERNAL reconcile outcomes.
// External-send recovery.
//
// SEND_EXTERNAL is the one operation with a genuine WAITING member: once the node's signed
// step-1 partial is durable, an external recipient — not the node — must co-sign and submit
// ("The node never submits SEND_EXTERNAL"). The safe automatic actions
// while awaiting redemption (bounded reads, verify a recipient-completed tx, re-serve the
// identical persisted transfer code) are exactly WAITING's definition: "Exact external
// partial remains valid and no contradictory evidence exists... optional exact redelivery
// only."
//
// This union has NO member, field, or branch that could close or release a delivered partial:
// Forbids "free the source lease because the recipient has not acted," and Appendix
// (states.contract.ts) is explicit that "There is no transition from a delivered
// AWAITING_REDEMPTION/NEEDS_ATTENTION partial to REJECTED in launch" — yet
// operations/states.contract.ts's SEND_EXTERNAL_TRANSITIONS already contains exactly that
// forbidden `NEEDS_ATTENTION -> REJECTED` row (citing a "positive non-landing oracle" landing-path oracle
// explicitly says does not exist). This module deliberately does not import or reuse that
// contract's transition table; see send.matrix.test.ts for the unrepresentability proof.

import {
  type LeaseLifecycleState,
} from "@zucoins/generic-node-contracts/wallet-state";

import { type LandingPathProof } from "./landing-proof.js";
import { type PathObservation, classifyPathObservation } from "./observation-input.js";
import {
  type ReconcileIndeterminateReason,
  type ReconcileInvariantBreachReason,
  assertUnreachable,
} from "./types.js";

export type SendNeverCrossedBoundary = "SIGNER" | "SUBMITTER";
export type SendResumeAction = "FIRST_FORMATION" | "SIGN_PERSISTED_PREIMAGE";

// The closed outcome union for SEND_EXTERNAL. `SUBMITTER` never appears as a
// `neverCrossedBoundary` value here (unlike receive.ts/move.ts) because the node never submits
// a send at all — there is no submitter boundary for this operation to prove uncrossed.
export type SendReconcileOutcome =
  | { readonly kind: "LANDED_VERIFIED"; readonly sendAttemptId: string; readonly sourcePath: LandingPathProof }
  | {
      readonly kind: "PROVEN_NOT_STARTED";
      readonly sendOperationId: string;
      readonly neverCrossedBoundary: SendNeverCrossedBoundary;
      readonly resumeAction: SendResumeAction;
    }
  | {
      readonly kind: "WAITING";
      readonly sendAttemptId: string;
      readonly redeliverableTransferCodeSha256: string;
    }
  | {
      readonly kind: "INDETERMINATE";
      readonly sendAttemptId: string;
      readonly reason: ReconcileIndeterminateReason;
    }
  | {
      readonly kind: "INVARIANT_BREACH";
      readonly sourceWalletId: string;
      readonly reason: ReconcileInvariantBreachReason;
    };

// Durable evidence before the deterministic step-1 signature (and therefore the partial
// and transfer code) exist.
export interface SendFormationEvidence {
  readonly boundary: "PRE_DELIVERY";
  readonly sendOperationId: string;
  readonly signIntentPersisted: boolean;
  readonly step1SignaturePersisted: boolean;
  readonly signerAuditIndicatesCall: boolean;
}

// The partial is delivered and durable; the recipient, not the node, must act. The only
// safe automatic actions are bounded reads, verifying a recipient-completed transaction, and
// re-serving the identical persisted code — never re-forming, never freeing the source lease
// for silence alone.
export interface SendDeliveredEvidence {
  readonly boundary: "DELIVERED";
  readonly sendAttemptId: string;
  readonly sourceWalletId: string;
  readonly sourceLeaseState: LeaseLifecycleState;
  readonly transferCodeSha256: string;
  readonly sourceObservation: PathObservation;
}

export type SendReconcileInput = SendFormationEvidence | SendDeliveredEvidence;

export function classifySendReconcile(input: SendReconcileInput): SendReconcileOutcome {
  if (input.boundary === "PRE_DELIVERY") {
    const { sendOperationId, signIntentPersisted, step1SignaturePersisted, signerAuditIndicatesCall } =
      input;

    if (!signIntentPersisted) {
      // "If the database says sign intent is absent but signer audit indicates a call...
      // classification is INVARIANT_BREACH, not PROVEN_NOT_STARTED."
      if (signerAuditIndicatesCall) {
        return {
          kind: "INVARIANT_BREACH",
          sourceWalletId: sendOperationId,
          reason: { source: "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD" },
        };
      }
      // Row 1: "APPROVED; no source lease, sign intent, or signer audit | Acquire lease
      // and begin first formation."
      return {
        kind: "PROVEN_NOT_STARTED",
        sendOperationId,
        neverCrossedBoundary: "SIGNER",
        resumeAction: "FIRST_FORMATION",
      };
    }

    if (!step1SignaturePersisted) {
      if (signerAuditIndicatesCall) {
        return {
          kind: "INVARIANT_BREACH",
          sourceWalletId: sendOperationId,
          reason: { source: "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD" },
        };
      }
      // Row 3: "Exact sign intent/preimage persisted; signature absent | Sign the
      // identical preimage. Never refresh either chain link."
      return {
        kind: "PROVEN_NOT_STARTED",
        sendOperationId,
        neverCrossedBoundary: "SIGNER",
        resumeAction: "SIGN_PERSISTED_PREIMAGE",
      };
    }

    // Step 3 persists the step-1 signature and the `APPROVED -> AWAITING_REDEMPTION`
    // transition in the SAME DB-TX — durable step1SignaturePersisted=true therefore implies the
    // caller should have supplied `SendDeliveredEvidence`, not this PRE_DELIVERY shape. Seeing
    // the signature persisted while boundary evidence still reports PRE_DELIVERY contradicts
    // that atomicity guarantee: stored phases/bytes cannot arise under the contract.
    return {
      kind: "INVARIANT_BREACH",
      sourceWalletId: sendOperationId,
      reason: { source: "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD" },
    };
  }

  // DELIVERED: the node never submits, so the only path to LANDED_VERIFIED is the
  // RECIPIENT's completed submit, observed on the source wallet's lineage.
  if (input.sourceLeaseState !== "ACTIVE") {
    return {
      kind: "INVARIANT_BREACH",
      sourceWalletId: input.sourceWalletId,
      reason: { source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" },
    };
  }

  const classification = classifyPathObservation(input.sourceObservation);
  switch (classification.tier) {
    case "LANDED":
      return {
        kind: "LANDED_VERIFIED",
        sendAttemptId: input.sendAttemptId,
        sourcePath: classification.proof,
      };
    case "INVARIANT_BREACH":
      return {
        kind: "INVARIANT_BREACH",
        sourceWalletId: input.sourceWalletId,
        reason: classification.reason,
      };
    case "INDETERMINATE":
      // "exact external partial remains valid and no contradictory evidence exists" is
      // WAITING — and NO_SUCCESSOR_OBSERVED (a clean unchanged-head read) is the only
      // indeterminate reason that evidence shape produces. The recovery table is equally explicit that a
      // GENUINE gap/anomaly/contradiction/resource-exhaustion — every other reason this
      // classifier can return — stays INDETERMINATE even for a delivered send partial: "keep
      // the immutable partial, approval, observations, source lease, and audit trail." Only
      // this one reason downgrades to WAITING; nothing here ever authorizes closing or
      // releasing the delivered partial (see the module header's states.contract.ts citation).
      if (classification.reason.source === "NO_SUCCESSOR_OBSERVED") {
        return {
          kind: "WAITING",
          sendAttemptId: input.sendAttemptId,
          redeliverableTransferCodeSha256: input.transferCodeSha256,
        };
      }
      return {
        kind: "INDETERMINATE",
        sendAttemptId: input.sendAttemptId,
        reason: classification.reason,
      };
    default:
      return assertUnreachable(classification);
  }
}
