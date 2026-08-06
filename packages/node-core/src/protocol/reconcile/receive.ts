// RECEIVE_EXTERNAL reconcile outcomes.
// Receive recovery.
// landing-path oracle.
//
// RECEIVE_EXTERNAL has no WAITING member. The node itself signs step 2 and submits
// ("The node may submit the initial transaction for RECEIVE_EXTERNAL
// after validating the external step 1 and producing step 2"), so there is never an "our
// signed partial awaiting an external party's completion" state the way SEND_EXTERNAL's
// AWAITING_REDEMPTION is. An unpaid, still-open receive code is PROVEN_NOT_STARTED (nothing to
// sign yet because no external step-1 has arrived), never WAITING.

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

export type ReceiveNeverCrossedBoundary = "SIGNER" | "SUBMITTER";
export type ReceiveResumeAction =
  | "RESUME_T0_AND_CODE_FORMATION"
  | "SIGN_PERSISTED_STEP2_PREIMAGE"
  | "SUBMIT_ONCE";

// The closed outcome union for RECEIVE_EXTERNAL. Every `kind` is drawn from
// RECONCILE_CLASSIFICATION_KINDS (types.ts); WAITING is intentionally absent (see header).
export type ReceiveReconcileOutcome =
  | { readonly kind: "LANDED_VERIFIED"; readonly receiveAttemptId: string; readonly receiverPath: LandingPathProof }
  | {
      readonly kind: "PROVEN_NOT_STARTED";
      readonly receiveOperationId: string;
      readonly neverCrossedBoundary: ReceiveNeverCrossedBoundary;
      readonly resumeAction: ReceiveResumeAction;
    }
  | {
      readonly kind: "INDETERMINATE";
      readonly receiveAttemptId: string;
      readonly reason: ReconcileIndeterminateReason;
    }
  | {
      readonly kind: "INVARIANT_BREACH";
      readonly receiverWalletId: string;
      readonly reason: ReconcileInvariantBreachReason;
    };

// ("Lease acquired, operation not READY") folded with ("Crash around receive
// signing/submission"): durable evidence BEFORE any submit claim exists. `formationComplete`
// Covers the T0/code/artifact-preimage/artifact-signature durable set; `signerAuditIndicatesUse`
// is the audit trail that the last row and the PREIMAGE_PERSISTED row both check for a
// contradiction against.
export interface ReceiveFormationEvidence {
  readonly boundary: "PRE_SUBMIT";
  readonly receiveOperationId: string;
  readonly formationComplete: boolean;
  readonly step2SignaturePersisted: boolean;
  readonly signerAuditIndicatesUse: boolean;
}

// "Submit claim/call recorded, regardless of response | Never submit again. Reconcile by
// receiver observation." Once a submit claim exists, PROVEN_NOT_STARTED is permanently
// unreachable for this attempt — the only inputs from here on are fresh observation evidence.
export interface ReceiveObservationEvidence {
  readonly boundary: "POST_SUBMIT";
  readonly receiveAttemptId: string;
  readonly receiverWalletId: string;
  readonly receiverLeaseState: LeaseLifecycleState;
  readonly receiverObservation: PathObservation;
}

export type ReceiveReconcileInput = ReceiveFormationEvidence | ReceiveObservationEvidence;

export function classifyReceiveReconcile(input: ReceiveReconcileInput): ReceiveReconcileOutcome {
  if (input.boundary === "PRE_SUBMIT") {
    const { receiveOperationId, formationComplete, step2SignaturePersisted, signerAuditIndicatesUse } =
      input;

    if (!formationComplete) {
      // Last row: an expected exact byte record is missing while a signer audit indicates
      // use — a contradiction; "stored phases/bytes/leases cannot arise under the contract."
      if (signerAuditIndicatesUse) {
        return {
          kind: "INVARIANT_BREACH",
          receiverWalletId: receiveOperationId,
          reason: { source: "EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT" },
        };
      }
      // Row 1: "Lease exists; no T0, code, artifact preimage, or signer audit."
      return {
        kind: "PROVEN_NOT_STARTED",
        receiveOperationId,
        neverCrossedBoundary: "SIGNER",
        resumeAction: "RESUME_T0_AND_CODE_FORMATION",
      };
    }

    if (!step2SignaturePersisted) {
      if (signerAuditIndicatesUse) {
        return {
          kind: "INVARIANT_BREACH",
          receiverWalletId: receiveOperationId,
          reason: { source: "EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT" },
        };
      }
      // PREIMAGE_PERSISTED row: "Re-sign only the identical persisted step-2 preimage."
      return {
        kind: "PROVEN_NOT_STARTED",
        receiveOperationId,
        neverCrossedBoundary: "SIGNER",
        resumeAction: "SIGN_PERSISTED_STEP2_PREIMAGE",
      };
    }

    // SIGNED_PERSISTED-no-submit-claim row: "Invoke the initial submit once... This is
    // first submission, not retry." Reachable here only because `boundary` is PRE_SUBMIT, i.e.
    // the caller has already durably confirmed no submit claim exists for this attempt.
    return {
      kind: "PROVEN_NOT_STARTED",
      receiveOperationId,
      neverCrossedBoundary: "SUBMITTER",
      resumeAction: "SUBMIT_ONCE",
    };
  }

  if (input.receiverLeaseState !== "ACTIVE") {
    return {
      kind: "INVARIANT_BREACH",
      receiverWalletId: input.receiverWalletId,
      reason: { source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" },
    };
  }

  const classification = classifyPathObservation(input.receiverObservation);
  switch (classification.tier) {
    case "LANDED":
      return {
        kind: "LANDED_VERIFIED",
        receiveAttemptId: input.receiveAttemptId,
        receiverPath: classification.proof,
      };
    case "INDETERMINATE":
      return {
        kind: "INDETERMINATE",
        receiveAttemptId: input.receiveAttemptId,
        reason: classification.reason,
      };
    case "INVARIANT_BREACH":
      return {
        kind: "INVARIANT_BREACH",
        receiverWalletId: input.receiverWalletId,
        reason: classification.reason,
      };
    default:
      return assertUnreachable(classification);
  }
}
