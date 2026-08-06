// SEND_EXTERNAL post-approve formation orchestration.
//
// Sequence on APPROVED / APPROVED_UNSIGNED:
// 1. claimAndObserveSendBaselines (lease + source/dest OBSERVE)
// 2. load approval_id bound to the operation
// 3. formAndSignSendExternal under money-path gates (no second intent)
// 4. optional first-delivery stamp so GET may return the exact code
//
// The key-custody rule /: the node NEVER submits SEND_EXTERNAL. This module imports no
// submit surface; privilege tests prove the absence of submit_transaction markers.

import {
  formAndSignSendExternal,
  type FormAndSignClaim,
  type FormAndSignHeldLease,
  type FormAndSignResult,
  type PartialPersistPort,
  type SignIntentPersistPort,
} from "../core/send-form-and-sign.js";
import type { SignerBoundaryDeps } from "../core/signer-boundary.js";
import {
  claimAndObserveSendBaselines,
  type ApprovedSendClaimPort,
  type ClaimAndObserveResult,
  type LeaseAcquireBackoffOptions,
  type SendFormationObserver,
  type SourceLeasePort,
} from "./claim-and-observe.js";

export interface ApprovalIdLoader {
  loadConsumedApprovalId(operationId: string): Promise<string | null>;
}

export interface PartialDeliveryMarker {
  /** Set-once first_delivered_at / redelivery_count. Optional when delivery
   * is deferred to a GET handler that stamps on first read. */
  markFirstDelivered?(
    operationId: string,
    deliveredAt: string,
  ): Promise<"delivered" | "redelivered" | "missing">;
}

export type PostApproveFormationReason =
  | "claim_observe_rejected"
  | "approval_missing"
  | "form_and_sign_rejected";

export type PostApproveFormationResult =
  | {
      readonly ok: true;
      readonly operationId: string;
      readonly transferCodeSha256: string;
      /** Exact transfer code text — deliver only after partial commit (already true). */
      readonly transferCodeText: string;
      readonly step1Signature: string;
      readonly status: "AWAITING_REDEMPTION";
      readonly formation: FormAndSignResult & { readonly ok: true };
    }
  | {
      readonly ok: false;
      readonly operationId: string;
      readonly reason: PostApproveFormationReason;
      readonly detail: string;
      readonly claimObserve?: ClaimAndObserveResult & { readonly ok: false };
      readonly formAndSign?: FormAndSignResult & { readonly ok: false };
    };

export interface PostApproveFormationInput {
  readonly operationId: string;
  readonly ownerInstanceId: string;
  readonly capturedAt: number;
  readonly nodeClockMs: number;
  readonly preparedAt: string;
  readonly persistedAt: string;
  readonly claimPort: ApprovedSendClaimPort;
  readonly leasePort: SourceLeasePort;
  readonly observer: SendFormationObserver;
  readonly approvalIds: ApprovalIdLoader;
  readonly signIntentPort: SignIntentPersistPort;
  readonly partialPort: PartialPersistPort;
  readonly signerDeps: SignerBoundaryDeps;
  readonly backoff?: LeaseAcquireBackoffOptions;
  readonly delivery?: PartialDeliveryMarker;
}

/**
 * Drive one APPROVED send through claim+observe+form/sign to AWAITING_REDEMPTION.
 * Structurally submit-free: no gateway submit credential, no submit attempt insert.
 */
export async function runSendPostApproveFormation(
  input: PostApproveFormationInput,
): Promise<PostApproveFormationResult> {
  const claimObserve = await claimAndObserveSendBaselines({
    operationId: input.operationId,
    ownerInstanceId: input.ownerInstanceId,
    capturedAt: input.capturedAt,
    claimPort: input.claimPort,
    leasePort: input.leasePort,
    observer: input.observer,
    backoff: input.backoff,
  });
  if (!claimObserve.ok) {
    return {
      ok: false,
      operationId: input.operationId,
      reason: "claim_observe_rejected",
      detail: `${claimObserve.reason}: ${claimObserve.detail}`,
      claimObserve,
    };
  }

  const approvalId = await input.approvalIds.loadConsumedApprovalId(input.operationId);
  if (approvalId === null) {
    return {
      ok: false,
      operationId: input.operationId,
      reason: "approval_missing",
      detail: "no consumed operation_approvals row for APPROVED send",
    };
  }

  const claim: FormAndSignClaim = {
    operationId: claimObserve.claim.operationId,
    status: "APPROVED",
    formationState: "APPROVED_UNSIGNED",
    rowVersion: claimObserve.claim.rowVersion,
    sourceWalletId: claimObserve.claim.sourceWalletId,
    sourcePubkey: claimObserve.claim.sourcePubkey,
    destinationAddress: claimObserve.claim.destinationAddress,
    amountZkz: claimObserve.claim.amountZkz,
  };
  const held: FormAndSignHeldLease = {
    walletId: claimObserve.held.walletId,
    membershipId: claimObserve.held.membershipId,
    leaseGroupId: claimObserve.held.leaseGroupId,
    leaseEpoch: claimObserve.held.leaseEpoch,
    operationId: claimObserve.held.operationId,
  };

  const formed = await formAndSignSendExternal({
    claim,
    held,
    approvalId,
    sourceT0ObservationId: claimObserve.sourceT0ObservationId,
    destinationFormationObservationId: claimObserve.destinationFormationObservationId,
    capture: claimObserve.capture,
    nodeClockMs: input.nodeClockMs,
    preparedAt: input.preparedAt,
    persistedAt: input.persistedAt,
    signIntentPort: input.signIntentPort,
    partialPort: input.partialPort,
    signerDeps: input.signerDeps,
  });

  if (!formed.ok) {
    return {
      ok: false,
      operationId: input.operationId,
      reason: "form_and_sign_rejected",
      detail: `${formed.reason}: ${formed.detail}`,
      formAndSign: formed,
    };
  }

  if (input.delivery?.markFirstDelivered !== undefined) {
    await input.delivery.markFirstDelivered(input.operationId, input.persistedAt);
  }

  return {
    ok: true,
    operationId: input.operationId,
    transferCodeSha256: formed.transferCodeSha256,
    transferCodeText: formed.transferCodeText,
    step1Signature: formed.step1Signature,
    status: "AWAITING_REDEMPTION",
    formation: formed,
  };
}
