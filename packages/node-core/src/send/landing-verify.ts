// SEND_EXTERNAL nine-predicate landing verification.
//
// landing-path oracle (any-depth complete-path oracle supersedes the proposal's exact-head-only
// wording for this money path — LANDED_EXACT and LANDED_COMPLETE_PATH both land;
// the unadopted one-hop LANDED_DIRECT_SUCCESSOR shortcut is NOT implemented).
//
// This module is pure: typed evidence in, typed verdict out. It grants no retry, rebuild,
// resubmit, or lease-release authority (the never-blind-retry rule). A source-head / ancestry fault is
// INDETERMINATE (never a false positive landing). Callback / silence / gateway ACK / bare
// head change cannot land — those produce no positive landing-path oracle path proof and fail closed to
// INDETERMINATE under predicate 8's path-proof requirement.
//
// The nine predicates match and SEND_EXTERNAL_POLICY (proof/policies.ts) 1:1:
// 1 send_artifact_verify
// 2 approval_consumed
// 3 sign_intent_bind
// 4 preimage_exact_match
// 5 source_sender_bind
// 6 destination_key_approved
// 7 destination_predecessor_consistent
// 8 source_exact_head (exact head OR complete-path; never one-hop shortcut)
// 9 single_partial_delivery

import { createHash } from "node:crypto";

import {
  compareAmounts,
  inspectForeignAmount,
  subtractAmounts,
} from "@zucoins/generic-node-contracts";

import { evaluateExternalSendDelta } from "../protocol/economic-predicates.js";
import type { SettledSplitChainTransaction } from "../protocol/inner.js";
import {
  isLandingPathProof,
  revalidateLandingPathProofBindings,
  type LandingPathProof,
} from "../protocol/reconcile/landing-proof.js";
import type { WalletStateProjection } from "../protocol/wallet-role.js";
import {
  evaluateProof,
  type PredicateId,
  type PredicateResult,
  type ProofVerdict,
} from "../proof/index.js";

/** SHA-256 hex of UTF-8 text — settled-body / preimage identity (the byte-exact signing rule discipline). */
export function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// Ordered predicate ids — independent tests flip exactly one.
export const SEND_LANDING_PREDICATES = [
  "send_artifact_verify",
  "approval_consumed",
  "sign_intent_bind",
  "preimage_exact_match",
  "source_sender_bind",
  "destination_key_approved",
  "destination_predecessor_consistent",
  "source_exact_head",
  "single_partial_delivery",
] as const satisfies readonly PredicateId[];

export type SendLandingPredicateId = (typeof SEND_LANDING_PREDICATES)[number];

export type SendLandingEntryStatus = "AWAITING_REDEMPTION" | "NEEDS_ATTENTION";

export interface SendLandingEconomicIntent {
  readonly operationId: string;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
  readonly referencesOperationId: string | null;
}

export interface PersistedSignIntent {
  readonly approvalId: string;
  readonly sourceT0ObservationId: string;
  readonly destinationT0ObservationId: string;
  readonly innerPreimageText: string;
  readonly innerSha256: string;
}

export interface PersistedPartial {
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly transferCodeSha256: string;
  /** Exact transfer-code digest that was delivered (or null if never delivered). */
  readonly deliveredTransferCodeSha256: string | null;
  /** Any other delivered partial digests observed for this operation. */
  readonly otherDeliveredPartialSha256: readonly string[];
}

export interface CandidateCompletedEvidence {
  readonly completedTransaction: SettledSplitChainTransaction;
  /** Exact completed body text when available (persisted byte-exact on land). */
  readonly completedTransactionText: string | null;
  readonly completedTransactionSha256: string;
  /** Byte-exact reconstructed step-1 preimage (= JSON.stringify(inner)). */
  readonly step1PreimageText: string;
  readonly step1Signature: string;
  readonly step2Signature: string;
  /** Cryptographic step-2 verification under destination key already performed by caller. */
  readonly step2SignatureVerified: boolean;
}

export interface BaselineObservation {
  readonly observationId: string;
  readonly projection: WalletStateProjection;
}

export interface SendLandingEvidence {
  readonly operationId: string;
  readonly entryStatus: SendLandingEntryStatus;
  readonly economic: SendLandingEconomicIntent;

  readonly expectedArtifactVerified: boolean;
  readonly expectedArtifact: {
    readonly sourcePubkey: string;
    readonly destinationAddress: string;
    readonly amountZkz: string;
    readonly referencesOperationId: string | null;
  };

  readonly approval: {
    readonly approvalId: string;
    readonly totpConsumed: boolean;
    readonly deviceSignatureRequired: boolean;
    readonly deviceSignatureVerified: boolean;
    readonly sourcePubkey: string;
    readonly destinationAddress: string;
    readonly amountZkz: string;
    readonly referencesOperationId: string | null;
  };

  readonly signIntent: PersistedSignIntent | null;
  readonly signIntentRowCount: number;

  readonly partial: PersistedPartial | null;

  readonly sourceT0: BaselineObservation;
  readonly destinationT0: BaselineObservation;
  readonly candidate: CandidateCompletedEvidence | null;

  /**
   * path proof for the SOURCE wallet, expected body = completed E.
   * Null or `sourcePathProofIncomplete` → INDETERMINATE (never a landing).
   */
  readonly sourcePathProof: LandingPathProof | null;
  readonly sourcePathProofIncomplete: boolean;

  /** Source lease must remain ACTIVE; this verifier never releases it. */
  readonly sourceLeaseActive: boolean;
}

export type SendLandingVerdict =
  | {
      readonly kind: "VERIFIED";
      readonly operationId: string;
      readonly entryStatus: SendLandingEntryStatus;
      readonly proof: LandingPathProof;
      readonly predicateResults: readonly PredicateResult[];
      readonly proofVerdict: ProofVerdict;
      readonly candidate: CandidateCompletedEvidence;
      readonly terminalObservationId: string;
    }
  | {
      readonly kind: "FAILED";
      readonly operationId: string;
      readonly failedPredicate: SendLandingPredicateId;
      readonly detail: string;
      readonly predicateResults: readonly PredicateResult[];
      readonly proofVerdict: ProofVerdict;
    }
  | {
      readonly kind: "INDETERMINATE";
      readonly operationId: string;
      readonly reason:
        | "SOURCE_PATH_PROOF_INCOMPLETE"
        | "SOURCE_PATH_PROOF_ABSENT"
        | "SOURCE_LEASE_NOT_ACTIVE"
        | "CANDIDATE_ABSENT";
      readonly detail: string;
      readonly predicateResults: readonly PredicateResult[];
    };

function allPassResults(): PredicateResult[] {
  return SEND_LANDING_PREDICATES.map((predicate) => ({
    predicate,
    passed: true,
    determinate: true,
  }));
}

function markFail(results: PredicateResult[], predicate: SendLandingPredicateId): PredicateResult[] {
  return results.map((r) =>
    r.predicate === predicate ? { predicate, passed: false, determinate: true } : r,
  );
}

function failed(
  operationId: string,
  predicate: SendLandingPredicateId,
  detail: string,
  results: PredicateResult[],
): Extract<SendLandingVerdict, { kind: "FAILED" }> {
  const predicateResults = markFail(results, predicate);
  return {
    kind: "FAILED",
    operationId,
    failedPredicate: predicate,
    detail,
    predicateResults,
    proofVerdict: evaluateProof({
      operationType: "SEND_EXTERNAL",
      predicateResults,
      evidencePresent: ["recipient_confirmation", "submit_evidence"],
    }),
  };
}

/**
 * Run the nine predicates over one external-send landing candidate.
 *
 * Fail-closed: the first determinate predicate failure returns FAILED with that exact
 * predicate id (independently falsifiable). A missing or incomplete
 * source path proof is INDETERMINATE — never a false landing and never a re-form.
 */
export function verifyExternalSendLanding(evidence: SendLandingEvidence): SendLandingVerdict {
  const results = allPassResults();
  const opId = evidence.operationId;

  // Custody: lease must still be held. Release happens at a later step (step 6).
  if (!evidence.sourceLeaseActive) {
    return {
      kind: "INDETERMINATE",
      operationId: opId,
      reason: "SOURCE_LEASE_NOT_ACTIVE",
      detail: "source lease is not ACTIVE; landing cannot proceed and lease is not released here",
      predicateResults: results,
    };
  }

  // 1. send expected artifact verifies
  if (!evidence.expectedArtifactVerified) {
    return failed(opId, "send_artifact_verify", "expected artifact signature/envelope did not verify", results);
  }

  // 2. mandatory TOTP approval consumed; device signature when configured
  if (!evidence.approval.totpConsumed) {
    return failed(opId, "approval_consumed", "mandatory TOTP approval is not consumed", results);
  }
  if (evidence.approval.deviceSignatureRequired && !evidence.approval.deviceSignatureVerified) {
    return failed(opId, "approval_consumed", "device signature required but did not verify", results);
  }

  // 3. approval + expected artifact bind immutable economic intent; exactly one sign-intent
  const intent = evidence.signIntent;
  if (intent === null || evidence.signIntentRowCount !== 1) {
    return failed(
      opId,
      "sign_intent_bind",
      `expected exactly one sign-intent row, got ${evidence.signIntentRowCount}`,
      results,
    );
  }
  if (intent.approvalId !== evidence.approval.approvalId) {
    return failed(
      opId,
      "sign_intent_bind",
      "sign-intent approval_id does not match consumed approval",
      results,
    );
  }
  if (
    intent.sourceT0ObservationId !== evidence.sourceT0.observationId ||
    intent.destinationT0ObservationId !== evidence.destinationT0.observationId
  ) {
    return failed(
      opId,
      "sign_intent_bind",
      "sign-intent T0 observation ids do not bind the current baselines",
      results,
    );
  }

  const econ = evidence.economic;
  const art = evidence.expectedArtifact;
  const appr = evidence.approval;
  if (
    econ.sourcePubkey !== art.sourcePubkey ||
    econ.destinationAddress !== art.destinationAddress ||
    econ.amountZkz !== art.amountZkz ||
    econ.referencesOperationId !== art.referencesOperationId ||
    econ.sourcePubkey !== appr.sourcePubkey ||
    econ.destinationAddress !== appr.destinationAddress ||
    econ.amountZkz !== appr.amountZkz ||
    econ.referencesOperationId !== appr.referencesOperationId
  ) {
    return failed(
      opId,
      "sign_intent_bind",
      "approval/artifact/operation economic fields do not bind identically",
      results,
    );
  }

  const candidate = evidence.candidate;
  if (candidate === null) {
    return {
      kind: "INDETERMINATE",
      operationId: opId,
      reason: "CANDIDATE_ABSENT",
      detail: "no completed candidate transaction to verify",
      predicateResults: results,
    };
  }

  const partial = evidence.partial;
  if (partial === null) {
    return failed(opId, "preimage_exact_match", "persisted partial is absent", results);
  }

  // 4. E's step-1 preimage and signature exactly equal the persisted sign intent and partial.
  // Byte-exact string comparison only — never parsed-object / JSONB deep equality.
  // Also re-derive from E.inner and re-hash so caller string fields cannot diverge from E.
  if (candidate.step1PreimageText !== intent.innerPreimageText) {
    return failed(
      opId,
      "preimage_exact_match",
      "candidate step-1 preimage text is not byte-identical to persisted sign-intent preimage",
      results,
    );
  }
  const derivedStep1Preimage = JSON.stringify(candidate.completedTransaction.inner);
  if (derivedStep1Preimage !== candidate.step1PreimageText) {
    return failed(
      opId,
      "preimage_exact_match",
      "JSON.stringify(E.inner) is not byte-identical to candidate step-1 preimage text",
      results,
    );
  }
  if (sha256HexUtf8(candidate.step1PreimageText) !== intent.innerSha256) {
    return failed(
      opId,
      "preimage_exact_match",
      "sha256(step-1 preimage) does not equal sign-intent.inner_sha256",
      results,
    );
  }
  if (candidate.step1Signature !== partial.step1Signature) {
    return failed(
      opId,
      "preimage_exact_match",
      "candidate step-1 signature is not byte-identical to persisted partial",
      results,
    );
  }
  if (partial.innerSha256 !== intent.innerSha256) {
    return failed(
      opId,
      "preimage_exact_match",
      "partial.inner_sha256 does not equal sign-intent.inner_sha256",
      results,
    );
  }

  // 5. source is sender, previous_step_1_state_signature == Ts0.S, Ts0.B - Ts1.B == amount
  const economic = evaluateExternalSendDelta({
    baseline: evidence.sourceT0.projection,
    candidateTx: candidate.completedTransaction,
    sourceWalletPublicKey: evidence.economic.sourcePubkey,
    operation: {
      amountZkz: evidence.economic.amountZkz,
      sourcePubkey: evidence.economic.sourcePubkey,
      destinationAddress: evidence.economic.destinationAddress,
    },
  });
  if (!economic.ok) {
    if (economic.reason === "artifact_binding_mismatch" && economic.detail.includes("step_2")) {
      return failed(opId, "destination_key_approved", economic.detail, results);
    }
    return failed(opId, "source_sender_bind", `${economic.reason}: ${economic.detail}`, results);
  }

  // 6. destination key equals the approved address
  if (
    candidate.completedTransaction.inner.step_2_key_public__base64urlsafe !==
    evidence.economic.destinationAddress
  ) {
    return failed(
      opId,
      "destination_key_approved",
      "candidate destination key does not equal approved destination address",
      results,
    );
  }

  // 7. destination predecessor/balance in frozen inner consistent with Td0; step-2 verifies
  const destPred = candidate.completedTransaction.inner.previous_step_2_state_signature;
  if (destPred !== evidence.destinationT0.projection.S) {
    return failed(
      opId,
      "destination_predecessor_consistent",
      "candidate previous_step_2_state_signature does not equal destination T0.S",
      results,
    );
  }

  const t0B = evidence.destinationT0.projection.B;
  const step2B = candidate.completedTransaction.inner.step_2_state.amount;
  if (!inspectForeignAmount(t0B).wellFormed || !inspectForeignAmount(step2B).wellFormed) {
    return failed(
      opId,
      "destination_predecessor_consistent",
      "destination balance scalar is not well-formed",
      results,
    );
  }
  const credit = subtractAmounts(step2B, t0B);
  if (compareAmounts(credit, evidence.economic.amountZkz) !== 0) {
    return failed(
      opId,
      "destination_predecessor_consistent",
      `destination credit ${credit} does not equal amount ${evidence.economic.amountZkz}`,
      results,
    );
  }
  if (!candidate.step2SignatureVerified) {
    return failed(
      opId,
      "destination_predecessor_consistent",
      "completed step-2 signature does not verify under destination key",
      results,
    );
  }

  // 8. source accepted head is E (LANDED_EXACT or LANDED_COMPLETE_PATH).
  // Settled-body identity: text ↔ sha ↔ object must be one triple (SETTLED_BODY_PERSISTED).
  if (evidence.sourcePathProofIncomplete) {
    return {
      kind: "INDETERMINATE",
      operationId: opId,
      reason: "SOURCE_PATH_PROOF_INCOMPLETE",
      detail:
        "source path proof incomplete (gap/conflict/missing body/regression); park NEEDS_ATTENTION, do not re-form",
      predicateResults: results,
    };
  }
  const path = evidence.sourcePathProof;
  if (path === null) {
    return {
      kind: "INDETERMINATE",
      operationId: opId,
      reason: "SOURCE_PATH_PROOF_ABSENT",
      detail: "no complete-path source proof (callback/ACK/bare head change cannot land)",
      predicateResults: results,
    };
  }
  // structural/forgeable objects are not landing authority.
  if (!isLandingPathProof(path)) {
    return {
      kind: "INDETERMINATE",
      operationId: opId,
      reason: "SOURCE_PATH_PROOF_ABSENT",
      detail: "source path proof is not an issued oracle capability",
      predicateResults: results,
    };
  }
  // Independent evidence only: wallet + completed candidate body. Fresh-head anchors on the
  // path are trusted only because mint requires an issued single-use frozen landing-path oracle seal —
  // never compare proof fields to themselves (F3).
  if (
    !revalidateLandingPathProofBindings(path, {
      walletPubkeyBase64Urlsafe: evidence.economic.sourcePubkey,
      expectedBodySha256: candidate.completedTransactionSha256,
    })
  ) {
    return failed(
      opId,
      "source_exact_head",
      "source path proof bindings failed transactional revalidation",
      results,
    );
  }
  if (path.walletPubkeyBase64Urlsafe !== evidence.economic.sourcePubkey) {
    return failed(opId, "source_exact_head", "source path proof is bound to a different wallet", results);
  }
  const bodyText = candidate.completedTransactionText;
  if (bodyText !== null && bodyText.length > 0) {
    const derivedBodyText = JSON.stringify(candidate.completedTransaction);
    if (derivedBodyText !== bodyText) {
      return failed(
        opId,
        "source_exact_head",
        "completedTransactionText is not JSON.stringify(E)",
        results,
      );
    }
    if (sha256HexUtf8(bodyText) !== candidate.completedTransactionSha256) {
      return failed(
        opId,
        "source_exact_head",
        "sha256(completedTransactionText) does not equal completedTransactionSha256",
        results,
      );
    }
  }
  if (path.expectedBodySha256 !== candidate.completedTransactionSha256) {
    return failed(
      opId,
      "source_exact_head",
      "source path proof expected body is not the completed candidate E",
      results,
    );
  }
  if (path.kind !== "LANDED_EXACT" && path.kind !== "LANDED_COMPLETE_PATH") {
    return failed(
      opId,
      "source_exact_head",
      "unrecognized path proof kind (LANDED_DIRECT_SUCCESSOR is not implemented)",
      results,
    );
  }

  // 9. no partial other than the persisted exact bytes was delivered
  if (
    partial.deliveredTransferCodeSha256 !== null &&
    partial.deliveredTransferCodeSha256 !== partial.transferCodeSha256
  ) {
    return failed(
      opId,
      "single_partial_delivery",
      "delivered transfer-code digest differs from the persisted partial",
      results,
    );
  }
  for (const other of partial.otherDeliveredPartialSha256) {
    if (other !== partial.transferCodeSha256) {
      return failed(
        opId,
        "single_partial_delivery",
        "a partial other than the persisted exact bytes was delivered",
        results,
      );
    }
  }

  const proofVerdict = evaluateProof({
    operationType: "SEND_EXTERNAL",
    predicateResults: results,
    evidencePresent: ["recipient_confirmation", "submit_evidence"],
  });
  if (proofVerdict.outcome !== "VERIFIED") {
    return failed(
      opId,
      "send_artifact_verify",
      `proof shell returned ${proofVerdict.outcome} after all local predicates passed`,
      results,
    );
  }

  return {
    kind: "VERIFIED",
    operationId: opId,
    entryStatus: evidence.entryStatus,
    proof: path,
    predicateResults: results,
    proofVerdict,
    candidate,
    terminalObservationId: path.freshHeadObservationId,
  };
}
