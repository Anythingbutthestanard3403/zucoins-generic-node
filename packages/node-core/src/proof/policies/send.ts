// the SEND_EXTERNAL operation proof policy.
//
// ("SEND_EXTERNAL proof"), frozen as SEND_EXTERNAL_POLICY.verificationSteps.
// A send leaves node custody, so the proof is the strictest of the three: exactly one
// consumed approval, exactly one persisted sign-intent, and the landed transaction's step-1
// preimage byte-identical to the one that intent signed. A source head that
// does not name the landed transaction does not prove non-landing — puts that at
// INDETERMINATE, never REJECTED. All amounts are ZKZ.
import { evaluateExternalSendDelta, evaluateReceiveDelta } from "../../protocol/economic-predicates.js";
import type { SettledSplitChainTransaction } from "../../protocol/inner.js";
import type { WalletStateProjection } from "../../protocol/wallet-role.js";
import type { ParsedSettledTransaction } from "../../verifier/gateway-envelope.js";
import { verifySettledTransaction } from "../../verifier/transaction-verify.js";
import type { EvidenceKind } from "../types.js";
import {
  AMOUNT_DELTA_REASONS,
  attributeDelta,
  decide,
  describeArtifactRejection,
  describeTransactionRejection,
  finalizeOperationProof,
  held,
  mismatch,
  undecided,
  type ArtifactVerification,
  type EvaluatedPredicate,
  type OperationProofResult,
} from "./shared.js";

/** the TOTP approval that authorised this send, and whether it was consumed. */
export interface TotpApproval {
  readonly approvalId: string;
  readonly consumedAtUnixMs: number | null;
  readonly deviceSignatureRequired: boolean;
  readonly deviceSignatureVerified: boolean;
}

/**
 * A persisted sign-intent row: the exact step-1 preimage text and signature the node
 * committed to before submitting, together with everything the intent was bound to.
 */
export interface SignIntentRow {
  readonly approvalId: string;
  readonly amountZkz: string;
  readonly destinationAddress: string;
  readonly sourceBaselineObservationId: string;
  readonly destinationBaselineObservationId: string;
  readonly step1PreimageText: string;
  readonly step1Signature: string;
}

/** A partial actually handed to the gateway. More than one distinct partial is a determinate fault. */
export interface DeliveredPartial {
  readonly step1PreimageText: string;
  readonly step1Signature: string;
}

export interface SendSubmitEvidence {
  readonly sourceWalletPublicKey: string;
  readonly sourceBaseline: WalletStateProjection;
  readonly sourceBaselineObservationId: string;
  /** E — the completed external send transaction as observed. */
  readonly completed: ParsedSettledTransaction;
  readonly signIntents: readonly SignIntentRow[];
  readonly deliveredPartials: readonly DeliveredPartial[];
  /** The source wallet's current accepted head, or null when the head read failed. */
  readonly sourceAcceptedHeadStepTwoSignature: string | null;
  readonly approval: TotpApproval;
}

export interface SendRecipientConfirmation {
  readonly destinationBaseline: WalletStateProjection;
  readonly destinationBaselineObservationId: string;
  readonly approvedDestinationAddress: string;
}

export interface SendExpectedArtifact {
  readonly amount_zkz: string;
  readonly source_pubkey: string;
  readonly destination_address: string;
}

export interface SendPolicyInput {
  readonly artifact: SendExpectedArtifact;
  readonly artifactVerification: ArtifactVerification;
  readonly submitEvidence: SendSubmitEvidence | null;
  readonly recipientConfirmation: SendRecipientConfirmation | null;
}

const SEND_PREDICATE_ORDER = [
  "send_artifact_verify",
  "approval_consumed",
  "sign_intent_bind",
  "preimage_exact_match",
  "source_sender_bind",
  "destination_key_approved",
  "destination_predecessor_consistent",
  "source_exact_head",
  "single_partial_delivery",
] as const;

const SUBMIT_ONLY_PREDICATES = [
  "approval_consumed",
  "sign_intent_bind",
  "preimage_exact_match",
  "source_sender_bind",
  "source_exact_head",
  "single_partial_delivery",
] as const;

export function evaluateSendProof(input: SendPolicyInput): OperationProofResult {
  const { artifact, recipientConfirmation, submitEvidence } = input;
  const evidencePresent: EvidenceKind[] = [
    ...(submitEvidence === null ? [] : (["submit_evidence"] as const)),
    ...(recipientConfirmation === null ? [] : (["recipient_confirmation"] as const)),
  ];

  const predicates: EvaluatedPredicate[] = [
    input.artifactVerification.ok
      ? held("send_artifact_verify", "send expected-artifact envelope verified")
      : mismatch(
          "send_artifact_verify",
          `send expected-artifact envelope rejected: ${describeArtifactRejection(input.artifactVerification)}`,
        ),
  ];

  if (submitEvidence === null) {
    predicates.push(
      ...SUBMIT_ONLY_PREDICATES.map((predicate) =>
        undecided(predicate, "not decided: no submit evidence held"),
      ),
      undecided("destination_key_approved", "not decided: no submit evidence held"),
      undecided("destination_predecessor_consistent", "not decided: no submit evidence held"),
    );
    return finalizeOperationProof("SEND_EXTERNAL", SEND_PREDICATE_ORDER, predicates, evidencePresent);
  }

  const { approval, deliveredPartials, signIntents } = submitEvidence;
  const approvalConsumed =
    approval.consumedAtUnixMs !== null &&
    (!approval.deviceSignatureRequired || approval.deviceSignatureVerified);
  predicates.push(
    decide(
      "approval_consumed",
      approvalConsumed,
      approval.consumedAtUnixMs === null
        ? `approval ${approval.approvalId} was never consumed`
        : approvalConsumed
          ? `approval ${approval.approvalId} consumed at ${approval.consumedAtUnixMs}`
          : `approval ${approval.approvalId} required a device signature that did not verify`,
    ),
  );

  // exactly one sign-intent, bound to the consumed approval, to the artifact's amount
  // and destination, and to BOTH baselines this proof was computed against. A second intent
  // for one approval is itself the fault, so it is checked before anything reads intents[0].
  const boundIntents = signIntents.filter(
    (intent) =>
      intent.approvalId === approval.approvalId &&
      intent.amountZkz === artifact.amount_zkz &&
      intent.destinationAddress === artifact.destination_address &&
      intent.sourceBaselineObservationId === submitEvidence.sourceBaselineObservationId &&
      (recipientConfirmation === null ||
        intent.destinationBaselineObservationId === recipientConfirmation.destinationBaselineObservationId),
  );
  const intent = boundIntents.length === 1 ? boundIntents[0] : undefined;
  predicates.push(
    decide(
      "sign_intent_bind",
      intent !== undefined,
      `${boundIntents.length} of ${signIntents.length} sign-intents bind approval ${approval.approvalId} to this artifact and both baselines`,
    ),
  );

  const verdict = verifySettledTransaction(
    submitEvidence.completed,
    submitEvidence.sourceWalletPublicKey,
  );

  if (verdict.verdict !== "VERIFIED") {
    const detail =
      verdict.verdict === "MALFORMED_TRANSACTION"
        ? `completed transaction rejected: ${describeTransactionRejection(verdict.rejection)}`
        : verdict.verdict === "UNVERIFIED_SIGNATURE"
          ? `completed transaction step ${verdict.failedStep} signature did not verify`
          : verdict.detail;
    predicates.push(
      mismatch("source_sender_bind", detail),
      undecided("preimage_exact_match", "not decided: completed transaction did not verify"),
      undecided("destination_key_approved", "not decided: completed transaction did not verify"),
      undecided("destination_predecessor_consistent", "not decided: completed transaction did not verify"),
      evaluateSourceHead(submitEvidence, submitEvidence.completed.step_2_signature),
      evaluateSinglePartial(deliveredPartials, intent),
    );
    return finalizeOperationProof("SEND_EXTERNAL", SEND_PREDICATE_ORDER, predicates, evidencePresent);
  }

  const completed = verdict.transaction;

  // Byte-exact signing, as a proof predicate: the bytes that landed are the bytes the node
  // committed to signing. Compared as text, never re-serialized for comparison.
  predicates.push(
    intent === undefined
      ? undecided("preimage_exact_match", "not decided: no single bound sign-intent to compare against")
      : decide(
          "preimage_exact_match",
          verdict.innerPreimageText === intent.step1PreimageText &&
            completed.step_1_signature === intent.step1Signature,
          "landed step-1 preimage text and signature against the persisted sign-intent bytes",
        ),
  );

  predicates.push(
    ...attributeDelta(
      evaluateExternalSendDelta({
        baseline: submitEvidence.sourceBaseline,
        candidateTx: completed,
        sourceWalletPublicKey: submitEvidence.sourceWalletPublicKey,
        operation: {
          amountZkz: artifact.amount_zkz,
          sourcePubkey: artifact.source_pubkey,
          destinationAddress: artifact.destination_address,
        },
      }),
      [
        {
          predicate: "source_sender_bind",
          owns: (rejection) =>
            AMOUNT_DELTA_REASONS.includes(rejection.reason) ||
            rejection.reason === "wallet_role_invalid" ||
            rejection.reason === "chain_link_mismatch" ||
            rejection.reason === "artifact_binding_mismatch",
        },
      ],
    ),
  );

  predicates.push(
    ...evaluateRecipientSide(completed, artifact, recipientConfirmation),
    evaluateSourceHead(submitEvidence, completed.step_2_signature),
    evaluateSinglePartial(deliveredPartials, intent),
  );

  return finalizeOperationProof("SEND_EXTERNAL", SEND_PREDICATE_ORDER, predicates, evidencePresent);
}

/**
 * The two recipient_confirmation predicates: the destination key is the approved external
 * address, and the send links onto the destination's own accepted state.
 */
function evaluateRecipientSide(
  completed: SettledSplitChainTransaction,
  artifact: SendExpectedArtifact,
  recipientConfirmation: SendRecipientConfirmation | null,
): EvaluatedPredicate[] {
  if (recipientConfirmation === null) {
    return [
      undecided("destination_key_approved", "not decided: no recipient confirmation held"),
      undecided("destination_predecessor_consistent", "not decided: no recipient confirmation held"),
    ];
  }
  const destinationKey = completed.inner.step_2_key_public__base64urlsafe;
  const approved = recipientConfirmation.approvedDestinationAddress;
  // Read from the destination's side: the same landed transaction must link onto the
  // destination's accepted state and credit it by exactly the artifact amount.
  const receiveSide = evaluateReceiveDelta({
    baseline: recipientConfirmation.destinationBaseline,
    candidateTx: completed,
    reservedWalletPublicKey: destinationKey,
    operation: { amountZkz: artifact.amount_zkz, receiverPubkey: destinationKey },
  });
  return [
    decide(
      "destination_key_approved",
      destinationKey === approved && artifact.destination_address === approved,
      `landed step_2 key and artifact destination_address against the approved address ${approved}`,
    ),
    decide(
      "destination_predecessor_consistent",
      receiveSide.ok,
      receiveSide.ok
        ? "landed transaction links onto the destination's accepted state with the exact credit"
        : receiveSide.detail,
    ),
  ];
}

/**
 * the source head should name the landed transaction. A missing head or a head that
 * names a different transaction does not prove non-landing — it may be a regression, a
 * buried landing, an unrelated advance, or a gateway anomaly. Both paths are INDETERMINATE
 * (never REJECTED); recovery does not form a new partial.
 */
function evaluateSourceHead(
  submitEvidence: SendSubmitEvidence,
  landedStepTwoSignature: string,
): EvaluatedPredicate {
  const head = submitEvidence.sourceAcceptedHeadStepTwoSignature;
  if (head === null) {
    return undecided("source_exact_head", "not decided: no fresh source head read — non-landing is not proven");
  }
  if (head !== landedStepTwoSignature) {
    return undecided(
      "source_exact_head",
      `not decided: source accepted head ${head} does not name the landed transaction ${landedStepTwoSignature} — non-landing is not proven`,
    );
  }
  return decide(
    "source_exact_head",
    true,
    `source accepted head ${head} names the landed transaction`,
  );
}

/**
 * no partial other than the persisted exact bytes was delivered. Delivering a second,
 * byte-different partial is a determinate fault even when its economics match — that is the
 * double-spend shape a matching-amount check would wave through.
 */
function evaluateSinglePartial(
  deliveredPartials: readonly DeliveredPartial[],
  intent: SignIntentRow | undefined,
): EvaluatedPredicate {
  if (intent === undefined) {
    return undecided("single_partial_delivery", "not decided: no single bound sign-intent to compare against");
  }
  if (deliveredPartials.length === 0) {
    return undecided("single_partial_delivery", "not decided: no delivery record held");
  }
  const foreign = deliveredPartials.filter(
    (partial) =>
      partial.step1PreimageText !== intent.step1PreimageText ||
      partial.step1Signature !== intent.step1Signature,
  );
  return decide(
    "single_partial_delivery",
    foreign.length === 0,
    foreign.length === 0
      ? `all ${deliveredPartials.length} delivered partial(s) are the persisted exact bytes`
      : `${foreign.length} of ${deliveredPartials.length} delivered partial(s) differ from the persisted exact bytes`,
  );
}
