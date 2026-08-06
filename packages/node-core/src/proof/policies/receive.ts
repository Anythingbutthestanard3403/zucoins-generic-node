// the RECEIVE_EXTERNAL operation proof policy.
//
// ("RECEIVE_EXTERNAL proof"), whose ten predicates are already frozen as
// RECEIVE_EXTERNAL_POLICY.verificationSteps. This file only decides each of
// them from real evidence and hands the results to `evaluateProof` — the verdict rule
// (all true → VERIFIED, determinate mismatch → REJECTED, read failure or contradiction →
// INDETERMINATE) is not restated here. All amounts are ZKZ.
//
// Nothing load-bearing is re-implemented: `verifySettledTransaction` does the shape +
// dual-Ed25519 + role projection over the exact preimages, `classifyRelationship`
// decides SUCCESSOR, and `evaluateReceiveDelta` decides the exact-decimal economics
// under the canonical ZKZ amount contract amount domain.
import {
  RECEIVE_MESSAGE_PREFIX,
  transferCodeSha256,
} from "@zucoins/generic-node-contracts/transfer-code";
import {
  classifyRelationship,
  type AcceptedSemanticState,
} from "@zucoins/generic-node-contracts/observation";

import { evaluateReceiveDelta } from "../../protocol/economic-predicates.js";
import type { WalletStateProjection } from "../../protocol/wallet-role.js";
import type { ParsedSettledTransaction } from "../../verifier/gateway-envelope.js";
import {
  verifySettledTransaction,
  type TransactionVerifyVerdict,
} from "../../verifier/transaction-verify.js";
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

/**
 * The prior accepted state of the reserved wallet, plus the history the classifier needs.
 * `null` means the observation_match evidence was not obtained — the mandatory-evidence
 * branch of `evaluateProof` then yields INDETERMINATE.
 */
export interface ReceiverBaseline {
  readonly projection: WalletStateProjection;
  readonly semanticFingerprint: string;
  readonly isGenesis: boolean;
  readonly historyHasNonGenesis: boolean;
  readonly acceptedStateSignatureHistory: readonly string[];
}

/** The receive expected-artifact's bound values (half 2 — checked against the chain here). */
export interface ReceiveExpectedArtifact {
  readonly amount_zkz: string;
  readonly receiver_pubkey: string;
  readonly discriminator: string;
  readonly anchor: string;
  readonly transfer_code_sha256: string;
  readonly code_expiry__unix_time_secs: number;
}

export interface ReceivePolicyInput {
  readonly reservedWalletPublicKey: string;
  /** gateway_confirmation: the candidate settled transaction as the gateway returned it. */
  readonly candidate: ParsedSettledTransaction | null;
  /** observation_match: the accepted prior state this candidate is classified against. */
  readonly baseline: ReceiverBaseline | null;
  readonly artifact: ReceiveExpectedArtifact;
  /** Half 1: the artifact envelope's own signature/digest verdict. */
  readonly artifactVerification: ArtifactVerification;
  /** The exact transfer-code string as issued — hashed byte-for-byte, never re-encoded. */
  readonly exactTransferCodeString: string;
  readonly observedAtUnixSecs: number;
  /**
   * an independent sender-side claim about which transaction landed. A claim naming a
   * different transaction is a contradiction, not a mismatch — the relationship is then
   * left undecided rather than asserted.
   */
  readonly senderCorroboration?: { readonly stepTwoSignature: string } | null;
}

const RECEIVE_PREDICATE_ORDER = [
  "successor_relationship",
  "receiver_role_match",
  "predecessor_signature_bindsource",
  "receiver_pubkey_match",
  "amount_exact",
  "version_constants",
  "message_discriminator",
  "expiry_constraints",
  "dual_signatures_verify",
  "artifact_digest_verify",
] as const;

/**
 * shape narrowing proves the frozen version/type/signer constants; dual-Ed25519
 * proves both signatures. One `verifySettledTransaction` call therefore answers both
 * predicates, and a MALFORMED verdict leaves the signature check unreached — undecided,
 * never a determinate signature mismatch.
 */
function fromTransactionVerdict(verdict: TransactionVerifyVerdict): EvaluatedPredicate[] {
  if (verdict.verdict === "MALFORMED_TRANSACTION") {
    const detail = describeTransactionRejection(verdict.rejection);
    return [
      mismatch("version_constants", `inner shape or scalar grammar rejected: ${detail}`),
      undecided("dual_signatures_verify", "not decided: inner shape rejected before signature verification"),
    ];
  }
  if (verdict.verdict === "UNVERIFIED_SIGNATURE") {
    return [
      held("version_constants", "inner shape and frozen protocol constants verified"),
      mismatch("dual_signatures_verify", `step ${verdict.failedStep} Ed25519 signature did not verify`),
    ];
  }
  return [
    held("version_constants", "inner shape and frozen protocol constants verified"),
    held("dual_signatures_verify", "step 1 and step 2 Ed25519 signatures verified over the exact preimages"),
  ];
}

export function evaluateReceiveProof(input: ReceivePolicyInput): OperationProofResult {
  const { artifact, baseline, candidate } = input;
  const evidencePresent = [
    ...(candidate === null ? [] : (["gateway_confirmation"] as const)),
    ...(baseline === null ? [] : (["observation_match"] as const)),
  ];

  const predicates: EvaluatedPredicate[] = [];

  // the artifact's envelope verdict is half one; the transfer-code digest binding
  // the artifact to the code actually issued is the independent half computed here.
  const digestMatches =
    transferCodeSha256(input.exactTransferCodeString) === artifact.transfer_code_sha256;
  predicates.push(
    !input.artifactVerification.ok
      ? mismatch(
          "artifact_digest_verify",
          `expected-artifact envelope rejected: ${describeArtifactRejection(input.artifactVerification)}`,
        )
      : decide(
          "artifact_digest_verify",
          digestMatches,
          digestMatches
            ? "artifact envelope verified and transfer_code_sha256 matches the issued code"
            : "transfer_code_sha256 does not match SHA-256 of the exact issued transfer-code string",
        ),
  );

  if (candidate === null || baseline === null) {
    return finalizeOperationProof("RECEIVE_EXTERNAL", RECEIVE_PREDICATE_ORDER, predicates, evidencePresent);
  }

  const verified = verifySettledTransaction(candidate, input.reservedWalletPublicKey);
  predicates.push(...fromTransactionVerdict(verified));

  if (verified.verdict !== "VERIFIED") {
    predicates.push(
      verified.verdict === "WALLET_ROLE_INVALID"
        ? mismatch("receiver_role_match", verified.detail)
        : undecided("receiver_role_match", "not decided: transaction did not reach the role stage"),
    );
    return finalizeOperationProof("RECEIVE_EXTERNAL", RECEIVE_PREDICATE_ORDER, predicates, evidencePresent);
  }

  const { projection, transaction } = verified;
  const { inner } = transaction;

  predicates.push(
    decide(
      "receiver_role_match",
      projection.role === "receiver",
      `reserved wallet role in the candidate transaction is ${projection.role}`,
    ),
  );

  // relationship, on the semantic fingerprints — the classifier, not a hand-rolled
  // signature comparison, decides whether this candidate succeeds the accepted state.
  const next: AcceptedSemanticState = {
    isGenesis: false,
    sSignature: projection.S,
    pSignature: projection.P,
    semanticFingerprint: verified.semanticFingerprint,
  };
  const classification = classifyRelationship({
    prior: {
      isGenesis: baseline.isGenesis,
      sSignature: baseline.projection.S,
      pSignature: baseline.projection.P,
      semanticFingerprint: baseline.semanticFingerprint,
    },
    next,
    priorHistoryHasNonGenesis: baseline.historyHasNonGenesis,
    acceptedStateSignatureHistory: baseline.acceptedStateSignatureHistory,
  });
  const corroborated =
    input.senderCorroboration == null ||
    input.senderCorroboration.stepTwoSignature === transaction.step_2_signature;
  predicates.push(
    !corroborated
      ? undecided(
          "successor_relationship",
          `contradiction: sender corroboration names ${input.senderCorroboration?.stepTwoSignature ?? ""}, observation carries ${transaction.step_2_signature}`,
        )
      : decide(
          "successor_relationship",
          classification.relationship === "SUCCESSOR",
          `classified ${classification.relationship} (${classification.conditionId})`,
        ),
  );

  predicates.push(
    decide(
      "predecessor_signature_bindsource",
      projection.P === baseline.projection.S,
      `candidate P (${projection.P}) against accepted baseline S (${baseline.projection.S})`,
    ),
    decide(
      "receiver_pubkey_match",
      inner.step_2_key_public__base64urlsafe === artifact.receiver_pubkey,
      "candidate step_2 key against the artifact's receiver_pubkey",
    ),
    // Appendix A receive message: "zp1:" + discriminator + ":" + anchor, exact.
    decide(
      "message_discriminator",
      inner.message === `${RECEIVE_MESSAGE_PREFIX}${artifact.discriminator}:${artifact.anchor}`,
      `candidate message ${JSON.stringify(inner.message ?? null)} against the artifact discriminator and anchor`,
    ),
    evaluateExpiry(inner.expiry__unix_time_secs, artifact, input.observedAtUnixSecs),
  );

  // Exact-decimal economics — the only place an amount is compared, and never via Number.
  predicates.push(
    ...attributeDelta(
      evaluateReceiveDelta({
        baseline: baseline.projection,
        candidateTx: transaction,
        reservedWalletPublicKey: input.reservedWalletPublicKey,
        operation: { amountZkz: artifact.amount_zkz, receiverPubkey: artifact.receiver_pubkey },
      }),
      [{ predicate: "amount_exact", owns: (rejection) => AMOUNT_DELTA_REASONS.includes(rejection.reason) }],
    ),
  );

  return finalizeOperationProof("RECEIVE_EXTERNAL", RECEIVE_PREDICATE_ORDER, predicates, evidencePresent);
}

/**
 * expiry: the transaction's own expiry and the transfer code's expiry must both still
 * cover the moment of observation. These are protocol unix-second integers, never ZKZ
 * scalars, so numeric comparison is correct here and only here.
 */
function evaluateExpiry(
  transactionExpiry: string | undefined,
  artifact: ReceiveExpectedArtifact,
  observedAtUnixSecs: number,
): EvaluatedPredicate {
  if (transactionExpiry === undefined) {
    return mismatch("expiry_constraints", "candidate transaction carries no expiry__unix_time_secs");
  }
  const expiry = Number(transactionExpiry);
  if (!Number.isSafeInteger(expiry)) {
    return mismatch("expiry_constraints", `candidate expiry__unix_time_secs is not an integer: ${transactionExpiry}`);
  }
  if (expiry < observedAtUnixSecs) {
    return mismatch("expiry_constraints", `candidate expired at ${expiry}, observed at ${observedAtUnixSecs}`);
  }
  if (artifact.code_expiry__unix_time_secs < observedAtUnixSecs) {
    return mismatch(
      "expiry_constraints",
      `transfer code expired at ${artifact.code_expiry__unix_time_secs}, observed at ${observedAtUnixSecs}`,
    );
  }
  return held("expiry_constraints", `candidate and transfer-code expiries both cover ${observedAtUnixSecs}`);
}
