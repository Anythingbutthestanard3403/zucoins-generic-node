// Live SEND_EXTERNAL reconcile + evidence disposition harness.
//
// Offline-first post-landing coordination over injected seams. Closes the dual-control
// SEND_EXTERNAL acceptance path after LANDED_VERIFIED execute evidence:
// Independent fresh source-head re-read, OBS nine-predicate verification, landing
// DB-TX (AWAITING_REDEMPTION/NEEDS_ATTENTION → EXTERNAL_SEND_LANDED + external_send.landed),
// verification-complete ack with SOURCE + DESTINATION (external counterparty) evidence,
// group-predicate source-lease release, and evidence packet archive.
//
// Governing:
//   The one-in-flight-per-wallet and byte-exact signing rules, 4, 5
//
// Structural invariants:
//   - Fresh source head is re-read independently of the mid-run landing observation.
//   -: a source-head mismatch is INDETERMINATE — never inferred non-landing.
//   - Source lease releases only after the full lease-group predicate passes.
//   - No node submit / rebuild / second partial / second approval on this surface
//     (the never-blind-retry rule).
//   - Private keys never appear (the key-custody rule).

import { createHash } from "node:crypto";

import {
  evaluateSendProof,
  type DeliveredPartial,
  type SendExpectedArtifact,
  type SendPolicyInput,
  type SendRecipientConfirmation,
  type SendSubmitEvidence,
  type SignIntentRow,
  type TotpApproval,
} from "../../src/proof/policies/send.js";
import type { EvaluatedPredicate, OperationProofResult } from "../../src/proof/policies/shared.js";
import type { PredicateId, VerdictOutcome } from "../../src/proof/types.js";
import type { SettledSplitChainTransaction } from "../../src/protocol/inner.js";
import {
  buildSendTransferCodeText,
  hashTransferCodeText,
} from "../../src/protocol/send-transfer-code.js";
import type { WalletStateProjection } from "../../src/protocol/wallet-role.js";
import {
  clampReleaseToVerdict,
  evaluateGroupRelease,
  expectedWalletsForOperation,
  validateEvidenceSet,
  type AckVerdict,
  type DurableEvidenceFact,
  type GroupReleaseDecision,
  type GroupReleaseFacts,
  type LeaseReleaseStatus,
  type OperationWalletAssignment,
} from "../../src/verification/predicates.js";
import {
  parseGatewayEnvelope,
  type ParsedSettledTransaction,
} from "../../src/verifier/gateway-envelope.js";

import {
  sendAbortActionFor,
  type SendAbortAction,
  type SendAbortTrigger,
} from "./send-abort-criteria.js";
import type { SendExternalPlan } from "./send-preflight.js";
import type {
  SendDeliveryRecord,
  SendExecuteDisposition,
  SendExecuteEvidenceBundle,
  SendFormationRecord,
  SendObservation,
} from "./send-execute.js";
import { compareAmounts, signedDelta, type Amount } from "./types.js";

// ─── Public surface ──────────────────────────────────────────────────────────

/** Nine SEND_EXTERNAL predicates, in checklist order. */
export const SEND_EXTERNAL_PATH_PREDICATES = [
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

export type SendPathPredicateId = (typeof SEND_EXTERNAL_PATH_PREDICATES)[number];

/**
 * Terminal disposition outcomes for the send ceremony.
 * - DISPOSED_VERIFIED — landed + path VERIFIED + ack + source lease released.
 * - NEEDS_ATTENTION — ambiguous evidence; hold lease; never infer non-landing.
 * - REJECTED — determinate path REJECTED (invariant), still no lease release here without
 *   the positive non-landing oracle (out of scope for automatic disposition).
 */
export type SendDispositionOutcome =
  | "DISPOSED_VERIFIED"
  | "NEEDS_ATTENTION"
  | "REJECTED"
  | "HOLD_SOURCE_LEASE_AND_RECONCILE"
  | "ESCALATE_INVARIANT_BREACH"
  | "REFUSED_EXECUTE_NOT_LANDED"
  | "REFUSED_INCOMPLETE_EXECUTE_EVIDENCE"
  | "ACK_PINNED"
  | "EVIDENCE_ARCHIVE_FAILED";

/** Independent post-landing source-head re-read (not the mid-run landing observation). */
export interface SendFreshHeadReRead {
  readonly publicKey: string;
  readonly observationId: string;
  readonly step2Signature: string;
  readonly balance: Amount;
  readonly settled: SettledSplitChainTransaction;
  readonly settledTransactionText: string;
  /** Raw pre-parse gateway bytes SHA-256 (evidence bundle, not parsed JSON alone). */
  readonly rawResponseSha256: string;
  readonly rawResponseByteLength: number;
}

export interface SourceDebitCheck {
  readonly sourceDebit: Amount;
  readonly amount: Amount;
  readonly sourceExact: boolean;
}

export interface PartialIdentityCheck {
  readonly executeInnerPreimageText: string;
  readonly executeStep1Signature: string;
  readonly landedInnerPreimageText: string | null;
  readonly landedStep1Signature: string | null;
  readonly landedStep2Signature: string | null;
  readonly innerMatches: boolean;
  readonly step1Matches: boolean;
  readonly headNamesLanded: boolean;
}

export interface SendPathManifestEntry {
  readonly predicate: PredicateId;
  readonly passed: boolean;
  readonly determinate: boolean;
  readonly detail: string;
  readonly status: "VERIFIED" | "REJECTED" | "UNDECIDED";
}

export interface SendPathManifest {
  readonly outcome: VerdictOutcome;
  readonly entries: readonly SendPathManifestEntry[];
  /** True only when every path predicate is determinate and passed. */
  readonly allVerified: boolean;
}

export interface SendLandingCommitRecord {
  readonly operationId: string;
  readonly priorState: "AWAITING_REDEMPTION" | "NEEDS_ATTENTION";
  readonly nextState: "EXTERNAL_SEND_LANDED";
  readonly eventType: "external_send.landed";
  readonly sourceTerminalObservationId: string;
  readonly verifiedAt: string;
  /** True when event append and state transition committed in one DB-TX (seam-reported). */
  readonly sameDbTx: boolean;
}

export interface SendObservationEvidenceRecord {
  readonly operationId: string;
  readonly sourceTerminalObservationId: string;
  readonly verifiedAt: string;
}

export interface SendVerificationAckRecord {
  readonly operationId: string;
  readonly verdict: AckVerdict;
  readonly evidenceRoles: readonly ("SOURCE" | "DESTINATION")[];
  readonly evidence: readonly DurableEvidenceFact[];
  readonly evidenceSetComplete: boolean;
}

export interface SendLeaseReleaseRecord {
  readonly groupDecision: GroupReleaseDecision;
  readonly clampedStatus: LeaseReleaseStatus;
  readonly released: boolean;
  readonly sourceReleased: boolean;
  /** True when release was attempted only after group predicate returned RELEASED. */
  readonly releaseGatedOnGroupPredicate: boolean;
}

/**
 * Archived live-chain evidence packet. Key-free; external
 * counterparty leg present (distinguishes move packet).
 */
export interface SendEvidencePacket {
  readonly kind: "SEND_EXTERNAL_LIVE_CHAIN_EVIDENCE_V1";
  readonly attemptId: string;
  readonly operationId: string;
  readonly archivedAt: string;
  readonly governingRules: readonly string[];
  readonly decisions: readonly string[];
  readonly dualControl: true;
  readonly externalCounterparty: true;
  readonly amountZkz: Amount;
  readonly sourceWalletId: string;
  readonly destinationAddress: string;
  readonly step2Signature: string;
  readonly sourceDebit: SourceDebitCheck;
  readonly partialIdentity: PartialIdentityCheck;
  readonly pathManifest: SendPathManifest;
  readonly landing: SendLandingCommitRecord | null;
  readonly acknowledgement: SendVerificationAckRecord | null;
  readonly leaseRelease: SendLeaseReleaseRecord | null;
  readonly executeDisposition: SendExecuteDisposition;
  readonly trail: readonly string[];
  readonly commandsAndResults: readonly string[];
  readonly negativePathAssertion: string;
  readonly staleDestinationNegativeDocumented: true;
  readonly safeForbiddenHonored: true;
  readonly noSpeculativeContractImplemented: true;
  readonly packetSha256: string;
}

export interface SendDispositionEvidenceBundle {
  readonly attemptId: string;
  readonly operationId: string;
  readonly outcome: SendDispositionOutcome;
  readonly abortAction: SendAbortAction | null;
  readonly abortTrigger: SendAbortTrigger | null;
  readonly plan: SendExternalPlan | null;
  readonly freshSource: SendFreshHeadReRead | null;
  readonly sourceDebit: SourceDebitCheck | null;
  readonly partialIdentity: PartialIdentityCheck | null;
  readonly pathManifest: SendPathManifest | null;
  readonly sendProof: OperationProofResult | null;
  readonly landing: SendLandingCommitRecord | null;
  readonly observationEvidence: SendObservationEvidenceRecord | null;
  readonly acknowledgement: SendVerificationAckRecord | null;
  readonly leaseRelease: SendLeaseReleaseRecord | null;
  readonly evidencePacket: SendEvidencePacket | null;
  readonly trail: readonly string[];
  /** Explicit negative: this surface never issues a node submit. */
  readonly submitCallCount: 0;
  readonly mayResubmit: false;
  readonly mayMintReplacementPartial: false;
  readonly mayReconsumeApproval: false;
  readonly mayRebuildWithoutPositiveOracle: false;
  readonly mayInferNonLandingFromSilence: false;
  readonly mayFreeLeaseBecauseRecipientSilent: false;
}

export interface SendDispositionResult {
  readonly ok: boolean;
  readonly evidence: SendDispositionEvidenceBundle;
}

// ─── Injected seams ──────────────────────────────────────────────────────────

export interface SendFreshHeadSeam {
  /**
   * Independent post-landing source-head re-read (not the mid-run landing observation).
   * Returns null when the head cannot be established — never a guess. A mismatch against
   * expectedStep2 is still returned (with its actual step2) so can classify
   * source_exact_head as UNDECIDED rather than inventing non-landing.
   */
  reReadFreshSourceHead(input: {
    readonly publicKey: string;
    readonly expectedStep2Signature: string;
    readonly expectedInnerPreimageText: string;
    readonly expectedStep1Signature: string;
  }): Promise<SendFreshHeadReRead | null>;
}

export interface SendLandingPersistSeam {
  /**
   * DB-TX: attach terminal observation, AWAITING_REDEMPTION/NEEDS_ATTENTION →
   * EXTERNAL_SEND_LANDED, append external_send.landed, set verified_at. Must be one TX.
   */
  commitLanding(input: {
    readonly operationId: string;
    readonly priorState: "AWAITING_REDEMPTION" | "NEEDS_ATTENTION";
    readonly sourceTerminalObservationId: string;
    readonly settledTransactionText: string;
    readonly step2Signature: string;
    readonly verifiedAt: string;
  }): Promise<SendLandingCommitRecord>;
}

export interface SendAckSeam {
  /**
   * Record verification_acknowledgements + verification_ack_wallet_evidence (SOURCE +
   * DESTINATION where DESTINATION is the external counterparty address). Does not release
   * the source lease (acknowledgement.ts contract).
   */
  recordAcknowledgement(input: {
    readonly operationId: string;
    readonly verdict: AckVerdict;
    readonly evidence: readonly DurableEvidenceFact[];
    readonly sourceT0ObservationId: string;
    readonly destinationFormationObservationId: string;
    readonly sourceTerminalObservationId: string;
  }): Promise<SendVerificationAckRecord>;
}

export interface SendGroupFactsSeam {
  /** Read lease-group facts after this leg's acknowledgement for the release predicate. */
  loadGroupFacts(input: {
    readonly operationId: string;
    readonly thisLegAck: SendVerificationAckRecord;
  }): Promise<GroupReleaseFacts>;
}

export interface SendLeaseReleaseSeam {
  /**
   * Release the SOURCE lease only when status is RELEASED. Implementations MUST refuse
   * when status is not RELEASED (the one-in-flight-per-wallet rule — never free because recipient
   * has not acted). Destination is external and has no node lease.
   */
  releaseSourceIfGroupPassed(input: {
    readonly operationId: string;
    readonly sourceWalletId: string;
    readonly status: LeaseReleaseStatus;
  }): Promise<{ readonly sourceReleased: boolean }>;
}

export interface SendEvidenceArchiveSeam {
  /** Persist the archived evidence packet (key-free). */
  archive(packet: SendEvidencePacket): Promise<{ readonly archiveId: string }>;
}

export interface SendDbChainAgreeSeam {
  /**
   * Compare node-persisted formation / step_1 / row counts against the independently
   * re-read chain head. Returns true only on byte-for-byte agreement of the landed body
   * with the persisted sign-intent preimage + step-1 signature.
   */
  dbAgreesWithChain(input: {
    readonly operationId: string;
    readonly source: SendFreshHeadReRead;
    readonly formation: SendFormationRecord;
    readonly settledTransactionText: string;
    readonly step2Signature: string;
  }): Promise<{ readonly agrees: boolean; readonly detail: string }>;
}

export interface SendDispositionDeps {
  readonly freshHeads: SendFreshHeadSeam;
  readonly landing: SendLandingPersistSeam;
  readonly ack: SendAckSeam;
  readonly groupFacts: SendGroupFactsSeam;
  readonly leases: SendLeaseReleaseSeam;
  readonly evidenceArchive: SendEvidenceArchiveSeam;
  readonly dbChain: SendDbChainAgreeSeam;
  /** Optional clock (ISO-8601 UTC). Defaults to Date.now().toISOString(). */
  readonly nowIso?: () => string;
}

export interface SendDispositionInput {
  readonly operationId: string;
  /** LANDED_VERIFIED evidence from executeAuthorizedSendExternal. */
  readonly executeEvidence: SendExecuteEvidenceBundle;
  /**
   * Optional completed settled-body text when the execute bundle's landing observation
   * does not carry full settled bytes (execute surface only proves inner/step1 match).
   * Live runner supplies the raw settled body from the independent source-head read.
   * Offline tests supply the reconstructed body that matches formation + landing step2.
   */
  readonly completedSettledTransactionText?: string;
  /**
   * Destination baseline projection for predicates 6–7. Defaults to the execute
   * bundle's destinationFormation.projection when omitted.
   */
  readonly destinationBaseline?: WalletStateProjection;
  /** Expected-artifact envelope verification result. */
  readonly artifactVerificationOk: boolean;
  /**
   * Device-signature requirement on the TOTP approval. Live runner reads configuration;
   * offline defaults to not required (consumed-at alone satisfies).
   * When required is true, verified must be explicitly `=== true` (fail-closed; D5).
   */
  readonly deviceSignatureRequired?: boolean;
  readonly deviceSignatureVerified?: boolean;
  /** Prior operation state for the landing CAS. */
  readonly priorState?: "AWAITING_REDEMPTION" | "NEEDS_ATTENTION";
  /**
   * When true (default), refuse unless executeEvidence.disposition === LANDED_VERIFIED.
   * Tests may set false only for negative-path injection of incomplete bundles.
   */
  readonly requireLandedExecute?: boolean;
}

// ─── Internals ───────────────────────────────────────────────────────────────

const GOVERNING_RULES = [
  "observation and verification: the nine external-send path predicates",
  "operation flows: send disposition and the retention-and-release sequence",
  "operations and recovery: the safe actions after an ambiguous send",
  "data model: verification acknowledgements",
  "state and event reference: send terminal event data",
  "build and test plan: live-chain acceptance evidence",
] as const;

const DESIGN_RULES = [
  "complete-path-adjudication",
  "approve-before-formation",
  "distinct-expiry-timers",
  "dual-control-attestation",
  "amount-hard-cap",
  "live-chain-execution",
] as const;

const NEGATIVE_PATH_ASSERTION =
  "NEGATIVE: disposition never issues a node submit, never mints a replacement partial, " +
  "never reconsumes approval, never infers non-landing from silence or a source-head " +
  "mismatch (the never-blind-retry rule); source lease stays held until the " +
  "group predicate RELEASED. Stale-destination refusal is held (RECIPIENT_REFUSED_STALE_DESTINATION) " +
  "and never re-signs.";

function trailPush(trail: string[], line: string): void {
  trail.push(line);
}

/** Parse settled transaction text through the real envelope stage. */
export function parseSendSettledTransactionText(settledText: string): ParsedSettledTransaction {
  const verdict = parseGatewayEnvelope(
    new TextEncoder().encode(
      `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
    ),
  );
  if (verdict.classification !== "HEAD") {
    throw new Error(`expected HEAD envelope, got ${verdict.classification}`);
  }
  return verdict.parsed;
}

function emptyBundle(
  input: SendDispositionInput,
  trail: string[],
  outcome: SendDispositionOutcome,
  extras: Partial<SendDispositionEvidenceBundle> = {},
): SendDispositionEvidenceBundle {
  return {
    attemptId: input.executeEvidence.attemptId,
    operationId: input.operationId,
    outcome,
    abortAction: extras.abortAction ?? null,
    abortTrigger: extras.abortTrigger ?? null,
    plan: input.executeEvidence.plan,
    freshSource: null,
    sourceDebit: null,
    partialIdentity: null,
    pathManifest: null,
    sendProof: null,
    landing: null,
    observationEvidence: null,
    acknowledgement: null,
    leaseRelease: null,
    evidencePacket: null,
    trail,
    submitCallCount: 0,
    mayResubmit: false,
    mayMintReplacementPartial: false,
    mayReconsumeApproval: false,
    mayRebuildWithoutPositiveOracle: false,
    mayInferNonLandingFromSilence: false,
    mayFreeLeaseBecauseRecipientSilent: false,
    ...extras,
  };
}

function buildPathManifest(proof: OperationProofResult): SendPathManifest {
  const byId = new Map(proof.predicates.map((p) => [p.predicate, p]));
  const entries: SendPathManifestEntry[] = SEND_EXTERNAL_PATH_PREDICATES.map((id) => {
    const p: EvaluatedPredicate | undefined = byId.get(id);
    if (p === undefined) {
      return {
        predicate: id,
        passed: false,
        determinate: false,
        detail: "predicate absent from proof evaluation",
        status: "UNDECIDED",
      };
    }
    const status: SendPathManifestEntry["status"] = !p.determinate
      ? "UNDECIDED"
      : p.passed
        ? "VERIFIED"
        : "REJECTED";
    return {
      predicate: p.predicate,
      passed: p.passed,
      determinate: p.determinate,
      detail: p.detail,
      status,
    };
  });
  const allVerified = entries.every((e) => e.status === "VERIFIED");
  return {
    outcome: proof.verdict.outcome,
    entries,
    allVerified,
  };
}

function buildSourceDebit(
  sourceT0: SendObservation,
  freshSource: SendFreshHeadReRead,
  amount: Amount,
): SourceDebitCheck {
  // Ts0.B - Ts1.B == amount_zkz against the FRESH head.
  // signedDelta(before, after) = after - before. Debit magnitude = signedDelta(Ts1.B, Ts0.B).
  const sourceDebit = signedDelta(freshSource.balance, sourceT0.projection.B);
  const sourceExact = compareAmounts(sourceDebit, amount) === 0;
  return {
    sourceDebit,
    amount,
    sourceExact,
  };
}

function buildPartialIdentity(
  formation: SendFormationRecord,
  freshSource: SendFreshHeadReRead,
  parsed: ParsedSettledTransaction | null,
  /** Settled body bytes used for proof/landing — must already be bound to fresh head. */
  settledTransactionText: string,
): PartialIdentityCheck {
  const landedInner =
    parsed !== null
      ? // Re-derive preimage text from the settled body's inner via the exact bytes in
        // the settled text — prefer the parse's step signatures + extract from settled text.
        extractInnerPreimageText(settledTransactionText)
      : null;
  const landedStep1 = parsed?.step_1_signature ?? null;
  const landedStep2 = parsed?.step_2_signature ?? freshSource.step2Signature;
  const innerMatches =
    landedInner !== null && landedInner === formation.innerPreimageText;
  const step1Matches =
    landedStep1 !== null && landedStep1 === formation.step1Signature;
  const headNamesLanded = freshSource.step2Signature === landedStep2;
  return {
    executeInnerPreimageText: formation.innerPreimageText,
    executeStep1Signature: formation.step1Signature,
    landedInnerPreimageText: landedInner,
    landedStep1Signature: landedStep1,
    landedStep2Signature: landedStep2,
    innerMatches,
    step1Matches,
    headNamesLanded,
  };
}

/**
 * Extract the inner preimage text from a settled body of the form
 * `{"inner":<innerPreimageText>,"step_1_signature":...,"step_2_signature":...}`
 * without re-serializing (the byte-exact signing rule).
 */
function extractInnerPreimageText(settledText: string): string | null {
  // Settled body is {"inner":{...},"step_1_signature":"...","step_2_signature":"..."}
  // with insertion order fixed. Slice the inner object by balanced braces after "inner":.
  const marker = '"inner":';
  const start = settledText.indexOf(marker);
  if (start < 0) return null;
  let i = start + marker.length;
  if (settledText[i] !== "{") return null;
  let depth = 0;
  const begin = i;
  for (; i < settledText.length; i += 1) {
    const ch = settledText[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) {
        return settledText.slice(begin, i + 1);
      }
    }
  }
  return null;
}

/**
 * Project disposition-observed delivery records into DeliveredPartial inputs.
 *
 * Load-bearing (dual FAIL D2): each delivery's transfer-code bytes are compared to
 * the code rebuilt from formation.inner + formation.step1 (and to the formation's own
 * transferCodeText/sha). Only byte-identical deliveries project the formation partial.
 * Foreign delivery text/sha projects a distinct sentinel so evaluateSinglePartial REJECTS
 * — never synthesise formation bytes while discarding the delivery log.
 */
function deliveriesToPartials(
  deliveries: readonly SendDeliveryRecord[],
  formation: SendFormationRecord,
): DeliveredPartial[] {
  const expectedCode = buildSendTransferCodeText(
    formation.innerPreimageText,
    formation.step1Signature,
  );
  const expectedSha = hashTransferCodeText(expectedCode);
  const formationCodeMatchesRebuild =
    formation.transferCodeText === expectedCode &&
    formation.transferCodeSha256 === expectedSha;

  return deliveries.map((delivery) => {
    const deliverySha = hashTransferCodeText(delivery.transferCodeText);
    const shaSelfConsistent = delivery.transferCodeSha256 === deliverySha;
    const matchesExpected =
      formationCodeMatchesRebuild &&
      shaSelfConsistent &&
      delivery.transferCodeText === expectedCode &&
      delivery.transferCodeSha256 === expectedSha;

    if (matchesExpected) {
      return {
        step1PreimageText: formation.innerPreimageText,
        step1Signature: formation.step1Signature,
      };
    }
    // Foreign / inconsistent delivery — distinct from formation so predicate 9 reddens.
    return {
      step1PreimageText: `foreign-delivery:${delivery.transferCodeSha256}`,
      step1Signature: delivery.transferCodeSha256,
    };
  });
}

function buildArtifact(plan: SendExternalPlan): SendExpectedArtifact {
  return {
    amount_zkz: plan.amount,
    source_pubkey: plan.sourcePubkey,
    destination_address: plan.destinationAddress,
  };
}

function packetDigest(packet: Omit<SendEvidencePacket, "packetSha256">): string {
  const material = JSON.stringify({
    kind: packet.kind,
    attemptId: packet.attemptId,
    operationId: packet.operationId,
    archivedAt: packet.archivedAt,
    amountZkz: packet.amountZkz,
    sourceWalletId: packet.sourceWalletId,
    destinationAddress: packet.destinationAddress,
    step2Signature: packet.step2Signature,
    sourceDebit: packet.sourceDebit,
    partialIdentity: {
      innerMatches: packet.partialIdentity.innerMatches,
      step1Matches: packet.partialIdentity.step1Matches,
      headNamesLanded: packet.partialIdentity.headNamesLanded,
    },
    pathManifestOutcome: packet.pathManifest.outcome,
    pathAllVerified: packet.pathManifest.allVerified,
    executeDisposition: packet.executeDisposition,
    noSpeculativeContractImplemented: packet.noSpeculativeContractImplemented,
    externalCounterparty: packet.externalCounterparty,
    dualControl: packet.dualControl,
    staleDestinationNegativeDocumented: packet.staleDestinationNegativeDocumented,
    safeForbiddenHonored: packet.safeForbiddenHonored,
  });
  return createHash("sha256").update(material, "utf8").digest("hex");
}

/**
 * Reconcile and disposition one LANDED_VERIFIED SEND_EXTERNAL run.
 *
 * Sequence:
 *   1. Require execute LANDED_VERIFIED + complete formation/landing/approval evidence.
 *   2. Independently re-read fresh source head (not mid-run landing).
 *   3. Source debit exact + partial identity (inner + step1) against formation.
 *   4. OBS path manifest via evaluateSendProof (all nine → VERIFIED).
 *      Source-head mismatch → UNDECIDED/INDETERMINATE — never non-landing.
 *   5. DB-vs-chain byte agreement.
 *   6. Landing DB-TX: EXTERNAL_SEND_LANDED + external_send.landed same TX.
 *   7. verification_acknowledgements with SOURCE + DESTINATION (external) evidence.
 *   8. Group-predicate release — source lease only when RELEASED.
 *   9. Archive evidence packet.
 *
 * Never submits. Never rebuilds. Never frees the lease because the recipient is silent.
 */
export async function disposeSendExternalEvidence(
  deps: SendDispositionDeps,
  input: SendDispositionInput,
): Promise<SendDispositionResult> {
  const trail: string[] = [];
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const requireLanded = input.requireLandedExecute !== false;
  const exec = input.executeEvidence;

  trailPush(trail, `disposition start attempt=${exec.attemptId} op=${input.operationId}`);
  trailPush(trail, `execute disposition=${exec.disposition}; node submit never issued here`);
  trailPush(
    trail,
    "09: safe=bounded source-head reads / verify completed tx / re-serve identical " +
      "code / append diagnostics; forbidden=node submit / re-form / change expiry / " +
      "second step-1 / infer non-landing / free lease on recipient silence",
  );

  // Stale-destination negative is documented on every run (execute already held it).
  if (exec.disposition === "RECIPIENT_REFUSED_STALE_DESTINATION") {
    trailPush(
      trail,
      "stale-destination negative: recipient refused; node must NOT re-sign (execute held)",
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_SOURCE_LEASE_AND_RECONCILE", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
      }),
    };
  }

  if (requireLanded && exec.disposition !== "LANDED_VERIFIED") {
    trailPush(trail, `refuse: execute not LANDED_VERIFIED (${exec.disposition})`);
    // Ambiguous execute outcomes hold — never classify as non-landing.
    const outcome: SendDispositionOutcome =
      exec.disposition === "ESCALATE_INVARIANT_BREACH"
        ? "ESCALATE_INVARIANT_BREACH"
        : "REFUSED_EXECUTE_NOT_LANDED";
    const trigger: SendAbortTrigger =
      exec.disposition === "ESCALATE_INVARIANT_BREACH"
        ? "INVARIANT_BREACH"
        : "PARTIAL_DELIVERED_UNOBSERVED";
    return {
      ok: false,
      evidence: emptyBundle(input, trail, outcome, {
        abortAction: sendAbortActionFor(trigger).action,
        abortTrigger: trigger,
      }),
    };
  }

  const plan = exec.plan;
  const formation = exec.formation;
  const sourceT0 = exec.sourceT0;
  const destinationFormation = exec.destinationFormation;
  const approval = exec.approval;
  const landing = exec.landing;
  const rowCounts = exec.rowCounts;

  // D4 / disposition re-checks lease-before-read + single recipient submit.
  // Do not trust LANDED_VERIFIED alone when the execute counter was vacuous upstream.
  if (
    plan === null ||
    formation === null ||
    sourceT0 === null ||
    destinationFormation === null ||
    approval === null ||
    landing === null ||
    rowCounts === null ||
    !landing.innerTextMatchesPersisted ||
    !landing.step1SignatureMatchesPersisted ||
    rowCounts.totpConsumptions !== 1 ||
    rowCounts.signIntents !== 1 ||
    rowCounts.partials !== 1 ||
    rowCounts.submitDecisions !== 0 ||
    rowCounts.gatewaySubmitAttempts !== 0 ||
    exec.leaseHeldBeforeAnyRead !== true ||
    exec.recipient === null ||
    exec.recipient.recipientSubmitCallCount !== 1 ||
    exec.deliveries.length === 0
  ) {
    trailPush(
      trail,
      "refuse: incomplete execute landing / row-count / lease-before-read / " +
        "recipient-submit / delivery evidence",
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "REFUSED_INCOMPLETE_EXECUTE_EVIDENCE", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
      }),
    };
  }

  const expectedStep2 = landing.step2Signature;
  trailPush(
    trail,
    `expected step_2=${truncateSig(expectedStep2)} amount=${plan.amount} ` +
      `approval=${approval.approvalId}`,
  );

  // ── Independent fresh source-head re-read (not mid-run landing) ────────────
  let freshSource: SendFreshHeadReRead | null;
  try {
    freshSource = await deps.freshHeads.reReadFreshSourceHead({
      publicKey: sourceT0.publicKey,
      expectedStep2Signature: expectedStep2,
      expectedInnerPreimageText: formation.innerPreimageText,
      expectedStep1Signature: formation.step1Signature,
    });
  } catch (err) {
    trailPush(
      trail,
      `fresh source head re-read threw: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_SOURCE_LEASE_AND_RECONCILE", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
      }),
    };
  }

  if (freshSource === null) {
    // Missing head does not prove non-landing → NEEDS_ATTENTION / hold.
    trailPush(trail, "fresh source head incomplete — INDETERMINATE (non-landing NOT proven)");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "NEEDS_ATTENTION", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
        freshSource: null,
      }),
    };
  }

  trailPush(
    trail,
    `fresh source obs=${freshSource.observationId} step_2=${truncateSig(freshSource.step2Signature)} ` +
      `raw_sha=${freshSource.rawResponseSha256.slice(0, 16)}…`,
  );

  // Source-head identity first. A fresh head that does not name the
  // expected step_2 is INDETERMINATE — never non-landing, and never lose to debit ESCALATE
  // when both head identity and balance drift fail (the common combined case).
  if (freshSource.step2Signature !== expectedStep2) {
    trailPush(
      trail,
      `source head mismatch (fresh=${truncateSig(freshSource.step2Signature)} ` +
        `expected=${truncateSig(expectedStep2)}) — INDETERMINATE; non-landing NOT proven`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "NEEDS_ATTENTION", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
        freshSource,
      }),
    };
  }

  // D3: completed body for proof/landing must be byte-identical to the fresh-head settled
  // text. Caller override is accepted only when it equals the independent re-read.
  const freshSettledText = freshSource.settledTransactionText;
  if (
    input.completedSettledTransactionText !== undefined &&
    input.completedSettledTransactionText !== freshSettledText
  ) {
    trailPush(
      trail,
      "INVARIANT: caller completedSettledTransactionText ≠ fresh-head settled body bytes",
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: sendAbortActionFor("INVARIANT_BREACH").action,
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
      }),
    };
  }
  const settledText = freshSettledText;

  let parsed: ParsedSettledTransaction;
  try {
    parsed = parseSendSettledTransactionText(settledText);
  } catch (err) {
    trailPush(
      trail,
      `settled parse failed: ${err instanceof Error ? err.message : String(err)} — hold`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_SOURCE_LEASE_AND_RECONCILE", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
        freshSource,
      }),
    };
  }

  // ── Source debit against fresh head — only after head identity ─
  const sourceDebit = buildSourceDebit(sourceT0, freshSource, plan.amount);
  trailPush(
    trail,
    `source debit Δ=${sourceDebit.sourceDebit} amount=${sourceDebit.amount} exact=${sourceDebit.sourceExact}`,
  );

  // ── Partial identity (inner + step1 byte-exact; the byte-exact signing rule) ─────────────
  const partialIdentity = buildPartialIdentity(
    formation,
    freshSource,
    parsed,
    settledText,
  );
  trailPush(
    trail,
    `partial identity inner=${partialIdentity.innerMatches} step1=${partialIdentity.step1Matches} ` +
      `head_names=${partialIdentity.headNamesLanded}`,
  );

  if (!partialIdentity.innerMatches || !partialIdentity.step1Matches) {
    // Determinate fault when we have a completed body that does not match the intent.
    trailPush(trail, "INVARIANT: landed body ≠ persisted sign-intent / partial");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: sendAbortActionFor("INVARIANT_BREACH").action,
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        sourceDebit,
        partialIdentity,
      }),
    };
  }

  if (!sourceDebit.sourceExact) {
    trailPush(trail, "INVARIANT: fresh-head source debit does not equal amount_zkz");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: sendAbortActionFor("INVARIANT_BREACH").action,
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        sourceDebit,
        partialIdentity,
      }),
    };
  }

  // ── path manifest via evaluateSendProof ────────────────────────────
  // D5: when device signature is required, only explicit === true counts as verified.
  const deviceSignatureRequired = input.deviceSignatureRequired === true;
  const totpApproval: TotpApproval = {
    approvalId: approval.approvalId,
    consumedAtUnixMs: 1, // execute already proved consumption; positive stamp
    deviceSignatureRequired,
    deviceSignatureVerified: deviceSignatureRequired
      ? input.deviceSignatureVerified === true
      : input.deviceSignatureVerified !== false,
  };

  const signIntent: SignIntentRow = {
    approvalId: approval.approvalId,
    amountZkz: plan.amount,
    destinationAddress: plan.destinationAddress,
    sourceBaselineObservationId: sourceT0.observationId,
    destinationBaselineObservationId: destinationFormation.observationId,
    step1PreimageText: formation.innerPreimageText,
    step1Signature: formation.step1Signature,
  };

  const submitEvidence: SendSubmitEvidence = {
    sourceWalletPublicKey: sourceT0.publicKey,
    sourceBaseline: sourceT0.projection,
    sourceBaselineObservationId: sourceT0.observationId,
    completed: parsed,
    signIntents: [signIntent],
    deliveredPartials: deliveriesToPartials(exec.deliveries, formation),
    sourceAcceptedHeadStepTwoSignature: freshSource.step2Signature,
    approval: totpApproval,
  };

  const destBaseline = input.destinationBaseline ?? destinationFormation.projection;
  const recipientConfirmation: SendRecipientConfirmation = {
    destinationBaseline: destBaseline,
    destinationBaselineObservationId: destinationFormation.observationId,
    approvedDestinationAddress: plan.destinationAddress,
  };

  const policyInput: SendPolicyInput = {
    artifact: buildArtifact(plan),
    artifactVerification: input.artifactVerificationOk
      ? {
          ok: true,
          purpose: "zp-send-external-expected-v1",
          digest: createHash("sha256")
            .update(
              `${plan.attemptId}:${plan.sourceWalletId}:${plan.destinationAddress}:${plan.amount}`,
              "utf8",
            )
            .digest("hex"),
        }
      : { ok: false, reason: "envelope_rejected", detail: "artifact verification failed" },
    submitEvidence,
    recipientConfirmation,
  };

  const sendProof = evaluateSendProof(policyInput);
  const pathManifest = buildPathManifest(sendProof);
  trailPush(
    trail,
    `path manifest outcome=${pathManifest.outcome} allVerified=${pathManifest.allVerified}`,
  );
  for (const e of pathManifest.entries) {
    trailPush(trail, `  predicate ${e.predicate}: ${e.status} — ${e.detail}`);
  }

  if (!pathManifest.allVerified || pathManifest.outcome !== "VERIFIED") {
    const determinateFail = pathManifest.entries.some((e) => e.status === "REJECTED");
    // UNDECIDED on source_exact_head (or any undecided) → NEEDS_ATTENTION, not REJECTED.
    const outcome: SendDispositionOutcome = determinateFail
      ? "REJECTED"
      : "NEEDS_ATTENTION";
    const trigger: SendAbortTrigger = determinateFail
      ? "INVARIANT_BREACH"
      : "PARTIAL_DELIVERED_UNOBSERVED";
    trailPush(trail, `path manifest failed → ${outcome} (non-landing NOT inferred)`);
    return {
      ok: false,
      evidence: emptyBundle(input, trail, outcome, {
        abortAction: sendAbortActionFor(trigger).action,
        abortTrigger: trigger,
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
      }),
    };
  }

  // ── DB-vs-chain agreement ──────────────────────────────────────────────────
  let dbAgree: { readonly agrees: boolean; readonly detail: string };
  try {
    dbAgree = await deps.dbChain.dbAgreesWithChain({
      operationId: input.operationId,
      source: freshSource,
      formation,
      settledTransactionText: settledText,
      step2Signature: expectedStep2,
    });
  } catch (err) {
    trailPush(
      trail,
      `db-vs-chain check threw: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_SOURCE_LEASE_AND_RECONCILE", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
      }),
    };
  }

  trailPush(trail, `db-vs-chain agrees=${dbAgree.agrees}: ${dbAgree.detail}`);
  if (!dbAgree.agrees) {
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: sendAbortActionFor("INVARIANT_BREACH").action,
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
      }),
    };
  }

  // ── Landing DB-TX ─────────────────────────────────────────
  const verifiedAt = nowIso();
  let landingCommit: SendLandingCommitRecord;
  try {
    landingCommit = await deps.landing.commitLanding({
      operationId: input.operationId,
      priorState: input.priorState ?? "AWAITING_REDEMPTION",
      sourceTerminalObservationId: freshSource.observationId,
      settledTransactionText: settledText,
      step2Signature: expectedStep2,
      verifiedAt,
    });
  } catch (err) {
    trailPush(
      trail,
      `landing commit failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_SOURCE_LEASE_AND_RECONCILE", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
      }),
    };
  }

  if (
    landingCommit.nextState !== "EXTERNAL_SEND_LANDED" ||
    landingCommit.eventType !== "external_send.landed" ||
    !landingCommit.sameDbTx
  ) {
    trailPush(trail, "landing commit shape invalid (state/event/sameDbTx)");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: sendAbortActionFor("INVARIANT_BREACH").action,
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
        landing: landingCommit,
      }),
    };
  }

  const observationEvidence: SendObservationEvidenceRecord = {
    operationId: input.operationId,
    sourceTerminalObservationId: landingCommit.sourceTerminalObservationId,
    verifiedAt: landingCommit.verifiedAt,
  };
  trailPush(
    trail,
    `landing ${landingCommit.priorState}→${landingCommit.nextState} ` +
      `event=${landingCommit.eventType} sameDbTx=${landingCommit.sameDbTx}`,
  );

  // ── Verification acknowledgement (SOURCE + DESTINATION external) ─
  const expectedWallets: readonly OperationWalletAssignment[] = expectedWalletsForOperation(
    "SEND_EXTERNAL",
    {
      sourceWalletId: plan.sourceWalletId,
      sourcePublicKey: sourceT0.publicKey,
      receiverWalletId: null,
      receiverPublicKey: null,
      destinationWalletId: null,
      destinationPublicKey: null,
      destinationAddress: plan.destinationAddress,
    },
  );
  const evidenceFacts: DurableEvidenceFact[] = [
    {
      role: "SOURCE",
      walletId: plan.sourceWalletId,
      walletPublicKey: sourceT0.publicKey,
    },
    {
      role: "DESTINATION",
      walletId: null,
      walletPublicKey: plan.destinationAddress,
    },
  ];
  const evidenceFailure = validateEvidenceSet(
    "SEND_EXTERNAL",
    evidenceFacts.map((e) => ({
      role: e.role,
      walletId: e.walletId,
      walletPublicKey: e.walletPublicKey,
    })),
    expectedWallets,
  );
  if (evidenceFailure !== null) {
    trailPush(trail, `evidence set invalid: ${evidenceFailure.kind}`);
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: sendAbortActionFor("INVARIANT_BREACH").action,
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
        landing: landingCommit,
        observationEvidence,
      }),
    };
  }

  let ackRecord: SendVerificationAckRecord;
  try {
    ackRecord = await deps.ack.recordAcknowledgement({
      operationId: input.operationId,
      verdict: "VERIFIED",
      evidence: evidenceFacts,
      sourceT0ObservationId: sourceT0.observationId,
      destinationFormationObservationId: destinationFormation.observationId,
      sourceTerminalObservationId: freshSource.observationId,
    });
  } catch (err) {
    trailPush(
      trail,
      `ack record failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_SOURCE_LEASE_AND_RECONCILE", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
        landing: landingCommit,
        observationEvidence,
      }),
    };
  }

  if (
    ackRecord.verdict !== "VERIFIED" ||
    !ackRecord.evidenceSetComplete ||
    !ackRecord.evidenceRoles.includes("SOURCE") ||
    !ackRecord.evidenceRoles.includes("DESTINATION")
  ) {
    trailPush(trail, "ack incomplete or non-VERIFIED — source lease stays held");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ACK_PINNED", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
        landing: landingCommit,
        observationEvidence,
        acknowledgement: ackRecord,
      }),
    };
  }
  trailPush(
    trail,
    `ack VERIFIED roles=[${ackRecord.evidenceRoles.join(",")}] complete=${ackRecord.evidenceSetComplete}`,
  );

  // ── Group-predicate source-lease release ─────────────
  let groupFacts: GroupReleaseFacts;
  try {
    groupFacts = await deps.groupFacts.loadGroupFacts({
      operationId: input.operationId,
      thisLegAck: ackRecord,
    });
  } catch (err) {
    trailPush(
      trail,
      `group facts load failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_SOURCE_LEASE_AND_RECONCILE", {
        abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
        abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
        landing: landingCommit,
        observationEvidence,
        acknowledgement: ackRecord,
      }),
    };
  }

  const groupDecision = evaluateGroupRelease(groupFacts);
  const clampedStatus = clampReleaseToVerdict(ackRecord.verdict, groupDecision.status);
  trailPush(
    trail,
    `group release status=${groupDecision.status} reason=${groupDecision.reason} ` +
      `clamped=${clampedStatus}`,
  );

  let sourceReleased = false;
  const releaseGatedOnGroupPredicate = true;

  if (clampedStatus === "RELEASED") {
    try {
      const rel = await deps.leases.releaseSourceIfGroupPassed({
        operationId: input.operationId,
        sourceWalletId: plan.sourceWalletId,
        status: clampedStatus,
      });
      sourceReleased = rel.sourceReleased;
    } catch (err) {
      trailPush(
        trail,
        `source lease release failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return {
        ok: false,
        evidence: emptyBundle(input, trail, "HOLD_SOURCE_LEASE_AND_RECONCILE", {
          abortAction: sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").action,
          abortTrigger: "PARTIAL_DELIVERED_UNOBSERVED",
          freshSource,
          sourceDebit,
          partialIdentity,
          pathManifest,
          sendProof,
          landing: landingCommit,
          observationEvidence,
          acknowledgement: ackRecord,
          leaseRelease: {
            groupDecision,
            clampedStatus,
            released: false,
            sourceReleased: false,
            releaseGatedOnGroupPredicate,
          },
        }),
      };
    }
  } else {
    trailPush(trail, "source lease retained — group predicate not RELEASED");
  }

  const leaseRelease: SendLeaseReleaseRecord = {
    groupDecision,
    clampedStatus,
    released: sourceReleased && clampedStatus === "RELEASED",
    sourceReleased,
    releaseGatedOnGroupPredicate,
  };
  trailPush(
    trail,
    `lease release released=${leaseRelease.released} src=${sourceReleased}`,
  );

  if (clampedStatus !== "RELEASED" || !leaseRelease.released) {
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ACK_PINNED", {
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
        landing: landingCommit,
        observationEvidence,
        acknowledgement: ackRecord,
        leaseRelease,
      }),
    };
  }

  // ── evidence packet archive ─────────────────────────────────────────────
  const archivedAt = nowIso();
  const packetBase = {
    kind: "SEND_EXTERNAL_LIVE_CHAIN_EVIDENCE_V1" as const,
    attemptId: exec.attemptId,
    operationId: input.operationId,
    archivedAt,
    governingRules: GOVERNING_RULES,
    decisions: DESIGN_RULES,
    dualControl: true as const,
    externalCounterparty: true as const,
    amountZkz: plan.amount,
    sourceWalletId: plan.sourceWalletId,
    destinationAddress: plan.destinationAddress,
    step2Signature: expectedStep2,
    sourceDebit,
    partialIdentity,
    pathManifest,
    landing: landingCommit,
    acknowledgement: ackRecord,
    leaseRelease,
    executeDisposition: exec.disposition,
    trail: [...trail],
    commandsAndResults: [
      `disposeSendExternalEvidence attempt=${exec.attemptId}`,
      `fresh source re-read → step_2=${truncateSig(expectedStep2)}`,
      `source debit exact=${sourceDebit.sourceExact}`,
      `partial identity inner=${partialIdentity.innerMatches} step1=${partialIdentity.step1Matches}`,
      `path manifest allVerified=${pathManifest.allVerified}`,
      `landing ${landingCommit.priorState}→${landingCommit.nextState} + ${landingCommit.eventType}`,
      `ack verdict=${ackRecord.verdict} roles=${ackRecord.evidenceRoles.join("+")}`,
      `source lease release status=${clampedStatus} released=${leaseRelease.released}`,
    ],
    negativePathAssertion: NEGATIVE_PATH_ASSERTION,
    staleDestinationNegativeDocumented: true as const,
    safeForbiddenHonored: true as const,
    noSpeculativeContractImplemented: true as const,
  };
  const evidencePacket: SendEvidencePacket = {
    ...packetBase,
    packetSha256: packetDigest(packetBase),
  };

  try {
    const archived = await deps.evidenceArchive.archive(evidencePacket);
    trailPush(
      trail,
      `evidence packet archived id=${archived.archiveId} sha256=${evidencePacket.packetSha256.slice(0, 16)}…`,
    );
  } catch (err) {
    trailPush(
      trail,
      `evidence archive failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "EVIDENCE_ARCHIVE_FAILED", {
        freshSource,
        sourceDebit,
        partialIdentity,
        pathManifest,
        sendProof,
        landing: landingCommit,
        observationEvidence,
        acknowledgement: ackRecord,
        leaseRelease,
        evidencePacket,
      }),
    };
  }

  trailPush(trail, `DISPOSED_VERIFIED amount=${plan.amount} step_2=${truncateSig(expectedStep2)}`);

  return {
    ok: true,
    evidence: {
      attemptId: exec.attemptId,
      operationId: input.operationId,
      outcome: "DISPOSED_VERIFIED",
      abortAction: sendAbortActionFor("LANDED_VERIFIED").action,
      abortTrigger: "LANDED_VERIFIED",
      plan,
      freshSource,
      sourceDebit,
      partialIdentity,
      pathManifest,
      sendProof,
      landing: landingCommit,
      observationEvidence,
      acknowledgement: ackRecord,
      leaseRelease,
      evidencePacket,
      trail,
      submitCallCount: 0,
      mayResubmit: false,
      mayMintReplacementPartial: false,
      mayReconsumeApproval: false,
      mayRebuildWithoutPositiveOracle: false,
      mayInferNonLandingFromSilence: false,
      mayFreeLeaseBecauseRecipientSilent: false,
    },
  };
}

function truncateSig(sig: string): string {
  if (sig === "") return "∅";
  if (sig.length <= 12) return sig;
  return `${sig.slice(0, 8)}…${sig.slice(-4)}`;
}
