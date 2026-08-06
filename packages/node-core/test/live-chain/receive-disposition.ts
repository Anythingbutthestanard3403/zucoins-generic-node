// Live RECEIVE_EXTERNAL reconcile + evidence disposition harness.
//
// Offline-first post-landing coordination over injected seams. Closes the RECEIVE_EXTERNAL
// acceptance path after LANDED_VERIFIED execute evidence: dual observer-ledger
// reconciliation (node `gateway_observations` + an independent PLATFORM-domain direct read),
// ten-predicate verification, landing DB-TX (READY → RECEIVE_LANDED + receive.landed),
// the ordered retention-and-release sequence, a VERIFICATION_COMPLETE release proof bound
// to the acknowledgement, and the immutable evidence packet.
//
// Governing:
//   The one-in-flight-per-wallet and byte-exact signing rules, 4, 5
//
// Structural invariants:
//   - Settlement is declared only on a confirmation read. A submit response's own echo is
//     never landing evidence.
//   - The independent observer performs its own direct gateway read. A node-relayed response
//     is never accepted as the platform's observation.
//   - A receiver-head mismatch is INDETERMINATE — never inferred non-landing.
//   - The receiver lease releases only after the verification-complete acknowledgement and
//     only when the whole lease group's predicate passes.
//   - Proof-access expiry revokes access with HTTP 410; it never deletes ledger or
//     observation bytes (C-10).
//   - Private keys never appear (the key-custody rule). This surface never submits (the never-blind-retry rule).

import { createHash } from "node:crypto";

import {
  classifyRelationship,
  type AcceptedSemanticState,
} from "@zucoins/generic-node-contracts/observation";

import {
  evaluateReceiveProof,
  type ReceiveExpectedArtifact,
  type ReceivePolicyInput,
  type ReceiverBaseline,
} from "../../src/proof/policies/receive.js";
import type { EvaluatedPredicate, OperationProofResult } from "../../src/proof/policies/shared.js";
import type { PredicateId, VerdictOutcome } from "../../src/proof/types.js";
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
  receiveAbortActionFor,
  type ReceiveAbortAction,
  type ReceiveAbortTrigger,
} from "./receive-abort-criteria.js";
import type { ReceiveExternalPlan } from "./receive-preflight.js";
import { compareAmounts, signedDelta, type Amount } from "./types.js";

// ─── Public surface ──────────────────────────────────────────────────────────

/** Ten RECEIVE_EXTERNAL predicates, in checklist order. */
export const RECEIVE_EXTERNAL_PATH_PREDICATES = [
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
] as const satisfies readonly PredicateId[];

export type ReceivePathPredicateId = (typeof RECEIVE_EXTERNAL_PATH_PREDICATES)[number];

/**
 * Retention-and-release sequence, normative and ordered. The disposition records each
 * step as it actually completes and refuses to archive a run whose steps did not occur in
 * this order.
 */
export const RECEIVE_RELEASE_SEQUENCE = [
  "PERSIST_EVIDENCE",
  "EXPOSE_SCOPED_PROOF",
  "AWAIT_VERIFICATION_COMPLETE_ACK",
  "RELEASE_ON_GROUP_PREDICATE",
  "REVOKE_PROOF_ACCESS_410",
] as const;

export type ReceiveReleaseStep = (typeof RECEIVE_RELEASE_SEQUENCE)[number];

/**
 * Every rejection site this surface can take, declared. The census test derives the same set
 * from the source's `GUARD:` markers, so a new guard cannot be added without declaring it and
 * a removed guard cannot go unnoticed.
 */
export const RECEIVE_DISPOSITION_GUARDS = [
  "execute_not_landed",
  "incomplete_execute_evidence",
  "settlement_not_from_confirmation_read",
  "receiver_head_mismatch",
  "independent_observation_unavailable",
  "independent_observation_not_direct",
  "independent_observation_wrong_domain",
  "observer_ledgers_disagree",
  "settled_body_parse_failed",
  "credit_not_exact",
  "path_manifest_not_verified",
  "landing_commit_failed",
  "landing_commit_shape_invalid",
  "proof_exposure_failed",
  "evidence_set_invalid",
  "ack_failed",
  "ack_not_verified",
  "group_facts_failed",
  "lease_release_failed",
  "release_proof_invalid",
  "lease_not_released",
  "proof_access_revocation_failed",
  "proof_access_revocation_deleted_ledger",
  "evidence_archive_failed",
] as const;

export type ReceiveDispositionGuardId = (typeof RECEIVE_DISPOSITION_GUARDS)[number];

/**
 * Terminal disposition outcomes for the receive ceremony.
 * - DISPOSED_VERIFIED — landed + VERIFIED + both ledgers agree + ack + lease released.
 * - NEEDS_ATTENTION — ambiguous evidence; hold the receiver lease; never infer non-landing.
 * - REJECTED — determinate rejection; the lease still holds without the positive
 *   non-landing oracle, which this surface never consults.
 */
export type ReceiveDispositionOutcome =
  | "DISPOSED_VERIFIED"
  | "NEEDS_ATTENTION"
  | "REJECTED"
  | "HOLD_RECEIVER_LEASE_AND_RECONCILE"
  | "ESCALATE_INVARIANT_BREACH"
  | "REFUSED_EXECUTE_NOT_LANDED"
  | "REFUSED_INCOMPLETE_EXECUTE_EVIDENCE"
  | "ACK_PINNED"
  | "EVIDENCE_ARCHIVE_FAILED";

/** `observer_domain` — which ledger a row belongs to. */
export type ReceiveObserverDomain = "NODE" | "PLATFORM";

/**
 * How an observation was obtained. only `CONFIRMATION_READ` may carry settlement.
 * `SUBMIT_RESPONSE` is the gateway's own echo of the submit call and proves nothing landed.
 */
export type ReceiveObservationSource = "CONFIRMATION_READ" | "SUBMIT_RESPONSE";

/** One observer ledger's row for the receiver wallet's head. */
export interface ReceiveObservationRecord {
  readonly observationId: string;
  readonly observerDomain: ReceiveObserverDomain;
  readonly source: ReceiveObservationSource;
  readonly publicKey: string;
  readonly projection: WalletStateProjection;
  readonly semanticFingerprint: string;
  readonly isGenesis: boolean;
  readonly historyHasNonGenesis: boolean;
  readonly acceptedStateSignatureHistory: readonly string[];
  readonly step2Signature: string;
  readonly settledTransactionText: string;
  /** Raw pre-parse gateway bytes SHA-256 — the ledger bytes, not the parsed tree. */
  readonly rawResponseSha256: string;
  readonly rawResponseByteLength: number;
  /** True only when this observer issued its own gateway read. */
  readonly directRead: boolean;
  /** Non-null when the row was relayed by another party — G breach. */
  readonly relayedVia: string | null;
}

/** The arm/code formation values that bind this run's artifact to the issued code. */
export interface ReceiveCodeFormationRecord {
  readonly discriminator: string;
  readonly anchor: string;
  /** The exact transfer-code string as issued — hashed byte-for-byte, never re-encoded. */
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  readonly codeExpiryUnixSecs: number;
}

/** Execute-lane row counts the disposition re-checks before trusting LANDED_VERIFIED. */
export interface ReceiveExecuteRowCounts {
  readonly receiveArms: number;
  readonly candidateIntakes: number;
  readonly coSignatures: number;
  readonly gatewaySubmitAttempts: number;
  readonly landingProofs: number;
}

/**
 * Execute-lane disposition tokens. Declared structurally so this surface does not depend on
 * unmerged module — the two meet at the evidence shape, not at an import.
 */
export type ReceiveExecuteDisposition =
  | "LANDED_VERIFIED"
  | "SUBMIT_REJECTED"
  | "SUBMIT_AMBIGUOUS_OR_UNOBSERVED"
  | "CODE_EXPIRED_UNLANDED"
  | "ESCALATE_INVARIANT_BREACH";

/**
 * The execute evidence this disposition consumes. Structural by design: the execute
 * lane produces these facts, and any producer emitting this shape can be dispositioned.
 */
export interface ReceiveExecuteSummary {
  readonly attemptId: string;
  readonly disposition: ReceiveExecuteDisposition;
  readonly plan: ReceiveExternalPlan | null;
  readonly formation: ReceiveCodeFormationRecord | null;
  /** T0 receiver baseline captured under lease, before any candidate was admitted. */
  readonly receiverT0: ReceiveObservationRecord | null;
  /** The node's own post-landing observation row (`gateway_observations`, NODE domain). */
  readonly nodeTerminal: ReceiveObservationRecord | null;
  /**
   * The step_2 signature the node co-signed and submitted for THIS attempt. the
   * landing proof is bound to our own attempt byte-exact, so this — not whatever the head
   * happens to carry — is what every head is measured against.
   */
  readonly submittedStep2Signature: string;
  /**
   * The durable `operations` row's receiver columns. The acknowledgement's evidence
   * set is validated against these — NOT against the plan the run was authorized with — so a
   * run that credited a wallet the operation row does not name is caught here.
   */
  readonly operationReceiverWalletId: string | null;
  readonly operationReceiverPublicKey: string | null;
  readonly rowCounts: ReceiveExecuteRowCounts | null;
  /** The receiver lease was held before the first read of this run. */
  readonly leaseHeldBeforeAnyRead: boolean;
  /** Unix seconds the terminal observation was taken, for the expiry predicate. */
  readonly observedAtUnixSecs: number;
}

export interface ReceiverCreditCheck {
  readonly receiverCredit: Amount;
  readonly amount: Amount;
  readonly creditExact: boolean;
  readonly t0Balance: Amount;
  readonly terminalBalance: Amount;
}

/** The two-ledger reconciliation result for one receiver head. */
export interface ObserverLedgerAgreement {
  readonly nodeObservationId: string;
  readonly independentObservationId: string;
  readonly independentDomain: ReceiveObserverDomain;
  readonly independentDirectRead: boolean;
  readonly bytesIdentical: boolean;
  readonly relationship: string;
  readonly conditionId: string;
  /** Byte-identical, or fingerprint-equal with only wrapper bytes differing. */
  readonly agrees: boolean;
  readonly detail: string;
}

export interface ReceivePathManifestEntry {
  readonly predicate: PredicateId;
  readonly passed: boolean;
  readonly determinate: boolean;
  readonly detail: string;
  readonly status: "VERIFIED" | "REJECTED" | "UNDECIDED";
}

export interface ReceivePathManifest {
  readonly outcome: VerdictOutcome;
  readonly entries: readonly ReceivePathManifestEntry[];
  /** True only when every path predicate is determinate and passed. */
  readonly allVerified: boolean;
}

export interface ReceiveLandingCommitRecord {
  readonly operationId: string;
  readonly priorState: "READY";
  readonly nextState: "RECEIVE_LANDED";
  readonly eventType: "receive.landed";
  readonly receiverTerminalObservationId: string;
  readonly verifiedAt: string;
  /** True when event append and state transition committed in one DB-TX (seam-reported). */
  readonly sameDbTx: boolean;
  /** The appended event's hash-chain link verified. */
  readonly eventChainLinked: boolean;
}

/** Scoped verification material exposed to the independent verifier. */
export interface ReceiveProofExposure {
  readonly operationId: string;
  readonly proofAccessId: string;
  readonly scopedToOperation: boolean;
  readonly expiresAt: string;
}

export interface ReceiveVerificationAckRecord {
  readonly operationId: string;
  readonly verdict: AckVerdict;
  readonly evidenceRoles: readonly ("SOURCE" | "RECEIVER" | "DESTINATION")[];
  readonly evidence: readonly DurableEvidenceFact[];
  readonly evidenceSetComplete: boolean;
  /** `verification_acknowledgements.id` — the release proof must name it. */
  readonly acknowledgementId: string;
}

/** `receive_release_proofs` row. */
export interface ReceiveReleaseProofRecord {
  readonly operationId: string;
  readonly releaseKind: string;
  readonly verificationAcknowledgementId: string | null;
  readonly receiverWalletId: string;
}

export interface ReceiveLeaseReleaseRecord {
  readonly groupDecision: GroupReleaseDecision;
  readonly clampedStatus: LeaseReleaseStatus;
  readonly released: boolean;
  readonly receiverReleased: boolean;
  readonly releaseProof: ReceiveReleaseProofRecord | null;
  /** True when release was attempted only after the group predicate returned RELEASED. */
  readonly releaseGatedOnGroupPredicate: boolean;
}

/** Proof access revoked with HTTP 410, ledger bytes untouched (C-10). */
export interface ReceiveProofRevocationRecord {
  readonly operationId: string;
  readonly httpStatus: number;
  readonly ledgerBytesRetained: boolean;
  readonly observationBytesRetained: boolean;
}

/**
 * Archived live-chain evidence packet. Key-free and self-contained:
 * it carries the ledger bytes' digests, not pointers into an ephemeral session.
 */
export interface ReceiveEvidencePacket {
  readonly kind: "RECEIVE_EXTERNAL_LIVE_CHAIN_EVIDENCE_V1";
  readonly attemptId: string;
  readonly operationId: string;
  readonly archivedAt: string;
  readonly governingRules: readonly string[];
  readonly decisions: readonly string[];
  readonly externalCounterparty: true;
  readonly amountZkz: Amount;
  readonly receiverWalletId: string;
  readonly receiverPubkey: string;
  readonly externalPayerAddress: string;
  readonly step2Signature: string;
  /** Durable ledger bytes, separate from any time-boxed proof-access window (C-10). */
  readonly nodeLedgerBytesSha256: string;
  readonly independentLedgerBytesSha256: string;
  readonly settledBodySha256: string;
  readonly receiverCredit: ReceiverCreditCheck;
  readonly observerAgreement: ObserverLedgerAgreement;
  readonly pathManifest: ReceivePathManifest;
  readonly landing: ReceiveLandingCommitRecord;
  readonly acknowledgement: ReceiveVerificationAckRecord;
  readonly leaseRelease: ReceiveLeaseReleaseRecord;
  readonly proofRevocation: ReceiveProofRevocationRecord;
  readonly releaseSequence: readonly ReceiveReleaseStep[];
  readonly executeDisposition: ReceiveExecuteDisposition;
  readonly trail: readonly string[];
  readonly commandsAndResults: readonly string[];
  readonly negativePathAssertion: string;
  readonly safeForbiddenHonored: true;
  readonly noSpeculativeContractImplemented: true;
  readonly packetSha256: string;
}

export interface ReceiveDispositionEvidenceBundle {
  readonly attemptId: string;
  readonly operationId: string;
  readonly outcome: ReceiveDispositionOutcome;
  readonly guard: ReceiveDispositionGuardId | null;
  readonly abortAction: ReceiveAbortAction | null;
  readonly abortTrigger: ReceiveAbortTrigger | null;
  readonly plan: ReceiveExternalPlan | null;
  readonly independentTerminal: ReceiveObservationRecord | null;
  readonly observerAgreement: ObserverLedgerAgreement | null;
  readonly receiverCredit: ReceiverCreditCheck | null;
  readonly pathManifest: ReceivePathManifest | null;
  readonly receiveProof: OperationProofResult | null;
  readonly landing: ReceiveLandingCommitRecord | null;
  readonly proofExposure: ReceiveProofExposure | null;
  readonly acknowledgement: ReceiveVerificationAckRecord | null;
  readonly leaseRelease: ReceiveLeaseReleaseRecord | null;
  readonly proofRevocation: ReceiveProofRevocationRecord | null;
  readonly releaseSequence: readonly ReceiveReleaseStep[];
  readonly evidencePacket: ReceiveEvidencePacket | null;
  readonly trail: readonly string[];
  /** Explicit negatives: this surface never re-submits and never frees a lease early. */
  readonly submitCallCount: 0;
  readonly mayResubmit: false;
  readonly mayReconsumeTransferCode: false;
  readonly mayRebuildWithoutPositiveOracle: false;
  readonly mayInferNonLandingFromSilence: false;
  readonly mayReleaseLeaseOnLandingAlone: false;
  readonly maySettleOnSubmitEcho: false;
  readonly mayAcceptRelayedIndependentObservation: false;
}

export interface ReceiveDispositionResult {
  readonly ok: boolean;
  readonly evidence: ReceiveDispositionEvidenceBundle;
}

// ─── Injected seams ──────────────────────────────────────────────────────────

export interface IndependentObserverSeam {
  /**
   * The independent (platform-side) observer's OWN direct read of the receiver head. It must
   * not be handed the node's response — G invariant 6. Returns null when the independent
   * side could not establish a head; a head naming another transaction is still returned so
   * can classify it rather than inventing non-landing.
   */
  readReceiverHead(input: {
    readonly publicKey: string;
    readonly expectedStep2Signature: string;
  }): Promise<ReceiveObservationRecord | null>;
}

export interface ReceiveLandingPersistSeam {
  /**
   * DB-TX: attach the terminal observation, READY → RECEIVE_LANDED, append
   * receive.landed hash-chained, set verified_at. Must be one TX.
   */
  commitLanding(input: {
    readonly operationId: string;
    readonly priorState: "READY";
    readonly receiverTerminalObservationId: string;
    readonly settledTransactionText: string;
    readonly step2Signature: string;
    readonly verifiedAt: string;
  }): Promise<ReceiveLandingCommitRecord>;
}

export interface ReceiveProofAccessSeam {
  /** Expose scoped verification material to the independent verifier. */
  exposeScopedVerificationMaterial(input: {
    readonly operationId: string;
    readonly receiverTerminalObservationId: string;
  }): Promise<ReceiveProofExposure>;
  /**
   * Later revoke proof access with HTTP 410. C-10: this revokes access only;
   * the canonical wallet ledger and observation bytes stay verbatim and permanent.
   */
  revokeProofAccess(input: {
    readonly operationId: string;
    readonly proofAccessId: string;
  }): Promise<ReceiveProofRevocationRecord>;
}

export interface ReceiveAckSeam {
  /**
   * Record verification_acknowledgements +
   * verification_ack_wallet_evidence (RECEIVER role). Never releases the lease itself.
   */
  recordAcknowledgement(input: {
    readonly operationId: string;
    readonly verdict: AckVerdict;
    readonly evidence: readonly DurableEvidenceFact[];
    readonly receiverT0ObservationId: string;
    readonly receiverTerminalObservationId: string;
  }): Promise<ReceiveVerificationAckRecord>;
}

export interface ReceiveGroupFactsSeam {
  /** Read lease-group facts after this leg's acknowledgement, for the release predicate. */
  loadGroupFacts(input: {
    readonly operationId: string;
    readonly thisLegAck: ReceiveVerificationAckRecord;
  }): Promise<GroupReleaseFacts>;
}

export interface ReceiveLeaseReleaseSeam {
  /**
   * Release the RECEIVER lease only when status is RELEASED, writing the
   * `receive_release_proofs` row with release_kind = VERIFICATION_COMPLETE bound to the
   * acknowledgement. Implementations MUST refuse when status is not RELEASED.
   */
  releaseReceiverIfGroupPassed(input: {
    readonly operationId: string;
    readonly receiverWalletId: string;
    readonly status: LeaseReleaseStatus;
    readonly verificationAcknowledgementId: string;
  }): Promise<{
    readonly receiverReleased: boolean;
    readonly releaseProof: ReceiveReleaseProofRecord | null;
  }>;
}

export interface ReceiveEvidenceArchiveSeam {
  /** Persist the archived evidence packet (key-free). */
  archive(packet: ReceiveEvidencePacket): Promise<{ readonly archiveId: string }>;
}

export interface ReceiveDispositionDeps {
  readonly independentObserver: IndependentObserverSeam;
  readonly landing: ReceiveLandingPersistSeam;
  readonly proofAccess: ReceiveProofAccessSeam;
  readonly ack: ReceiveAckSeam;
  readonly groupFacts: ReceiveGroupFactsSeam;
  readonly leases: ReceiveLeaseReleaseSeam;
  readonly evidenceArchive: ReceiveEvidenceArchiveSeam;
  /** Optional clock (ISO-8601 UTC). Defaults to Date.now().toISOString(). */
  readonly nowIso?: () => string;
}

export interface ReceiveDispositionInput {
  readonly operationId: string;
  /** LANDED_VERIFIED evidence from the execute lane. */
  readonly executeEvidence: ReceiveExecuteSummary;
  /** Expected-artifact envelope verification result (half 1). */
  readonly artifactVerificationOk: boolean;
  /**
   * When true (default), refuse unless executeEvidence.disposition === LANDED_VERIFIED.
   * Tests may set false only for negative-path injection of incomplete bundles.
   */
  readonly requireLandedExecute?: boolean;
}

// ─── Internals ───────────────────────────────────────────────────────────────

const GOVERNING_RULES = [
  "observation and verification: the ten receive path predicates",
  "operation flows: receive acceptance and the retention-and-release sequence",
  "node core: the group-predicate lease-release rule",
  "data model: verification acknowledgements and the event ledger",
  "invariant gate: the independent observation is never node-relayed",
  "build and test plan: live-chain acceptance evidence",
] as const;

const DESIGN_RULES = [
  "observation-dedup",
  "complete-path-adjudication",
  "distinct-expiry-timers",
  "dual-control-attestation",
  "amount-hard-cap",
  "live-chain-execution",
] as const;

const NEGATIVE_PATH_ASSERTION =
  "NEGATIVE: disposition never re-submits, never re-serves or re-consumes the transfer code, " +
  "never infers non-landing from a receiver-head mismatch or from silence (the never-blind-retry rule), " +
  "never declares settlement from a submit response echo, " +
  "never accepts a node-relayed row as the independent observation, " +
  "and never releases the receiver lease merely because the operation landed.";

const RELEASE_KIND_VERIFICATION_COMPLETE = "VERIFICATION_COMPLETE";

function trailPush(trail: string[], line: string): void {
  trail.push(line);
}

/** Parse settled transaction text through the real envelope stage. */
export function parseReceiveSettledTransactionText(settledText: string): ParsedSettledTransaction {
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
  input: ReceiveDispositionInput,
  trail: string[],
  outcome: ReceiveDispositionOutcome,
  guard: ReceiveDispositionGuardId,
  releaseSequence: readonly ReceiveReleaseStep[],
  extras: Partial<ReceiveDispositionEvidenceBundle> = {},
): ReceiveDispositionEvidenceBundle {
  return {
    attemptId: input.executeEvidence.attemptId,
    operationId: input.operationId,
    outcome,
    guard,
    abortAction: extras.abortAction ?? null,
    abortTrigger: extras.abortTrigger ?? null,
    plan: input.executeEvidence.plan,
    independentTerminal: null,
    observerAgreement: null,
    receiverCredit: null,
    pathManifest: null,
    receiveProof: null,
    landing: null,
    proofExposure: null,
    acknowledgement: null,
    leaseRelease: null,
    proofRevocation: null,
    releaseSequence: [...releaseSequence],
    evidencePacket: null,
    trail,
    submitCallCount: 0,
    mayResubmit: false,
    mayReconsumeTransferCode: false,
    mayRebuildWithoutPositiveOracle: false,
    mayInferNonLandingFromSilence: false,
    mayReleaseLeaseOnLandingAlone: false,
    maySettleOnSubmitEcho: false,
    mayAcceptRelayedIndependentObservation: false,
    ...extras,
  };
}

/** Ambiguity holds the receiver lease; a determinate breach escalates. */
function holdRule(): { action: ReceiveAbortAction; trigger: ReceiveAbortTrigger } {
  const trigger: ReceiveAbortTrigger = "SUBMIT_AMBIGUOUS_OR_UNOBSERVED";
  return { action: receiveAbortActionFor(trigger).action, trigger };
}

function breachRule(): { action: ReceiveAbortAction; trigger: ReceiveAbortTrigger } {
  const trigger: ReceiveAbortTrigger = "INVARIANT_BREACH";
  return { action: receiveAbortActionFor(trigger).action, trigger };
}

function buildPathManifest(proof: OperationProofResult): ReceivePathManifest {
  const byId = new Map(proof.predicates.map((p) => [p.predicate, p]));
  const entries: ReceivePathManifestEntry[] = RECEIVE_EXTERNAL_PATH_PREDICATES.map((id) => {
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
    const status: ReceivePathManifestEntry["status"] = !p.determinate
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
  return {
    outcome: proof.verdict.outcome,
    entries,
    allVerified: entries.every((e) => e.status === "VERIFIED"),
  };
}

/**
 * Economics as the ticket states them: receiver terminal balance − receiver T0.B0
 * must equal amount_zkz exactly. Decimal strings throughout — never Number().
 */
function buildReceiverCredit(
  receiverT0: ReceiveObservationRecord,
  terminal: ReceiveObservationRecord,
  amount: Amount,
): ReceiverCreditCheck {
  const receiverCredit = signedDelta(receiverT0.projection.B, terminal.projection.B);
  return {
    receiverCredit,
    amount,
    creditExact: compareAmounts(receiverCredit, amount) === 0,
    t0Balance: receiverT0.projection.B,
    terminalBalance: terminal.projection.B,
  };
}

function semanticStateOf(observation: ReceiveObservationRecord): AcceptedSemanticState {
  return {
    isGenesis: observation.isGenesis,
    sSignature: observation.projection.S,
    pSignature: observation.projection.P,
    semanticFingerprint: observation.semanticFingerprint,
  };
}

/**
 * Reconcile the node's own observation ledger against the
 * independent observer's. Byte-identical raw responses agree outright. Otherwise the
 * classifier decides, and only EQUIVALENT_STATE_DIFFERENT_ENVELOPE — the same semantic state
 * in a different wrapper — counts as agreement. Any other relationship is a disagreement to
 * be reconciled by an operator, never smoothed over here.
 */
function reconcileObserverLedgers(
  nodeTerminal: ReceiveObservationRecord,
  independent: ReceiveObservationRecord,
): ObserverLedgerAgreement {
  const bytesIdentical =
    nodeTerminal.rawResponseSha256 === independent.rawResponseSha256 &&
    nodeTerminal.rawResponseByteLength === independent.rawResponseByteLength;

  const classification = classifyRelationship({
    prior: semanticStateOf(nodeTerminal),
    next: semanticStateOf(independent),
    priorHistoryHasNonGenesis: nodeTerminal.historyHasNonGenesis,
    acceptedStateSignatureHistory: nodeTerminal.acceptedStateSignatureHistory,
  });

  // Byte-identical raw responses agree outright; otherwise only a fingerprint-equal envelope
  // does. Whether the agreed head is OUR attempt is a separate question, decided against the
  // submitted step_2 rather than against the other observer.
  const agrees =
    bytesIdentical || classification.relationship === "EQUIVALENT_STATE_DIFFERENT_ENVELOPE";

  return {
    nodeObservationId: nodeTerminal.observationId,
    independentObservationId: independent.observationId,
    independentDomain: independent.observerDomain,
    independentDirectRead: independent.directRead,
    bytesIdentical,
    relationship: classification.relationship,
    conditionId: classification.conditionId,
    agrees,
    detail: bytesIdentical
      ? "independent read is byte-identical to the node observation"
      : `independent read classified ${classification.relationship} (${classification.conditionId})`,
  };
}

function buildArtifact(
  plan: ReceiveExternalPlan,
  formation: ReceiveCodeFormationRecord,
): ReceiveExpectedArtifact {
  return {
    amount_zkz: plan.amount,
    receiver_pubkey: plan.receiverPubkey,
    discriminator: formation.discriminator,
    anchor: formation.anchor,
    transfer_code_sha256: formation.transferCodeSha256,
    code_expiry__unix_time_secs: formation.codeExpiryUnixSecs,
  };
}

function baselineFrom(receiverT0: ReceiveObservationRecord): ReceiverBaseline {
  return {
    projection: receiverT0.projection,
    semanticFingerprint: receiverT0.semanticFingerprint,
    isGenesis: receiverT0.isGenesis,
    historyHasNonGenesis: receiverT0.historyHasNonGenesis,
    acceptedStateSignatureHistory: receiverT0.acceptedStateSignatureHistory,
  };
}

function packetDigest(packet: Omit<ReceiveEvidencePacket, "packetSha256">): string {
  const material = JSON.stringify({
    kind: packet.kind,
    attemptId: packet.attemptId,
    operationId: packet.operationId,
    archivedAt: packet.archivedAt,
    amountZkz: packet.amountZkz,
    receiverWalletId: packet.receiverWalletId,
    receiverPubkey: packet.receiverPubkey,
    externalPayerAddress: packet.externalPayerAddress,
    step2Signature: packet.step2Signature,
    nodeLedgerBytesSha256: packet.nodeLedgerBytesSha256,
    independentLedgerBytesSha256: packet.independentLedgerBytesSha256,
    settledBodySha256: packet.settledBodySha256,
    receiverCredit: packet.receiverCredit,
    observerAgreement: {
      agrees: packet.observerAgreement.agrees,
      bytesIdentical: packet.observerAgreement.bytesIdentical,
      relationship: packet.observerAgreement.relationship,
      independentDomain: packet.observerAgreement.independentDomain,
    },
    pathManifestOutcome: packet.pathManifest.outcome,
    pathAllVerified: packet.pathManifest.allVerified,
    acknowledgementId: packet.acknowledgement.acknowledgementId,
    releaseKind: packet.leaseRelease.releaseProof?.releaseKind ?? null,
    releaseSequence: packet.releaseSequence,
    executeDisposition: packet.executeDisposition,
    externalCounterparty: packet.externalCounterparty,
    safeForbiddenHonored: packet.safeForbiddenHonored,
    noSpeculativeContractImplemented: packet.noSpeculativeContractImplemented,
  });
  return createHash("sha256").update(material, "utf8").digest("hex");
}

function sha256Of(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function truncateSig(sig: string): string {
  if (sig === "") return "∅";
  if (sig.length <= 12) return sig;
  return `${sig.slice(0, 8)}…${sig.slice(-4)}`;
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Reconcile and disposition one LANDED_VERIFIED RECEIVE_EXTERNAL run.
 *
 * Sequence:
 *   1. Require execute LANDED_VERIFIED and complete formation / T0 / terminal / row evidence.
 *   2. Require settlement to come from a confirmation read, naming this attempt's step_2.
 *   3. Take the independent observer's OWN direct read and reconcile the two ledgers.
 *   4. Receiver credit exact: terminal B − T0.B == amount_zkz.
 *   5. OBS path manifest via evaluateReceiveProof (all ten → VERIFIED).
 *   6. Release step 1 — landing DB-TX: READY → RECEIVE_LANDED + receive.landed, one TX.
 *   7. Release step 2 — expose scoped verification material.
 *   8. Release step 3 — verification_acknowledgements (RECEIVER evidence), verdict VERIFIED.
 *   9. Release step 4 — group-predicate release with a VERIFICATION_COMPLETE release proof.
 *  10. Release step 5 — revoke proof access with HTTP 410, ledger bytes retained.
 *  11. Archive the immutable evidence packet.
 *
 * Never submits. Never re-serves the code. Never releases the lease on landing alone.
 */
export async function disposeReceiveExternalEvidence(
  deps: ReceiveDispositionDeps,
  input: ReceiveDispositionInput,
): Promise<ReceiveDispositionResult> {
  const trail: string[] = [];
  const releaseSequence: ReceiveReleaseStep[] = [];
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const requireLanded = input.requireLandedExecute !== false;
  const exec = input.executeEvidence;

  trailPush(trail, `disposition start attempt=${exec.attemptId} op=${input.operationId}`);
  trailPush(trail, `execute disposition=${exec.disposition}; no submit is issued on this surface`);
  trailPush(
    trail,
    "09: safe=bounded receiver-head reads / verify completed tx / re-read observations / " +
      "append diagnostics; forbidden=resubmit / re-serve the code / extend expiry / " +
      "infer non-landing / release the lease on landing alone",
  );

  if (requireLanded && exec.disposition !== "LANDED_VERIFIED") {
    // GUARD: execute_not_landed
    trailPush(trail, `refuse: execute not LANDED_VERIFIED (${exec.disposition})`);
    const breach = exec.disposition === "ESCALATE_INVARIANT_BREACH";
    const rule = breach ? breachRule() : holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        breach ? "ESCALATE_INVARIANT_BREACH" : "REFUSED_EXECUTE_NOT_LANDED",
        "execute_not_landed",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger },
      ),
    };
  }

  const plan = exec.plan;
  const formation = exec.formation;
  const receiverT0 = exec.receiverT0;
  const nodeTerminal = exec.nodeTerminal;
  const rowCounts = exec.rowCounts;

  if (
    plan === null ||
    formation === null ||
    receiverT0 === null ||
    nodeTerminal === null ||
    rowCounts === null ||
    exec.submittedStep2Signature === "" ||
    exec.leaseHeldBeforeAnyRead !== true ||
    rowCounts.receiveArms !== 1 ||
    rowCounts.candidateIntakes !== 1 ||
    rowCounts.coSignatures !== 1 ||
    rowCounts.gatewaySubmitAttempts !== 1 ||
    rowCounts.landingProofs !== 1 ||
    nodeTerminal.observerDomain !== "NODE"
  ) {
    // GUARD: incomplete_execute_evidence
    trailPush(
      trail,
      "refuse: incomplete execute formation / T0 / terminal / row-count / " +
        "lease-before-read evidence",
    );
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "REFUSED_INCOMPLETE_EXECUTE_EVIDENCE",
        "incomplete_execute_evidence",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger },
      ),
    };
  }

  // Every head is measured against the step_2 we actually submitted.
  const expectedStep2 = exec.submittedStep2Signature;
  trailPush(
    trail,
    `submitted step_2=${truncateSig(expectedStep2)} amount=${plan.amount} ` +
      `receiver=${plan.receiverWalletId}`,
  );

  // ── settlement only on a confirmation read ────────────────────────
  if (nodeTerminal.source !== "CONFIRMATION_READ") {
    // GUARD: settlement_not_from_confirmation_read
    trailPush(
      trail,
      `node terminal observation source=${nodeTerminal.source} — a submit response echo is ` +
        "not landing evidence; hold and re-read",
    );
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "NEEDS_ATTENTION",
        "settlement_not_from_confirmation_read",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger },
      ),
    };
  }

  // ── Independent observer's own direct read ───────
  let independent: ReceiveObservationRecord | null;
  try {
    independent = await deps.independentObserver.readReceiverHead({
      publicKey: receiverT0.publicKey,
      expectedStep2Signature: expectedStep2,
    });
  } catch (err) {
    // GUARD: independent_observation_unavailable
    trailPush(trail, `independent observer read threw: ${errText(err)} — hold`);
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "HOLD_RECEIVER_LEASE_AND_RECONCILE",
        "independent_observation_unavailable",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger },
      ),
    };
  }

  if (independent === null) {
    // GUARD: independent_observation_unavailable
    trailPush(
      trail,
      "independent observation absent — reconciliation INDETERMINATE; non-landing NOT proven",
    );
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "NEEDS_ATTENTION",
        "independent_observation_unavailable",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger },
      ),
    };
  }

  if (independent.observerDomain !== "PLATFORM") {
    // GUARD: independent_observation_wrong_domain
    trailPush(
      trail,
      `independent observation carries observer_domain=${independent.observerDomain}; the ` +
        "second ledger must be the platform's own",
    );
    const rule = breachRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "ESCALATE_INVARIANT_BREACH",
        "independent_observation_wrong_domain",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger, independentTerminal: independent },
      ),
    };
  }

  if (independent.directRead !== true || independent.relayedVia !== null) {
    // GUARD: independent_observation_not_direct
    trailPush(
      trail,
      `independent observation was relayed (via=${independent.relayedVia ?? "unknown"}); the ` +
        "platform never accepts a node-relayed gateway response as its own observation",
    );
    const rule = breachRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "ESCALATE_INVARIANT_BREACH",
        "independent_observation_not_direct",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger, independentTerminal: independent },
      ),
    };
  }

  const observerAgreement = reconcileObserverLedgers(nodeTerminal, independent);
  trailPush(
    trail,
    `observer ledgers agree=${observerAgreement.agrees} bytesIdentical=` +
      `${observerAgreement.bytesIdentical} rel=${observerAgreement.relationship}`,
  );

  if (!observerAgreement.agrees) {
    // GUARD: observer_ledgers_disagree
    trailPush(trail, "node and independent observer ledgers disagree — hold and reconcile");
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "NEEDS_ATTENTION",
        "observer_ledgers_disagree",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          independentTerminal: independent,
          observerAgreement,
        },
      ),
    };
  }

  // ── Receiver head names this attempt's transaction (never non-landing) ─────
  // Both ledgers already agree on a head; the question here is whether that agreed head is
  // the transaction WE submitted. A head naming another transaction is INDETERMINATE.
  if (
    nodeTerminal.step2Signature !== expectedStep2 ||
    independent.step2Signature !== expectedStep2
  ) {
    // GUARD: receiver_head_mismatch
    trailPush(
      trail,
      `receiver head mismatch (node=${truncateSig(nodeTerminal.step2Signature)} ` +
        `independent=${truncateSig(independent.step2Signature)} ` +
        `submitted=${truncateSig(expectedStep2)}) — INDETERMINATE; non-landing NOT proven`,
    );
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "NEEDS_ATTENTION",
        "receiver_head_mismatch",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          independentTerminal: independent,
          observerAgreement,
        },
      ),
    };
  }

  const settledText = nodeTerminal.settledTransactionText;
  let parsed: ParsedSettledTransaction;
  try {
    parsed = parseReceiveSettledTransactionText(settledText);
  } catch (err) {
    // GUARD: settled_body_parse_failed
    trailPush(trail, `settled parse failed: ${errText(err)} — hold`);
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "HOLD_RECEIVER_LEASE_AND_RECONCILE",
        "settled_body_parse_failed",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          independentTerminal: independent,
          observerAgreement,
        },
      ),
    };
  }

  // ── Economics: terminal B − T0.B == amount_zkz ─────────────────────────────
  const receiverCredit = buildReceiverCredit(receiverT0, nodeTerminal, plan.amount);
  trailPush(
    trail,
    `receiver credit Δ=${receiverCredit.receiverCredit} amount=${receiverCredit.amount} ` +
      `exact=${receiverCredit.creditExact}`,
  );

  if (!receiverCredit.creditExact) {
    // GUARD: credit_not_exact
    trailPush(trail, "INVARIANT: receiver terminal balance − T0.B0 does not equal amount_zkz");
    const rule = breachRule();
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", "credit_not_exact", releaseSequence, {
        abortAction: rule.action,
        abortTrigger: rule.trigger,
        independentTerminal: independent,
        observerAgreement,
        receiverCredit,
      }),
    };
  }

  // ── path manifest via evaluateReceiveProof ──────────────────────────
  const policyInput: ReceivePolicyInput = {
    reservedWalletPublicKey: plan.receiverPubkey,
    candidate: parsed,
    baseline: baselineFrom(receiverT0),
    artifact: buildArtifact(plan, formation),
    artifactVerification: input.artifactVerificationOk
      ? {
          ok: true,
          purpose: "zp-receive-expected-v1",
          digest: sha256Of(
            `${plan.attemptId}:${plan.receiverWalletId}:${plan.externalPayerAddress}:${plan.amount}`,
          ),
        }
      : { ok: false, reason: "envelope_rejected", detail: "artifact verification failed" },
    exactTransferCodeString: formation.transferCodeText,
    observedAtUnixSecs: exec.observedAtUnixSecs,
    // No senderCorroboration: the head-identity question is already decided above against the
    // submitted step_2, and feeding an already-checked value back in would make the policy's
    // corroboration branch unfalsifiable rather than independent.
    senderCorroboration: null,
  };

  const receiveProof = evaluateReceiveProof(policyInput);
  const pathManifest = buildPathManifest(receiveProof);
  trailPush(
    trail,
    `path manifest outcome=${pathManifest.outcome} allVerified=${pathManifest.allVerified}`,
  );
  for (const e of pathManifest.entries) {
    trailPush(trail, `  predicate ${e.predicate}: ${e.status} — ${e.detail}`);
  }

  if (!pathManifest.allVerified || pathManifest.outcome !== "VERIFIED") {
    // GUARD: path_manifest_not_verified
    const determinateFail = pathManifest.entries.some((e) => e.status === "REJECTED");
    const outcome: ReceiveDispositionOutcome = determinateFail ? "REJECTED" : "NEEDS_ATTENTION";
    const rule = determinateFail ? breachRule() : holdRule();
    trailPush(trail, `path manifest failed → ${outcome} (non-landing NOT inferred)`);
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        outcome,
        "path_manifest_not_verified",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          independentTerminal: independent,
          observerAgreement,
          receiverCredit,
          pathManifest,
          receiveProof,
        },
      ),
    };
  }

  const carried = {
    independentTerminal: independent,
    observerAgreement,
    receiverCredit,
    pathManifest,
    receiveProof,
  };

  // ── landing DB-TX ───────────────────────────────────────────────
  const verifiedAt = nowIso();
  let landingCommit: ReceiveLandingCommitRecord;
  try {
    landingCommit = await deps.landing.commitLanding({
      operationId: input.operationId,
      priorState: "READY",
      receiverTerminalObservationId: nodeTerminal.observationId,
      settledTransactionText: settledText,
      step2Signature: expectedStep2,
      verifiedAt,
    });
  } catch (err) {
    // GUARD: landing_commit_failed
    trailPush(trail, `landing commit failed: ${errText(err)}`);
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "HOLD_RECEIVER_LEASE_AND_RECONCILE",
        "landing_commit_failed",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger, ...carried },
      ),
    };
  }

  if (
    landingCommit.priorState !== "READY" ||
    landingCommit.nextState !== "RECEIVE_LANDED" ||
    landingCommit.eventType !== "receive.landed" ||
    !landingCommit.sameDbTx ||
    !landingCommit.eventChainLinked
  ) {
    // GUARD: landing_commit_shape_invalid
    trailPush(trail, "landing commit shape invalid (state / event / sameDbTx / chain link)");
    const rule = breachRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "ESCALATE_INVARIANT_BREACH",
        "landing_commit_shape_invalid",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger, ...carried, landing: landingCommit },
      ),
    };
  }
  releaseSequence.push("PERSIST_EVIDENCE");
  trailPush(
    trail,
    `release step 1 persisted ${landingCommit.priorState}→${landingCommit.nextState} ` +
      `event=${landingCommit.eventType} sameDbTx=${landingCommit.sameDbTx} ` +
      `chainLinked=${landingCommit.eventChainLinked}`,
  );

  // ── expose scoped verification material ─────────────────────────
  let proofExposure: ReceiveProofExposure;
  try {
    proofExposure = await deps.proofAccess.exposeScopedVerificationMaterial({
      operationId: input.operationId,
      receiverTerminalObservationId: landingCommit.receiverTerminalObservationId,
    });
  } catch (err) {
    // GUARD: proof_exposure_failed
    trailPush(trail, `scoped proof exposure failed: ${errText(err)}`);
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "HOLD_RECEIVER_LEASE_AND_RECONCILE",
        "proof_exposure_failed",
        releaseSequence,
        { abortAction: rule.action, abortTrigger: rule.trigger, ...carried, landing: landingCommit },
      ),
    };
  }
  releaseSequence.push("EXPOSE_SCOPED_PROOF");
  trailPush(trail, `release step 2 scoped proof exposed id=${proofExposure.proofAccessId}`);

  // ── verification-complete acknowledgement ──────────────
  // Expected wallets come from the durable operation row; the evidence facts come from the
  // wallet this run actually leased and observed. Two independent sources, so a disagreement
  // between them is detectable rather than tautological.
  const expectedWallets: readonly OperationWalletAssignment[] = expectedWalletsForOperation(
    "RECEIVE_EXTERNAL",
    {
      sourceWalletId: null,
      sourcePublicKey: null,
      receiverWalletId: exec.operationReceiverWalletId,
      receiverPublicKey: exec.operationReceiverPublicKey,
      destinationWalletId: null,
      destinationPublicKey: null,
      destinationAddress: null,
    },
  );
  const evidenceFacts: DurableEvidenceFact[] = [
    {
      role: "RECEIVER",
      walletId: plan.receiverWalletId,
      walletPublicKey: receiverT0.publicKey,
    },
  ];
  const evidenceFailure = validateEvidenceSet(
    "RECEIVE_EXTERNAL",
    evidenceFacts.map((e) => ({
      role: e.role,
      walletId: e.walletId,
      walletPublicKey: e.walletPublicKey,
    })),
    expectedWallets,
  );
  if (evidenceFailure !== null) {
    // GUARD: evidence_set_invalid
    trailPush(trail, `evidence set invalid: ${evidenceFailure.kind}`);
    const rule = breachRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "ESCALATE_INVARIANT_BREACH",
        "evidence_set_invalid",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          ...carried,
          landing: landingCommit,
          proofExposure,
        },
      ),
    };
  }

  let ackRecord: ReceiveVerificationAckRecord;
  try {
    ackRecord = await deps.ack.recordAcknowledgement({
      operationId: input.operationId,
      verdict: "VERIFIED",
      evidence: evidenceFacts,
      receiverT0ObservationId: receiverT0.observationId,
      receiverTerminalObservationId: nodeTerminal.observationId,
    });
  } catch (err) {
    // GUARD: ack_failed
    trailPush(trail, `ack record failed: ${errText(err)}`);
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "HOLD_RECEIVER_LEASE_AND_RECONCILE",
        "ack_failed",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          ...carried,
          landing: landingCommit,
          proofExposure,
        },
      ),
    };
  }

  if (
    ackRecord.verdict !== "VERIFIED" ||
    !ackRecord.evidenceSetComplete ||
    !ackRecord.evidenceRoles.includes("RECEIVER") ||
    ackRecord.acknowledgementId === ""
  ) {
    // GUARD: ack_not_verified
    trailPush(trail, "ack incomplete or non-VERIFIED — receiver lease stays held");
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ACK_PINNED", "ack_not_verified", releaseSequence, {
        abortAction: rule.action,
        abortTrigger: rule.trigger,
        ...carried,
        landing: landingCommit,
        proofExposure,
        acknowledgement: ackRecord,
      }),
    };
  }
  releaseSequence.push("AWAIT_VERIFICATION_COMPLETE_ACK");
  trailPush(
    trail,
    `release step 3 ack VERIFIED id=${ackRecord.acknowledgementId} ` +
      `roles=[${ackRecord.evidenceRoles.join(",")}] complete=${ackRecord.evidenceSetComplete}`,
  );

  // ── group-predicate receiver-lease release ──────────────────────
  let groupFacts: GroupReleaseFacts;
  try {
    groupFacts = await deps.groupFacts.loadGroupFacts({
      operationId: input.operationId,
      thisLegAck: ackRecord,
    });
  } catch (err) {
    // GUARD: group_facts_failed
    trailPush(trail, `group facts load failed: ${errText(err)}`);
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "HOLD_RECEIVER_LEASE_AND_RECONCILE",
        "group_facts_failed",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          ...carried,
          landing: landingCommit,
          proofExposure,
          acknowledgement: ackRecord,
        },
      ),
    };
  }

  const groupDecision = evaluateGroupRelease(groupFacts);
  const clampedStatus = clampReleaseToVerdict(ackRecord.verdict, groupDecision.status);
  trailPush(
    trail,
    `group release status=${groupDecision.status} reason=${groupDecision.reason} ` +
      `clamped=${clampedStatus}`,
  );

  let receiverReleased = false;
  let releaseProof: ReceiveReleaseProofRecord | null = null;
  const releaseGatedOnGroupPredicate = true;

  if (clampedStatus === "RELEASED") {
    try {
      const rel = await deps.leases.releaseReceiverIfGroupPassed({
        operationId: input.operationId,
        receiverWalletId: plan.receiverWalletId,
        status: clampedStatus,
        verificationAcknowledgementId: ackRecord.acknowledgementId,
      });
      receiverReleased = rel.receiverReleased;
      releaseProof = rel.releaseProof;
    } catch (err) {
      // GUARD: lease_release_failed
      trailPush(trail, `receiver lease release failed: ${errText(err)}`);
      const rule = holdRule();
      return {
        ok: false,
        evidence: emptyBundle(
          input,
          trail,
          "HOLD_RECEIVER_LEASE_AND_RECONCILE",
          "lease_release_failed",
          releaseSequence,
          {
            abortAction: rule.action,
            abortTrigger: rule.trigger,
            ...carried,
            landing: landingCommit,
            proofExposure,
            acknowledgement: ackRecord,
            leaseRelease: {
              groupDecision,
              clampedStatus,
              released: false,
              receiverReleased: false,
              releaseProof: null,
              releaseGatedOnGroupPredicate,
            },
          },
        ),
      };
    }
  } else {
    trailPush(trail, "receiver lease retained — group predicate not RELEASED");
  }

  const leaseRelease: ReceiveLeaseReleaseRecord = {
    groupDecision,
    clampedStatus,
    released: receiverReleased && clampedStatus === "RELEASED",
    receiverReleased,
    releaseProof,
    releaseGatedOnGroupPredicate,
  };

  if (clampedStatus !== "RELEASED" || !leaseRelease.released) {
    // GUARD: lease_not_released
    trailPush(trail, `lease not released (status=${clampedStatus}) — pinned for attention`);
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ACK_PINNED", "lease_not_released", releaseSequence, {
        ...carried,
        landing: landingCommit,
        proofExposure,
        acknowledgement: ackRecord,
        leaseRelease,
      }),
    };
  }

  if (
    releaseProof === null ||
    releaseProof.releaseKind !== RELEASE_KIND_VERIFICATION_COMPLETE ||
    releaseProof.verificationAcknowledgementId !== ackRecord.acknowledgementId
  ) {
    // GUARD: release_proof_invalid
    trailPush(
      trail,
      "INVARIANT: receive_release_proofs row missing, wrong release_kind, or not bound to " +
        "this acknowledgement",
    );
    const rule = breachRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "ESCALATE_INVARIANT_BREACH",
        "release_proof_invalid",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          ...carried,
          landing: landingCommit,
          proofExposure,
          acknowledgement: ackRecord,
          leaseRelease,
        },
      ),
    };
  }
  releaseSequence.push("RELEASE_ON_GROUP_PREDICATE");
  trailPush(
    trail,
    `release step 4 receiver lease released kind=${releaseProof.releaseKind} ` +
      `ack=${releaseProof.verificationAcknowledgementId}`,
  );

  // ── revoke proof access with 410, ledger bytes retained (C-10) ──
  let proofRevocation: ReceiveProofRevocationRecord;
  try {
    proofRevocation = await deps.proofAccess.revokeProofAccess({
      operationId: input.operationId,
      proofAccessId: proofExposure.proofAccessId,
    });
  } catch (err) {
    // GUARD: proof_access_revocation_failed
    trailPush(trail, `proof-access revocation failed: ${errText(err)}`);
    const rule = holdRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "HOLD_RECEIVER_LEASE_AND_RECONCILE",
        "proof_access_revocation_failed",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          ...carried,
          landing: landingCommit,
          proofExposure,
          acknowledgement: ackRecord,
          leaseRelease,
        },
      ),
    };
  }

  if (
    proofRevocation.httpStatus !== 410 ||
    !proofRevocation.ledgerBytesRetained ||
    !proofRevocation.observationBytesRetained
  ) {
    // GUARD: proof_access_revocation_deleted_ledger
    trailPush(
      trail,
      `INVARIANT: proof-access expiry must answer 410 and retain ledger + observation bytes ` +
        `(status=${proofRevocation.httpStatus} ledger=${proofRevocation.ledgerBytesRetained} ` +
        `observations=${proofRevocation.observationBytesRetained})`,
    );
    const rule = breachRule();
    return {
      ok: false,
      evidence: emptyBundle(
        input,
        trail,
        "ESCALATE_INVARIANT_BREACH",
        "proof_access_revocation_deleted_ledger",
        releaseSequence,
        {
          abortAction: rule.action,
          abortTrigger: rule.trigger,
          ...carried,
          landing: landingCommit,
          proofExposure,
          acknowledgement: ackRecord,
          leaseRelease,
          proofRevocation,
        },
      ),
    };
  }
  releaseSequence.push("REVOKE_PROOF_ACCESS_410");
  trailPush(
    trail,
    `release step 5 proof access revoked http=${proofRevocation.httpStatus}; ledger bytes retained`,
  );

  // The order is carried by control flow: each step pushes its own marker at its own
  // site, and every earlier refusal returns before the later steps are reached. The recorded
  // sequence therefore IS the ordering evidence — it is asserted by the happy-path test and
  // ratcheted statically by the census, rather than re-checked here by a branch that could
  // never be false.

  // ── evidence packet archive ─────────────────────────────────────────────
  const archivedAt = nowIso();
  const packetBase = {
    kind: "RECEIVE_EXTERNAL_LIVE_CHAIN_EVIDENCE_V1" as const,
    attemptId: exec.attemptId,
    operationId: input.operationId,
    archivedAt,
    governingRules: GOVERNING_RULES,
    decisions: DESIGN_RULES,
    externalCounterparty: true as const,
    amountZkz: plan.amount,
    receiverWalletId: plan.receiverWalletId,
    receiverPubkey: plan.receiverPubkey,
    externalPayerAddress: plan.externalPayerAddress,
    step2Signature: expectedStep2,
    nodeLedgerBytesSha256: nodeTerminal.rawResponseSha256,
    independentLedgerBytesSha256: independent.rawResponseSha256,
    settledBodySha256: sha256Of(settledText),
    receiverCredit,
    observerAgreement,
    pathManifest,
    landing: landingCommit,
    acknowledgement: ackRecord,
    leaseRelease,
    proofRevocation,
    releaseSequence: [...releaseSequence],
    executeDisposition: exec.disposition,
    trail: [...trail],
    commandsAndResults: [
      `disposeReceiveExternalEvidence attempt=${exec.attemptId}`,
      `independent platform read → step_2=${truncateSig(independent.step2Signature)}`,
      `observer ledgers agree=${observerAgreement.agrees} (${observerAgreement.detail})`,
      `receiver credit ${receiverCredit.t0Balance} → ${receiverCredit.terminalBalance} ` +
        `Δ=${receiverCredit.receiverCredit} exact=${receiverCredit.creditExact}`,
      `path manifest allVerified=${pathManifest.allVerified}`,
      `landing ${landingCommit.priorState}→${landingCommit.nextState} + ${landingCommit.eventType}`,
      `ack verdict=${ackRecord.verdict} id=${ackRecord.acknowledgementId}`,
      `release proof kind=${releaseProof.releaseKind} released=${leaseRelease.released}`,
      `proof access revoked http=${proofRevocation.httpStatus} ledger retained`,
    ],
    negativePathAssertion: NEGATIVE_PATH_ASSERTION,
    safeForbiddenHonored: true as const,
    noSpeculativeContractImplemented: true as const,
  };
  const evidencePacket: ReceiveEvidencePacket = {
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
    // GUARD: evidence_archive_failed
    trailPush(trail, `evidence archive failed: ${errText(err)}`);
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "EVIDENCE_ARCHIVE_FAILED", "evidence_archive_failed", releaseSequence, {
        ...carried,
        landing: landingCommit,
        proofExposure,
        acknowledgement: ackRecord,
        leaseRelease,
        proofRevocation,
        evidencePacket,
      }),
    };
  }

  trailPush(
    trail,
    `DISPOSED_VERIFIED amount=${plan.amount} step_2=${truncateSig(expectedStep2)}`,
  );

  return {
    ok: true,
    evidence: {
      attemptId: exec.attemptId,
      operationId: input.operationId,
      outcome: "DISPOSED_VERIFIED",
      guard: null,
      abortAction: receiveAbortActionFor("LANDED_VERIFIED").action,
      abortTrigger: "LANDED_VERIFIED",
      plan,
      independentTerminal: independent,
      observerAgreement,
      receiverCredit,
      pathManifest,
      receiveProof,
      landing: landingCommit,
      proofExposure,
      acknowledgement: ackRecord,
      leaseRelease,
      proofRevocation,
      releaseSequence: [...releaseSequence],
      evidencePacket,
      trail,
      submitCallCount: 0,
      mayResubmit: false,
      mayReconsumeTransferCode: false,
      mayRebuildWithoutPositiveOracle: false,
      mayInferNonLandingFromSilence: false,
      mayReleaseLeaseOnLandingAlone: false,
      maySettleOnSubmitEcho: false,
      mayAcceptRelayedIndependentObservation: false,
    },
  };
}
