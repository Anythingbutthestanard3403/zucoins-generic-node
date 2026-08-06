// Live MOVE_INTERNAL reconcile + evidence disposition harness.
//
// Offline-first post-landing coordination over injected seams. Closes the dual-control
// MOVE_INTERNAL acceptance path after LANDED_VERIFIED execute evidence:
// Independent fresh-head re-read, OBS eight-predicate verification, landing DB-TX
// (CREATED → INTERNAL_MOVE_LANDED + internal_move.landed), verification-complete ack with
// SOURCE + DESTINATION wallet evidence, group-predicate lease release, and evidence packet archive.
//
// Governing:
//   The one-in-flight-per-wallet and byte-exact signing rules, 4
//
// Structural invariants:
//   - Fresh heads are re-read independently of the mid-run execute observations.
//   - Destination-side verification is mandatory — never source-only.
//   - Leases release only after the full lease-group predicate passes.
//   - No submit / rebuild / second attempt on this surface (the never-blind-retry rule).
//   - Private keys never appear (the key-custody rule).

import { createHash } from "node:crypto";

import {
  evaluateMoveProof,
  type MoveDestinationCustody,
  type MoveExpectedArtifact,
  type MovePolicyInput,
  type MoveSourceCustody,
} from "../../src/proof/policies/move.js";
import type { EvaluatedPredicate, OperationProofResult } from "../../src/proof/policies/shared.js";
import type { PredicateId, VerdictOutcome } from "../../src/proof/types.js";
import type { SettledSplitChainTransaction } from "../../src/protocol/inner.js";
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
import { parseGatewayEnvelope, type ParsedSettledTransaction } from "../../src/verifier/gateway-envelope.js";

import { abortActionFor, type MoveAbortAction, type MoveAbortTrigger } from "./abort-criteria.js";
import {
  compareAmounts,
  signedDelta,
  type Amount,
  type MoveInternalPlan,
} from "./types.js";
import type {
  MoveExecuteEvidenceBundle,
  MoveExecuteDisposition,
  MoveFormationRecord,
  MoveT0Snapshot,
} from "./move-execute.js";

// ─── Public surface ──────────────────────────────────────────────────────────

/** Eight MOVE_INTERNAL predicates, in checklist order. */
export const MOVE_INTERNAL_PATH_PREDICATES = [
  "send_artifact_verify",
  "source_role_verify",
  "destination_role_verify",
  "source_predecessor_bind",
  "destination_predecessor_bind",
  "source_balance_delta",
  "destination_balance_delta",
  "artifact_key_bindsource",
  // spawn_continuity is N/A for standalone dual-control acceptance runs; still
  // evaluated (held via non-spawned path) so the path manifest is complete.
  "spawn_continuity",
] as const satisfies readonly PredicateId[];

export type MovePathPredicateId = (typeof MOVE_INTERNAL_PATH_PREDICATES)[number];

export type MoveDispositionOutcome =
  | "DISPOSED_VERIFIED"
  | "HOLD_BOTH_LEASES_AND_RECONCILE"
  | "ESCALATE_INVARIANT_BREACH"
  | "REFUSED_EXECUTE_NOT_LANDED"
  | "REFUSED_INCOMPLETE_EXECUTE_EVIDENCE"
  | "ACK_PINNED"
  | "EVIDENCE_ARCHIVE_FAILED";

export interface FreshHeadReRead {
  readonly walletId: string;
  readonly publicKey: string;
  readonly observationId: string;
  readonly step2Signature: string;
  readonly balance: Amount;
  readonly settled: SettledSplitChainTransaction;
  readonly settledTransactionText: string;
}

export interface DualDeltaCheck {
  readonly sourceDebit: Amount;
  readonly destinationCredit: Amount;
  readonly amount: Amount;
  readonly sourceExact: boolean;
  readonly destinationExact: boolean;
  readonly bothExact: boolean;
}

export interface BodyIdentityCheck {
  readonly sourceText: string;
  readonly destinationText: string;
  readonly executeFormedText: string | null;
  readonly sourceEqualsDestination: boolean;
  readonly matchesExecuteFormation: boolean;
  readonly sameStep2Signature: boolean;
}

export interface PathManifestEntry {
  readonly predicate: PredicateId;
  readonly passed: boolean;
  readonly determinate: boolean;
  readonly detail: string;
  readonly status: "VERIFIED" | "REJECTED" | "UNDECIDED";
}

export interface PathManifest {
  readonly outcome: VerdictOutcome;
  readonly entries: readonly PathManifestEntry[];
  /** True only when every path predicate is determinate and passed. */
  readonly allVerified: boolean;
}

export interface LandingCommitRecord {
  readonly operationId: string;
  readonly priorState: "CREATED" | "NEEDS_ATTENTION";
  readonly nextState: "INTERNAL_MOVE_LANDED";
  readonly eventType: "internal_move.landed";
  readonly sourceTerminalObservationId: string;
  readonly destinationTerminalObservationId: string;
  readonly verifiedAt: string;
  /** True when event append and state transition committed in one DB-TX (seam-reported). */
  readonly sameDbTx: boolean;
}

export interface MoveObservationEvidenceRecord {
  readonly operationId: string;
  readonly sourceTerminalObservationId: string;
  readonly destinationTerminalObservationId: string;
  readonly verifiedAt: string;
}

export interface VerificationAckRecord {
  readonly operationId: string;
  readonly verdict: AckVerdict;
  readonly evidenceRoles: readonly ("SOURCE" | "DESTINATION")[];
  readonly evidence: readonly DurableEvidenceFact[];
  readonly evidenceSetComplete: boolean;
}

export interface LeaseReleaseRecord {
  readonly groupDecision: GroupReleaseDecision;
  readonly clampedStatus: LeaseReleaseStatus;
  readonly released: boolean;
  readonly sourceReleased: boolean;
  readonly destinationReleased: boolean;
  /** True when release was attempted only after group predicate returned RELEASED. */
  readonly releaseGatedOnGroupPredicate: boolean;
}

/**
 * Archived live-chain evidence packet. Key-free; two node-controlled
 * wallets only — no external counterparty leg (distinguishes receive packet).
 */
export interface MoveEvidencePacket {
  readonly kind: "MOVE_INTERNAL_LIVE_CHAIN_EVIDENCE_V1";
  readonly attemptId: string;
  readonly operationId: string;
  readonly archivedAt: string;
  readonly governingRules: readonly string[];
  readonly decisions: readonly string[];
  readonly dualControl: true;
  readonly externalCounterparty: false;
  readonly amountZkz: Amount;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  readonly step2Signature: string;
  readonly dualDeltas: DualDeltaCheck;
  readonly bodyIdentity: BodyIdentityCheck;
  readonly pathManifest: PathManifest;
  readonly landing: LandingCommitRecord | null;
  readonly acknowledgement: VerificationAckRecord | null;
  readonly leaseRelease: LeaseReleaseRecord | null;
  readonly executeDisposition: MoveExecuteDisposition;
  readonly trail: readonly string[];
  readonly commandsAndResults: readonly string[];
  readonly negativePathAssertion: string;
  readonly noSpeculativeContractImplemented: true;
  readonly packetSha256: string;
}

export interface MoveDispositionEvidenceBundle {
  readonly attemptId: string;
  readonly operationId: string;
  readonly outcome: MoveDispositionOutcome;
  readonly abortAction: MoveAbortAction | null;
  readonly abortTrigger: MoveAbortTrigger | null;
  readonly plan: MoveInternalPlan | null;
  readonly freshSource: FreshHeadReRead | null;
  readonly freshDestination: FreshHeadReRead | null;
  readonly dualDeltas: DualDeltaCheck | null;
  readonly bodyIdentity: BodyIdentityCheck | null;
  readonly pathManifest: PathManifest | null;
  readonly moveProof: OperationProofResult | null;
  readonly landing: LandingCommitRecord | null;
  readonly observationEvidence: MoveObservationEvidenceRecord | null;
  readonly acknowledgement: VerificationAckRecord | null;
  readonly leaseRelease: LeaseReleaseRecord | null;
  readonly evidencePacket: MoveEvidencePacket | null;
  readonly trail: readonly string[];
  /** Explicit negative: this surface never issues a submit. */
  readonly submitCallCount: 0;
  readonly mayResubmit: false;
  readonly mayRebuildWithoutPositiveOracle: false;
}

export interface MoveDispositionResult {
  readonly ok: boolean;
  readonly evidence: MoveDispositionEvidenceBundle;
}

// ─── Injected seams ──────────────────────────────────────────────────────────

export interface MoveFreshHeadSeam {
  /**
   * Independent post-landing head re-read (not the mid-run terminal observation).
   * Returns null when the head cannot be established — never a guess.
   */
  reReadFreshHead(input: {
    readonly walletId: string;
    readonly publicKey: string;
    readonly role: "SOURCE" | "DESTINATION";
    readonly expectedStep2Signature: string;
  }): Promise<FreshHeadReRead | null>;
}

export interface MoveLandingPersistSeam {
  /**
   * DB-TX: attach terminal observations, CREATED/NEEDS_ATTENTION →
   * INTERNAL_MOVE_LANDED, append internal_move.landed, set verified_at. Must be one TX.
   */
  commitLanding(input: {
    readonly operationId: string;
    readonly priorState: "CREATED" | "NEEDS_ATTENTION";
    readonly sourceTerminalObservationId: string;
    readonly destinationTerminalObservationId: string;
    readonly settledTransactionText: string;
    readonly step2Signature: string;
    readonly verifiedAt: string;
  }): Promise<LandingCommitRecord>;
}

export interface MoveAckSeam {
  /**
   * Record verification_acknowledgements + verification_ack_wallet_evidence (SOURCE +
   * DESTINATION). Does not release leases (acknowledgement.ts contract).
   */
  recordAcknowledgement(input: {
    readonly operationId: string;
    readonly verdict: AckVerdict;
    readonly evidence: readonly DurableEvidenceFact[];
    readonly sourceT0ObservationId: string;
    readonly destinationT0ObservationId: string;
    readonly sourceTerminalObservationId: string;
    readonly destinationTerminalObservationId: string;
  }): Promise<VerificationAckRecord>;
}

export interface MoveGroupFactsSeam {
  /** Read lease-group facts after this leg's acknowledgement for the release predicate. */
  loadGroupFacts(input: {
    readonly operationId: string;
    readonly thisLegAck: VerificationAckRecord;
  }): Promise<GroupReleaseFacts>;
}

export interface MoveLeaseReleaseSeam {
  /**
   * Release source + destination leases only when status is RELEASED. Implementations
   * MUST refuse when status is not RELEASED (the one-in-flight-per-wallet rule).
   */
  releaseBothIfGroupPassed(input: {
    readonly operationId: string;
    readonly sourceWalletId: string;
    readonly destinationWalletId: string;
    readonly status: LeaseReleaseStatus;
  }): Promise<{ readonly sourceReleased: boolean; readonly destinationReleased: boolean }>;
}

export interface MoveEvidenceArchiveSeam {
  /** Persist the archived evidence packet (key-free). */
  archive(packet: MoveEvidencePacket): Promise<{ readonly archiveId: string }>;
}

export interface MoveDbChainAgreeSeam {
  /**
   * Compare node-persisted settled body / step_2 / balances against the independently
   * re-read chain heads. Returns true only on byte-for-byte agreement.
   */
  dbAgreesWithChain(input: {
    readonly operationId: string;
    readonly source: FreshHeadReRead;
    readonly destination: FreshHeadReRead;
    readonly settledTransactionText: string;
    readonly step2Signature: string;
  }): Promise<{ readonly agrees: boolean; readonly detail: string }>;
}

export interface MoveDispositionDeps {
  readonly freshHeads: MoveFreshHeadSeam;
  readonly landing: MoveLandingPersistSeam;
  readonly ack: MoveAckSeam;
  readonly groupFacts: MoveGroupFactsSeam;
  readonly leases: MoveLeaseReleaseSeam;
  readonly evidenceArchive: MoveEvidenceArchiveSeam;
  readonly dbChain: MoveDbChainAgreeSeam;
  /** Optional clock (ISO-8601 UTC). Defaults to Date.now().toISOString(). */
  readonly nowIso?: () => string;
}

export interface MoveDispositionInput {
  readonly operationId: string;
  /** LANDED_VERIFIED evidence from executeAuthorizedMoveInternal. */
  readonly executeEvidence: MoveExecuteEvidenceBundle;
  /**
   * Custody facts for predicates 2–3. Live runner loads from lease/wallet rows;
   * offline tests supply fixtures.
   */
  readonly sourceCustody: MoveSourceCustody;
  readonly destinationCustody: MoveDestinationCustody;
  /** Expected-artifact envelope verification result (live runner verifies the node-signed artifact). */
  readonly artifactVerificationOk: boolean;
  /** Prior operation state for the landing CAS (CREATED or NEEDS_ATTENTION). */
  readonly priorState?: "CREATED" | "NEEDS_ATTENTION";
  /**
   * When true (default), refuse unless executeEvidence.disposition === LANDED_VERIFIED.
   * Tests may set false only for negative-path injection of incomplete bundles.
   */
  readonly requireLandedExecute?: boolean;
}

// ─── Internals ───────────────────────────────────────────────────────────────

const GOVERNING_RULES = [
  "observation and verification: the eight internal-move path predicates",
  "operation flows: move disposition and the retention-and-release sequence",
  "data model: verification acknowledgements",
  "state and event reference: move terminal event data",
  "build and test plan: live-chain acceptance evidence",
] as const;

const DESIGN_RULES = [
  "complete-path-adjudication",
  "dual-control-attestation",
  "amount-hard-cap",
  "live-chain-execution",
] as const;

const NEGATIVE_PATH_ASSERTION =
  "NEGATIVE: disposition never issues a submit or rebuild; incomplete/fresh-head mismatch " +
  "holds both leases and reconciles by observation (the never-blind-retry rule).";

function trailPush(trail: string[], line: string): void {
  trail.push(line);
}

/** Parse settled transaction text through the real envelope stage. */
export function parseSettledTransactionText(settledText: string): ParsedSettledTransaction {
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
  input: MoveDispositionInput,
  trail: string[],
  outcome: MoveDispositionOutcome,
  extras: Partial<MoveDispositionEvidenceBundle> = {},
): MoveDispositionEvidenceBundle {
  return {
    attemptId: input.executeEvidence.attemptId,
    operationId: input.operationId,
    outcome,
    abortAction: extras.abortAction ?? null,
    abortTrigger: extras.abortTrigger ?? null,
    plan: input.executeEvidence.plan,
    freshSource: null,
    freshDestination: null,
    dualDeltas: null,
    bodyIdentity: null,
    pathManifest: null,
    moveProof: null,
    landing: null,
    observationEvidence: null,
    acknowledgement: null,
    leaseRelease: null,
    evidencePacket: null,
    trail,
    submitCallCount: 0,
    mayResubmit: false,
    mayRebuildWithoutPositiveOracle: false,
    ...extras,
  };
}

function buildPathManifest(proof: OperationProofResult): PathManifest {
  const byId = new Map(proof.predicates.map((p) => [p.predicate, p]));
  const entries: PathManifestEntry[] = MOVE_INTERNAL_PATH_PREDICATES.map((id) => {
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
    const status: PathManifestEntry["status"] = !p.determinate
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

function buildDualDeltas(
  sourceT0: MoveT0Snapshot,
  destT0: MoveT0Snapshot,
  freshSource: FreshHeadReRead,
  freshDest: FreshHeadReRead,
  amount: Amount,
): DualDeltaCheck {
  // Ts0.B - Ts1.B == amount and Td1.B - Td0.B == amount, against FRESH heads.
  // signedDelta(before, after) = after - before. Debit magnitude = signedDelta(Ts1.B, Ts0.B).
  const sourceDebit = signedDelta(freshSource.balance, sourceT0.projection.B);
  const destinationCredit = signedDelta(destT0.projection.B, freshDest.balance);
  const sourceExact = compareAmounts(sourceDebit, amount) === 0;
  const destinationExact = compareAmounts(destinationCredit, amount) === 0;
  return {
    sourceDebit,
    destinationCredit,
    amount,
    sourceExact,
    destinationExact,
    bothExact: sourceExact && destinationExact,
  };
}

function buildBodyIdentity(
  freshSource: FreshHeadReRead,
  freshDest: FreshHeadReRead,
  formation: MoveFormationRecord | null,
): BodyIdentityCheck {
  const sourceText = freshSource.settledTransactionText;
  const destinationText = freshDest.settledTransactionText;
  const formed = formation?.settledTransactionText ?? null;
  return {
    sourceText,
    destinationText,
    executeFormedText: formed,
    sourceEqualsDestination: sourceText === destinationText,
    matchesExecuteFormation: formed !== null && sourceText === formed && destinationText === formed,
    sameStep2Signature:
      freshSource.step2Signature === freshDest.step2Signature &&
      (formation === null || freshSource.step2Signature === formation.settledStep2Signature),
  };
}

function buildArtifact(
  plan: MoveInternalPlan,
  sourcePk: string,
  destPk: string,
): MoveExpectedArtifact {
  return {
    amount_zkz: plan.amount,
    source_wallet_id: plan.sourceWalletId,
    destination_wallet_id: plan.destinationWalletId,
    source_pubkey: sourcePk,
    destination_pubkey: destPk,
    spawn_reference: null,
  };
}

function packetDigest(packet: Omit<MoveEvidencePacket, "packetSha256">): string {
  // Stable key order via explicit field list — not Object key enumeration.
  const material = JSON.stringify({
    kind: packet.kind,
    attemptId: packet.attemptId,
    operationId: packet.operationId,
    archivedAt: packet.archivedAt,
    amountZkz: packet.amountZkz,
    sourceWalletId: packet.sourceWalletId,
    destinationWalletId: packet.destinationWalletId,
    step2Signature: packet.step2Signature,
    dualDeltas: packet.dualDeltas,
    bodyIdentity: {
      sourceEqualsDestination: packet.bodyIdentity.sourceEqualsDestination,
      matchesExecuteFormation: packet.bodyIdentity.matchesExecuteFormation,
      sameStep2Signature: packet.bodyIdentity.sameStep2Signature,
      // Digest over identity flags + step2, not full bodies (bodies already in trail/archive).
    },
    pathManifestOutcome: packet.pathManifest.outcome,
    pathAllVerified: packet.pathManifest.allVerified,
    executeDisposition: packet.executeDisposition,
    noSpeculativeContractImplemented: packet.noSpeculativeContractImplemented,
    externalCounterparty: packet.externalCounterparty,
    dualControl: packet.dualControl,
  });
  return createHash("sha256").update(material, "utf8").digest("hex");
}

/**
 * Reconcile and disposition one LANDED_VERIFIED MOVE_INTERNAL run.
 *
 * Sequence:
 *   1. Require execute LANDED_VERIFIED + complete dual-path landing evidence.
 *   2. Independently re-read both fresh heads (not mid-run values).
 *   3. Dual exact deltas + byte-identical bodies + same step_2_signature.
 *   4. OBS path manifest via evaluateMoveProof (all eight → VERIFIED).
 *   5. DB-vs-chain byte agreement.
 *   6. Landing DB-TX: INTERNAL_MOVE_LANDED + internal_move.landed same TX.
 *   7. verification_acknowledgements with SOURCE + DESTINATION evidence.
 *   8. Group-predicate release — leases only when RELEASED.
 *   9. Archive evidence packet.
 *
 * Never submits. Never rebuilds without positive non-landing oracle (out of scope).
 */
export async function disposeMoveInternalEvidence(
  deps: MoveDispositionDeps,
  input: MoveDispositionInput,
): Promise<MoveDispositionResult> {
  const trail: string[] = [];
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const requireLanded = input.requireLandedExecute !== false;
  const exec = input.executeEvidence;

  trailPush(trail, `disposition start attempt=${exec.attemptId} op=${input.operationId}`);
  trailPush(trail, `execute disposition=${exec.disposition}; submitCalls never issued here`);

  if (requireLanded && exec.disposition !== "LANDED_VERIFIED") {
    trailPush(trail, `refuse: execute not LANDED_VERIFIED (${exec.disposition})`);
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "REFUSED_EXECUTE_NOT_LANDED", {
        abortAction: abortActionFor("SUBMIT_AMBIGUOUS_OR_UNOBSERVED").action,
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
      }),
    };
  }

  const plan = exec.plan;
  const landing = exec.landing;
  const formation = exec.formation;
  const sourceT0 = exec.sourceT0;
  const destT0 = exec.destinationT0;

  if (
    plan === null ||
    landing === null ||
    formation === null ||
    sourceT0 === null ||
    destT0 === null ||
    !landing.sameStep2Signature ||
    !landing.deltasMatchAmount
  ) {
    trailPush(trail, "refuse: incomplete execute landing evidence");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "REFUSED_INCOMPLETE_EXECUTE_EVIDENCE", {
        abortAction: abortActionFor("SUBMIT_AMBIGUOUS_OR_UNOBSERVED").action,
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
      }),
    };
  }

  const expectedStep2 = formation.settledStep2Signature;
  trailPush(trail, `expected step_2=${truncateSig(expectedStep2)} amount=${plan.amount}`);

  // ── Independent fresh-head re-reads (not mid-run terminals) ────────────────
  let freshSource: FreshHeadReRead | null;
  let freshDest: FreshHeadReRead | null;
  try {
    freshSource = await deps.freshHeads.reReadFreshHead({
      walletId: plan.sourceWalletId,
      publicKey: sourceT0.publicKey,
      role: "SOURCE",
      expectedStep2Signature: expectedStep2,
    });
    freshDest = await deps.freshHeads.reReadFreshHead({
      walletId: plan.destinationWalletId,
      publicKey: destT0.publicKey,
      role: "DESTINATION",
      expectedStep2Signature: expectedStep2,
    });
  } catch (err) {
    trailPush(
      trail,
      `fresh head re-read threw: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
      }),
    };
  }

  if (freshSource === null || freshDest === null) {
    trailPush(
      trail,
      `fresh head incomplete: source=${freshSource !== null} dest=${freshDest !== null}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
      }),
    };
  }

  trailPush(
    trail,
    `fresh heads source_obs=${freshSource.observationId} dest_obs=${freshDest.observationId}`,
  );

  // ── Dual deltas against fresh heads ────────────────────────────
  const dualDeltas = buildDualDeltas(sourceT0, destT0, freshSource, freshDest, plan.amount);
  trailPush(
    trail,
    `dual deltas srcΔ=${dualDeltas.sourceDebit} dstΔ=${dualDeltas.destinationCredit} ` +
      `exact=${dualDeltas.bothExact}`,
  );

  // ── Body identity (byte-identical settled bodies + same step_2) ────────────
  const bodyIdentity = buildBodyIdentity(freshSource, freshDest, formation);
  trailPush(
    trail,
    `bodies equal=${bodyIdentity.sourceEqualsDestination} ` +
      `match_formation=${bodyIdentity.matchesExecuteFormation} ` +
      `same_sig=${bodyIdentity.sameStep2Signature}`,
  );

  if (!bodyIdentity.sameStep2Signature || !bodyIdentity.sourceEqualsDestination) {
    trailPush(trail, "INDETERMINATE: fresh paths disagree on settled body / step_2");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
      }),
    };
  }

  if (!dualDeltas.bothExact) {
    trailPush(trail, "INVARIANT: fresh-head dual deltas do not equal amount");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: "ESCALATE_INVARIANT_BREACH",
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
      }),
    };
  }

  if (!bodyIdentity.matchesExecuteFormation) {
    trailPush(trail, "INDETERMINATE: fresh body ≠ execute formation text");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
      }),
    };
  }

  // ── path manifest via evaluateMoveProof ─────────────────────────────
  let sourceParsed: ParsedSettledTransaction;
  let destParsed: ParsedSettledTransaction;
  try {
    sourceParsed = parseSettledTransactionText(freshSource.settledTransactionText);
    destParsed = parseSettledTransactionText(freshDest.settledTransactionText);
  } catch (err) {
    trailPush(
      trail,
      `settled parse failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
      }),
    };
  }

  const policyInput: MovePolicyInput = {
    artifact: buildArtifact(plan, sourceT0.publicKey, destT0.publicKey),
    artifactVerification: input.artifactVerificationOk
      ? {
          ok: true,
          purpose: "zp-move-internal-expected-v1",
          digest: createHash("sha256")
            .update(
              `${plan.attemptId}:${plan.sourceWalletId}:${plan.destinationWalletId}:${plan.amount}`,
              "utf8",
            )
            .digest("hex"),
        }
      : { ok: false, reason: "envelope_rejected", detail: "artifact verification failed" },
    source: {
      walletPublicKey: sourceT0.publicKey,
      baseline: sourceT0.projection,
      observation: sourceParsed,
      custody: input.sourceCustody,
    },
    destination: {
      walletPublicKey: destT0.publicKey,
      baseline: destT0.projection,
      observation: destParsed,
      custody: input.destinationCustody,
    },
    spawnedFrom: null,
  };

  const moveProof = evaluateMoveProof(policyInput);
  const pathManifest = buildPathManifest(moveProof);
  trailPush(
    trail,
    `path manifest outcome=${pathManifest.outcome} allVerified=${pathManifest.allVerified}`,
  );
  for (const e of pathManifest.entries) {
    trailPush(trail, `  predicate ${e.predicate}: ${e.status} — ${e.detail}`);
  }

  if (!pathManifest.allVerified || pathManifest.outcome !== "VERIFIED") {
    const determinateFail = pathManifest.entries.some((e) => e.status === "REJECTED");
    const outcome: MoveDispositionOutcome = determinateFail
      ? "ESCALATE_INVARIANT_BREACH"
      : "HOLD_BOTH_LEASES_AND_RECONCILE";
    const trigger: MoveAbortTrigger = determinateFail
      ? "INVARIANT_BREACH"
      : "SUBMIT_AMBIGUOUS_OR_UNOBSERVED";
    trailPush(trail, `path manifest failed → ${outcome}`);
    return {
      ok: false,
      evidence: emptyBundle(input, trail, outcome, {
        abortAction: abortActionFor(trigger).action,
        abortTrigger: trigger,
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
      }),
    };
  }

  // ── DB-vs-chain agreement ──────────────────────────────────────────────────
  let dbAgree: { readonly agrees: boolean; readonly detail: string };
  try {
    dbAgree = await deps.dbChain.dbAgreesWithChain({
      operationId: input.operationId,
      source: freshSource,
      destination: freshDest,
      settledTransactionText: formation.settledTransactionText,
      step2Signature: expectedStep2,
    });
  } catch (err) {
    trailPush(
      trail,
      `db-vs-chain check threw: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
      }),
    };
  }

  trailPush(trail, `db-vs-chain agrees=${dbAgree.agrees}: ${dbAgree.detail}`);
  if (!dbAgree.agrees) {
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: "ESCALATE_INVARIANT_BREACH",
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
      }),
    };
  }

  // ── Landing DB-TX ─────────────────────────────────────────
  const verifiedAt = nowIso();
  let landingCommit: LandingCommitRecord;
  try {
    landingCommit = await deps.landing.commitLanding({
      operationId: input.operationId,
      priorState: input.priorState ?? "CREATED",
      sourceTerminalObservationId: freshSource.observationId,
      destinationTerminalObservationId: freshDest.observationId,
      settledTransactionText: formation.settledTransactionText,
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
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
      }),
    };
  }

  if (
    landingCommit.nextState !== "INTERNAL_MOVE_LANDED" ||
    landingCommit.eventType !== "internal_move.landed" ||
    !landingCommit.sameDbTx
  ) {
    trailPush(trail, "landing commit shape invalid (state/event/sameDbTx)");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ESCALATE_INVARIANT_BREACH", {
        abortAction: "ESCALATE_INVARIANT_BREACH",
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
        landing: landingCommit,
      }),
    };
  }

  const observationEvidence: MoveObservationEvidenceRecord = {
    operationId: input.operationId,
    sourceTerminalObservationId: landingCommit.sourceTerminalObservationId,
    destinationTerminalObservationId: landingCommit.destinationTerminalObservationId,
    verifiedAt: landingCommit.verifiedAt,
  };
  trailPush(
    trail,
    `landing ${landingCommit.priorState}→${landingCommit.nextState} ` +
      `event=${landingCommit.eventType} sameDbTx=${landingCommit.sameDbTx}`,
  );

  // ── Verification acknowledgement (SOURCE + DESTINATION) ──────────
  const expectedWallets: readonly OperationWalletAssignment[] = expectedWalletsForOperation(
    "MOVE_INTERNAL",
    {
      sourceWalletId: plan.sourceWalletId,
      sourcePublicKey: sourceT0.publicKey,
      receiverWalletId: null,
      receiverPublicKey: null,
      destinationWalletId: plan.destinationWalletId,
      destinationPublicKey: destT0.publicKey,
      destinationAddress: null,
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
      walletId: plan.destinationWalletId,
      walletPublicKey: destT0.publicKey,
    },
  ];
  const evidenceFailure = validateEvidenceSet(
    "MOVE_INTERNAL",
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
        abortAction: "ESCALATE_INVARIANT_BREACH",
        abortTrigger: "INVARIANT_BREACH",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
        landing: landingCommit,
        observationEvidence,
      }),
    };
  }

  let ackRecord: VerificationAckRecord;
  try {
    ackRecord = await deps.ack.recordAcknowledgement({
      operationId: input.operationId,
      verdict: "VERIFIED",
      evidence: evidenceFacts,
      sourceT0ObservationId: sourceT0.observationId,
      destinationT0ObservationId: destT0.observationId,
      sourceTerminalObservationId: freshSource.observationId,
      destinationTerminalObservationId: freshDest.observationId,
    });
  } catch (err) {
    trailPush(
      trail,
      `ack record failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
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
    trailPush(trail, "ack incomplete or non-VERIFIED — leases stay held");
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ACK_PINNED", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
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

  // ── Group-predicate lease release ────────────────────
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
      evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
        abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
        abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
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
  let destinationReleased = false;
  const releaseGatedOnGroupPredicate = true;

  if (clampedStatus === "RELEASED") {
    try {
      const rel = await deps.leases.releaseBothIfGroupPassed({
        operationId: input.operationId,
        sourceWalletId: plan.sourceWalletId,
        destinationWalletId: plan.destinationWalletId,
        status: clampedStatus,
      });
      sourceReleased = rel.sourceReleased;
      destinationReleased = rel.destinationReleased;
    } catch (err) {
      trailPush(
        trail,
        `lease release failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return {
        ok: false,
        evidence: emptyBundle(input, trail, "HOLD_BOTH_LEASES_AND_RECONCILE", {
          abortAction: "HOLD_BOTH_LEASES_AND_RECONCILE",
          abortTrigger: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
          freshSource,
          freshDestination: freshDest,
          dualDeltas,
          bodyIdentity,
          pathManifest,
          moveProof,
          landing: landingCommit,
          observationEvidence,
          acknowledgement: ackRecord,
          leaseRelease: {
            groupDecision,
            clampedStatus,
            released: false,
            sourceReleased: false,
            destinationReleased: false,
            releaseGatedOnGroupPredicate,
          },
        }),
      };
    }
  } else {
    trailPush(trail, "leases retained — group predicate not RELEASED");
  }

  const leaseRelease: LeaseReleaseRecord = {
    groupDecision,
    clampedStatus,
    released: sourceReleased && destinationReleased && clampedStatus === "RELEASED",
    sourceReleased,
    destinationReleased,
    releaseGatedOnGroupPredicate,
  };
  trailPush(
    trail,
    `lease release released=${leaseRelease.released} src=${sourceReleased} dst=${destinationReleased}`,
  );

  if (clampedStatus !== "RELEASED" || !leaseRelease.released) {
    // Full economic proof may be VERIFIED but group still pending (e.g. child disposition).
    // That is ACK_PINNED, not a land failure — leases correctly stay held.
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "ACK_PINNED", {
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
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
    kind: "MOVE_INTERNAL_LIVE_CHAIN_EVIDENCE_V1" as const,
    attemptId: exec.attemptId,
    operationId: input.operationId,
    archivedAt,
    governingRules: GOVERNING_RULES,
    decisions: DESIGN_RULES,
    dualControl: true as const,
    externalCounterparty: false as const,
    amountZkz: plan.amount,
    sourceWalletId: plan.sourceWalletId,
    destinationWalletId: plan.destinationWalletId,
    step2Signature: expectedStep2,
    dualDeltas,
    bodyIdentity,
    pathManifest,
    landing: landingCommit,
    acknowledgement: ackRecord,
    leaseRelease,
    executeDisposition: exec.disposition,
    trail: [...trail],
    commandsAndResults: [
      `disposeMoveInternalEvidence attempt=${exec.attemptId}`,
      `fresh dual re-read → step_2=${truncateSig(expectedStep2)}`,
      `dual deltas exact=${dualDeltas.bothExact}`,
      `path manifest allVerified=${pathManifest.allVerified}`,
      `landing ${landingCommit.priorState}→${landingCommit.nextState} + ${landingCommit.eventType}`,
      `ack verdict=${ackRecord.verdict} roles=${ackRecord.evidenceRoles.join("+")}`,
      `lease release status=${clampedStatus} released=${leaseRelease.released}`,
    ],
    negativePathAssertion: NEGATIVE_PATH_ASSERTION,
    noSpeculativeContractImplemented: true as const,
  };
  const evidencePacket: MoveEvidencePacket = {
    ...packetBase,
    packetSha256: packetDigest(packetBase),
  };

  try {
    const archived = await deps.evidenceArchive.archive(evidencePacket);
    trailPush(trail, `evidence packet archived id=${archived.archiveId} sha256=${evidencePacket.packetSha256.slice(0, 16)}…`);
  } catch (err) {
    trailPush(
      trail,
      `evidence archive failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return {
      ok: false,
      evidence: emptyBundle(input, trail, "EVIDENCE_ARCHIVE_FAILED", {
        freshSource,
        freshDestination: freshDest,
        dualDeltas,
        bodyIdentity,
        pathManifest,
        moveProof,
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
      abortAction: abortActionFor("LANDED_VERIFIED").action,
      abortTrigger: "LANDED_VERIFIED",
      plan,
      freshSource,
      freshDestination: freshDest,
      dualDeltas,
      bodyIdentity,
      pathManifest,
      moveProof,
      landing: landingCommit,
      observationEvidence,
      acknowledgement: ackRecord,
      leaseRelease,
      evidencePacket,
      trail,
      submitCallCount: 0,
      mayResubmit: false,
      mayRebuildWithoutPositiveOracle: false,
    },
  };
}

function truncateSig(sig: string): string {
  if (sig === "") return "∅";
  if (sig.length <= 12) return sig;
  return `${sig.slice(0, 8)}…${sig.slice(-4)}`;
}
