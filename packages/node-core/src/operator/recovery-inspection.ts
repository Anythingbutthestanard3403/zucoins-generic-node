// pure recovery classification and permitted-action derivation.
//
// The closed classification set, the action predicates, the nine permitted actions, and the
// forbidden surface are all defined here. There is no generic PROVEN_NOT_LANDED oracle —
// evidence-complete cases only.
//
// Classification is pure: it reads an immutable durable snapshot and returns a
// typed result. Permitted actions are re-derived on every read by evaluating the
// same predicates the follow-on POST will re-check under locks. Nothing
// here mutates state, signs, submits, or releases a lease.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

/** Closed set. */
export const RECOVERY_CLASSIFICATIONS = [
  "LANDED_VERIFIED",
  "PROVEN_NOT_STARTED",
  "PROVEN_NOT_LANDED",
  "WAITING",
  "INDETERMINATE",
  "INVARIANT_BREACH",
] as const;

export type RecoveryClassification = (typeof RECOVERY_CLASSIFICATIONS)[number];

/** Closed set of nine operator recovery actions. */
export const OPERATOR_RECOVERY_ACTIONS = [
  "RETRY_OBSERVATION",
  "REDELIVER_EXACT_PARTIAL",
  "CONTINUE_EXTERNAL_WAIT",
  "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
  "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
  "REBUILD_INTERNAL_MOVE",
  "RELEASE_EXPIRED_RECEIVE",
  "QUARANTINE_WALLETS",
  "ACKNOWLEDGE_KEEP_PINNED",
] as const;

export type OperatorRecoveryAction = (typeof OPERATOR_RECOVERY_ACTIONS)[number];

/** Non-actions that must never appear in permitted sets. */
export const FORBIDDEN_RECOVERY_ACTIONS = [
  "RETRY_SUBMIT",
  "FORCE_LANDED",
  "FORCE_RELEASE",
  "EDIT_TRANSACTION",
  "CHANGE_DESTINATION",
  "CHANGE_AMOUNT",
  "REFORM_EXTERNAL_SEND",
  "NODE_SUBMIT_EXTERNAL_SEND",
  "DELETE_EVIDENCE",
  "SKIP_VERIFICATION",
] as const;

export type ForbiddenRecoveryAction = (typeof FORBIDDEN_RECOVERY_ACTIONS)[number];

/**
 * Immutable evidence-manifest entry surfaced to operators. Never carries private
 * keys or raw unredacted gateway bytes beyond operator-safe digests/ids.
 */
export interface EvidenceManifestEntry {
  readonly kind: string;
  readonly id: string | null;
  readonly role: string | null;
  readonly digest_sha256: string | null;
  readonly summary: string;
}

/** Durable receive predicates, pre-resolved by the store. */
export interface ReceiveRecoveryFacts {
  readonly codeExpiredPlusMargin: boolean;
  readonly noPersistedLandedProof: boolean;
  readonly freshObservationEqualsT0: boolean;
  readonly noAnomalyOrSubmitReconcileDebt: boolean;
  readonly childAbsentOrTerminal: boolean;
  readonly hasT0: boolean;
  readonly hasCodeOrArtifactPreimage: boolean;
  readonly hasArtifactSignature: boolean;
  readonly hasSignerAudit: boolean;
  readonly hasMatchingExactByteRecord: boolean;
}

/** Durable move predicates. */
export interface MoveRecoveryFacts {
  /** Case 1 — deterministic pre-acceptance rejection with captured authenticated response. */
  readonly deterministicPreAcceptanceRejection: boolean;
  /** Case 2 — expiry+margin passed and both wallets fresh-head equal their attempt T0. */
  readonly expiredAndBothWalletsUnchangedAtT0: boolean;
  /** Case 3 — no submit claim/call; first submission of an already-signed attempt, not rebuild. */
  readonly submitProvablyNeverStarted: boolean;
  /** Stored positive non-landing proof id (operator-supplied on POST). */
  readonly positiveNonLandingProofId: string | null;
  readonly unexpectedSuccessorOutsideLease: boolean;
  readonly hasPreimage: boolean;
  readonly hasSignature: boolean;
  readonly hasSignerAudit: boolean;
  readonly hasMatchingExactByteRecord: boolean;
  readonly oneWalletLandedOtherUnconnected: boolean;
}

/** Durable send predicates. */
export interface SendRecoveryFacts {
  readonly hasSignIntent: boolean;
  readonly hasSignerCall: boolean;
  readonly hasSignature: boolean;
  readonly hasDurablePartial: boolean;
  readonly hasDelivery: boolean;
  /** Redemption expiry + SEND_PARTIAL_AGING_MARGIN_SECS has passed (column read). */
  readonly protocolExpiredPlusMargin: boolean;
  /** Fresh verified authoritative head equals source T0 in {S,P,B}. */
  readonly freshHeadEqualsSourceT0: boolean;
  /**
   * complete-path exclusion proved non-landing (not a generic oracle).
   * Only when every body is present and path classification excludes the partial.
   */
  readonly completePathExclusionProved: boolean;
  readonly hasSignerAudit: boolean;
  readonly hasMatchingExactByteRecord: boolean;
}

/**
 * Immutable operation snapshot for pure classification. Callers resolve durable
 * rows into these booleans/ids once; the pure functions never touch the DB.
 */
export interface RecoveryFacts {
  readonly operationId: string;
  readonly kind: OperationKind;
  readonly status: string;
  readonly attentionRequired: boolean;
  readonly attentionReason: string | null;
  readonly rowVersion: number;
  /** Max held lease epoch across active leases; null when none held. */
  readonly leaseEpoch: number | null;
  readonly heldLeases: readonly {
    readonly walletId: string;
    readonly leaseEpoch: number;
    readonly role: string;
  }[];
  readonly hasLandingProof: boolean;
  readonly landingProofVerdict: "LANDED_EXACT" | "LANDED_COMPLETE_PATH" | null;
  readonly hasObservationAnomaly: boolean;
  readonly hasLineageGap: boolean;
  /** Stored phases/bytes/leases cannot arise under the contract. */
  readonly invariantBreachNoted: boolean;
  readonly evidenceManifest: readonly EvidenceManifestEntry[];
  readonly diagnostics: readonly {
    readonly at: string;
    readonly code: string;
    readonly message: string;
  }[];
  readonly receive: ReceiveRecoveryFacts | null;
  readonly move: MoveRecoveryFacts | null;
  readonly send: SendRecoveryFacts | null;
  /** When true, REBUILD_INTERNAL_MOVE is refused (halt gate). */
  readonly haltEngaged: boolean;
}

export interface ClassificationResult {
  readonly classification: RecoveryClassification;
  readonly rationale: string;
}

export interface PermittedActionsResult {
  readonly classification: RecoveryClassification;
  readonly permittedActions: readonly OperatorRecoveryAction[];
  readonly rationale: string;
}

function receiveExpiredNoPaymentAllFive(r: ReceiveRecoveryFacts): boolean {
  return (
    r.codeExpiredPlusMargin &&
    r.noPersistedLandedProof &&
    r.freshObservationEqualsT0 &&
    r.noAnomalyOrSubmitReconcileDebt &&
    r.childAbsentOrTerminal
  );
}

function movePositiveNonLandingCases12(m: MoveRecoveryFacts): boolean {
  return m.deterministicPreAcceptanceRejection || m.expiredAndBothWalletsUnchangedAtT0;
}

function sendProvenNotLandedOracle(s: SendRecoveryFacts): boolean {
  // Two-part oracle: expiry+margin AND (fresh head == T0 OR complete-path exclusion).
  return (
    s.protocolExpiredPlusMargin &&
    (s.freshHeadEqualsSourceT0 || s.completePathExclusionProved)
  );
}

function sendNeverStarted(s: SendRecoveryFacts): boolean {
  return (
    !s.hasSignIntent &&
    !s.hasSignerCall &&
    !s.hasSignature &&
    !s.hasDurablePartial &&
    !s.hasDelivery
  );
}

/**
 * Pure classification. Reads the durable snapshot only.
 */
export function classifyRecovery(facts: RecoveryFacts): ClassificationResult {
  if (facts.invariantBreachNoted) {
    return { classification: "INVARIANT_BREACH", rationale: "invariant_breach_noted" };
  }

  // Positive landing proof is authoritative once present (LANDED_VERIFIED).
  // Exact-byte / signer-audit consistency checks still apply when no landing proof
  // exists; a landing proof must not be masked by a stale or mis-matched
  // exact-byte fact (live false positive: receive_signer_audit_without_exact_bytes
  // on a RECEIVE_LANDED op whose expected-artifact audit was present and correct).
  if (facts.hasLandingProof) {
    return {
      classification: "LANDED_VERIFIED",
      rationale:
        facts.landingProofVerdict === "LANDED_COMPLETE_PATH"
          ? "landing_complete_path"
          : "landing_exact",
    };
  }

  if (facts.kind === "RECEIVE_EXTERNAL" && facts.receive !== null) {
    const r = facts.receive;
    if (r.hasSignerAudit && !r.hasMatchingExactByteRecord) {
      return {
        classification: "INVARIANT_BREACH",
        rationale: "receive_signer_audit_without_exact_bytes",
      };
    }
  }

  if (facts.kind === "MOVE_INTERNAL" && facts.move !== null) {
    const m = facts.move;
    if (m.unexpectedSuccessorOutsideLease) {
      return {
        classification: "INVARIANT_BREACH",
        rationale: "move_unexpected_successor_outside_lease",
      };
    }
    if (m.hasSignerAudit && !m.hasMatchingExactByteRecord) {
      return {
        classification: "INVARIANT_BREACH",
        rationale: "move_signer_audit_without_exact_bytes",
      };
    }
  }

  if (facts.kind === "SEND_EXTERNAL" && facts.send !== null) {
    const s = facts.send;
    if (s.hasSignerAudit && !s.hasMatchingExactByteRecord) {
      return {
        classification: "INVARIANT_BREACH",
        rationale: "send_signer_audit_without_exact_bytes",
      };
    }
    // DB says no sign intent but signer audit indicates a call.
    if (!s.hasSignIntent && s.hasSignerCall) {
      return {
        classification: "INVARIANT_BREACH",
        rationale: "send_signer_call_without_intent",
      };
    }
  }

  if (facts.kind === "RECEIVE_EXTERNAL" && facts.receive !== null) {
    const r = facts.receive;
    if (
      !r.hasT0 &&
      !r.hasCodeOrArtifactPreimage &&
      !r.hasArtifactSignature &&
      !r.hasSignerAudit
    ) {
      return {
        classification: "PROVEN_NOT_STARTED",
        rationale: "receive_no_formation_boundary_crossed",
      };
    }
    if (receiveExpiredNoPaymentAllFive(r)) {
      // Do not invent PROVEN_NOT_LANDED without the T0 equality oracle: the five
      // predicates themselves are the release proof path, classified as proven release ground.
      return {
        classification: "PROVEN_NOT_LANDED",
        rationale: "receive_expired_t0_unchanged_all_five",
      };
    }
    if (facts.hasObservationAnomaly || facts.hasLineageGap) {
      return {
        classification: "INDETERMINATE",
        rationale: "receive_anomaly_or_lineage_gap",
      };
    }
    return { classification: "INDETERMINATE", rationale: "receive_insufficient_evidence" };
  }

  if (facts.kind === "MOVE_INTERNAL" && facts.move !== null) {
    const m = facts.move;
    if (m.oneWalletLandedOtherUnconnected) {
      return {
        classification: "INDETERMINATE",
        rationale: "move_asymmetric_landing",
      };
    }
    if (movePositiveNonLandingCases12(m) && m.positiveNonLandingProofId !== null) {
      return {
        classification: "PROVEN_NOT_LANDED",
        rationale: m.deterministicPreAcceptanceRejection
          ? "move_deterministic_pre_acceptance_rejection"
          : "move_expired_both_wallets_t0_equal",
      };
    }
    if (m.submitProvablyNeverStarted && !m.hasSignature) {
      return {
        classification: "PROVEN_NOT_STARTED",
        rationale: "move_no_preimage_or_sign_audit",
      };
    }
    if (m.submitProvablyNeverStarted && m.hasSignature) {
      // First submission of the already-signed attempt — still not a rebuild.
      return {
        classification: "PROVEN_NOT_STARTED",
        rationale: "move_signed_submit_never_started",
      };
    }
    if (facts.hasObservationAnomaly || facts.hasLineageGap) {
      return { classification: "INDETERMINATE", rationale: "move_anomaly_or_lineage_gap" };
    }
    return { classification: "INDETERMINATE", rationale: "move_insufficient_evidence" };
  }

  if (facts.kind === "SEND_EXTERNAL" && facts.send !== null) {
    const s = facts.send;
    if (sendNeverStarted(s) && (facts.status === "APPROVED" || facts.status === "CREATED")) {
      return {
        classification: "PROVEN_NOT_STARTED",
        rationale: "send_no_formation_boundary_crossed",
      };
    }
    if (sendProvenNotLandedOracle(s)) {
      return {
        classification: "PROVEN_NOT_LANDED",
        rationale: s.freshHeadEqualsSourceT0
          ? "send_expired_source_t0_equal"
          : "send_expired_complete_path_exclusion",
      };
    }
    if (s.hasDurablePartial && !s.protocolExpiredPlusMargin) {
      return {
        classification: "WAITING",
        rationale: "send_partial_intact_unexpired",
      };
    }
    if (facts.hasObservationAnomaly || facts.hasLineageGap) {
      return { classification: "INDETERMINATE", rationale: "send_anomaly_or_lineage_gap" };
    }
    return { classification: "INDETERMINATE", rationale: "send_insufficient_evidence" };
  }

  return { classification: "INDETERMINATE", rationale: "insufficient_facts" };
}

/**
 * Fresh permitted-actions derivation. Evaluates durable predicates at
 * call time; never returns a cached/static table mapping alone.
 *
 * INVARIANT_BREACH (required negative path): only QUARANTINE_WALLETS and
 * ACKNOWLEDGE_KEEP_PINNED — never a resolving action.
 */
export function derivePermittedActions(
  facts: RecoveryFacts,
  classification: RecoveryClassification = classifyRecovery(facts).classification,
): PermittedActionsResult {
  if (classification === "INVARIANT_BREACH") {
    return {
      classification,
      permittedActions: ["QUARANTINE_WALLETS", "ACKNOWLEDGE_KEEP_PINNED"],
      rationale: "invariant_breach_no_resolving_actions",
    };
  }

  const actions = new Set<OperatorRecoveryAction>();
  const nonterminalOrAttention =
    facts.attentionRequired ||
    facts.status === "NEEDS_ATTENTION" ||
    !isTerminalStatus(facts.kind, facts.status);

  if (nonterminalOrAttention) {
    actions.add("RETRY_OBSERVATION");
  }

  if (facts.attentionRequired || facts.status === "NEEDS_ATTENTION") {
    actions.add("ACKNOWLEDGE_KEEP_PINNED");
  }

  if (
    facts.hasObservationAnomaly ||
    facts.hasLineageGap ||
    classification === "INDETERMINATE"
  ) {
    actions.add("QUARANTINE_WALLETS");
  }

  if (facts.kind === "RECEIVE_EXTERNAL" && facts.receive !== null) {
    if (receiveExpiredNoPaymentAllFive(facts.receive)) {
      actions.add("RELEASE_EXPIRED_RECEIVE");
    }
  }

  if (facts.kind === "MOVE_INTERNAL" && facts.move !== null) {
    const m = facts.move;
    // Cases 1–2 only for rebuild. Case 3 authorizes first submit, not REBUILD.
    // RESERVED until evidence-complete positive proof is held.
    if (
      movePositiveNonLandingCases12(m) &&
      m.positiveNonLandingProofId !== null &&
      classification === "PROVEN_NOT_LANDED" &&
      !facts.haltEngaged
    ) {
      actions.add("REBUILD_INTERNAL_MOVE");
    }
  }

  if (facts.kind === "SEND_EXTERNAL" && facts.send !== null) {
    const s = facts.send;
    if (s.hasDurablePartial) {
      actions.add("REDELIVER_EXACT_PARTIAL");
    }
    if (
      facts.status === "NEEDS_ATTENTION" &&
      s.hasDurablePartial &&
      !s.protocolExpiredPlusMargin
    ) {
      actions.add("CONTINUE_EXTERNAL_WAIT");
    }
    if (facts.status === "APPROVED" && classification === "PROVEN_NOT_STARTED") {
      actions.add("CLOSE_NEVER_STARTED_EXTERNAL_SEND");
    }
    // Only when the two-part oracle holds against durable data.
    if (
      classification === "PROVEN_NOT_LANDED" &&
      sendProvenNotLandedOracle(s)
    ) {
      actions.add("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED");
    }
  }

  // LANDED_VERIFIED: automatic effect is advance-to-landed. Inspection reports
  // no resolving operator action beyond acknowledgement if already attention-flagged.
  if (classification === "LANDED_VERIFIED") {
    actions.delete("RELEASE_EXPIRED_RECEIVE");
    actions.delete("REBUILD_INTERNAL_MOVE");
    actions.delete("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED");
    actions.delete("CLOSE_NEVER_STARTED_EXTERNAL_SEND");
    actions.delete("CONTINUE_EXTERNAL_WAIT");
  }

  const ordered = OPERATOR_RECOVERY_ACTIONS.filter((a) => actions.has(a));
  return {
    classification,
    permittedActions: ordered,
    rationale: "fresh_predicate_derivation",
  };
}

function isTerminalStatus(kind: OperationKind, status: string): boolean {
  if (kind === "RECEIVE_EXTERNAL") {
    return status === "RECEIVE_LANDED" || status === "EXPIRED";
  }
  if (kind === "MOVE_INTERNAL") {
    return status === "INTERNAL_MOVE_LANDED";
  }
  return status === "EXTERNAL_SEND_LANDED" || status === "REJECTED";
}

/**
 * Inspect one snapshot: classify + derive actions + bind evidence.
 * Pure. Callers issue the recovery nonce separately via the store.
 */
export function inspectRecovery(facts: RecoveryFacts): {
  readonly classification: RecoveryClassification;
  readonly classificationRationale: string;
  readonly permittedActions: readonly OperatorRecoveryAction[];
  readonly evidenceManifest: readonly EvidenceManifestEntry[];
  readonly rowVersion: number;
  readonly leaseEpoch: number | null;
} {
  const { classification, rationale } = classifyRecovery(facts);
  const permitted = derivePermittedActions(facts, classification);
  return {
    classification,
    classificationRationale: rationale,
    permittedActions: permitted.permittedActions,
    evidenceManifest: facts.evidenceManifest,
    rowVersion: facts.rowVersion,
    leaseEpoch: facts.leaseEpoch,
  };
}
