// pure relationship classifier for appended verified observations.
//
// Landing-path oracle (jump
// immutability — this module never revises a prior classification; complete-path
// adjudication is). Decision procedure ordering and 7-value output vocabulary are
// (`@zucoins/generic-node-contracts/observation`); this module is the
// node-core capture-path surface that accepts projection+fingerprint state and
// returns typed evidence for every branch.
//
// Invariants:
// - DUPLICATE is never an output (byte-identical repeats are suppressed upstream by
// decideAppend).
// - Only SUCCESSOR establishes a new ordinary head (establishesOrdinaryHead).
// - UNEXPLAINED_JUMP is never silently accepted as landed; residual only.
// - Original relationship is immutable; no COMPLETE_PATH_SUCCESSOR here.

import {
  classifyRelationship as classifyRelationshipFrozen,
  type AcceptedSemanticState,
  type ClassifierOutputRelationship,
} from "@zucoins/generic-node-contracts/observation";

import type { GenesisStateProjection, RoleStateProjection } from "./projection.js";

/** Verified semantic state the classifier compares — S/P + fingerprint + genesis flag. */
export interface VerifiedSemanticState {
  readonly isGenesis: boolean;
  /** Role-relative current state signature S ("" at genesis). */
  readonly sSignature: string;
  /** Role-relative predecessor signature P ("" at genesis). */
  readonly pSignature: string;
  /** / A.7 semantic fingerprint SHA-256 hex. */
  readonly semanticFingerprint: string;
}

/**
 * Permanent prior-state index for this observer/read stream. REGRESSION matches against
 * every historically accepted S, not only the immediate prior row (A,B,C,A).
 */
export interface RelationshipClassifierInput {
  /** Immediately prior accepted state, or null when this is the first accepted state. */
  readonly prior: VerifiedSemanticState | null;
  /** Newly verified semantic state about to be appended. */
  readonly next: VerifiedSemanticState;
  /**
   * True when any historically accepted non-genesis state exists on this stream
   * (GENESIS_AFTER_HISTORY gate). Distinct from `prior !== null` when prior itself is genesis.
   */
  readonly priorHistoryHasNonGenesis: boolean;
  /**
   * All previously accepted state signatures S for this stream, oldest→newest including
   * the immediate prior. Used only for REGRESSION (recurrence of an older S).
   */
  readonly acceptedStateSignatureHistory: readonly string[];
}

/** Shared comparison material every evidence object carries for audit trails. */
export interface ClassificationComparison {
  readonly priorS: string | null;
  readonly priorP: string | null;
  readonly priorFingerprint: string | null;
  readonly nextS: string;
  readonly nextP: string;
  readonly nextFingerprint: string;
  readonly fingerprintsEqual: boolean;
  readonly nextPEqualsPriorS: boolean;
  readonly nextSEqualsPriorS: boolean;
}

export type RelationshipEvidence =
  | {
      readonly conditionId: "NO_PRIOR";
      readonly relationship: "FIRST";
      readonly comparison: ClassificationComparison;
    }
  | {
      readonly conditionId: "SEMANTIC_FINGERPRINT_EQUAL";
      readonly relationship: "EQUIVALENT_STATE_DIFFERENT_ENVELOPE";
      readonly comparison: ClassificationComparison;
    }
  | {
      readonly conditionId: "BACKLINK_TO_PRIOR";
      readonly relationship: "SUCCESSOR";
      readonly comparison: ClassificationComparison;
    }
  | {
      readonly conditionId: "SAME_S_FINGERPRINT_DIFFERS";
      readonly relationship: "SIGNATURE_COLLISION";
      readonly comparison: ClassificationComparison;
    }
  | {
      readonly conditionId: "GENESIS_AFTER_HISTORY";
      readonly relationship: "GENESIS_AFTER_HISTORY";
      readonly comparison: ClassificationComparison;
      readonly priorHistoryHasNonGenesis: true;
    }
  | {
      readonly conditionId: "RECURRENCE_OF_OLDER_S";
      readonly relationship: "REGRESSION";
      readonly comparison: ClassificationComparison;
      /** The historically accepted S that matched `next.sSignature` (may be below current). */
      readonly matchedHistoricalS: string;
      readonly matchedHistoryIndex: number;
    }
  | {
      readonly conditionId: "DIFFERENT_S_NO_BACKLINK";
      readonly relationship: "UNEXPLAINED_JUMP";
      readonly comparison: ClassificationComparison;
    };

export interface RelationshipResult {
  readonly relationship: ClassifierOutputRelationship;
  readonly stateChanged: boolean;
  readonly conditionId: RelationshipEvidence["conditionId"];
  readonly evidence: RelationshipEvidence;
}

/** The seven capture-path outputs — closed set; DUPLICATE / COMPLETE_PATH_SUCCESSOR absent. */
export const CLASSIFIER_RELATIONSHIPS = [
  "FIRST",
  "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
  "SUCCESSOR",
  "SIGNATURE_COLLISION",
  "GENESIS_AFTER_HISTORY",
  "REGRESSION",
  "UNEXPLAINED_JUMP",
] as const satisfies readonly ClassifierOutputRelationship[];

/**
 * Only SUCCESSOR establishes a new ordinary head. FIRST establishes a cursor but
 * is not an ordinary head advance from a prior accepted state. Anomalies never promote.
 */
export function establishesOrdinaryHead(result: RelationshipResult): boolean {
  return result.relationship === "SUCCESSOR";
}

/** True when the classification is an anomaly that must quarantine / fail closed. */
export function isAnomalousRelationship(relationship: ClassifierOutputRelationship): boolean {
  return (
    relationship === "SIGNATURE_COLLISION" ||
    relationship === "GENESIS_AFTER_HISTORY" ||
    relationship === "REGRESSION" ||
    relationship === "UNEXPLAINED_JUMP"
  );
}

/** Build classifier state from a verified HEAD role projection + its A.7 fingerprint digest. */
export function verifiedStateFromHeadProjection(
  projection: RoleStateProjection,
  semanticFingerprint: string,
): VerifiedSemanticState {
  return {
    isGenesis: false,
    sSignature: projection.S,
    pSignature: projection.P,
    semanticFingerprint,
  };
}

/** Build classifier state from a verified genesis projection + its A.7 fingerprint digest. */
export function verifiedStateFromGenesisProjection(
  _projection: GenesisStateProjection,
  semanticFingerprint: string,
): VerifiedSemanticState {
  return {
    isGenesis: true,
    sSignature: "",
    pSignature: "",
    semanticFingerprint,
  };
}

function toAccepted(state: VerifiedSemanticState): AcceptedSemanticState {
  return {
    isGenesis: state.isGenesis,
    sSignature: state.sSignature,
    pSignature: state.pSignature,
    semanticFingerprint: state.semanticFingerprint,
  };
}

function buildComparison(
  prior: VerifiedSemanticState | null,
  next: VerifiedSemanticState,
): ClassificationComparison {
  return {
    priorS: prior?.sSignature ?? null,
    priorP: prior?.pSignature ?? null,
    priorFingerprint: prior?.semanticFingerprint ?? null,
    nextS: next.sSignature,
    nextP: next.pSignature,
    nextFingerprint: next.semanticFingerprint,
    fingerprintsEqual:
      prior !== null && next.semanticFingerprint === prior.semanticFingerprint,
    nextPEqualsPriorS: prior !== null && next.pSignature === prior.sSignature,
    nextSEqualsPriorS: prior !== null && next.sSignature === prior.sSignature,
  };
}

/**
 * Classify a newly verified semantic state against the immediate prior accepted state and
 * the permanent prior-state index. Pure and total. Call only after decided APPEND
 * (raw bytes differ) and produced projection + fingerprint.
 *
 * Evaluation ordering is the frozen table (first match wins). Delegates the branch decision
 * to the frozen procedure so capture-path and contracts cannot drift, then attaches
 * typed evidence for anomaly rows / audit.
 */
export function classifyRelationship(input: RelationshipClassifierInput): RelationshipResult {
  const { prior, next, priorHistoryHasNonGenesis, acceptedStateSignatureHistory } = input;
  const comparison = buildComparison(prior, next);

  const frozen = classifyRelationshipFrozen({
    prior: prior === null ? null : toAccepted(prior),
    next: toAccepted(next),
    priorHistoryHasNonGenesis,
    acceptedStateSignatureHistory,
  });

  switch (frozen.relationship) {
    case "FIRST":
      return {
        relationship: "FIRST",
        stateChanged: true,
        conditionId: "NO_PRIOR",
        evidence: { conditionId: "NO_PRIOR", relationship: "FIRST", comparison },
      };
    case "EQUIVALENT_STATE_DIFFERENT_ENVELOPE":
      return {
        relationship: "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
        stateChanged: false,
        conditionId: "SEMANTIC_FINGERPRINT_EQUAL",
        evidence: {
          conditionId: "SEMANTIC_FINGERPRINT_EQUAL",
          relationship: "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
          comparison,
        },
      };
    case "SUCCESSOR":
      return {
        relationship: "SUCCESSOR",
        stateChanged: true,
        conditionId: "BACKLINK_TO_PRIOR",
        evidence: {
          conditionId: "BACKLINK_TO_PRIOR",
          relationship: "SUCCESSOR",
          comparison,
        },
      };
    case "SIGNATURE_COLLISION":
      return {
        relationship: "SIGNATURE_COLLISION",
        stateChanged: true,
        conditionId: "SAME_S_FINGERPRINT_DIFFERS",
        evidence: {
          conditionId: "SAME_S_FINGERPRINT_DIFFERS",
          relationship: "SIGNATURE_COLLISION",
          comparison,
        },
      };
    case "GENESIS_AFTER_HISTORY":
      return {
        relationship: "GENESIS_AFTER_HISTORY",
        stateChanged: true,
        conditionId: "GENESIS_AFTER_HISTORY",
        evidence: {
          conditionId: "GENESIS_AFTER_HISTORY",
          relationship: "GENESIS_AFTER_HISTORY",
          comparison,
          priorHistoryHasNonGenesis: true,
        },
      };
    case "REGRESSION": {
      const matchedHistoryIndex = acceptedStateSignatureHistory.indexOf(next.sSignature);
      const matchedHistoricalS =
        matchedHistoryIndex >= 0
          ? acceptedStateSignatureHistory[matchedHistoryIndex]!
          : next.sSignature;
      return {
        relationship: "REGRESSION",
        stateChanged: true,
        conditionId: "RECURRENCE_OF_OLDER_S",
        evidence: {
          conditionId: "RECURRENCE_OF_OLDER_S",
          relationship: "REGRESSION",
          comparison,
          matchedHistoricalS,
          matchedHistoryIndex,
        },
      };
    }
    case "UNEXPLAINED_JUMP":
      return {
        relationship: "UNEXPLAINED_JUMP",
        stateChanged: true,
        conditionId: "DIFFERENT_S_NO_BACKLINK",
        evidence: {
          conditionId: "DIFFERENT_S_NO_BACKLINK",
          relationship: "UNEXPLAINED_JUMP",
          comparison,
        },
      };
    default: {
      // Exhaustiveness: frozen classifier cannot emit DUPLICATE / COMPLETE_PATH_SUCCESSOR /
      // NOT_APPLICABLE. Refuse rather than invent a relationship.
      const _exhaustive: never = frozen.relationship;
      throw new Error(`classifier emitted non-capture relationship: ${String(_exhaustive)}`);
    }
  }
}
