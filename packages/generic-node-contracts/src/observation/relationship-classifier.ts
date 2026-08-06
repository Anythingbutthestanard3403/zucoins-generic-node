import { type ClassifierOutputRelationship } from "./relationship.contract.ts";

/**
 * A verified accepted semantic state, reduced to the values the classification table classifies on. `sSignature` is
 * "" at genesis; `semanticFingerprint` is the semantic fingerprint that makes two byte-different
 * envelopes comparable. This slice never sees raw bytes — the byte comparison is the observation dedup freeze's.
 */
export interface AcceptedSemanticState {
  readonly isGenesis: boolean;
  readonly sSignature: string;
  readonly pSignature: string;
  readonly semanticFingerprint: string;
}

export interface RelationshipClassificationInput {
  readonly prior: AcceptedSemanticState | null;
  readonly next: AcceptedSemanticState;
  readonly priorHistoryHasNonGenesis: boolean;
  readonly acceptedStateSignatureHistory: readonly string[];
}

export interface RelationshipClassification {
  readonly relationship: ClassifierOutputRelationship;
  readonly stateChanged: boolean;
  readonly conditionId: string;
}

/**
 * Classify an appended verified row against the immediately prior accepted state and the
 * permanent prior-state index, evaluating the classification conditions in their frozen sequence
 * (first match wins). Pure and total. It is called only when the observation dedup freeze's primitive has already
 * decided to APPEND (raw bytes differ), so the fingerprint-equal case is an equivalent
 * envelope, never a byte-identical duplicate.
 */
export const classifyRelationship = (
  input: RelationshipClassificationInput,
): RelationshipClassification => {
  const { prior, next, priorHistoryHasNonGenesis, acceptedStateSignatureHistory } = input;

  if (prior === null) {
    return { relationship: "FIRST", stateChanged: true, conditionId: "NO_PRIOR" };
  }
  if (next.semanticFingerprint === prior.semanticFingerprint) {
    return {
      relationship: "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
      stateChanged: false,
      conditionId: "SEMANTIC_FINGERPRINT_EQUAL",
    };
  }
  if (next.pSignature === prior.sSignature && next.sSignature !== prior.sSignature) {
    return { relationship: "SUCCESSOR", stateChanged: true, conditionId: "BACKLINK_TO_PRIOR" };
  }
  if (next.sSignature === prior.sSignature) {
    return {
      relationship: "SIGNATURE_COLLISION",
      stateChanged: true,
      conditionId: "SAME_S_FINGERPRINT_DIFFERS",
    };
  }
  if (next.isGenesis && priorHistoryHasNonGenesis) {
    return {
      relationship: "GENESIS_AFTER_HISTORY",
      stateChanged: true,
      conditionId: "GENESIS_AFTER_HISTORY",
    };
  }
  if (acceptedStateSignatureHistory.includes(next.sSignature)) {
    return {
      relationship: "REGRESSION",
      stateChanged: true,
      conditionId: "RECURRENCE_OF_OLDER_S",
    };
  }
  return {
    relationship: "UNEXPLAINED_JUMP",
    stateChanged: true,
    conditionId: "DIFFERENT_S_NO_BACKLINK",
  };
};
