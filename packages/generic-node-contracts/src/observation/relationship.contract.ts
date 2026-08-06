/**
 * SOURCE: the observation-verification contract (relationship classification and semantic
 * fingerprint), the data-model observation tables, the integration observation feed, and
 * the canonical observation-dedup decision.
 *
 * the observation concern.2 freezes the SEMANTIC relationship classification that runs on an appended verified
 * row, ON TOP of the observation dedup freeze atomic byte primitive. the observation dedup freeze owns the exact-raw-byte
 * suppress/append decision; this slice owns the fingerprint-driven separation of an
 * equivalent-envelope change from a real state transition and the decision procedure over the
 * relationship vocabulary. The relationship enum itself is frozen by the observation dedup freeze
 * (enums.contract.ts); this slice consumes it and must never re-shape it.
 */

import { type ObservationRelationship } from "./enums.contract.ts";

/**
 * The full comparison ladder. Tier 1 is the observation dedup freeze's byte primitive (suppress vs append); tiers
 * 2-3 are this slice's semantic layer over an appended verified row.
 */
export const COMPARISON_LADDER = [
  "raw byte length, digest, then exact bytes decide suppress vs append (the byte-dedup primitive)",
  "among appended verified rows, an equal semantic fingerprint is EQUIVALENT_STATE_DIFFERENT_ENVELOPE (envelope change, not state change)",
  "a differing semantic fingerprint is a state transition classified by backlink and state-signature comparison",
] as const;

export interface RelationshipRule {
  readonly conditionId: string;
  readonly condition: string;
  readonly relationship: ObservationRelationship;
  readonly stateChanged: boolean;
  readonly action: string;
}

/**
 * The classification table, transcribed verbatim. The rule SEQUENCE is the frozen evaluation precedence
 * (first match wins); relationship-classifier.ts evaluates in exactly this sequence.
 */
export const RELATIONSHIP_CLASSIFICATION_RULES = [
  {
    conditionId: "NO_PRIOR",
    condition: "no prior accepted state",
    relationship: "FIRST",
    stateChanged: true,
    action: "establish cursor; operation policy decides usability",
  },
  {
    conditionId: "SEMANTIC_FINGERPRINT_EQUAL",
    condition: "raw bytes differ, semantic fingerprint equal to prior",
    relationship: "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
    stateChanged: false,
    action: "retain; no chain transition",
  },
  {
    conditionId: "BACKLINK_TO_PRIOR",
    condition: "new P equals prior S and new S differs from prior S",
    relationship: "SUCCESSOR",
    stateChanged: true,
    action: "accepted direct advance",
  },
  {
    conditionId: "SAME_S_FINGERPRINT_DIFFERS",
    condition: "new S equals prior S but semantic fingerprint differs",
    relationship: "SIGNATURE_COLLISION",
    stateChanged: true,
    action: "anomaly; quarantine/fail closed",
  },
  {
    conditionId: "GENESIS_AFTER_HISTORY",
    condition: "new genesis after prior non-genesis history",
    relationship: "GENESIS_AFTER_HISTORY",
    stateChanged: true,
    action: "anomaly; quarantine/fail closed",
  },
  {
    conditionId: "RECURRENCE_OF_OLDER_S",
    condition: "new S equals an accepted S below current",
    relationship: "REGRESSION",
    stateChanged: true,
    action: "anomaly; quarantine/fail closed",
  },
  {
    conditionId: "DIFFERENT_S_NO_BACKLINK",
    condition: "new state differs and new P does not equal prior S",
    relationship: "UNEXPLAINED_JUMP",
    stateChanged: true,
    action: "anomaly; quarantine/fail closed",
  },
] as const satisfies readonly RelationshipRule[];

/** The relationship values the pure classifier can emit at capture, in table sequence. */
export const CLASSIFIER_OUTPUT_RELATIONSHIPS = [
  "FIRST",
  "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
  "SUCCESSOR",
  "SIGNATURE_COLLISION",
  "GENESIS_AFTER_HISTORY",
  "REGRESSION",
  "UNEXPLAINED_JUMP",
] as const satisfies readonly ObservationRelationship[];

export type ClassifierOutputRelationship = (typeof CLASSIFIER_OUTPUT_RELATIONSHIPS)[number];

/**
 * Relationship vocabulary members the classifier NEVER emits at capture, with why. Freezing
 * them keeps a later lane from wiring one into the capture path by mistake.
 */
export const NON_CLASSIFIER_RELATIONSHIPS = {
  DUPLICATE:
    "diagnostic only; a byte-identical verified repeat is suppressed by the byte-dedup primitive and has no row",
  COMPLETE_PATH_SUCCESSOR:
    "derived only by a complete-path adjudication, never at capture",
  NOT_APPLICABLE: "non-verified rows only; set by the record contract, not the classifier",
} as const;

/** The only classifier output whose state_changed is false: an equivalent envelope. */
export const STATE_UNCHANGED_RELATIONSHIP = "EQUIVALENT_STATE_DIFFERENT_ENVELOPE" as const;
