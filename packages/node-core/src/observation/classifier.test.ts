// relationship classifier unit tests (table + review indicators).
import { describe, expect, it } from "vitest";

import {
  CLASSIFIER_RELATIONSHIPS,
  classifyRelationship,
  establishesOrdinaryHead,
  isAnomalousRelationship,
  verifiedStateFromGenesisProjection,
  verifiedStateFromHeadProjection,
  type RelationshipResult,
  type VerifiedSemanticState,
} from "./classifier.js";
import type { GenesisStateProjection, RoleStateProjection } from "./projection.js";

const head = (
  sSignature: string,
  pSignature: string,
  semanticFingerprint: string,
): VerifiedSemanticState => ({
  isGenesis: false,
  sSignature,
  pSignature,
  semanticFingerprint,
});

const A = head("sigA", "", "fpA");
const B = head("sigB", "sigA", "fpB");
const C = head("sigC", "sigB", "fpC");
/** Same semantic head as A, different envelope fingerprint equal. */
const A_PRIME = head("sigA", "", "fpA");
const GENESIS: VerifiedSemanticState = {
  isGenesis: true,
  sSignature: "",
  pSignature: "",
  semanticFingerprint: "fpGen",
};

function classify(
  prior: VerifiedSemanticState | null,
  next: VerifiedSemanticState,
  history: readonly string[],
  priorHistoryHasNonGenesis = false,
): RelationshipResult {
  return classifyRelationship({
    prior,
    next,
    priorHistoryHasNonGenesis,
    acceptedStateSignatureHistory: history,
  });
}

describe("relationship table (one test per row)", () => {
  it("FIRST when there is no prior accepted state", () => {
    const result = classify(null, A, []);
    expect(result.relationship).toBe("FIRST");
    expect(result.stateChanged).toBe(true);
    expect(result.conditionId).toBe("NO_PRIOR");
    expect(result.evidence.conditionId).toBe("NO_PRIOR");
    expect(result.evidence.comparison.priorS).toBeNull();
    expect(result.evidence.comparison.nextS).toBe("sigA");
    expect(establishesOrdinaryHead(result)).toBe(false);
  });

  it("EQUIVALENT_STATE_DIFFERENT_ENVELOPE when fingerprint equal (state_changed false)", () => {
    const result = classify(A, A_PRIME, ["sigA"]);
    expect(result.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    expect(result.stateChanged).toBe(false);
    expect(result.conditionId).toBe("SEMANTIC_FINGERPRINT_EQUAL");
    expect(result.evidence.comparison.fingerprintsEqual).toBe(true);
    expect(result.evidence.comparison.priorFingerprint).toBe("fpA");
    expect(result.evidence.comparison.nextFingerprint).toBe("fpA");
    expect(establishesOrdinaryHead(result)).toBe(false);
  });

  it("SUCCESSOR when new P backlinks prior S and new S advances", () => {
    const result = classify(A, B, ["sigA"]);
    expect(result.relationship).toBe("SUCCESSOR");
    expect(result.stateChanged).toBe(true);
    expect(result.conditionId).toBe("BACKLINK_TO_PRIOR");
    expect(result.evidence.comparison.nextPEqualsPriorS).toBe(true);
    expect(result.evidence.comparison.nextSEqualsPriorS).toBe(false);
    expect(result.evidence.comparison.priorS).toBe("sigA");
    expect(result.evidence.comparison.nextP).toBe("sigA");
    expect(result.evidence.comparison.nextS).toBe("sigB");
    expect(establishesOrdinaryHead(result)).toBe(true);
  });

  it("SIGNATURE_COLLISION when new S equals prior S but fingerprint differs", () => {
    const collided = head("sigA", "sigX", "fpCollision");
    const result = classify(A, collided, ["sigA"]);
    expect(result.relationship).toBe("SIGNATURE_COLLISION");
    expect(result.stateChanged).toBe(true);
    expect(result.conditionId).toBe("SAME_S_FINGERPRINT_DIFFERS");
    expect(result.evidence.comparison.nextSEqualsPriorS).toBe(true);
    expect(result.evidence.comparison.fingerprintsEqual).toBe(false);
    expect(result.evidence.comparison.priorFingerprint).toBe("fpA");
    expect(result.evidence.comparison.nextFingerprint).toBe("fpCollision");
    expect(establishesOrdinaryHead(result)).toBe(false);
    expect(isAnomalousRelationship(result.relationship)).toBe(true);
  });

  it("GENESIS_AFTER_HISTORY when a genesis follows non-genesis history", () => {
    const result = classify(C, GENESIS, ["sigA", "sigB", "sigC"], true);
    expect(result.relationship).toBe("GENESIS_AFTER_HISTORY");
    expect(result.stateChanged).toBe(true);
    expect(result.conditionId).toBe("GENESIS_AFTER_HISTORY");
    if (result.evidence.conditionId !== "GENESIS_AFTER_HISTORY") {
      throw new Error("expected GENESIS_AFTER_HISTORY evidence");
    }
    expect(result.evidence.priorHistoryHasNonGenesis).toBe(true);
    expect(result.evidence.comparison.nextS).toBe("");
    expect(establishesOrdinaryHead(result)).toBe(false);
  });

  it("REGRESSION when new S equals an older accepted S below current (A,B,C,A)", () => {
    const result = classify(C, A, ["sigA", "sigB", "sigC"]);
    expect(result.relationship).toBe("REGRESSION");
    expect(result.stateChanged).toBe(true);
    expect(result.conditionId).toBe("RECURRENCE_OF_OLDER_S");
    if (result.evidence.conditionId !== "RECURRENCE_OF_OLDER_S") {
      throw new Error("expected RECURRENCE_OF_OLDER_S evidence");
    }
    expect(result.evidence.matchedHistoricalS).toBe("sigA");
    expect(result.evidence.matchedHistoryIndex).toBe(0);
    expect(result.evidence.comparison.nextS).toBe("sigA");
    expect(result.evidence.comparison.priorS).toBe("sigC");
    expect(establishesOrdinaryHead(result)).toBe(false);
  });

  it("UNEXPLAINED_JUMP when state differs and no backlink or history explains it", () => {
    const jump = head("sigD", "sigUnknown", "fpD");
    const result = classify(C, jump, ["sigA", "sigB", "sigC"]);
    expect(result.relationship).toBe("UNEXPLAINED_JUMP");
    expect(result.stateChanged).toBe(true);
    expect(result.conditionId).toBe("DIFFERENT_S_NO_BACKLINK");
    expect(result.evidence.comparison.nextPEqualsPriorS).toBe(false);
    expect(result.evidence.comparison.nextS).toBe("sigD");
    expect(result.evidence.comparison.nextP).toBe("sigUnknown");
    expect(establishesOrdinaryHead(result)).toBe(false);
  });
});

describe("review indicators — distinction and head promotion", () => {
  it("distinguishes SIGNATURE_COLLISION from EQUIVALENT_STATE_DIFFERENT_ENVELOPE", () => {
    const equivalent = classify(A, A_PRIME, ["sigA"]);
    const collision = classify(A, head("sigA", "sigX", "fpDiff"), ["sigA"]);
    expect(equivalent.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    expect(equivalent.stateChanged).toBe(false);
    expect(collision.relationship).toBe("SIGNATURE_COLLISION");
    expect(collision.stateChanged).toBe(true);
    expect(equivalent.relationship).not.toBe(collision.relationship);
  });

  it("catches regression 2+ positions back against full historical set, not only prior", () => {
    // History A,B,C,D — next is B (two steps below current D), not the immediate prior.
    const D = head("sigD", "sigC", "fpD");
    const result = classify(D, B, ["sigA", "sigB", "sigC", "sigD"]);
    expect(result.relationship).toBe("REGRESSION");
    if (result.evidence.conditionId !== "RECURRENCE_OF_OLDER_S") {
      throw new Error("expected RECURRENCE_OF_OLDER_S evidence");
    }
    expect(result.evidence.matchedHistoricalS).toBe("sigB");
    expect(result.evidence.matchedHistoryIndex).toBe(1);
  });

  it("only SUCCESSOR sets establishesOrdinaryHead; anomalies and FIRST never do", () => {
    const cases: RelationshipResult[] = [
      classify(null, A, []),
      classify(A, A_PRIME, ["sigA"]),
      classify(A, B, ["sigA"]),
      classify(A, head("sigA", "sigX", "fpDiff"), ["sigA"]),
      classify(C, GENESIS, ["sigA", "sigB", "sigC"], true),
      classify(C, A, ["sigA", "sigB", "sigC"]),
      classify(C, head("sigD", "sigUnknown", "fpD"), ["sigA", "sigB", "sigC"]),
    ];
    for (const result of cases) {
      if (result.relationship === "SUCCESSOR") {
        expect(establishesOrdinaryHead(result)).toBe(true);
      } else {
        expect(establishesOrdinaryHead(result)).toBe(false);
      }
    }
  });

  it("never emits DUPLICATE (or any non-classifier relationship)", () => {
    const cases: RelationshipResult[] = [
      classify(null, A, []),
      classify(A, A_PRIME, ["sigA"]),
      classify(A, B, ["sigA"]),
      classify(A, head("sigA", "sigX", "fpDiff"), ["sigA"]),
      classify(C, GENESIS, ["sigA", "sigB", "sigC"], true),
      classify(C, A, ["sigA", "sigB", "sigC"]),
      classify(C, head("sigD", "sigUnknown", "fpD"), ["sigA", "sigB", "sigC"]),
    ];
    const forbidden = new Set(["DUPLICATE", "COMPLETE_PATH_SUCCESSOR", "NOT_APPLICABLE"]);
    for (const result of cases) {
      expect(forbidden.has(result.relationship)).toBe(false);
      expect(CLASSIFIER_RELATIONSHIPS).toContain(result.relationship);
    }
  });

  it("A,B,C,A walk ends in REGRESSION on the recurring A", () => {
    expect(classify(null, A, []).relationship).toBe("FIRST");
    expect(classify(A, B, ["sigA"]).relationship).toBe("SUCCESSOR");
    expect(classify(B, C, ["sigA", "sigB"]).relationship).toBe("SUCCESSOR");
    expect(classify(C, A, ["sigA", "sigB", "sigC"]).relationship).toBe("REGRESSION");
  });
});

describe("projection adapters", () => {
  it("verifiedStateFromHeadProjection maps S/P and fingerprint", () => {
    const projection: RoleStateProjection = {
      role: "receiver",
      S: "sigHead",
      P: "sigPrior",
      B: "1.0",
      I: "a".repeat(64),
      step_1_signature: "s1",
      step_2_signature: "s2",
      inner_preimage_text: "{}",
    };
    const state = verifiedStateFromHeadProjection(projection, "fpHead");
    expect(state).toEqual({
      isGenesis: false,
      sSignature: "sigHead",
      pSignature: "sigPrior",
      semanticFingerprint: "fpHead",
    });
  });

  it("verifiedStateFromGenesisProjection is always empty S/P genesis", () => {
    const genesis: GenesisStateProjection = {
      role: "genesis",
      S: "",
      P: "",
      B: "0",
      I: null,
      step_1_signature: null,
      step_2_signature: null,
      inner_preimage_text: null,
    };
    const state = verifiedStateFromGenesisProjection(genesis, "fpGen");
    expect(state.isGenesis).toBe(true);
    expect(state.sSignature).toBe("");
    expect(state.pSignature).toBe("");
  });
});
