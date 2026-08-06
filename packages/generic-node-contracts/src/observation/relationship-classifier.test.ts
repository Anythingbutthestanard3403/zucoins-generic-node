import { describe, expect, it } from "vitest";

import { CLASSIFIER_OUTPUT_RELATIONSHIPS } from "./relationship.contract.ts";
import {
  classifyRelationship,
  type AcceptedSemanticState,
} from "./relationship-classifier.ts";

const head = (
  sSignature: string,
  pSignature: string,
  semanticFingerprint: string,
): AcceptedSemanticState => ({ isGenesis: false, sSignature, pSignature, semanticFingerprint });

const A = head("sigA", "", "fpA");
const B = head("sigB", "sigA", "fpB");
const C = head("sigC", "sigB", "fpC");
const A_PRIME = head("sigA", "", "fpA"); // same head, byte-different envelope -> equal fingerprint
const GENESIS = { isGenesis: true, sSignature: "", pSignature: "", semanticFingerprint: "fpGen" };

describe("classifyRelationship decision procedure (the observation concern.2)", () => {
  it("FIRST when there is no prior accepted state", () => {
    const result = classifyRelationship({
      prior: null,
      next: A,
      priorHistoryHasNonGenesis: false,
      acceptedStateSignatureHistory: [],
    });
    expect(result.relationship).toBe("FIRST");
    expect(result.stateChanged).toBe(true);
  });

  it("EQUIVALENT_STATE_DIFFERENT_ENVELOPE when the semantic fingerprint is equal (state_changed false)", () => {
    const result = classifyRelationship({
      prior: A,
      next: A_PRIME,
      priorHistoryHasNonGenesis: false,
      acceptedStateSignatureHistory: ["sigA"],
    });
    expect(result.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    expect(result.stateChanged).toBe(false);
  });

  it("SUCCESSOR when new P backlinks prior S and new S advances", () => {
    const result = classifyRelationship({
      prior: A,
      next: B,
      priorHistoryHasNonGenesis: false,
      acceptedStateSignatureHistory: ["sigA"],
    });
    expect(result.relationship).toBe("SUCCESSOR");
    expect(result.stateChanged).toBe(true);
  });

  it("SIGNATURE_COLLISION when new S equals prior S but the fingerprint differs", () => {
    const result = classifyRelationship({
      prior: A,
      next: head("sigA", "sigX", "fpCollision"),
      priorHistoryHasNonGenesis: false,
      acceptedStateSignatureHistory: ["sigA"],
    });
    expect(result.relationship).toBe("SIGNATURE_COLLISION");
    expect(result.stateChanged).toBe(true);
  });

  it("GENESIS_AFTER_HISTORY when a genesis follows non-genesis history", () => {
    const result = classifyRelationship({
      prior: C,
      next: GENESIS,
      priorHistoryHasNonGenesis: true,
      acceptedStateSignatureHistory: ["sigA", "sigB", "sigC"],
    });
    expect(result.relationship).toBe("GENESIS_AFTER_HISTORY");
    expect(result.stateChanged).toBe(true);
  });

  it("REGRESSION when new S recurs an accepted S below current", () => {
    const result = classifyRelationship({
      prior: C,
      next: A,
      priorHistoryHasNonGenesis: false,
      acceptedStateSignatureHistory: ["sigA", "sigB", "sigC"],
    });
    expect(result.relationship).toBe("REGRESSION");
    expect(result.stateChanged).toBe(true);
  });

  it("UNEXPLAINED_JUMP when the state differs and no backlink or history explains it", () => {
    const result = classifyRelationship({
      prior: C,
      next: head("sigD", "sigUnknown", "fpD"),
      priorHistoryHasNonGenesis: false,
      acceptedStateSignatureHistory: ["sigA", "sigB", "sigC"],
    });
    expect(result.relationship).toBe("UNEXPLAINED_JUMP");
    expect(result.stateChanged).toBe(true);
  });
});

describe("A,B,C,A classifier walk (the observation concern.2; final A is a REGRESSION, not a dedup)", () => {
  it("classifies each transition, ending in REGRESSION on the recurring A", () => {
    expect(
      classifyRelationship({
        prior: null,
        next: A,
        priorHistoryHasNonGenesis: false,
        acceptedStateSignatureHistory: [],
      }).relationship,
    ).toBe("FIRST");
    expect(
      classifyRelationship({
        prior: A,
        next: B,
        priorHistoryHasNonGenesis: false,
        acceptedStateSignatureHistory: ["sigA"],
      }).relationship,
    ).toBe("SUCCESSOR");
    expect(
      classifyRelationship({
        prior: B,
        next: C,
        priorHistoryHasNonGenesis: false,
        acceptedStateSignatureHistory: ["sigA", "sigB"],
      }).relationship,
    ).toBe("SUCCESSOR");
    expect(
      classifyRelationship({
        prior: C,
        next: A,
        priorHistoryHasNonGenesis: false,
        acceptedStateSignatureHistory: ["sigA", "sigB", "sigC"],
      }).relationship,
    ).toBe("REGRESSION");
  });
});

describe("envelope change is never confused with a state transition (the observation concern.2 negative path)", () => {
  it("a differing fingerprint is never EQUIVALENT_STATE_DIFFERENT_ENVELOPE", () => {
    const stateChangeInputs = [
      { prior: A, next: B, hist: ["sigA"] },
      { prior: A, next: head("sigA", "sigX", "fpDiff"), hist: ["sigA"] },
      { prior: C, next: A, hist: ["sigA", "sigB", "sigC"] },
      { prior: C, next: head("sigD", "sigUnknown", "fpD"), hist: ["sigA", "sigB", "sigC"] },
    ];
    for (const testCase of stateChangeInputs) {
      const result = classifyRelationship({
        prior: testCase.prior,
        next: testCase.next,
        priorHistoryHasNonGenesis: false,
        acceptedStateSignatureHistory: testCase.hist,
      });
      expect(result.relationship).not.toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
      expect(result.stateChanged).toBe(true);
    }
  });

  it("only a fingerprint-equal row is state_changed=false", () => {
    const equivalent = classifyRelationship({
      prior: A,
      next: A_PRIME,
      priorHistoryHasNonGenesis: false,
      acceptedStateSignatureHistory: ["sigA"],
    });
    expect(equivalent.stateChanged).toBe(false);
  });

  it("every emitted relationship is a declared classifier output", () => {
    const inputs = [
      { prior: null as AcceptedSemanticState | null, next: A },
      { prior: A, next: A_PRIME },
      { prior: A, next: B },
      { prior: A, next: head("sigA", "sigX", "fpDiff") },
      { prior: C, next: GENESIS },
      { prior: C, next: A },
      { prior: C, next: head("sigD", "sigUnknown", "fpD") },
    ];
    for (const input of inputs) {
      const result = classifyRelationship({
        prior: input.prior,
        next: input.next,
        priorHistoryHasNonGenesis: true,
        acceptedStateSignatureHistory: ["sigA", "sigB", "sigC"],
      });
      expect(CLASSIFIER_OUTPUT_RELATIONSHIPS).toContain(result.relationship);
    }
  });
});
