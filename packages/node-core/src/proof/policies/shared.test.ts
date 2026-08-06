// shared finalizeOperationProof parity across three kinds.
// Kind set is iterated from PROOF_POLICIES keys (unquoted) so anti-self-reference
// does not see a co-located three-literal quoted Redeclaration in this consumer file.
import { describe, expect, it } from "vitest";

import { PROOF_POLICIES } from "../policies.js";
import type { EvidenceKind, OperationType, PredicateId } from "../types.js";
import {
  finalizeOperationProof,
  held,
  mismatch,
  undecided,
  type EvaluatedPredicate,
} from "./shared.js";

const OPERATION_CASES: readonly {
  readonly operationType: OperationType;
  readonly steps: readonly PredicateId[];
}[] = (Object.keys(PROOF_POLICIES) as OperationType[]).map((operationType) => ({
  operationType,
  steps: PROOF_POLICIES[operationType].verificationSteps.map((step) => step.predicate),
}));

function shuffledHeld(steps: readonly PredicateId[]): EvaluatedPredicate[] {
  return [...steps].reverse().map((predicate) => held(predicate, "held"));
}

function mandatoryEvidence(operationType: OperationType): EvidenceKind[] {
  return PROOF_POLICIES[operationType].requiredEvidence
    .filter((req) => req.mandatory)
    .map((req) => req.kind);
}

describe("finalizeOperationProof — parity across policy kinds", () => {
  it.each(OPERATION_CASES)(
    "$operationType sequences predicates to frozen verificationSteps and VERIFIES all-held",
    ({ operationType, steps }) => {
      const result = finalizeOperationProof(
        operationType,
        steps,
        shuffledHeld(steps),
        mandatoryEvidence(operationType),
      );
      expect(result.predicates.map((p) => p.predicate)).toEqual(steps);
      expect(result.predicates.every((p) => p.passed && p.determinate)).toBe(true);
      expect(result.verdict.outcome).toBe("VERIFIED");
      expect(result.verdict.operationType).toBe(operationType);
      expect(result.verdict.failedPredicates).toEqual([]);
      expect(result.verdict.missingEvidence).toEqual([]);
    },
  );

  it.each(OPERATION_CASES)(
    "$operationType REJECTS on a determinate mismatch while retaining sequenced evidence",
    ({ operationType, steps }) => {
      const failing = steps[0]!;
      const evaluated: EvaluatedPredicate[] = steps.map((predicate) =>
        predicate === failing
          ? mismatch(predicate, "determinate fault")
          : held(predicate, "held"),
      );
      const result = finalizeOperationProof(
        operationType,
        steps,
        evaluated,
        mandatoryEvidence(operationType),
      );
      expect(result.predicates.map((p) => p.predicate)).toEqual(steps);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual([failing]);
      expect(result.predicates.find((p) => p.predicate === failing)?.detail).toBe(
        "determinate fault",
      );
    },
  );

  it.each(OPERATION_CASES)(
    "$operationType is INDETERMINATE on undecided predicate (never REJECTED)",
    ({ operationType, steps }) => {
      const soft = steps[Math.min(1, steps.length - 1)]!;
      const evaluated: EvaluatedPredicate[] = steps.map((predicate) =>
        predicate === soft ? undecided(predicate, "gap") : held(predicate, "held"),
      );
      const result = finalizeOperationProof(
        operationType,
        steps,
        evaluated,
        mandatoryEvidence(operationType),
      );
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.failedPredicates).toEqual([]);
      expect(result.predicates.map((p) => p.predicate)).toEqual(steps);
    },
  );

  it.each(OPERATION_CASES)(
    "$operationType is INDETERMINATE when mandatory evidence is absent",
    ({ operationType, steps }) => {
      const result = finalizeOperationProof(operationType, steps, shuffledHeld(steps), []);
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.missingEvidence.length).toBeGreaterThan(0);
      expect(result.predicates.map((p) => p.predicate)).toEqual(steps);
    },
  );
});
