import { PROOF_POLICIES } from "./policies.js";
import type {
  EvidenceKind,
  OperationType,
  PredicateId,
  ProofEvaluationInput,
  ProofVerdict,
} from "./types.js";

export function evaluateProof(input: ProofEvaluationInput): ProofVerdict {
  const policy = PROOF_POLICIES[input.operationType];

  const missingEvidence = policy.requiredEvidence
    .filter((req) => req.mandatory && !input.evidencePresent.includes(req.kind))
    .map((req) => req.kind);

  if (missingEvidence.length > 0) {
    return {
      outcome: "INDETERMINATE",
      operationType: input.operationType,
      failedPredicates: [],
      missingEvidence,
    };
  }

  const requiredPredicates = new Set<PredicateId>(
    policy.verificationSteps.map((step) => step.predicate),
  );

  const resultMap = new Map<PredicateId, { passed: boolean; determinate: boolean }>();
  for (const result of input.predicateResults) {
    if (requiredPredicates.has(result.predicate)) {
      resultMap.set(result.predicate, { passed: result.passed, determinate: result.determinate });
    }
  }

  const failedPredicates: PredicateId[] = [];
  let hasIndeterminate = false;

  for (const step of policy.verificationSteps) {
    const result = resultMap.get(step.predicate);
    if (result === undefined) {
      hasIndeterminate = true;
      continue;
    }
    if (!result.passed) {
      if (result.determinate) {
        failedPredicates.push(step.predicate);
      } else {
        hasIndeterminate = true;
      }
    }
  }

  if (failedPredicates.length > 0) {
    return {
      outcome: "REJECTED",
      operationType: input.operationType,
      failedPredicates,
      missingEvidence: [],
    };
  }

  if (hasIndeterminate) {
    return {
      outcome: "INDETERMINATE",
      operationType: input.operationType,
      failedPredicates: [],
      missingEvidence: [],
    };
  }

  return {
    outcome: "VERIFIED",
    operationType: input.operationType,
    failedPredicates: [],
    missingEvidence: [],
  };
}

export function getPolicy(operationType: OperationType) {
  return PROOF_POLICIES[operationType];
}

export function getRequiredEvidenceKinds(operationType: OperationType): readonly EvidenceKind[] {
  return PROOF_POLICIES[operationType].requiredEvidence
    .filter((e) => e.mandatory)
    .map((e) => e.kind);
}
