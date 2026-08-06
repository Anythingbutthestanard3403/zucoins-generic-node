import { describe, expect, it } from "vitest";

import { evaluateProof, getPolicy, getRequiredEvidenceKinds } from "./evaluate.js";
import {
  MOVE_INTERNAL_POLICY,
  PROOF_POLICIES,
  RECEIVE_EXTERNAL_POLICY,
  SEND_EXTERNAL_POLICY,
} from "./policies.js";
import type { EvidenceKind, PredicateId, PredicateResult, ProofEvaluationInput } from "./types.js";

function allPass(predicates: readonly PredicateId[]): PredicateResult[] {
  return predicates.map((predicate) => ({ predicate, passed: true, determinate: true }));
}

function policyPredicates(op: ProofEvaluationInput["operationType"]): PredicateId[] {
  return PROOF_POLICIES[op].verificationSteps.map((s) => s.predicate);
}

function policyEvidence(op: ProofEvaluationInput["operationType"]): EvidenceKind[] {
  return PROOF_POLICIES[op].requiredEvidence.filter((e) => e.mandatory).map((e) => e.kind);
}

describe("proof policy definitions", () => {
  it("RECEIVE_EXTERNAL requires gateway_confirmation + observation_match", () => {
    expect(RECEIVE_EXTERNAL_POLICY.requiredEvidence).toEqual([
      { kind: "gateway_confirmation", mandatory: true },
      { kind: "observation_match", mandatory: true },
    ]);
  });

  it("MOVE_INTERNAL requires both wallet path confirmations", () => {
    expect(MOVE_INTERNAL_POLICY.requiredEvidence).toEqual([
      { kind: "source_path_confirmation", mandatory: true },
      { kind: "destination_path_confirmation", mandatory: true },
    ]);
  });

  it("SEND_EXTERNAL requires recipient_confirmation + submit_evidence", () => {
    expect(SEND_EXTERNAL_POLICY.requiredEvidence).toEqual([
      { kind: "recipient_confirmation", mandatory: true },
      { kind: "submit_evidence", mandatory: true },
    ]);
  });

  it("all policies use ALL_PREDICATES pass criteria", () => {
    for (const policy of Object.values(PROOF_POLICIES)) {
      expect(policy.passCriteria).toBe("ALL_PREDICATES");
      expect(policy.failCriteria).toBe("ANY_DETERMINATE_MISMATCH");
      expect(policy.indeterminateCriteria).toBe("READ_FAILURE_OR_ANOMALY");
    }
  });

  it("RECEIVE_EXTERNAL has 10 verification steps per OBS S8", () => {
    expect(RECEIVE_EXTERNAL_POLICY.verificationSteps).toHaveLength(10);
  });

  it("MOVE_INTERNAL has 9 verification steps per OBS S9", () => {
    expect(MOVE_INTERNAL_POLICY.verificationSteps).toHaveLength(9);
  });

  it("SEND_EXTERNAL has 9 verification steps per OBS S10", () => {
    expect(SEND_EXTERNAL_POLICY.verificationSteps).toHaveLength(9);
  });

  it("every verification step references at least one evidence kind", () => {
    for (const policy of Object.values(PROOF_POLICIES)) {
      for (const step of policy.verificationSteps) {
        expect(step.evidenceKinds.length).toBeGreaterThanOrEqual(1);
      }
    }
  });
});

describe("evaluateProof - RECEIVE_EXTERNAL", () => {
  const op = "RECEIVE_EXTERNAL" as const;

  it("returns VERIFIED when all predicates pass and evidence present", () => {
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: allPass(policyPredicates(op)),
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("VERIFIED");
    expect(verdict.failedPredicates).toEqual([]);
    expect(verdict.missingEvidence).toEqual([]);
  });

  it("returns REJECTED on determinate predicate failure", () => {
    const predicates = policyPredicates(op);
    const results: PredicateResult[] = allPass(predicates).map((r) =>
      r.predicate === "amount_exact" ? { ...r, passed: false, determinate: true } : r,
    );
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: results,
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("REJECTED");
    expect(verdict.failedPredicates).toContain("amount_exact");
  });

  it("returns INDETERMINATE on non-determinate failure", () => {
    const predicates = policyPredicates(op);
    const results: PredicateResult[] = allPass(predicates).map((r) =>
      r.predicate === "dual_signatures_verify" ? { ...r, passed: false, determinate: false } : r,
    );
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: results,
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("INDETERMINATE");
    expect(verdict.failedPredicates).toEqual([]);
  });

  it("returns INDETERMINATE when mandatory evidence is missing", () => {
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: allPass(policyPredicates(op)),
      evidencePresent: ["gateway_confirmation"],
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("INDETERMINATE");
    expect(verdict.missingEvidence).toContain("observation_match");
  });

  it("REJECTED takes priority over INDETERMINATE when both exist", () => {
    const predicates = policyPredicates(op);
    const results: PredicateResult[] = allPass(predicates).map((r) => {
      if (r.predicate === "amount_exact") return { ...r, passed: false, determinate: true };
      if (r.predicate === "dual_signatures_verify")
        return { ...r, passed: false, determinate: false };
      return r;
    });
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: results,
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("REJECTED");
    expect(verdict.failedPredicates).toContain("amount_exact");
  });
});

describe("evaluateProof - MOVE_INTERNAL", () => {
  const op = "MOVE_INTERNAL" as const;

  it("returns VERIFIED when both path confirmations pass", () => {
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: allPass(policyPredicates(op)),
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("VERIFIED");
  });

  it("returns INDETERMINATE when destination path evidence missing", () => {
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: allPass(policyPredicates(op)),
      evidencePresent: ["source_path_confirmation"],
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("INDETERMINATE");
    expect(verdict.missingEvidence).toContain("destination_path_confirmation");
  });

  it("returns REJECTED on source_balance_delta determinate failure", () => {
    const predicates = policyPredicates(op);
    const results: PredicateResult[] = allPass(predicates).map((r) =>
      r.predicate === "source_balance_delta" ? { ...r, passed: false, determinate: true } : r,
    );
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: results,
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("REJECTED");
    expect(verdict.failedPredicates).toContain("source_balance_delta");
  });
});

describe("evaluateProof - SEND_EXTERNAL", () => {
  const op = "SEND_EXTERNAL" as const;

  it("returns VERIFIED when recipient confirmation and submit evidence pass", () => {
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: allPass(policyPredicates(op)),
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("VERIFIED");
  });

  it("returns INDETERMINATE when submit_evidence missing", () => {
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: allPass(policyPredicates(op)),
      evidencePresent: ["recipient_confirmation"],
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("INDETERMINATE");
    expect(verdict.missingEvidence).toContain("submit_evidence");
  });

  it("returns REJECTED on preimage_exact_match determinate failure", () => {
    const predicates = policyPredicates(op);
    const results: PredicateResult[] = allPass(predicates).map((r) =>
      r.predicate === "preimage_exact_match" ? { ...r, passed: false, determinate: true } : r,
    );
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: results,
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("REJECTED");
    expect(verdict.failedPredicates).toContain("preimage_exact_match");
  });

  it("returns INDETERMINATE when a predicate result is absent", () => {
    const predicates = policyPredicates(op).filter((p) => p !== "source_exact_head");
    const input: ProofEvaluationInput = {
      operationType: op,
      predicateResults: allPass(predicates),
      evidencePresent: policyEvidence(op),
    };
    const verdict = evaluateProof(input);
    expect(verdict.outcome).toBe("INDETERMINATE");
  });
});

describe("getPolicy / getRequiredEvidenceKinds", () => {
  it("getPolicy returns the correct policy for each operation type", () => {
    expect(getPolicy("RECEIVE_EXTERNAL")).toBe(RECEIVE_EXTERNAL_POLICY);
    expect(getPolicy("MOVE_INTERNAL")).toBe(MOVE_INTERNAL_POLICY);
    expect(getPolicy("SEND_EXTERNAL")).toBe(SEND_EXTERNAL_POLICY);
  });

  it("getRequiredEvidenceKinds returns mandatory evidence kinds", () => {
    expect(getRequiredEvidenceKinds("RECEIVE_EXTERNAL")).toEqual([
      "gateway_confirmation",
      "observation_match",
    ]);
    expect(getRequiredEvidenceKinds("MOVE_INTERNAL")).toEqual([
      "source_path_confirmation",
      "destination_path_confirmation",
    ]);
    expect(getRequiredEvidenceKinds("SEND_EXTERNAL")).toEqual([
      "recipient_confirmation",
      "submit_evidence",
    ]);
  });
});
