// Pure unit coverage for the evidence read/classify surface. The real-Postgres
// crash-restart proof lives in test/submit-decision-claim-store.pg.test.ts; this file
// pins the closed-vocabulary mapping without a database so the classifier cannot drift
// without a non-PG failure.
import { describe, expect, it } from "vitest";

import {
  classifySubmitAttemptEvidence,
  type SubmitAttemptEvidence,
} from "./submit-decision-claim-store.js";
import { toAttentionReason } from "../protocol/reconcile/types.js";

describe("classifySubmitAttemptEvidence", () => {
  it("maps CLAIMED_UNRETURNED to SUBMIT_OUTCOME_AMBIGUOUS attention", () => {
    const evidence: SubmitAttemptEvidence = {
      status: "CLAIMED_UNRETURNED",
      transportOutcome: null,
    };
    const reason = classifySubmitAttemptEvidence(evidence);
    expect(reason).toEqual({ source: "SUBMIT_OUTCOME_UNKNOWN" });
    expect(toAttentionReason(reason!)).toBe("SUBMIT_OUTCOME_AMBIGUOUS");
  });

  it("maps RETURNED INDETERMINATE to SUBMIT_OUTCOME_AMBIGUOUS attention", () => {
    const evidence: SubmitAttemptEvidence = {
      status: "RETURNED",
      transportOutcome: "INDETERMINATE",
    };
    const reason = classifySubmitAttemptEvidence(evidence);
    expect(reason).toEqual({ source: "SUBMIT_OUTCOME_UNKNOWN" });
    expect(toAttentionReason(reason!)).toBe("SUBMIT_OUTCOME_AMBIGUOUS");
  });

  it("does not treat NOT_CLAIMED or definite ACK/REJECT as ambiguity", () => {
    expect(
      classifySubmitAttemptEvidence({ status: "NOT_CLAIMED", transportOutcome: null }),
    ).toBeNull();
    expect(
      classifySubmitAttemptEvidence({ status: "RETURNED", transportOutcome: "ACK" }),
    ).toBeNull();
    expect(
      classifySubmitAttemptEvidence({ status: "RETURNED", transportOutcome: "REJECT" }),
    ).toBeNull();
  });

  it("return type cannot be used as insert authority (structural: null | indeterminate reason only)", () => {
    // Compile-time contract documented by runtime shape: every non-null result is a
    // ReconcileIndeterminateReason with source SUBMIT_OUTCOME_UNKNOWN — never a decision
    // id, never a "retry" flag, never a submit authorization token.
    for (const evidence of [
      { status: "CLAIMED_UNRETURNED" as const, transportOutcome: null },
      { status: "RETURNED" as const, transportOutcome: "INDETERMINATE" as const },
    ]) {
      const reason = classifySubmitAttemptEvidence(evidence);
      expect(reason).not.toBeNull();
      expect(Object.keys(reason!).sort()).toEqual(["source"]);
      expect(reason!.source).toBe("SUBMIT_OUTCOME_UNKNOWN");
    }
  });
});
