import { describe, it, expect } from "vitest";
import {
  isPastDurableCandidateBoundary,
  boundaryFromExecutionPhaseIsUnsafe,
  DURABLE_CANDIDATE_BOUNDARY_SOURCE,
  DURABLE_CANDIDATE_BOUNDARY_MIN_PHASE,
  BOUNDARY_MUST_NOT_KEY_ON,
} from "./boundary.js";

describe("isPastDurableCandidateBoundary — EXISTS(operation_transactions) at/after STEP1", () => {
  it("is false with no operation_transactions row (pre-boundary)", () => {
    expect(isPastDurableCandidateBoundary(null)).toBe(false);
  });
  it("is false at INNER_PREIMAGE_PERSISTED — a row exists but no payer step-1 signature is durable", () => {
    // Schema invariant: `(attempt_phase = 'INNER_PREIMAGE_PERSISTED') = (step_1_signature IS NULL)`.
    expect(isPastDurableCandidateBoundary("INNER_PREIMAGE_PERSISTED")).toBe(false);
  });
  it("is true once a row is persisted at or beyond STEP1_SIGNATURE_PERSISTED", () => {
    expect(isPastDurableCandidateBoundary("STEP1_SIGNATURE_PERSISTED")).toBe(true);
    expect(isPastDurableCandidateBoundary("STEP2_PREIMAGE_PERSISTED")).toBe(true);
    expect(isPastDurableCandidateBoundary("STEP2_SIGNATURE_PERSISTED")).toBe(true);
    expect(isPastDurableCandidateBoundary("SETTLED_BODY_PERSISTED")).toBe(true);
  });
});

describe("boundary source — operation_transactions, never execution_phase", () => {
  it("freezes the source and the forbidden field", () => {
    expect(DURABLE_CANDIDATE_BOUNDARY_SOURCE).toBe("operation_transactions");
    expect(DURABLE_CANDIDATE_BOUNDARY_MIN_PHASE).toBe("STEP1_SIGNATURE_PERSISTED");
    expect(BOUNDARY_MUST_NOT_KEY_ON).toBe("execution_phase");
  });
  it("NEGATIVE: an execution_phase-keyed boundary is unsafe — it reads NOT_STARTED at the boundary", () => {
    // At the boundary, execution_phase still reads NOT_STARTED while an operation_transactions row
    // is already persisted: an execution_phase-keyed boundary would wrongly say "not past".
    expect(boundaryFromExecutionPhaseIsUnsafe(true, true)).toBe(true);
    expect(isPastDurableCandidateBoundary("STEP1_SIGNATURE_PERSISTED")).toBe(true);
  });
});
