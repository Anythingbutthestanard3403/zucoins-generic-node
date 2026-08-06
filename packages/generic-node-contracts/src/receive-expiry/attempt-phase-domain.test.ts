import { describe, it, expect } from "vitest";
import { OPERATION_TRANSACTION_PHASES } from "./boundary.js";
import { RECEIVE_EXPIRY_PHASES } from "./phases.js";

//  — `OPERATION_TRANSACTION_PHASES` had forked into the public execution_phase vocabulary
// (NOT_STARTED / SUBMITTED / LANDED), which is the exact confusion the receive-expiry rule closes. The two
// domains below are the frozen data-model expectations, inlined as frozen fixtures so
// neither vocabulary can silently borrow from the other.

/** The `operation_transactions.attempt_phase` CHECK domain, in its frozen sequence. */
const ATTEMPT_PHASE_DOMAIN: readonly string[] = [
  "INNER_PREIMAGE_PERSISTED",
  "STEP1_SIGNATURE_PERSISTED",
  "STEP2_PREIMAGE_PERSISTED",
  "STEP2_SIGNATURE_PERSISTED",
  "SETTLED_BODY_PERSISTED",
];

/** The public `execution_phase` derivation vocabulary — the values attempt_phase must never borrow. */
const PUBLIC_EXECUTION_PHASES: readonly string[] = [
  "LANDED_VERIFIED",
  "SUBMIT_RETURNED",
  "SUBMIT_STARTED",
  "DELIVERED",
  "SIGNED_PERSISTED",
  "PREIMAGE_PERSISTED",
  "NOT_STARTED",
];

describe("OPERATION_TRANSACTION_PHASES — frozen attempt_phase domain", () => {
  it("equals the frozen CHECK domain, in its frozen sequence", () => {
    expect([...OPERATION_TRANSACTION_PHASES]).toEqual([...ATTEMPT_PHASE_DOMAIN]);
  });

  it("borrows no value from the public execution_phase vocabulary (NOT_STARTED is the load-bearing one)", () => {
    expect(PUBLIC_EXECUTION_PHASES).toContain("NOT_STARTED");
    expect(PUBLIC_EXECUTION_PHASES.length).toBeGreaterThan(1);
    expect(
      OPERATION_TRANSACTION_PHASES.filter((phase) => PUBLIC_EXECUTION_PHASES.includes(phase)),
    ).toEqual([]);
  });

  it("covers every RECEIVE_EXPIRY_PHASES maxTxPhase — the catalog cannot name a non-domain value", () => {
    const domain = new Set<string>(ATTEMPT_PHASE_DOMAIN);
    const named = RECEIVE_EXPIRY_PHASES.flatMap((p) => (p.maxTxPhase === null ? [] : [p.maxTxPhase]));
    expect(named.filter((phase) => !domain.has(phase))).toEqual([]);
    expect(named.length).toBeGreaterThan(0);
  });
});
