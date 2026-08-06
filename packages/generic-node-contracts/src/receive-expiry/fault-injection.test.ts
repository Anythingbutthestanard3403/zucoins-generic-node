import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  RECEIVE_EXPIRY_PHASES,
  receiveExpiryFaultInjectionContract,
} from "./phases.js";
import { isPastDurableCandidateBoundary, boundaryFromExecutionPhaseIsUnsafe } from "./boundary.js";
import { isExpiryToExpiredLegal, receiveExpiryEvents, POST_BOUNDARY_EXPIRY_OUTCOME } from "./lifecycle.js";
import { postBoundaryExpiryDisposition, leaseDropAllowed } from "./ordering.js"; // contract-allow:ordering-module-path

describe("fault injection — boundary classification derives from operation_transactions", () => {
  it.each(RECEIVE_EXPIRY_PHASES)("$phase: isPastDurableCandidateBoundary matches the catalog", (p) => {
    expect(isPastDurableCandidateBoundary(p.maxTxPhase)).toBe(p.pastBoundary);
  });
});

describe("fault injection — expiry outcome per phase (terminal pre-boundary, held post-boundary)", () => {
  it.each(RECEIVE_EXPIRY_PHASES)("$phase -> $expiry", (p) => {
    if (p.expiry === "terminal") {
      expect(isExpiryToExpiredLegal("READY", p.pastBoundary)).toBe(true);
      expect(receiveExpiryEvents(p.pastBoundary).appendsExpired).toBe(true);
    } else {
      expect(isExpiryToExpiredLegal("READY", p.pastBoundary)).toBe(false);
      expect(POST_BOUNDARY_EXPIRY_OUTCOME.state).toBe("READY");
      const events = receiveExpiryEvents(p.pastBoundary);
      expect(events.appendsExpired).toBe(false);
      expect(events.appendsNeedsAttention).toBe(true);
    }
  });
});

describe("fault injection — restart races preserve the boundary (durable operation_transactions)", () => {
  it.each(RECEIVE_EXPIRY_PHASES)("$phase: a restart re-reads the same durable boundary", (p) => {
    // A restart re-reads maxTxPhase from the durable operation_transactions table; the boundary is
    // unchanged, so the expiry outcome is unchanged.
    expect(isPastDurableCandidateBoundary(p.maxTxPhase)).toBe(p.pastBoundary);
  });
  it.each(RECEIVE_EXPIRY_PHASES.filter((p) => p.pastBoundary))(
    "NEGATIVE: a restart at $phase never produces terminal expiry (post-boundary)",
    (p) => {
      const boundaryAfterRestart = isPastDurableCandidateBoundary(p.maxTxPhase);
      expect(isExpiryToExpiredLegal("READY", boundaryAfterRestart)).toBe(false);
      // An execution_phase-keyed restart would wrongly read NOT_STARTED and allow terminal expiry.
      expect(boundaryFromExecutionPhaseIsUnsafe(true, true)).toBe(true);
    },
  );
});

describe("fault injection — .2 sequencing wiring at the landing-race phases", () => {
  it("landed_before_read reconciles to RECEIVE_LANDED once the landing is observed", () => {
    expect(
      postBoundaryExpiryDisposition({
        reconcileCompleted: true,
        landingObserved: true,
        t0Unchanged: false,
        groupAcknowledgementsComplete: false,
        durablyInconclusive: false,
      }),
    ).toEqual({ kind: "resolved", resolution: "RECEIVE_LANDED" });
  });
  it("ambiguous_submit stays held while the reconcile is inconclusive (never terminal)", () => {
    expect(
      postBoundaryExpiryDisposition({
        reconcileCompleted: true,
        landingObserved: false,
        t0Unchanged: false,
        groupAcknowledgementsComplete: false,
        durablyInconclusive: false,
      }).kind,
    ).toBe("held");
  });
  it("MONEY-LOSS regression (/the receive-expiry rule): ambiguous_submit (SUBMITTED) with a head-only reconcile read never releases — a head-unchanged, fully-acked read is NOT no-landing proof while a signed tx is still in flight; the durably-inconclusive read resolves INDETERMINATE and the lease stays held", () => {
    const disposition = postBoundaryExpiryDisposition({
      reconcileCompleted: true,
      landingObserved: false,
      t0Unchanged: true,
      groupAcknowledgementsComplete: true,
      durablyInconclusive: true,
    });
    expect(disposition).toEqual({ kind: "resolved", resolution: "INDETERMINATE" });
    expect(leaseDropAllowed(disposition)).toBe(false);
  });
});

describe("fault injection — MONEY-LOSS regression (/the receive-expiry rule) at every post-boundary phase", () => {
  // The releasing combination the defect used to accept as no-landing proof: a completed reconcile
  // that only confirms the head hasn't moved, with complete group acks. postBoundaryExpiryDisposition
  // takes no phase argument — it is driven purely by these four booleans — so this asserts the
  // invariant holds independent of which post-boundary operation_transactions phase the op is in
  // (candidate_persisted through landed_before_read), not just the SUBMITTED phase the exploit named.
  const releasingCombination = {
    reconcileCompleted: true,
    landingObserved: false,
    t0Unchanged: true,
    groupAcknowledgementsComplete: true,
  };
  it.each(RECEIVE_EXPIRY_PHASES.filter((p) => p.pastBoundary))(
    "$phase: the releasing combination never releases, whether or not the reconcile is (yet) durably inconclusive",
    (p) => {
      const stillReconciling = postBoundaryExpiryDisposition({ ...releasingCombination, durablyInconclusive: false });
      expect(stillReconciling).toEqual({ kind: "held", attentionReason: "POST_EXPIRY_RECONCILING" });
      expect(leaseDropAllowed(stillReconciling)).toBe(false);

      const durablyInconclusive = postBoundaryExpiryDisposition({ ...releasingCombination, durablyInconclusive: true });
      expect(durablyInconclusive).toEqual({ kind: "resolved", resolution: "INDETERMINATE" });
      expect(leaseDropAllowed(durablyInconclusive)).toBe(false);
      // Sanity: this phase's own catalog row still says "held" (non-terminal), consistent with the
      // disposition never being a landing.
      expect(p.expiry).toBe("held");
    },
  );
});

describe("fault injection — phase catalog census + snapshot sync", () => {
  const snapshotPath = fileURLToPath(new URL("../../gen/receive-expiry-phases.json", import.meta.url));
  it("gen/receive-expiry-phases.json equals the as-const contract", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(receiveExpiryFaultInjectionContract);
  });
  it("covers all eight phases with three pre-boundary (terminal) and five post-boundary (held)", () => {
    expect(RECEIVE_EXPIRY_PHASES).toHaveLength(8);
    expect(RECEIVE_EXPIRY_PHASES.filter((p) => !p.pastBoundary)).toHaveLength(3);
    expect(RECEIVE_EXPIRY_PHASES.filter((p) => p.pastBoundary)).toHaveLength(5);
  });
  it("the candidate-persisted phase is exactly the boundary", () => {
    const candidate = RECEIVE_EXPIRY_PHASES.find((p) => p.phase === "candidate_persisted");
    expect(candidate?.pastBoundary).toBe(true);
    expect(candidate?.maxTxPhase).toBe("STEP1_SIGNATURE_PERSISTED");
  });
});
