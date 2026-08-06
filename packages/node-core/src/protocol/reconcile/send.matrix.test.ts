// SEND_EXTERNAL reconcile decision matrix.
//
// The other safety-critical member: exit criterion is literally "no later
// observation, timeout, expiry, ACK, or operator action... closes/releases a delivered SEND
// partial."

import { describe, expect, it } from "vitest";

import {
  mintLandingPathProofFromOracle,
} from "./landing-oracle-mint.fixture.js";
import { type PathObservation } from "./observation-input.js";
import { classifySendReconcile, type SendReconcileInput, type SendReconcileOutcome } from "./send.js";

const ATTEMPT = "send-attempt-1";
const SOURCE = "wallet-source";
const CODE = "transfer-code-sha256";

const LANDED_OBS: PathObservation = {
  result: "PROOF",
  proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub",
      expectedBodySha256: "body-sha",
      freshHeadBodySha256: "body-sha",
      freshHeadObservationId: "obs",
      depth: 0,
    }),
};
const NO_SUCCESSOR_OBS: PathObservation = { result: "NO_SUCCESSOR" };
const GAP_OBS: PathObservation = { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" };
const BREACH_OBS: PathObservation = { result: "ANOMALY", anomaly: "SIGNATURE_COLLISION" };

function delivered(overrides: Partial<Extract<SendReconcileInput, { boundary: "DELIVERED" }>> = {}): SendReconcileInput {
  return {
    boundary: "DELIVERED",
    sendAttemptId: ATTEMPT,
    sourceWalletId: SOURCE,
    sourceLeaseState: "ACTIVE",
    transferCodeSha256: CODE,
    sourceObservation: NO_SUCCESSOR_OBS,
    ...overrides,
  };
}

describe("SEND_EXTERNAL PRE_DELIVERY matrix", () => {
  it.each([
    [false, false, "PROVEN_NOT_STARTED", "FIRST_FORMATION"],
    [false, true, "INVARIANT_BREACH", undefined],
    [true, false, "PROVEN_NOT_STARTED", "SIGN_PERSISTED_PREIMAGE"],
    [true, true, "INVARIANT_BREACH", undefined],
  ] as const)("signIntentPersisted=%s auditCall=%s -> %s (%s)", (signIntentPersisted, signerAuditIndicatesCall, expectedKind, expectedResume) => {
    const outcome = classifySendReconcile({
      boundary: "PRE_DELIVERY",
      sendOperationId: ATTEMPT,
      signIntentPersisted,
      step1SignaturePersisted: false,
      signerAuditIndicatesCall,
    });
    expect(outcome.kind).toBe(expectedKind);
    if (outcome.kind === "PROVEN_NOT_STARTED") {
      expect(outcome.resumeAction).toBe(expectedResume);
    }
  });

  it("step1SignaturePersisted=true while boundary is still PRE_DELIVERY -> INVARIANT_BREACH (contradicts the atomic sig+AWAITING_REDEMPTION commit)", () => {
    const outcome = classifySendReconcile({
      boundary: "PRE_DELIVERY",
      sendOperationId: ATTEMPT,
      signIntentPersisted: true,
      step1SignaturePersisted: true,
      signerAuditIndicatesCall: false,
    });
    expect(outcome.kind).toBe("INVARIANT_BREACH");
  });

  it("PRE_DELIVERY never returns LANDED_VERIFIED or WAITING", () => {
    const reachableKinds = new Set<SendReconcileOutcome["kind"]>();
    for (const signIntentPersisted of [false, true]) {
      for (const step1SignaturePersisted of [false, true]) {
        for (const signerAuditIndicatesCall of [false, true]) {
          reachableKinds.add(
            classifySendReconcile({
              boundary: "PRE_DELIVERY",
              sendOperationId: ATTEMPT,
              signIntentPersisted,
              step1SignaturePersisted,
              signerAuditIndicatesCall,
            }).kind,
          );
        }
      }
    }
    expect(reachableKinds.has("LANDED_VERIFIED")).toBe(false);
    expect(reachableKinds.has("WAITING")).toBe(false);
  });
});

describe("SEND_EXTERNAL lease axis", () => {
  it("RELEASED source lease during DELIVERED reconcile -> INVARIANT_BREACH", () => {
    const outcome = classifySendReconcile(delivered({ sourceLeaseState: "RELEASED" }));
    expect(outcome.kind).toBe("INVARIANT_BREACH");
  });

  it("ACTIVE source lease with no successor observed -> WAITING", () => {
    const outcome = classifySendReconcile(delivered());
    expect(outcome.kind).toBe("WAITING");
  });
});

describe("SEND_EXTERNAL DELIVERED matrix — WAITING vs INDETERMINATE split", () => {
  it("clean unchanged head (no successor) -> WAITING, with the identical redeliverable code", () => {
    const outcome = classifySendReconcile(delivered());
    expect(outcome.kind).toBe("WAITING");
    if (outcome.kind === "WAITING") {
      expect(outcome.redeliverableTransferCodeSha256).toBe(CODE);
    }
  });

  it("recipient-completed landing proof -> LANDED_VERIFIED", () => {
    const outcome = classifySendReconcile(delivered({ sourceObservation: LANDED_OBS }));
    expect(outcome.kind).toBe("LANDED_VERIFIED");
  });

  it("a genuine gap (missing recipient-completed body) -> INDETERMINATE, never WAITING and never a release", () => {
    // "Missing recipient-completed body... is INDETERMINATE: keep the immutable partial,
    // approval, observations, source lease, and audit trail." This is NOT the same as WAITING's
    // "no contradictory evidence" — a gap is positive evidence something is wrong, even though
    // neither classification authorizes any different action on the lease.
    const outcome = classifySendReconcile(delivered({ sourceObservation: GAP_OBS }));
    expect(outcome.kind).toBe("INDETERMINATE");
  });

  it("an invariant-breach anomaly -> INVARIANT_BREACH, never downgraded to WAITING", () => {
    const outcome = classifySendReconcile(delivered({ sourceObservation: BREACH_OBS }));
    expect(outcome.kind).toBe("INVARIANT_BREACH");
  });
});

describe("SEND_EXTERNAL — never closes or releases a delivered partial (exit criterion)", () => {
  it("no evidence shape reachable from DELIVERED ever yields PROVEN_NOT_STARTED", () => {
    const observations: PathObservation[] = [LANDED_OBS, NO_SUCCESSOR_OBS, GAP_OBS, BREACH_OBS];
    const reachableKinds = new Set<SendReconcileOutcome["kind"]>();
    for (const sourceObservation of observations) {
      for (const sourceLeaseState of ["ACTIVE", "RELEASED"] as const) {
        reachableKinds.add(classifySendReconcile(delivered({ sourceObservation, sourceLeaseState })).kind);
      }
    }
    expect(reachableKinds.has("PROVEN_NOT_STARTED")).toBe(false);
  });

  it("SendReconcileOutcome has no REJECTED/closed/released member at all", () => {
    // FINDING: packages/generic-node-contracts/src/operations/states.contract.ts
    // SEND_EXTERNAL_TRANSITIONS already contains a `{ from: "NEEDS_ATTENTION", to: "REJECTED",
    // guard: "Exact partial is protocol-expired and the positive non-landing oracle proves it
    // did not land and cannot still land." }` row. The state/event reference is explicit that "There is
    // no transition from a delivered AWAITING_REDEMPTION/NEEDS_ATTENTION partial to REJECTED in
    // launch, because landing-path oracle supplies a landing oracle and no generic non-landing/release oracle"
    // and landing-path oracle itself: "There is no generic PROVEN_NOT_LANDED verdict." The merged
    // contract's row cites an oracle the canonical decision says does not exist. This
    // module deliberately does not import operations/states.contract.ts for exactly this
    // reason; the assertion below is the structural half of that avoidance.
    // @ts-expect-error — "REJECTED" is not a member of SendReconcileOutcome["kind"]; no
    // evidence shape this module accepts can produce it.
    const bad: SendReconcileOutcome["kind"] = "REJECTED";
    expect(bad).toBeDefined();
  });

  it("WAITING never carries a release/close field — only the identical redeliverable code", () => {
    const outcome = classifySendReconcile(delivered());
    if (outcome.kind === "WAITING") {
      expect(Object.keys(outcome).sort()).toEqual(["kind", "redeliverableTransferCodeSha256", "sendAttemptId"]);
    } else {
      throw new Error("expected WAITING");
    }
  });
});
