// RECEIVE_EXTERNAL reconcile decision matrix.

import { describe, expect, it } from "vitest";

import {
  mintLandingPathProofFromOracle,
} from "./landing-oracle-mint.fixture.js";
import { type PathObservation } from "./observation-input.js";
import {
  classifyReceiveReconcile,
  type ReceiveReconcileInput,
  type ReceiveReconcileOutcome,
} from "./receive.js";

const ATTEMPT = "receive-attempt-1";
const WALLET = "wallet-receiver";

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
const INDETERMINATE_OBS: PathObservation = { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" };
const BREACH_OBS: PathObservation = { result: "ANOMALY", anomaly: "GENESIS_AFTER_HISTORY" };

function postSubmit(overrides: Partial<Extract<ReceiveReconcileInput, { boundary: "POST_SUBMIT" }>> = {}): ReceiveReconcileInput {
  return {
    boundary: "POST_SUBMIT",
    receiveAttemptId: ATTEMPT,
    receiverWalletId: WALLET,
    receiverLeaseState: "ACTIVE",
    receiverObservation: LANDED_OBS,
    ...overrides,
  };
}

describe("RECEIVE_EXTERNAL PRE_SUBMIT matrix", () => {
  it.each([
    [false, false, false, "PROVEN_NOT_STARTED", "RESUME_T0_AND_CODE_FORMATION"],
    [false, false, true, "INVARIANT_BREACH", undefined],
    [false, true, false, "PROVEN_NOT_STARTED", "RESUME_T0_AND_CODE_FORMATION"],
    [false, true, true, "INVARIANT_BREACH", undefined],
    [true, false, false, "PROVEN_NOT_STARTED", "SIGN_PERSISTED_STEP2_PREIMAGE"],
    [true, false, true, "INVARIANT_BREACH", undefined],
    [true, true, false, "PROVEN_NOT_STARTED", "SUBMIT_ONCE"],
    [true, true, true, "PROVEN_NOT_STARTED", "SUBMIT_ONCE"],
  ] as const)(
    "formationComplete=%s sig=%s auditUse=%s -> %s (%s)",
    (formationComplete, step2SignaturePersisted, signerAuditIndicatesUse, expectedKind, expectedResume) => {
      const outcome = classifyReceiveReconcile({
        boundary: "PRE_SUBMIT",
        receiveOperationId: ATTEMPT,
        formationComplete,
        step2SignaturePersisted,
        signerAuditIndicatesUse,
      });
      expect(outcome.kind).toBe(expectedKind);
      if (outcome.kind === "PROVEN_NOT_STARTED") {
        expect(outcome.resumeAction).toBe(expectedResume);
      }
    },
  );
});

describe("RECEIVE_EXTERNAL lease axis", () => {
  it("RELEASED receiver lease during POST_SUBMIT reconcile -> INVARIANT_BREACH", () => {
    const outcome = classifyReceiveReconcile(postSubmit({ receiverLeaseState: "RELEASED" }));
    expect(outcome.kind).toBe("INVARIANT_BREACH");
  });
});

describe("RECEIVE_EXTERNAL POST_SUBMIT matrix", () => {
  it("landed observation -> LANDED_VERIFIED", () => {
    const outcome = classifyReceiveReconcile(postSubmit());
    expect(outcome.kind).toBe("LANDED_VERIFIED");
  });

  it("indeterminate-class anomaly -> INDETERMINATE", () => {
    const outcome = classifyReceiveReconcile(postSubmit({ receiverObservation: INDETERMINATE_OBS }));
    expect(outcome.kind).toBe("INDETERMINATE");
  });

  it("breach-class anomaly -> INVARIANT_BREACH", () => {
    const outcome = classifyReceiveReconcile(postSubmit({ receiverObservation: BREACH_OBS }));
    expect(outcome.kind).toBe("INVARIANT_BREACH");
  });

  it("no evidence shape reachable from POST_SUBMIT ever yields PROVEN_NOT_STARTED or WAITING", () => {
    const observations: PathObservation[] = [LANDED_OBS, INDETERMINATE_OBS, BREACH_OBS, { result: "NO_SUCCESSOR" }];
    const reachableKinds = new Set<ReceiveReconcileOutcome["kind"]>();
    for (const receiverObservation of observations) {
      reachableKinds.add(classifyReceiveReconcile(postSubmit({ receiverObservation })).kind);
    }
    expect(reachableKinds.has("PROVEN_NOT_STARTED")).toBe(false);
    // ReceiveReconcileOutcome["kind"] structurally excludes "WAITING" already (proven at
    // compile time in types.test.ts).
  });
});
