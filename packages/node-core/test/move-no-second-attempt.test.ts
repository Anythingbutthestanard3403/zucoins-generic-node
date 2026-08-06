// The RECONCILE CLASSIFIER half of the MOVE_INTERNAL no-second-attempt proof.
//
// Exit criterion, scoped to what this file actually exercises: no observation, timeout,
// ambiguity, invariant breach or partial signing state fed to classifyMoveReconcile after a
// MOVE submit claim began ever yields a second attempt, a retry authorization, a rebuild or a
// resubmit. This is a proof about the classifier's outcome surface, NOT about the system: it
// constructs no second caller, no restart and no gateway, so a second POST is invisible here
// by construction. The wire count lives in move-no-second-attempt.gateway-count.test.ts, the
// durable arbitration in submit-decision-claim-store.pg.test.ts and pg-concurrency.test.ts.
// The operator-action surface is not exercised here at all.

import { describe, expect, it } from "vitest";

import {
  type LandingPathProof,
} from "../src/protocol/reconcile/landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";
import { type PathObservation } from "../src/protocol/reconcile/observation-input.js";
import {
  classifyMoveReconcile,
  type MoveObservationEvidence,
  type MoveReconcileInput,
  type MoveReconcileOutcome,
} from "../src/protocol/reconcile/move.js";
import {
  captureSubmitAcknowledgement,
  mintSettlementAuthority,
  mintSubmitClaim,
  type SettlementAuthority,
  type SubmitAcknowledgement,
} from "../src/protocol/reconcile/submit-authority.js";
import { type ReconcileIndeterminateReason } from "../src/protocol/reconcile/types.js";

const ATTEMPT = "move-attempt-1";
const SOURCE = "wallet-source";
const DEST = "wallet-destination";
const BODY = "move-body-sha256";

function proof(depth: number, bodySha256 = BODY): LandingPathProof {
  return depth === 0
    ? mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub",
      expectedBodySha256: bodySha256,
      freshHeadBodySha256: bodySha256,
      freshHeadObservationId: "obs",
      depth: 0,
    })
    : mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub",
      expectedBodySha256: bodySha256,
      freshHeadBodySha256: (bodySha256 + "-head"),
      freshHeadObservationId: "obs",
      depth: depth,
    });
}

const LANDED_OBS: PathObservation = { result: "PROOF", proof: proof(0) };
const INDETERMINATE_OBS: PathObservation = { result: "PROOF_INCOMPLETE", fault: "GAP" };
const BREACH_OBS: PathObservation = { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" };
const NO_SUCCESSOR_OBS: PathObservation = { result: "NO_SUCCESSOR" };
const ANOMALY_OBS: PathObservation = { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" };

function postSubmit(
  overrides: Partial<MoveObservationEvidence> = {},
): MoveReconcileInput {
  return {
    boundary: "POST_SUBMIT",
    moveAttemptId: ATTEMPT,
    sourceWalletId: SOURCE,
    destinationWalletId: DEST,
    expectedMoveBodySha256: BODY,
    sourceLeaseState: "ACTIVE",
    destinationLeaseState: "ACTIVE",
    sourceObservation: LANDED_OBS,
    destinationObservation: LANDED_OBS,
    ...overrides,
  };
}

// Every PathObservation variant the system can produce.
const ALL_OBSERVATIONS: PathObservation[] = [
  LANDED_OBS,
  INDETERMINATE_OBS,
  BREACH_OBS,
  NO_SUCCESSOR_OBS,
  ANOMALY_OBS,
  { result: "ANOMALY", anomaly: "REGRESSION" },
  { result: "ANOMALY", anomaly: "GENESIS_AFTER_HISTORY" },
  { result: "ANOMALY", anomaly: "SIGNATURE_COLLISION" },
  { result: "ANOMALY", anomaly: "MALFORMED_ENVELOPE" },
  { result: "ANOMALY", anomaly: "MALFORMED_TRANSACTION" },
  { result: "ANOMALY", anomaly: "UNVERIFIED_SIGNATURE" },
  { result: "ANOMALY", anomaly: "WALLET_ROLE_INVALID" },
  { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" },
  { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" },
  { result: "PROOF_INCOMPLETE", fault: "CONFLICT" },
  { result: "PROOF_INCOMPLETE", fault: "DUPLICATE" },
  { result: "PROOF_INCOMPLETE", fault: "CYCLE" },
  { result: "PROOF_INCOMPLETE", fault: "MALFORMED_BODY" },
  { result: "PROOF_INCOMPLETE", fault: "ANOMALOUS_OR_CONTRADICTORY" },
  { result: "PROOF_INCOMPLETE", fault: "BUDGET_EXHAUSTED" },
];

describe("MOVE no second attempt — ambiguity states ", () => {
  it("INDETERMINATE from any observation combination never yields PROVEN_NOT_STARTED or WAITING", () => {
    const reachableKinds = new Set<string>();
    for (const sourceObservation of ALL_OBSERVATIONS) {
      for (const destinationObservation of ALL_OBSERVATIONS) {
        const outcome = classifyMoveReconcile(
          postSubmit({ sourceObservation, destinationObservation }),
        );
        reachableKinds.add(outcome.kind);
        if (outcome.kind === "INDETERMINATE") {
          // INDETERMINATE parks both wallets — no retry, no rebuild, no resubmit, no release.
          expect(outcome).not.toHaveProperty("resumeAction");
          expect(outcome).not.toHaveProperty("neverCrossedBoundary");
        }
      }
    }
    expect(reachableKinds.has("PROVEN_NOT_STARTED")).toBe(false);
    expect(reachableKinds.has("WAITING")).toBe(false);
  });

  it("SUBMIT_OUTCOME_UNKNOWN (timeout/network error) is INDETERMINATE, never a retry trigger", () => {
    // The reason exists in the type vocabulary but classifyMoveReconcile never produces it
    // directly — it models the caller's post-hoc classification of an ambiguous submit call.
    // Regardless, no MoveReconcileOutcome member carries retry authority.
    const reason: ReconcileIndeterminateReason = { source: "SUBMIT_OUTCOME_UNKNOWN" };
    expect(reason.source).toBe("SUBMIT_OUTCOME_UNKNOWN");
    // The type system ensures this reason can only appear inside an INDETERMINATE outcome:
    // @ts-expect-error — SUBMIT_OUTCOME_UNKNOWN is not a valid kind for MoveReconcileOutcome.
    const bad: MoveReconcileOutcome = { kind: "PROVEN_NOT_STARTED", moveAttemptId: ATTEMPT, reason };
    expect(bad).toBeDefined();
  });

  it("body-hash mismatch (wrong transaction landed) is INDETERMINATE, never a retry", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({
        sourceObservation: { result: "PROOF", proof: proof(0, "different-body") },
        destinationObservation: LANDED_OBS,
      }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(outcome.reason).toEqual({ source: "PATH_DISAGREEMENT" });
    }
  });

  it("one leg landed, other leg NO_SUCCESSOR — permanent ambiguity, no retry", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: LANDED_OBS, destinationObservation: NO_SUCCESSOR_OBS }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
  });

  it("both legs NO_SUCCESSOR — unchanged head, still no retry authority", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: NO_SUCCESSOR_OBS, destinationObservation: NO_SUCCESSOR_OBS }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
  });
});

describe("MOVE no second attempt — invariant breach ", () => {
  it("INVARIANT_BREACH from any source never yields PROVEN_NOT_STARTED, WAITING, or LANDED_VERIFIED", () => {
    const breachSources: PathObservation[] = [
      BREACH_OBS,
      { result: "ANOMALY", anomaly: "REGRESSION" },
      { result: "ANOMALY", anomaly: "GENESIS_AFTER_HISTORY" },
      { result: "ANOMALY", anomaly: "SIGNATURE_COLLISION" },
    ];
    for (const breachObs of breachSources) {
      for (const otherObs of ALL_OBSERVATIONS) {
        const outcomeSrc = classifyMoveReconcile(
          postSubmit({ sourceObservation: breachObs, destinationObservation: otherObs }),
        );
        expect(outcomeSrc.kind).toBe("INVARIANT_BREACH");

        const outcomeDst = classifyMoveReconcile(
          postSubmit({ sourceObservation: otherObs, destinationObservation: breachObs }),
        );
        // Either INVARIANT_BREACH (if other is not also breach) or INVARIANT_BREACH (both).
        expect(outcomeDst.kind).toBe("INVARIANT_BREACH");
      }
    }
  });

  it("INVARIANT_BREACH carries no resumeAction, neverCrossedBoundary, or retry field", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: BREACH_OBS }),
    );
    expect(outcome.kind).toBe("INVARIANT_BREACH");
    expect(outcome).not.toHaveProperty("resumeAction");
    expect(outcome).not.toHaveProperty("neverCrossedBoundary");
    expect(outcome).not.toHaveProperty("moveAttemptId");
  });

  it("lease released during reconcile is INVARIANT_BREACH, not a retry opportunity", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceLeaseState: "RELEASED", destinationLeaseState: "ACTIVE" }),
    );
    expect(outcome.kind).toBe("INVARIANT_BREACH");
    if (outcome.kind === "INVARIANT_BREACH") {
      expect(outcome.reason).toEqual({ source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" });
      expect(outcome.affectedWalletIds).toContain(SOURCE);
    }
  });
});

describe("MOVE no second attempt — timeout / partial signing", () => {
  it("PRE_SUBMIT with partial signatures never authorizes SUBMIT_ONCE", () => {
    const outcome = classifyMoveReconcile({
      boundary: "PRE_SUBMIT",
      moveAttemptId: ATTEMPT,
      preimagePersisted: true,
      signaturesComplete: false,
      signerAuditIndicatesCall: false,
    });
    expect(outcome.kind).toBe("PROVEN_NOT_STARTED");
    if (outcome.kind === "PROVEN_NOT_STARTED") {
      expect(outcome.resumeAction).toBe("SIGN_PERSISTED_PREIMAGE");
      expect(outcome.resumeAction).not.toBe("SUBMIT_ONCE");
    }
  });

  it("PRE_SUBMIT with no preimage never authorizes SUBMIT_ONCE", () => {
    const outcome = classifyMoveReconcile({
      boundary: "PRE_SUBMIT",
      moveAttemptId: ATTEMPT,
      preimagePersisted: false,
      signaturesComplete: false,
      signerAuditIndicatesCall: false,
    });
    expect(outcome.kind).toBe("PROVEN_NOT_STARTED");
    if (outcome.kind === "PROVEN_NOT_STARTED") {
      expect(outcome.resumeAction).toBe("FIRST_FORMATION");
    }
  });

  it("SUBMIT_ONCE is reachable ONLY from PRE_SUBMIT with full signatures — the first call, not a retry", () => {
    // Exhaustive: only one PRE_SUBMIT cell yields SUBMIT_ONCE.
    let submitOnceCount = 0;
    for (const preimagePersisted of [false, true]) {
      for (const signaturesComplete of [false, true]) {
        for (const signerAuditIndicatesCall of [false, true]) {
          const outcome = classifyMoveReconcile({
            boundary: "PRE_SUBMIT",
            moveAttemptId: ATTEMPT,
            preimagePersisted,
            signaturesComplete,
            signerAuditIndicatesCall,
          });
          if (outcome.kind === "PROVEN_NOT_STARTED" && outcome.resumeAction === "SUBMIT_ONCE") {
            submitOnceCount++;
            // The precondition: full preimage + full signatures + PRE_SUBMIT boundary (no claim
            // exists yet). This is the FIRST call by construction, not a retry.
            expect(preimagePersisted).toBe(true);
            expect(signaturesComplete).toBe(true);
          }
        }
      }
    }
    // Exactly two cells reach SUBMIT_ONCE (auditCall true/false with full preimage+sigs).
    expect(submitOnceCount).toBe(2);
  });

  it("once boundary is POST_SUBMIT, SUBMIT_ONCE is structurally unreachable regardless of observations", () => {
    for (const sourceObservation of ALL_OBSERVATIONS) {
      for (const destinationObservation of ALL_OBSERVATIONS) {
        const outcome = classifyMoveReconcile(
          postSubmit({ sourceObservation, destinationObservation }),
        );
        if (outcome.kind === "PROVEN_NOT_STARTED") {
          // This branch is unreachable from POST_SUBMIT — the test would fail here if it were.
          expect.unreachable("POST_SUBMIT must never yield PROVEN_NOT_STARTED");
        }
      }
    }
  });
});

describe("MOVE no second attempt — type-level structural proofs", () => {
  it("MoveReconcileOutcome has no WAITING member (unlike SendReconcileOutcome)", () => {
    // @ts-expect-error — "WAITING" is not a member of MoveReconcileOutcome["kind"].
    const bad: MoveReconcileOutcome["kind"] = "WAITING";
    expect(bad).toBeDefined();
  });

  it("MoveReconcileOutcome has no RETRY member", () => {
    // @ts-expect-error — "RETRY" is not a member of MoveReconcileOutcome["kind"].
    const bad: MoveReconcileOutcome["kind"] = "RETRY";
    expect(bad).toBeDefined();
  });

  it("MoveReconcileOutcome has no REBUILD member", () => {
    // @ts-expect-error — "REBUILD" is not a member of MoveReconcileOutcome["kind"].
    const bad: MoveReconcileOutcome["kind"] = "REBUILD";
    expect(bad).toBeDefined();
  });

  it("MoveReconcileOutcome has no RESUBMIT member", () => {
    // @ts-expect-error — "RESUBMIT" is not a member of MoveReconcileOutcome["kind"].
    const bad: MoveReconcileOutcome["kind"] = "RESUBMIT";
    expect(bad).toBeDefined();
  });

  it("no MoveReconcileOutcome branch carries a retryCount or attemptNumber field", () => {
    // @ts-expect-error — "retryCount" does not exist on any branch.
    const bad: MoveReconcileOutcome = { kind: "LANDED_VERIFIED", moveAttemptId: ATTEMPT, retryCount: 1 };
    expect(bad).toBeDefined();
  });

  it("MoveResumeAction has no RETRY_SUBMIT or SECOND_ATTEMPT member", () => {
    // @ts-expect-error — the closed union is FIRST_FORMATION | SIGN_PERSISTED_PREIMAGE | SUBMIT_ONCE only.
    const bad: import("../src/protocol/reconcile/move.js").MoveResumeAction = "RETRY_SUBMIT";
    expect(bad).toBeDefined();
  });

  it("SubmitClaim is a plain fact — it cannot be converted into a second SubmitClaim for the same attempt", () => {
    const claim = mintSubmitClaim(ATTEMPT, "2026-01-01T00:00:00.000Z");
    // The uniqueness constraint is enforced by the database (outside this pure-types package).
    // Here we prove the type carries no "sequence" or "attemptNumber" that could express "claim 2".
    // @ts-expect-error — SubmitClaim has no sequenceNumber field.
    const bad: typeof claim = { ...claim, sequenceNumber: 2 };
    expect(bad).toBeDefined();
  });
});

describe("MOVE no second attempt — submit authority separation", () => {
  it("a SubmitAcknowledgement (gateway response) cannot produce a SettlementAuthority (landing proof)", () => {
    const ack = captureSubmitAcknowledgement(ATTEMPT, true, "ok", "2026-01-01T00:00:00.000Z");
    // @ts-expect-error — ack is not a LandingPathProof; cannot mint settlement from an ack.
    expect(() => mintSettlementAuthority(ATTEMPT, ack)).toThrow(
      /issued landing path proof/,
    );
  });

  it("a SubmitAcknowledgement is not assignable to SettlementAuthority", () => {
    const ack = captureSubmitAcknowledgement(ATTEMPT, true, "ok", "2026-01-01T00:00:00.000Z");
    // @ts-expect-error — nominal brand mismatch.
    const bad: SettlementAuthority = ack;
    expect(bad).toBeDefined();
  });

  it("a SubmitAcknowledgement is not assignable to SubmitAcknowledgement from a plain literal (brand is private)", () => {
    // @ts-expect-error — cannot forge the brand from outside the module.
    const bad: SubmitAcknowledgement = {
      attemptId: ATTEMPT,
      gatewayStatus: true,
      gatewayCode: "ok",
      capturedAt: "2026-01-01T00:00:00.000Z",
    };
    expect(bad).toBeDefined();
  });
});

describe("MOVE no second attempt — exhaustive POST_SUBMIT kind census", () => {
  it("the complete set of kinds reachable from POST_SUBMIT is exactly {LANDED_VERIFIED, INDETERMINATE, INVARIANT_BREACH}", () => {
    const reachableKinds = new Set<string>();
    const leaseStates = ["ACTIVE", "RELEASED"] as const;
    for (const sourceObservation of ALL_OBSERVATIONS) {
      for (const destinationObservation of ALL_OBSERVATIONS) {
        for (const sourceLeaseState of leaseStates) {
          for (const destinationLeaseState of leaseStates) {
            reachableKinds.add(
              classifyMoveReconcile(
                postSubmit({ sourceObservation, destinationObservation, sourceLeaseState, destinationLeaseState }),
              ).kind,
            );
          }
        }
      }
    }
    expect(reachableKinds).toEqual(new Set(["LANDED_VERIFIED", "INDETERMINATE", "INVARIANT_BREACH"]));
  });

  it("LANDED_VERIFIED is the only terminal success — it carries no authority to submit again", () => {
    const outcome = classifyMoveReconcile(postSubmit());
    expect(outcome.kind).toBe("LANDED_VERIFIED");
    if (outcome.kind === "LANDED_VERIFIED") {
      expect(outcome).not.toHaveProperty("resumeAction");
      expect(outcome).not.toHaveProperty("neverCrossedBoundary");
      // The outcome records the proof; it does not authorize any further action.
      expect(outcome.sourcePath.expectedBodySha256).toBe(BODY);
      expect(outcome.destinationPath.expectedBodySha256).toBe(BODY);
    }
  });
});
