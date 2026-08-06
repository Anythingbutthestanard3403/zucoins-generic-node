// MOVE_INTERNAL reconcile decision matrix.
//
// This is the safety-critical member of the family: exit criterion is literally "no
// later observation, timeout, expiry, ACK, or operator action creates a second MOVE attempt."

import { describe, expect, it } from "vitest";

import {
  type LandingPathProof,
} from "./landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "./landing-oracle-mint.fixture.js";
import { type PathObservation } from "./observation-input.js";
import { classifyMoveReconcile, type MoveReconcileInput, type MoveReconcileOutcome } from "./move.js";

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

function postSubmit(
  overrides: Partial<Extract<MoveReconcileInput, { boundary: "POST_SUBMIT" }>> = {},
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

describe("MOVE_INTERNAL PRE_SUBMIT matrix", () => {
  it.each([
    [false, false, false, "PROVEN_NOT_STARTED", "FIRST_FORMATION"],
    [false, false, true, "INVARIANT_BREACH", undefined],
    [false, true, false, "PROVEN_NOT_STARTED", "FIRST_FORMATION"],
    [false, true, true, "INVARIANT_BREACH", undefined],
    [true, false, false, "PROVEN_NOT_STARTED", "SIGN_PERSISTED_PREIMAGE"],
    [true, false, true, "INVARIANT_BREACH", undefined],
    [true, true, false, "PROVEN_NOT_STARTED", "SUBMIT_ONCE"],
    [true, true, true, "PROVEN_NOT_STARTED", "SUBMIT_ONCE"],
  ] as const)(
    "preimage=%s signatures=%s auditCall=%s -> %s (%s)",
    (preimagePersisted, signaturesComplete, signerAuditIndicatesCall, expectedKind, expectedResume) => {
      const outcome = classifyMoveReconcile({
        boundary: "PRE_SUBMIT",
        moveAttemptId: ATTEMPT,
        preimagePersisted,
        signaturesComplete,
        signerAuditIndicatesCall,
      });
      expect(outcome.kind).toBe(expectedKind);
      if (expectedKind === "PROVEN_NOT_STARTED" && outcome.kind === "PROVEN_NOT_STARTED") {
        expect(outcome.resumeAction).toBe(expectedResume);
      }
    },
  );

  it("PRE_SUBMIT never returns LANDED_VERIFIED, WAITING, or INDETERMINATE", () => {
    // No submit claim can exist while boundary is PRE_SUBMIT by construction (see move.ts), so
    // there is no evidence shape on this branch that could produce a landing or park verdict.
    const reachableKinds = new Set<MoveReconcileOutcome["kind"]>();
    for (const preimagePersisted of [false, true]) {
      for (const signaturesComplete of [false, true]) {
        for (const signerAuditIndicatesCall of [false, true]) {
          reachableKinds.add(
            classifyMoveReconcile({
              boundary: "PRE_SUBMIT",
              moveAttemptId: ATTEMPT,
              preimagePersisted,
              signaturesComplete,
              signerAuditIndicatesCall,
            }).kind,
          );
        }
      }
    }
    expect(reachableKinds).toEqual(new Set(["PROVEN_NOT_STARTED", "INVARIANT_BREACH"]));
  });
});

describe("MOVE_INTERNAL lease axis", () => {
  it.each([
    ["ACTIVE", "ACTIVE", false],
    ["RELEASED", "ACTIVE", true],
    ["ACTIVE", "RELEASED", true],
    ["RELEASED", "RELEASED", true],
  ] as const)("sourceLease=%s destinationLease=%s -> breach=%s", (sourceLeaseState, destinationLeaseState, breach) => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceLeaseState, destinationLeaseState }),
    );
    expect(outcome.kind).toBe(breach ? "INVARIANT_BREACH" : "LANDED_VERIFIED");
    if (outcome.kind === "INVARIANT_BREACH") {
      expect(outcome.reason).toEqual({ source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" });
    }
  });
});

describe("MOVE_INTERNAL POST_SUBMIT path-combination matrix", () => {
  it("both paths LANDED, anchored to the same move body -> LANDED_VERIFIED", () => {
    const outcome = classifyMoveReconcile(postSubmit());
    expect(outcome.kind).toBe("LANDED_VERIFIED");
    if (outcome.kind === "LANDED_VERIFIED") {
      expect(outcome.sourcePath.expectedBodySha256).toBe(BODY);
      expect(outcome.destinationPath.expectedBodySha256).toBe(BODY);
    }
  });

  it("both paths LANDED but anchored to a DIFFERENT body -> INDETERMINATE (never LANDED_VERIFIED)", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({
        sourceObservation: { result: "PROOF", proof: proof(0, "some-other-body-sha256") },
      }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(outcome.reason).toEqual({ source: "PATH_DISAGREEMENT" });
    }
  });

  it.each([
    ["LANDED", "INDETERMINATE", "INDETERMINATE"],
    ["LANDED", "INVARIANT_BREACH", "INVARIANT_BREACH"],
    ["INDETERMINATE", "LANDED", "INDETERMINATE"],
    ["INDETERMINATE", "INDETERMINATE", "INDETERMINATE"],
    ["INDETERMINATE", "INVARIANT_BREACH", "INVARIANT_BREACH"],
    ["INVARIANT_BREACH", "LANDED", "INVARIANT_BREACH"],
    ["INVARIANT_BREACH", "INDETERMINATE", "INVARIANT_BREACH"],
    ["INVARIANT_BREACH", "INVARIANT_BREACH", "INVARIANT_BREACH"],
  ] as const)("source=%s destination=%s -> %s (last row: disagreement parks both wallets)", (
    sourceTier,
    destinationTier,
    expectedKind,
  ) => {
    const byTier: Record<string, PathObservation> = {
      LANDED: LANDED_OBS,
      INDETERMINATE: INDETERMINATE_OBS,
      INVARIANT_BREACH: BREACH_OBS,
    };
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: byTier[sourceTier], destinationObservation: byTier[destinationTier] }),
    );
    expect(outcome.kind).toBe(expectedKind);
    // Never fabricates a landing from a disagreement, and never authorizes retry/rebuild/
    // resubmit/release — both are structurally absent from every non-LANDED_VERIFIED branch of
    // MoveReconcileOutcome (see move.ts; no such field exists anywhere in the union).
    expect(outcome.kind).not.toBe("LANDED_VERIFIED");
  });
});

describe("MOVE_INTERNAL — no second attempt, ever (exit criterion)", () => {
  it("no evidence shape reachable from POST_SUBMIT ever yields PROVEN_NOT_STARTED", () => {
    // "PROVEN_NOT_STARTED may authorize the first call only when the submit boundary was
    // durably never crossed... it never creates attempt 2 or licenses another call after a
    // submit claim began." A submit claim's mere existence is what routes evidence through
    // MoveObservationEvidence (boundary: POST_SUBMIT) rather than MoveFormationEvidence in the
    // first place (see move.ts's MoveReconcileInput doc comment) — this test exhausts every
    // tier combination reachable from that boundary and confirms none reaches
    // PROVEN_NOT_STARTED, matching classifyMoveReconcile's source: only its PRE_SUBMIT branch
    // ever returns that kind.
    const tiers: PathObservation[] = [LANDED_OBS, INDETERMINATE_OBS, BREACH_OBS];
    const reachableKinds = new Set<MoveReconcileOutcome["kind"]>();
    for (const sourceObservation of tiers) {
      for (const destinationObservation of tiers) {
        for (const sourceLeaseState of ["ACTIVE", "RELEASED"] as const) {
          for (const destinationLeaseState of ["ACTIVE", "RELEASED"] as const) {
            reachableKinds.add(
              classifyMoveReconcile(
                postSubmit({ sourceObservation, destinationObservation, sourceLeaseState, destinationLeaseState }),
              ).kind,
            );
          }
        }
      }
    }
    expect(reachableKinds.has("PROVEN_NOT_STARTED")).toBe(false);
    // MoveReconcileOutcome["kind"] structurally excludes "WAITING" already (proven at compile
    // time in types.test.ts); a runtime .has("WAITING") check here would not type-check against
    // this Set's element type, which is itself part of the proof.
  });

  it("MoveReconcileOutcome has no field or member representing a second attempt or rebuild", () => {
    // @ts-expect-error — "attemptNumber" is not a member of any MoveReconcileOutcome branch;
    // there is no way to spell "this is attempt 2" in this type.
    const bad: MoveReconcileOutcome = { kind: "LANDED_VERIFIED", moveAttemptId: ATTEMPT, attemptNumber: 2 };
    expect(bad).toBeDefined();
  });

  it("MoveReconcileOutcome cannot express the CREATED<-NEEDS_ATTENTION rebuild transition already present in the merged states.contract.ts", () => {
    // FINDING: packages/generic-node-contracts/src/operations/states.contract.ts
    // MOVE_INTERNAL_TRANSITIONS already contains a `{ from: "NEEDS_ATTENTION", to: "CREATED",
    // guard: "Operator requests rebuild and the node has positive non-landing proof for the
    // archived attempt." }` row. That row exists nowhere in the transition tables (which
    // list exactly four MOVE_INTERNAL transitions, none a rebuild) and directly contradicts
    // "no generic PROVEN_NOT_LANDED... never creates attempt 2"
    // and landing-path oracle ("There is no generic PROVEN_NOT_LANDED verdict"). This module deliberately
    // does not import operations/states.contract.ts for exactly this reason. The assertion below
    // is the structural half of that avoidance: no rebuild-shaped value satisfies
    // MoveReconcileOutcome.
    // @ts-expect-error — "REBUILD" (or any second-attempt kind) is not a member of
    // MoveReconcileOutcome["kind"].
    const bad: MoveReconcileOutcome["kind"] = "REBUILD";
    expect(bad).toBeDefined();
  });
});
