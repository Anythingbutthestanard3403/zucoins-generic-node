// Asymmetric burial and observation-anomaly coverage for MOVE_INTERNAL reconcile.
// Internal-move recovery: the pre-submit table's last row and the post-submit table's
// point 3, plus observation and lineage anomalies, and the any-depth complete-path
// burial oracle.
//
// "Burial" = the move's exact transaction is not the current exact head of a wallet but sits at
// some depth >= 1 behind it, provable only via a complete gap-free path (LANDED_COMPLETE_PATH).
// A move has TWO independently-complete legs (source and destination); burial is asymmetric when
// one leg proves landing (at any depth) and the other cannot connect to the same transaction.
// Last row: that disagreement is INDETERMINATE and parks BOTH wallets — it never fabricates
// a landing and never authorizes retry/rebuild/resubmit/release.

import { describe, expect, it } from "vitest";

import { type ObservationAnomalyKind } from "@zucoins/generic-node-contracts/observation";

import {
  type LandingPathProof,
} from "./landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "./landing-oracle-mint.fixture.js";
import { type PathObservation } from "./observation-input.js";
import { classifyMoveReconcile, type MoveReconcileInput, type MoveReconcileOutcome } from "./move.js";
import { toAttentionReason } from "./types.js";

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

const landedAt = (depth: number, bodySha256 = BODY): PathObservation => ({
  result: "PROOF",
  proof: proof(depth, bodySha256),
});

// The park-class anomalies: rows that "park for attention" rather
// than quarantine (the three breach-class anomalies are covered separately below).
const PARK_ANOMALIES: readonly ObservationAnomalyKind[] = [
  "TRANSPORT_ERROR",
  "MALFORMED_ENVELOPE",
  "MALFORMED_TRANSACTION",
  "UNVERIFIED_SIGNATURE",
  "WALLET_ROLE_INVALID",
  "UNEXPLAINED_JUMP",
];

// The breach-class anomalies: rows that "quarantine wallet"/"stop money engines"/"escalate as
// a protocol/security incident" — the INVARIANT_BREACH automatic effect.
const BREACH_ANOMALIES: readonly ObservationAnomalyKind[] = [
  "REGRESSION",
  "GENESIS_AFTER_HISTORY",
  "SIGNATURE_COLLISION",
];

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
    sourceObservation: landedAt(0),
    destinationObservation: landedAt(0),
    ...overrides,
  };
}

describe("MOVE_INTERNAL asymmetric burial (pre-submit last row / post-submit point 3)", () => {
  it("exact/exact baseline: both legs land at the current head, same body -> LANDED_VERIFIED", () => {
    const outcome = classifyMoveReconcile(postSubmit());
    expect(outcome.kind).toBe("LANDED_VERIFIED");
    if (outcome.kind === "LANDED_VERIFIED") {
      expect(outcome.sourcePath.depth).toBe(0);
      expect(outcome.destinationPath.depth).toBe(0);
    }
  });

  it("source buried (depth>=1) and destination exact-head landed, same body -> LANDED_VERIFIED", () => {
    // Burial on ONE leg is not itself asymmetric: requires each leg independently complete,
    // and a complete-path proof at depth satisfies that leg exactly as depth-0 does. Both legs
    // anchor to the one persisted move body, so this is a verified landing, not a disagreement.
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: landedAt(3), destinationObservation: landedAt(0) }),
    );
    expect(outcome.kind).toBe("LANDED_VERIFIED");
    if (outcome.kind === "LANDED_VERIFIED") {
      expect(outcome.sourcePath.depth).toBe(3);
      expect(outcome.destinationPath.depth).toBe(0);
    }
  });

  it("both legs buried at differing depths, same body -> LANDED_VERIFIED (depth need not match)", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: landedAt(2), destinationObservation: landedAt(5) }),
    );
    expect(outcome.kind).toBe("LANDED_VERIFIED");
    if (outcome.kind === "LANDED_VERIFIED") {
      expect(outcome.sourcePath.depth).toBe(2);
      expect(outcome.destinationPath.depth).toBe(5);
    }
  });

  it.each([
    ["NO_SUCCESSOR", { result: "NO_SUCCESSOR" }],
    ["PROOF_INCOMPLETE(GAP)", { result: "PROOF_INCOMPLETE", fault: "GAP" }],
    ["PROOF_INCOMPLETE(MISSING_BODY)", { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" }],
  ] as const)(
    "source buried-and-landed but destination cannot connect (%s) -> INDETERMINATE PATH_DISAGREEMENT, parks both",
    (_label, destinationObservation) => {
      const outcome = classifyMoveReconcile(
        postSubmit({ sourceObservation: landedAt(4), destinationObservation }),
      );
      expect(outcome.kind).toBe("INDETERMINATE");
      if (outcome.kind === "INDETERMINATE") {
        expect(outcome.moveAttemptId).toBe(ATTEMPT);
        expect(outcome.reason).toEqual({ source: "PATH_DISAGREEMENT" });
      }
    },
  );

  it("destination landed but source cannot connect -> INDETERMINATE PATH_DISAGREEMENT (symmetric rule)", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: { result: "NO_SUCCESSOR" }, destinationObservation: landedAt(2) }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(outcome.reason).toEqual({ source: "PATH_DISAGREEMENT" });
    }
  });

  it("both legs landed but anchored to DIFFERENT bodies -> INDETERMINATE PATH_DISAGREEMENT, never LANDED_VERIFIED", () => {
    // Point 3: both body-0 values must byte-equal the one persisted move transaction. A leg
    // proven against some OTHER body is not a landing of THIS attempt, even at depth.
    const outcome = classifyMoveReconcile(
      postSubmit({
        sourceObservation: landedAt(2, "some-other-body-sha256"),
        destinationObservation: landedAt(2, BODY),
      }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(outcome.reason).toEqual({ source: "PATH_DISAGREEMENT" });
    }
  });
});

describe("MOVE_INTERNAL observation-anomaly handling", () => {
  it.each(PARK_ANOMALIES)(
    "park-class anomaly on the source leg with a landed destination -> INDETERMINATE (park, not breach)",
    (anomaly) => {
      const outcome = classifyMoveReconcile(
        postSubmit({
          sourceObservation: { result: "ANOMALY", anomaly },
          destinationObservation: landedAt(0),
        }),
      );
      expect(outcome.kind).toBe("INDETERMINATE");
      if (outcome.kind === "INDETERMINATE") {
        // One leg landed + the other not connectable to the same transaction is the last-row
        // disagreement class, reported as PATH_DISAGREEMENT (the landed leg forces the disagreement
        // branch ahead of the source leg's own anomaly reason).
        expect(outcome.reason).toEqual({ source: "PATH_DISAGREEMENT" });
      }
    },
  );

  it.each(PARK_ANOMALIES)(
    "park-class anomaly on BOTH legs -> INDETERMINATE carrying the source leg's anomaly reason",
    (anomaly) => {
      const outcome = classifyMoveReconcile(
        postSubmit({
          sourceObservation: { result: "ANOMALY", anomaly },
          destinationObservation: { result: "ANOMALY", anomaly },
        }),
      );
      expect(outcome.kind).toBe("INDETERMINATE");
      if (outcome.kind === "INDETERMINATE") {
        // Neither leg landed, so the disagreement branch is not reached; the source leg's own
        // narrowed reason is reported for a stable, deterministic diagnostic.
        expect(outcome.reason).toEqual({ source: "OBSERVATION_ANOMALY", anomaly });
      }
    },
  );

  it.each(BREACH_ANOMALIES)(
    "breach-class anomaly on the source leg -> INVARIANT_BREACH quarantining the source wallet",
    (anomaly) => {
      const outcome = classifyMoveReconcile(
        postSubmit({
          sourceObservation: { result: "ANOMALY", anomaly },
          destinationObservation: landedAt(0),
        }),
      );
      expect(outcome.kind).toBe("INVARIANT_BREACH");
      if (outcome.kind === "INVARIANT_BREACH") {
        expect(outcome.affectedWalletIds).toEqual([SOURCE]);
        expect(outcome.reason).toEqual({ source: "OBSERVATION_ANOMALY", anomaly });
      }
    },
  );

  it.each(BREACH_ANOMALIES)(
    "breach-class anomaly on the destination leg -> INVARIANT_BREACH quarantining the destination wallet",
    (anomaly) => {
      const outcome = classifyMoveReconcile(
        postSubmit({
          sourceObservation: landedAt(0),
          destinationObservation: { result: "ANOMALY", anomaly },
        }),
      );
      expect(outcome.kind).toBe("INVARIANT_BREACH");
      if (outcome.kind === "INVARIANT_BREACH") {
        expect(outcome.affectedWalletIds).toEqual([DEST]);
        expect(outcome.reason).toEqual({ source: "OBSERVATION_ANOMALY", anomaly });
      }
    },
  );

  it("destination advance under active lease while source reads landed -> INVARIANT_BREACH quarantining the destination wallet", () => {
    // Defense-in-depth: the universal destination lease is meant to prevent this, but if the
    // destination head advances beyond the expected move body while still leased,
    // treat it as INVARIANT_BREACH — never repaired by lease metadata, never LANDED_VERIFIED.
    const outcome = classifyMoveReconcile(
      postSubmit({
        sourceObservation: landedAt(0),
        destinationObservation: { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" },
      }),
    );
    expect(outcome.kind).toBe("INVARIANT_BREACH");
    if (outcome.kind === "INVARIANT_BREACH") {
      expect(outcome.affectedWalletIds).toEqual([DEST]);
      expect(outcome.reason).toEqual({ source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" });
    }
  });

  it("breach-class anomaly on BOTH legs -> INVARIANT_BREACH quarantining both wallets", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({
        sourceObservation: { result: "ANOMALY", anomaly: "REGRESSION" },
        destinationObservation: { result: "ANOMALY", anomaly: "SIGNATURE_COLLISION" },
      }),
    );
    expect(outcome.kind).toBe("INVARIANT_BREACH");
    if (outcome.kind === "INVARIANT_BREACH") {
      expect(outcome.affectedWalletIds).toEqual([SOURCE, DEST]);
      // The source leg's own narrowed reason is reported (checked first and decisively).
      expect(outcome.reason).toEqual({ source: "OBSERVATION_ANOMALY", anomaly: "REGRESSION" });
    }
  });
});

describe("MOVE_INTERNAL attention mapping (closed attention_reason vocabulary)", () => {
  it("PATH_DISAGREEMENT maps to VERIFICATION_INDETERMINATE attention", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: landedAt(3), destinationObservation: { result: "NO_SUCCESSOR" } }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(toAttentionReason(outcome.reason)).toBe("VERIFICATION_INDETERMINATE");
    }
  });

  it("a park-class anomaly reason maps to UNEXPECTED_HEAD_CHANGE attention", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({
        sourceObservation: { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" },
        destinationObservation: { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" },
      }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(toAttentionReason(outcome.reason)).toBe("UNEXPECTED_HEAD_CHANGE");
    }
  });

  it("a breach-class anomaly reason maps to LEASE_INVARIANT_VIOLATION attention", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({ sourceObservation: { result: "ANOMALY", anomaly: "GENESIS_AFTER_HISTORY" } }),
    );
    expect(outcome.kind).toBe("INVARIANT_BREACH");
    if (outcome.kind === "INVARIANT_BREACH") {
      expect(toAttentionReason(outcome.reason)).toBe("LEASE_INVARIANT_VIOLATION");
    }
  });

  it("an incomplete burial proof (GAP) maps to LINEAGE_GAP attention", () => {
    const outcome = classifyMoveReconcile(
      postSubmit({
        sourceObservation: { result: "PROOF_INCOMPLETE", fault: "GAP" },
        destinationObservation: { result: "PROOF_INCOMPLETE", fault: "GAP" },
      }),
    );
    expect(outcome.kind).toBe("INDETERMINATE");
    if (outcome.kind === "INDETERMINATE") {
      expect(toAttentionReason(outcome.reason)).toBe("LINEAGE_GAP");
    }
  });
});

describe("MOVE_INTERNAL no premature completion on partial confirmation", () => {
  // The full observation alphabet a POST_SUBMIT reconcile can see on one leg.
  const LEG_OBSERVATIONS: readonly PathObservation[] = [
    landedAt(0),
    landedAt(3),
    landedAt(0, "some-other-body-sha256"),
    { result: "PROOF_INCOMPLETE", fault: "GAP" },
    { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" },
    { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" },
    { result: "ANOMALY", anomaly: "REGRESSION" },
    { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" },
    { result: "NO_SUCCESSOR" },
  ];

  it("LANDED_VERIFIED is reachable ONLY when both legs prove the same persisted move body", () => {
    // Exhaustive over the leg alphabet: any pairing that is not two proofs anchored to BODY must
    // NOT be classified as a verified landing. This is the no-premature-completion guarantee — a
    // single confirmed leg, a proof against the wrong body, an incomplete proof, an anomaly, or an
    // unchanged head can never be mistaken for a completed move.
    for (const sourceObservation of LEG_OBSERVATIONS) {
      for (const destinationObservation of LEG_OBSERVATIONS) {
        const outcome = classifyMoveReconcile(postSubmit({ sourceObservation, destinationObservation }));
        const bothAnchoredToBody =
          sourceObservation.result === "PROOF" &&
          destinationObservation.result === "PROOF" &&
          sourceObservation.proof.expectedBodySha256 === BODY &&
          destinationObservation.proof.expectedBodySha256 === BODY;
        if (outcome.kind === "LANDED_VERIFIED") {
          expect(bothAnchoredToBody).toBe(true);
        }
      }
    }
  });

  it("a single confirmed leg never completes the move (the other leg always blocks LANDED_VERIFIED)", () => {
    for (const otherLeg of LEG_OBSERVATIONS) {
      if (otherLeg.result === "PROOF" && otherLeg.proof.expectedBodySha256 === BODY) continue;
      const sourceConfirmed = classifyMoveReconcile(
        postSubmit({ sourceObservation: landedAt(2), destinationObservation: otherLeg }),
      );
      const destinationConfirmed = classifyMoveReconcile(
        postSubmit({ sourceObservation: otherLeg, destinationObservation: landedAt(2) }),
      );
      expect(sourceConfirmed.kind).not.toBe("LANDED_VERIFIED");
      expect(destinationConfirmed.kind).not.toBe("LANDED_VERIFIED");
    }
  });

  it("no POST_SUBMIT observation pairing ever authorizes a second attempt, retry, rebuild, or release", () => {
    // The never-blind-retry rule / landing-path oracle: once a submit claim exists (which is exactly what routes evidence
    // through POST_SUBMIT), no outcome may license another call. PROVEN_NOT_STARTED is the only kind
    // that authorizes a first call and it is unreachable from POST_SUBMIT; WAITING/retry/rebuild/
    // release authority fields do not exist anywhere on MoveReconcileOutcome.
    const reachableKinds = new Set<MoveReconcileOutcome["kind"]>();
    for (const sourceObservation of LEG_OBSERVATIONS) {
      for (const destinationObservation of LEG_OBSERVATIONS) {
        reachableKinds.add(
          classifyMoveReconcile(postSubmit({ sourceObservation, destinationObservation })).kind,
        );
      }
    }
    expect(reachableKinds.has("PROVEN_NOT_STARTED")).toBe(false);
    expect(reachableKinds).toEqual(new Set(["LANDED_VERIFIED", "INDETERMINATE", "INVARIANT_BREACH"]));
  });

  it("MoveReconcileOutcome carries no retry/rebuild/resubmit/release field on any branch", () => {
    // @ts-expect-error — no branch of MoveReconcileOutcome has a "retryAuthorized" (or equivalent)
    // field; there is no way to spell "may resubmit/rebuild/release" in this type.
    const bad: MoveReconcileOutcome = { kind: "INDETERMINATE", moveAttemptId: ATTEMPT, retryAuthorized: true, reason: { source: "PATH_DISAGREEMENT" } };
    expect(bad).toBeDefined();
  });
});
