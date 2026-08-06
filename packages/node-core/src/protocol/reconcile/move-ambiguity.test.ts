// permanent MOVE ambiguity handling.
//
// Exit criteria pinned here:
// 1. Every named evidence kind → WAITING | INDETERMINATE | INVARIANT_BREACH | LANDED_VERIFIED
// — never a second attempt, never lease release.
// 2. PROVEN_NOT_STARTED authorizes only the first call of the still-unsubmitted attempt
// (isRebuild: false; no archive-old-attempt field).
// 3. Indefinite reconciliation: N bounded re-reads retain both leases; no auto-release.
// 4. REBUILD_INTERNAL_MOVE / SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING deliberately absent
// (MOVE_AMBIGUITY_FORBIDDEN_ACTIONS + isMoveAmbiguityActionPermitted === false).

import { describe, expect, it } from "vitest";

import { type ObservationAnomalyKind } from "@zucoins/generic-node-contracts/observation";

import {
  mintLandingPathProofFromOracle,
} from "./landing-oracle-mint.fixture.js";
import { type PathObservation } from "./observation-input.js";
import {
  MOVE_AMBIGUITY_FORBIDDEN_ACTIONS,
  assertMoveAmbiguityLeasesHeld,
  classifyMoveAmbiguity,
  continueMoveAmbiguityReconciliation,
  isMoveAmbiguityActionPermitted,
  moveAmbiguityPermitsSecondAttempt,
  moveAmbiguityPermitsSubmitCall,
  moveAmbiguityRetainsBothLeases,
  type MoveAmbiguityEvidenceKind,
  type MoveAmbiguityOutcome,
  type MoveSubmitTransportEvidence,
} from "./move-ambiguity.js";
import { type MoveObservationEvidence } from "./move.js";

const ATTEMPT = "move-attempt-1";
const SOURCE = "wallet-source";
const DEST = "wallet-destination";
const BODY = "move-body-sha256";

function proof(depth = 0) {
  return depth === 0
    ? mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub",
      expectedBodySha256: BODY,
      freshHeadBodySha256: BODY,
      freshHeadObservationId: "obs",
      depth: 0,
    })
    : mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub",
      expectedBodySha256: BODY,
      freshHeadBodySha256: (BODY + "-head"),
      freshHeadObservationId: "obs",
      depth: depth,
    });
}

const LANDED: PathObservation = { result: "PROOF", proof: proof(0) };
const NO_SUCCESSOR: PathObservation = { result: "NO_SUCCESSOR" };
const GAP: PathObservation = { result: "PROOF_INCOMPLETE", fault: "GAP" };
const BUDGET: PathObservation = { result: "PROOF_INCOMPLETE", fault: "BUDGET_EXHAUSTED" };
const BREACH: PathObservation = { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" };

function observation(
  overrides: Partial<MoveObservationEvidence> = {},
): MoveObservationEvidence {
  return {
    boundary: "POST_SUBMIT",
    moveAttemptId: ATTEMPT,
    sourceWalletId: SOURCE,
    destinationWalletId: DEST,
    expectedMoveBodySha256: BODY,
    sourceLeaseState: "ACTIVE",
    destinationLeaseState: "ACTIVE",
    sourceObservation: NO_SUCCESSOR,
    destinationObservation: NO_SUCCESSOR,
    ...overrides,
  };
}

function post(
  obs: Partial<MoveObservationEvidence> = {},
  extras: {
    readonly transport?: MoveSubmitTransportEvidence;
    readonly operatorActionRecorded?: boolean;
    readonly transactionExpired?: boolean;
  } = {},
): MoveAmbiguityOutcome {
  return classifyMoveAmbiguity({
    phase: "POST_SUBMIT",
    observation: observation(obs),
    ...extras,
  });
}

function assertPermanentPin(outcome: MoveAmbiguityOutcome): void {
  expect(moveAmbiguityRetainsBothLeases(outcome)).toBe(true);
  expect(outcome.retainSourceLease).toBe(true);
  expect(outcome.retainDestinationLease).toBe(true);
  expect(moveAmbiguityPermitsSecondAttempt(outcome)).toBe(false);
  if (outcome.kind !== "PROVEN_NOT_STARTED") {
    expect(outcome.permitsSubmitCall).toBe(false);
    expect(outcome.permitsSecondAttempt).toBe(false);
    expect(moveAmbiguityPermitsSubmitCall(outcome)).toBe(false);
  }
  // No rebuild / second-attempt field may appear on any outcome object.
  expect(outcome).not.toHaveProperty("secondAttemptId");
  expect(outcome).not.toHaveProperty("attemptNumber");
  expect(outcome).not.toHaveProperty("rebuild");
  expect(outcome).not.toHaveProperty("archiveOldAttempt");
  expect(outcome).not.toHaveProperty("provenNotLanded");
  expect(outcome).not.toHaveProperty("releaseSourceLease");
  expect(outcome).not.toHaveProperty("releaseDestinationLease");
}

// ─── Forbidden rebuild surface (deliberate omission) ───────────────────

describe("landing-path oracle — REBUILD_INTERNAL_MOVE deliberately not implemented", () => {
  it("lists every stale-spec rebuild/release token as forbidden", () => {
    expect(MOVE_AMBIGUITY_FORBIDDEN_ACTIONS).toEqual(
      expect.arrayContaining([
        "REBUILD_INTERNAL_MOVE",
        "SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING",
        "PROVEN_NOT_LANDED",
        "ARCHIVE_OLD_ATTEMPT",
        "CREATE_ATTEMPT_2",
        "RETRY_SUBMIT",
        "RESUBMIT",
        "FORCE_RELEASE_SOURCE_LEASE",
        "FORCE_RELEASE_DESTINATION_LEASE",
        "ASSUME_NOT_LANDED_FROM_TIMEOUT",
        "ASSUME_NOT_LANDED_FROM_UNCHANGED_HEAD",
        "ASSUME_NOT_LANDED_FROM_EXPIRY",
        "ASSUME_NOT_LANDED_FROM_ACK",
      ]),
    );
  });

  it.each([...MOVE_AMBIGUITY_FORBIDDEN_ACTIONS])(
    "isMoveAmbiguityActionPermitted(%s) === false",
    (action) => {
      expect(isMoveAmbiguityActionPermitted(action)).toBe(false);
    },
  );

  it("outcome union has no PROVEN_NOT_LANDED / REBUILD member (compile + runtime)", () => {
    type OutcomeKind = MoveAmbiguityOutcome["kind"];
    type HasProvenNotLanded = "PROVEN_NOT_LANDED" extends OutcomeKind ? true : false;
    const provenNotLandedUnrepresentable: HasProvenNotLanded = false;
    expect(provenNotLandedUnrepresentable).toBe(false);

    // Excess-property check: a rebuild token cannot be carried on any outcome branch.
    const bad: MoveAmbiguityOutcome = {
      kind: "INDETERMINATE",
      moveAttemptId: ATTEMPT,
      evidenceKind: "TIMEOUT",
      reason: { source: "SUBMIT_OUTCOME_UNKNOWN" },
      retainSourceLease: true,
      retainDestinationLease: true,
      permitsSubmitCall: false,
      permitsSecondAttempt: false,
      automaticEffect: "PARK_NEEDS_ATTENTION_RETAIN_LEASES",
      attentionReason: "SUBMIT_OUTCOME_AMBIGUOUS",
      // @ts-expect-error — rebuildAction is not a member of any MoveAmbiguityOutcome branch (landing-path oracle).
      rebuildAction: "REBUILD_INTERNAL_MOVE",
    };
    expect(bad).toBeDefined();
  });
});

// ─── PRE_SUBMIT: PROVEN_NOT_STARTED is first-call only ──────────────────────

describe("PRE_SUBMIT — PROVEN_NOT_STARTED authorizes first call only", () => {
  it("no preimage → FIRST_FORMATION; isRebuild false; permitsSubmitCall true", () => {
    const outcome = classifyMoveAmbiguity({
      phase: "PRE_SUBMIT",
      formation: {
        boundary: "PRE_SUBMIT",
        moveAttemptId: ATTEMPT,
        preimagePersisted: false,
        signaturesComplete: false,
        signerAuditIndicatesCall: false,
      },
    });
    expect(outcome.kind).toBe("PROVEN_NOT_STARTED");
    if (outcome.kind === "PROVEN_NOT_STARTED") {
      expect(outcome.resumeAction).toBe("FIRST_FORMATION");
      expect(outcome.isRebuild).toBe(false);
      expect(outcome.permitsSubmitCall).toBe(true);
      expect(outcome.automaticEffect).toBe("CONTINUE_FIRST_FORMATION_OR_SUBMIT");
    }
    assertPermanentPin(outcome);
    expect(moveAmbiguityPermitsSubmitCall(outcome)).toBe(true);
  });

  it("full transaction, no submit claim → SUBMIT_ONCE of the same attempt (not rebuild)", () => {
    const outcome = classifyMoveAmbiguity({
      phase: "PRE_SUBMIT",
      formation: {
        boundary: "PRE_SUBMIT",
        moveAttemptId: ATTEMPT,
        preimagePersisted: true,
        signaturesComplete: true,
        signerAuditIndicatesCall: false,
      },
    });
    expect(outcome.kind).toBe("PROVEN_NOT_STARTED");
    if (outcome.kind === "PROVEN_NOT_STARTED") {
      expect(outcome.resumeAction).toBe("SUBMIT_ONCE");
      expect(outcome.isRebuild).toBe(false);
      // Distinguishable from rebuild: no archive step, same moveAttemptId, isRebuild=false.
      expect(outcome).not.toHaveProperty("archivedAttemptId");
      expect(outcome.moveAttemptId).toBe(ATTEMPT);
    }
    assertPermanentPin(outcome);
  });

  it("signer audit contradicts missing preimage → INVARIANT_BREACH, no submit", () => {
    const outcome = classifyMoveAmbiguity({
      phase: "PRE_SUBMIT",
      formation: {
        boundary: "PRE_SUBMIT",
        moveAttemptId: ATTEMPT,
        preimagePersisted: false,
        signaturesComplete: false,
        signerAuditIndicatesCall: true,
      },
    });
    expect(outcome.kind).toBe("INVARIANT_BREACH");
    assertPermanentPin(outcome);
    expect(moveAmbiguityPermitsSubmitCall(outcome)).toBe(false);
  });
});

// ─── Every named evidence kind ──────────────────────────────────────────────

describe("POST_SUBMIT — every evidence kind parks or waits; never second attempt", () => {
  const cases: ReadonlyArray<{
    readonly label: MoveAmbiguityEvidenceKind | string;
    readonly obs?: Partial<MoveObservationEvidence>;
    readonly extras?: {
      readonly transport?: MoveSubmitTransportEvidence;
      readonly operatorActionRecorded?: boolean;
      readonly transactionExpired?: boolean;
    };
    readonly expectedKind: MoveAmbiguityOutcome["kind"];
    readonly expectedEvidence?: MoveAmbiguityEvidenceKind;
  }> = [
    {
      label: "TIMEOUT",
      extras: { transport: { kind: "TIMEOUT" } },
      expectedKind: "WAITING",
      expectedEvidence: "TIMEOUT",
    },
    {
      label: "ACK",
      extras: { transport: { kind: "ACK", gatewayCode: "ok" } },
      expectedKind: "WAITING",
      expectedEvidence: "ACK",
    },
    {
      label: "REJECT",
      extras: { transport: { kind: "REJECT", gatewayCode: "bad" } },
      expectedKind: "WAITING",
      expectedEvidence: "REJECT",
    },
    {
      label: "TRANSPORT_ERROR",
      extras: { transport: { kind: "TRANSPORT_ERROR", detail: "ECONNRESET" } },
      expectedKind: "WAITING",
      expectedEvidence: "TRANSPORT_ERROR",
    },
    {
      label: "UNREADABLE_RESPONSE",
      extras: { transport: { kind: "UNREADABLE_RESPONSE" } },
      expectedKind: "WAITING",
      expectedEvidence: "UNREADABLE_RESPONSE",
    },
    {
      label: "EXPIRY (unchanged heads)",
      extras: { transactionExpired: true },
      expectedKind: "WAITING",
      expectedEvidence: "EXPIRY",
    },
    {
      label: "UNCHANGED_HEAD",
      expectedKind: "WAITING",
      expectedEvidence: "UNCHANGED_HEAD",
    },
    {
      label: "CHANGED_HEAD / unattributed successor",
      obs: { sourceObservation: BREACH, destinationObservation: NO_SUCCESSOR },
      expectedKind: "INVARIANT_BREACH",
      expectedEvidence: "CHANGED_HEAD",
    },
    {
      label: "INCOMPLETE_LINEAGE (GAP)",
      obs: { sourceObservation: GAP, destinationObservation: GAP },
      expectedKind: "INDETERMINATE",
      expectedEvidence: "INCOMPLETE_LINEAGE",
    },
    {
      label: "RESOURCE_EXHAUSTION",
      obs: { sourceObservation: BUDGET, destinationObservation: BUDGET },
      expectedKind: "INDETERMINATE",
      expectedEvidence: "RESOURCE_EXHAUSTION",
    },
    {
      label: "ANOMALY (park-class)",
      obs: {
        sourceObservation: { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" },
        destinationObservation: { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" },
      },
      expectedKind: "INDETERMINATE",
      expectedEvidence: "ANOMALY",
    },
    {
      label: "OPERATOR_ACTION",
      extras: { operatorActionRecorded: true },
      expectedKind: "INDETERMINATE",
      expectedEvidence: "OPERATOR_ACTION",
    },
    {
      label: "PATH_DISAGREEMENT (one landed, one not)",
      obs: { sourceObservation: LANDED, destinationObservation: NO_SUCCESSOR },
      expectedKind: "INDETERMINATE",
      expectedEvidence: "PATH_DISAGREEMENT",
    },
    {
      label: "DUAL_PATH_LANDED",
      obs: { sourceObservation: LANDED, destinationObservation: LANDED },
      expectedKind: "LANDED_VERIFIED",
      expectedEvidence: "DUAL_PATH_LANDED",
    },
    {
      label: "LEASE_NOT_ACTIVE",
      obs: { sourceLeaseState: "RELEASED" },
      expectedKind: "INVARIANT_BREACH",
      expectedEvidence: "LEASE_NOT_ACTIVE",
    },
  ];

  it.each(cases)("$label → $expectedKind (pin holds)", (c) => {
    const outcome = post(c.obs, c.extras);
    expect(outcome.kind).toBe(c.expectedKind);
    if (c.expectedEvidence !== undefined && outcome.kind !== "PROVEN_NOT_STARTED") {
      expect(outcome.evidenceKind).toBe(c.expectedEvidence);
    }
    assertPermanentPin(outcome);
    // Never invents a second attempt identity.
    if (outcome.kind !== "PROVEN_NOT_STARTED") {
      expect(outcome.moveAttemptId).toBe(ATTEMPT);
    }
  });

  it("ACK + dual landed paths → LANDED_VERIFIED (ACK never blocks proven landing)", () => {
    const outcome = post(
      { sourceObservation: LANDED, destinationObservation: LANDED },
      { transport: { kind: "ACK" } },
    );
    expect(outcome.kind).toBe("LANDED_VERIFIED");
    assertPermanentPin(outcome);
  });

  it("TIMEOUT + incomplete lineage → INDETERMINATE (timeout is not non-landing)", () => {
    const outcome = post(
      { sourceObservation: GAP, destinationObservation: GAP },
      { transport: { kind: "TIMEOUT" } },
    );
    expect(outcome.kind).toBe("INDETERMINATE");
    assertPermanentPin(outcome);
  });

  it("REJECT transport is NOT rebuild authority (superseded case 1)", () => {
    // Case 1 described deterministic pre-acceptance rejection as rebuild evidence.
    // REJECT never creates attempt 2 or releases either wallet.
    const outcome = post(
      { sourceObservation: NO_SUCCESSOR, destinationObservation: NO_SUCCESSOR },
      { transport: { kind: "REJECT", gatewayCode: "rejected_before_accept" } },
    );
    expect(outcome.kind).toBe("WAITING");
    expect(moveAmbiguityPermitsSecondAttempt(outcome)).toBe(false);
    expect(isMoveAmbiguityActionPermitted("REBUILD_INTERNAL_MOVE")).toBe(false);
    assertPermanentPin(outcome);
  });

  it("EXPIRY + unchanged heads is NOT rebuild authority (superseded case 2)", () => {
    const outcome = post(
      {},
      { transactionExpired: true, transport: { kind: "ACK" } },
    );
    // Expiry flag wins evidence kind; still WAITING (keep reading), never rebuild.
    expect(["WAITING", "INDETERMINATE"]).toContain(outcome.kind);
    expect(moveAmbiguityPermitsSecondAttempt(outcome)).toBe(false);
    expect(isMoveAmbiguityActionPermitted("ASSUME_NOT_LANDED_FROM_EXPIRY")).toBe(false);
    assertPermanentPin(outcome);
  });
});

// ─── Evidence combinations (every combination) ─────────────────────────────

describe("evidence combinations never unlock second attempt", () => {
  const transports: MoveSubmitTransportEvidence[] = [
    { kind: "TIMEOUT" },
    { kind: "ACK" },
    { kind: "REJECT" },
    { kind: "TRANSPORT_ERROR" },
    { kind: "UNREADABLE_RESPONSE" },
    { kind: "NO_RESPONSE_CAPTURED" },
  ];
  const obsPairs: Array<readonly [PathObservation, PathObservation]> = [
    [NO_SUCCESSOR, NO_SUCCESSOR],
    [GAP, GAP],
    [LANDED, NO_SUCCESSOR],
    [NO_SUCCESSOR, LANDED],
    [LANDED, LANDED],
    [BREACH, NO_SUCCESSOR],
    [BUDGET, BUDGET],
    [
      { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" satisfies ObservationAnomalyKind },
      { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
    ],
  ];

  it("cartesian transport × observation leaves permitsSecondAttempt=false and leases held", () => {
    const kinds = new Set<MoveAmbiguityOutcome["kind"]>();
    for (const transport of transports) {
      for (const [sourceObservation, destinationObservation] of obsPairs) {
        for (const transactionExpired of [false, true]) {
          for (const operatorActionRecorded of [false, true]) {
            const outcome = post(
              { sourceObservation, destinationObservation },
              { transport, transactionExpired, operatorActionRecorded },
            );
            kinds.add(outcome.kind);
            assertPermanentPin(outcome);
            expect(outcome.kind).not.toBe("PROVEN_NOT_STARTED");
          }
        }
      }
    }
    // Reachable set is the closed post-submit set only.
    for (const k of kinds) {
      expect(["WAITING", "INDETERMINATE", "INVARIANT_BREACH", "LANDED_VERIFIED"]).toContain(k);
    }
    expect(kinds.has("PROVEN_NOT_STARTED" as MoveAmbiguityOutcome["kind"])).toBe(false);
  });
});

// ─── Indefinite reconciliation ──────────────────────────────────────────────

describe("indefinite reconciliation — leases held across many passes", () => {
  it("100 bounded re-reads with no resolving evidence retain both leases; never submit", () => {
    let outcome = post({}, { transport: { kind: "TIMEOUT" } });
    expect(outcome.kind).toBe("WAITING");

    for (let pass = 1; pass <= 100; pass++) {
      if (outcome.kind === "LANDED_VERIFIED" || outcome.kind === "PROVEN_NOT_STARTED") {
        throw new Error("test fixture broke: unexpected terminal before loop end");
      }
      outcome = continueMoveAmbiguityReconciliation(
        outcome,
        observation({ sourceObservation: NO_SUCCESSOR, destinationObservation: NO_SUCCESSOR }),
        { transport: { kind: "TIMEOUT" }, passCount: pass },
      );
      assertPermanentPin(outcome);
      expect(moveAmbiguityPermitsSubmitCall(outcome)).toBe(false);
      expect(["WAITING", "INDETERMINATE", "INVARIANT_BREACH"]).toContain(outcome.kind);
    }
    // Still parked/waiting after extended reconciliation — no auto-release, no rebuild.
    expect(outcome.kind).toBe("WAITING");
    expect(isMoveAmbiguityActionPermitted("FORCE_RELEASE_EITHER_LEASE")).toBe(false);
  });

  it("passCount is ignored for authority (no attempt budget / no auto-release timer)", () => {
    const first = post({}, { transport: { kind: "ACK" } });
    if (first.kind === "LANDED_VERIFIED" || first.kind === "PROVEN_NOT_STARTED") {
      throw new Error("unexpected");
    }
    const later = continueMoveAmbiguityReconciliation(first, observation(), {
      transport: { kind: "ACK" },
      passCount: 10_000,
    });
    expect(later.kind).toBe(first.kind);
    assertPermanentPin(later);
  });

  it("a later dual-path landing resolves without ever having submitted again", () => {
    let outcome = post({}, { transport: { kind: "TIMEOUT" } });
    if (outcome.kind === "LANDED_VERIFIED" || outcome.kind === "PROVEN_NOT_STARTED") {
      throw new Error("unexpected");
    }
    for (let i = 0; i < 5; i++) {
      if (outcome.kind === "LANDED_VERIFIED" || outcome.kind === "PROVEN_NOT_STARTED") {
        throw new Error("unexpected mid-loop land");
      }
      outcome = continueMoveAmbiguityReconciliation(outcome, observation());
      assertPermanentPin(outcome);
    }
    if (outcome.kind === "LANDED_VERIFIED" || outcome.kind === "PROVEN_NOT_STARTED") {
      throw new Error("unexpected mid-loop land");
    }
    // Buried destination still lands when both paths complete — no second submit required.
    const landed = continueMoveAmbiguityReconciliation(
      outcome,
      observation({
        sourceObservation: { result: "PROOF", proof: proof(0) },
        destinationObservation: { result: "PROOF", proof: proof(3) },
      }),
    );
    expect(landed.kind).toBe("LANDED_VERIFIED");
    assertPermanentPin(landed);
  });
});

// ─── Lease helper ───────────────────────────────────────────────────────────

describe("lease retention helper", () => {
  it("both ACTIVE → held", () => {
    expect(assertMoveAmbiguityLeasesHeld("ACTIVE", "ACTIVE")).toEqual({ bothHeld: true });
  });

  it.each([
    ["RELEASED", "ACTIVE"],
    ["ACTIVE", "RELEASED"],
    ["RELEASED", "RELEASED"],
  ] as const)("source=%s dest=%s → not held (breach class)", (s, d) => {
    expect(assertMoveAmbiguityLeasesHeld(s, d)).toEqual({
      bothHeld: false,
      kind: "INVARIANT_BREACH",
    });
  });
});

// ─── Structural: no second-attempt constructor ──────────────────────────────

describe("structural no-second-attempt guarantees", () => {
  it("POST_SUBMIT never returns PROVEN_NOT_STARTED (would re-authorize submit)", () => {
    const outcome = post({
      sourceObservation: GAP,
      destinationObservation: BREACH,
      sourceLeaseState: "RELEASED",
    });
    expect(outcome.kind).not.toBe("PROVEN_NOT_STARTED");
    assertPermanentPin(outcome);
  });

  it("automaticEffect vocabulary excludes rebuild/release/resubmit", () => {
    const effects = new Set<string>();
    const samples: MoveAmbiguityOutcome[] = [
      post({}),
      post({ sourceObservation: GAP, destinationObservation: GAP }),
      post({ sourceObservation: BREACH }),
      post({ sourceObservation: LANDED, destinationObservation: LANDED }),
      classifyMoveAmbiguity({
        phase: "PRE_SUBMIT",
        formation: {
          boundary: "PRE_SUBMIT",
          moveAttemptId: ATTEMPT,
          preimagePersisted: true,
          signaturesComplete: true,
          signerAuditIndicatesCall: false,
        },
      }),
    ];
    for (const o of samples) {
      effects.add(o.automaticEffect);
      assertPermanentPin(o);
    }
    expect(effects.has("CONTINUE_BOUNDED_READ_RECONCILIATION") || effects.has("PARK_NEEDS_ATTENTION_RETAIN_LEASES")).toBe(
      true,
    );
    for (const forbidden of [
      "REBUILD",
      "RELEASE_LEASES",
      "RESUBMIT",
      "ARCHIVE_AND_RETRY",
      "PROVEN_NOT_LANDED",
    ]) {
      expect([...effects].join(",")).not.toContain(forbidden);
    }
  });
});
