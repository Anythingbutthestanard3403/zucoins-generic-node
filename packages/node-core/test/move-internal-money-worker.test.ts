// Offline MOVE_INTERNAL money-worker composition.
// CREATED → INTERNAL_MOVE_LANDED via lease, baseline OBSERVE, form/sign, submit-once, land.
// Reconcile-first on ambiguous submit (never second submit). No network.
// Review A+B: No-blind-retry durable claim reload; dual-path land; crash-resume durable reload;
// lease revalidate; AMBIGUOUS-without-claim fails closed.

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import type { DualBaselineCapture } from "../src/protocol/move-baseline.js";
import { mintLandingPathProofFromOracle } from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";
import type { MoveReconcileOutcome } from "../src/protocol/reconcile/move.js";
import type { PersistedExpectedArtifact } from "../src/core/move-baseline-binding.js";
import type { DurableMoveInner } from "../src/core/move-form-inner.js";
import type { SignedMoveSteps } from "../src/core/move-form-and-sign.js";
import type { MoveSubmitExecutionResult } from "../src/core/move-submit-claim.js";
import {
  MOVE_MONEY_WORKER_STEPS,
  advanceMoveInternalMoneyWorker,
  nextMoveMoneyWorkerStep,
  runMoveInternalMoneyWorker,
  type MoveBaselineBound,
  type MoveHeldLeasePair,
  type MoveInternalMoneyWorkerPorts,
  type MoveWorkerDurableProgress,
} from "../src/workers/move-internal-money-worker.js";

const OP = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SRC = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DST = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const SRC_T0 = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const DST_T0 = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const SRC_TERM = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const DST_TERM = "11111111-1111-4111-8111-111111111111";
const BODY_SHA = "a".repeat(64);
const PUBKEY = `${"A".repeat(43)}=`;

function emptyProgress(overrides: Partial<MoveWorkerDurableProgress> = {}): MoveWorkerDurableProgress {
  return {
    operationId: OP,
    operationStatus: "CREATED",
    rowVersion: 1,
    bothLeasesHeld: false,
    baselinesBound: false,
    innerPreimagePersisted: false,
    signaturesComplete: false,
    submitClaimed: false,
    submitOutcome: null,
    landDualPathVerified: false,
    landed: false,
    ...overrides,
  };
}

function fakeCapture(): DualBaselineCapture {
  return {
    operationId: OP,
    sourceWalletPublicKey: PUBKEY,
    destinationWalletPublicKey: `${"B".repeat(43)}=`,
    sourceBaseline: { role: "sender", S: "s0", P: "p0", B: "1.00", I: null },
    destinationBaseline: { role: "receiver", S: "s1", P: "p1", B: "0", I: null },
    amountZkz: "0.01" as DualBaselineCapture["amountZkz"],
    capturedAt: 1_700_000_000_000,
  };
}

function fakeArtifact(): PersistedExpectedArtifact {
  return {
    id: randomUUID(),
    operationId: OP,
    purpose: "zp-move-internal-expected-v1",
    canonicalVersion: 1,
    signingKeyId: randomUUID(),
    preimageText: "zp-move-internal-expected-v1\n{}",
    preimageSha256: BODY_SHA,
    signature: `${"C".repeat(86)}==`,
  };
}

function fakeDurableInner(): DurableMoveInner {
  return {
    operationId: OP,
    attemptNo: 1 as const,
    attemptPhase: "INNER_PREIMAGE_PERSISTED",
    innerPreimageText: '{"amount":"0.01"}',
    innerSha256: BODY_SHA,
    sourceT0ObservationId: SRC_T0,
    destinationT0ObservationId: DST_T0,
    expectedArtifactPreimageText: "zp-move-internal-expected-v1\n{}",
    expectedArtifactPreimageSha256: BODY_SHA,
    formedAt: "2026-07-29T00:00:00.000Z",
  } as DurableMoveInner;
}

function fakeSigned(): SignedMoveSteps {
  return {
    operationId: OP,
    innerPreimageText: '{"amount":"0.01"}',
    step1Signature: `${"D".repeat(86)}==`,
    step2PreimageText: '{"inner":{},"step_1_signature":"x"}',
    step2PreimageSha256: BODY_SHA,
    step2Signature: `${"E".repeat(86)}==`,
    completedTransactionText: '{"inner":{},"step_1_signature":"x","step_2_signature":"y"}',
    completedTransactionSha256: BODY_SHA,
  };
}

function dualPathLandedOutcome(): MoveReconcileOutcome {
  return {
    kind: "LANDED_VERIFIED",
    moveAttemptId: OP,
    sourcePath: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: PUBKEY,
      expectedBodySha256: BODY_SHA,
      freshHeadBodySha256: BODY_SHA,
      freshHeadObservationId: SRC_TERM,
      depth: 0,
    }),
    destinationPath: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: `${"B".repeat(43)}=`,
      expectedBodySha256: BODY_SHA,
      freshHeadBodySha256: BODY_SHA,
      freshHeadObservationId: DST_TERM,
      depth: 0,
    }),
  };
}

/**
 * In-memory double that advances durable progress exactly as a SQL-backed store would.
 * submitOnce options exercise No-blind-retry claim durability vs injectable lies.
 */
function createOfflinePorts(options?: {
  readonly submitStatus?: "ACK" | "AMBIGUOUS" | "REJECT";
  readonly loseMint?: boolean;
  /** Return AMBIGUOUS without minting a durable claim — must NOT HOLD as if claimed. */
  readonly ambiguousWithoutClaim?: boolean;
  readonly landFail?: boolean;
}): {
  readonly ports: MoveInternalMoneyWorkerPorts;
  readonly submitCalls: number;
  readonly acquireCalls: number;
  readonly progress: () => MoveWorkerDurableProgress;
} {
  const progress = emptyProgress();
  let submitCalls = 0;
  let acquireCalls = 0;
  const leases: MoveHeldLeasePair = {
    sourceWalletId: SRC,
    sourceLeaseEpoch: 1n,
    destinationWalletId: DST,
    destinationLeaseEpoch: 1n,
  };
  const bound: MoveBaselineBound = {
    capture: fakeCapture(),
    sourceT0ObservationId: SRC_T0,
    destinationT0ObservationId: DST_T0,
    artifact: fakeArtifact(),
  };
  const signedMaterial = { signed: fakeSigned() };

  const ports: MoveInternalMoneyWorkerPorts = {
    loadProgress: async () => ({ ...progress }),

    acquireDualLeases: async () => {
      acquireCalls += 1;
      progress.bothLeasesHeld = true;
      return { ok: true, leases };
    },

    captureBaselines: async () => {
      progress.baselinesBound = true;
      return { ok: true, bound };
    },

    loadBaselineBound: async () => {
      if (!progress.baselinesBound) return null;
      return bound;
    },

    formInner: async () => {
      progress.innerPreimagePersisted = true;
      return { ok: true, formed: { durable: fakeDurableInner() } };
    },

    signUnderLeases: async () => {
      progress.signaturesComplete = true;
      return { ok: true, signed: signedMaterial };
    },

    loadSignedMaterial: async () => {
      if (!progress.signaturesComplete) return null;
      return signedMaterial;
    },

    submitOnce: async () => {
      submitCalls += 1;
      if (options?.ambiguousWithoutClaim === true) {
        // Break the envelope: report AMBIGUOUS but leave durable claim false.
        return { ok: false, reason: "port lied: ambiguous without claim", ambiguous: true };
      }
      progress.submitClaimed = true;
      if (options?.loseMint === true) {
        const result: MoveSubmitExecutionResult = {
          claim: {
            attemptId: randomUUID(),
            claimedAt: "2026-07-29T00:00:01.000Z",
            operationId: OP,
            transactionAttemptNo: 1,
          },
          executed: false,
          recordedOutcome: null,
        };
        return { ok: true, submitted: { result } };
      }
      const status = options?.submitStatus ?? "ACK";
      progress.submitOutcome = status;
      const result: MoveSubmitExecutionResult = {
        claim: {
          attemptId: randomUUID(),
          claimedAt: "2026-07-29T00:00:01.000Z",
          operationId: OP,
          transactionAttemptNo: 1,
        },
        executed: true,
        recordedOutcome: {
          status,
          capture: null,
          recordedAttempt: {
            decisionId: randomUUID(),
            operationId: OP,
            attemptNo: 1,
            transactionAttemptNo: 1,
            requestBytes: new Uint8Array(),
            requestSha256: BODY_SHA,
            responseBytes: null,
            responseSha256: null,
            transportOutcome: status === "AMBIGUOUS" ? "INDETERMINATE" : status,
            startedAt: "2026-07-29T00:00:01.000Z",
            completedAt: "2026-07-29T00:00:02.000Z",
          },
        },
      };
      if (status === "AMBIGUOUS") {
        // Claim is durable before outcome classification (No-blind-retry) — seam reports ambiguous.
        return { ok: false, reason: "transport AMBIGUOUS", ambiguous: true };
      }
      return { ok: true, submitted: { result } };
    },

    reconcileAndLand: async () => {
      if (options?.landFail === true) {
        return {
          ok: false,
          reason: "INDETERMINATE dual-path",
          holdReconcile: true,
        };
      }
      const outcome = dualPathLandedOutcome();
      progress.landed = true;
      progress.landDualPathVerified = true;
      progress.operationStatus = "INTERNAL_MOVE_LANDED";
      progress.rowVersion = 2;
      return {
        ok: true,
        land: {
          outcome,
          persist: {
            kind: "PERSISTED",
            state: "INTERNAL_MOVE_LANDED",
            rowVersion: 2,
          },
        },
      };
    },
  };

  return {
    ports,
    get submitCalls() {
      return submitCalls;
    },
    get acquireCalls() {
      return acquireCalls;
    },
    progress: () => ({ ...progress }),
  };
}

/** Progress already past sign — only SUBMIT remains. Scratch empty (crash resume). */
function progressReadyToSubmit(overrides: Partial<MoveWorkerDurableProgress> = {}): MoveWorkerDurableProgress {
  return emptyProgress({
    bothLeasesHeld: true,
    baselinesBound: true,
    innerPreimagePersisted: true,
    signaturesComplete: true,
    submitClaimed: false,
    ...overrides,
  });
}

describe("MOVE_INTERNAL money-worker pipeline", () => {
  it("exposes the closed operation-flow step set", () => {
    expect(MOVE_MONEY_WORKER_STEPS).toEqual([
      "LEASE",
      "BASELINE",
      "FORM",
      "SIGN",
      "SUBMIT",
      "LAND",
    ]);
  });

  it("nextMoveMoneyWorkerStep never returns SUBMIT once claim exists (No-blind-retry)", () => {
    expect(nextMoveMoneyWorkerStep(emptyProgress())).toBe("LEASE");
    expect(
      nextMoveMoneyWorkerStep(
        emptyProgress({
          bothLeasesHeld: true,
          baselinesBound: true,
          innerPreimagePersisted: true,
          signaturesComplete: true,
          submitClaimed: true,
        }),
      ),
    ).toBe("LAND");
    expect(
      nextMoveMoneyWorkerStep(
        emptyProgress({
          bothLeasesHeld: true,
          baselinesBound: true,
          innerPreimagePersisted: true,
          signaturesComplete: true,
          submitClaimed: false,
        }),
      ),
    ).toBe("SUBMIT");
  });

  it("status INTERNAL_MOVE_LANDED without dual-path proof is LAND not DONE", () => {
    expect(
      nextMoveMoneyWorkerStep(
        emptyProgress({
          operationStatus: "INTERNAL_MOVE_LANDED",
          landed: true,
          landDualPathVerified: false,
          bothLeasesHeld: true,
          baselinesBound: true,
          innerPreimagePersisted: true,
          signaturesComplete: true,
          submitClaimed: true,
        }),
      ),
    ).toBe("LAND");
    expect(
      nextMoveMoneyWorkerStep(
        emptyProgress({
          operationStatus: "INTERNAL_MOVE_LANDED",
          landed: true,
          landDualPathVerified: true,
        }),
      ),
    ).toBe("DONE");
  });

  it("landed:true + CREATED + dual-path is LAND not DONE (Fake LANDED residual)", () => {
    expect(
      nextMoveMoneyWorkerStep(
        emptyProgress({
          operationStatus: "CREATED",
          landed: true,
          landDualPathVerified: true,
          bothLeasesHeld: true,
          baselinesBound: true,
          innerPreimagePersisted: true,
          signaturesComplete: true,
          submitClaimed: true,
        }),
      ),
    ).toBe("LAND");
  });

  it("offline CREATED → INTERNAL_MOVE_LANDED: lease, OBSERVE, form/sign, submit once, land", async () => {
    const harness = createOfflinePorts();
    const { terminal, trail, attemptNo } = await runMoveInternalMoneyWorker(harness.ports, OP);

    expect(attemptNo).toBe(1);
    expect(terminal).toEqual({
      kind: "TERMINAL",
      operationId: OP,
      status: "INTERNAL_MOVE_LANDED",
    });
    expect(harness.submitCalls).toBe(1);
    expect(harness.progress().operationStatus).toBe("INTERNAL_MOVE_LANDED");
    expect(harness.progress().landed).toBe(true);
    expect(harness.progress().landDualPathVerified).toBe(true);

    const steps = trail
      .filter((t) => t.kind === "ADVANCED")
      .map((t) => (t.kind === "ADVANCED" ? t.step : null));
    expect(steps).toEqual(["LEASE", "BASELINE", "FORM", "SIGN", "SUBMIT"]);
    expect(trail[trail.length - 1]).toMatchObject({
      kind: "TERMINAL",
      status: "INTERNAL_MOVE_LANDED",
    });
  });

  it("AMBIGUOUS submit with durable claim → HOLD_RECONCILE and never a second submit (No-blind-retry)", async () => {
    const harness = createOfflinePorts({ submitStatus: "AMBIGUOUS" });
    const first = await runMoveInternalMoneyWorker(harness.ports, OP);
    expect(first.terminal.kind).toBe("HOLD_RECONCILE");
    if (first.terminal.kind === "HOLD_RECONCILE") {
      expect(first.terminal.submitClaimed).toBe(true);
    }
    expect(harness.submitCalls).toBe(1);
    expect(harness.progress().submitClaimed).toBe(true);

    const second = await advanceMoveInternalMoneyWorker(harness.ports, OP, {});
    expect(harness.submitCalls).toBe(1);
    expect(second.kind === "TERMINAL" || second.kind === "HOLD_RECONCILE" || second.kind === "ADVANCED").toBe(
      true,
    );
    if (second.kind === "ADVANCED") {
      expect(second.step).not.toBe("SUBMIT");
    }
  });

  it("AMBIGUOUS without durable claim → FAILED (not HOLD); does not invent submitClaimed (No-blind-retry)", async () => {
    // Would pass on old code that hardcodes submitClaimed:true without reload.
    const progress = progressReadyToSubmit();
    let submitCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => ({ signed: fakeSigned() }),
      submitOnce: async () => {
        submitCalls += 1;
        // No progress.submitClaimed = true — durable claim never minted.
        return { ok: false, reason: "ambiguous without mint", ambiguous: true };
      },
      reconcileAndLand: async () => ({ ok: false, reason: "n/a", holdReconcile: true }),
    };

    const first = await advanceMoveInternalMoneyWorker(ports, OP, {});
    expect(first.kind).toBe("FAILED");
    if (first.kind === "FAILED") {
      expect(first.step).toBe("SUBMIT");
      expect(first.reason).toMatch(/durable submit claim missing/i);
    }
    expect(submitCalls).toBe(1);
    expect(progress.submitClaimed).toBe(false);

    // Without durable claim progress still says SUBMIT — but we proved HOLD was not faked.
    // A blind HOLD with hard-coded claim:true would have jumped to LAND without a second call;
    // durable path correctly remains unclaimed (next step still SUBMIT, not LAND).
    expect(nextMoveMoneyWorkerStep(progress)).toBe("SUBMIT");
    expect(progress.submitClaimed).toBe(false);
  });

  it("executed:false / mint-loss path without durable claim → FAILED not HOLD (No-blind-retry)", async () => {
    const progress = progressReadyToSubmit();
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => ({ signed: fakeSigned() }),
      submitOnce: async () => ({
        ok: true,
        submitted: {
          result: {
            claim: {
              attemptId: randomUUID(),
              claimedAt: "2026-07-29T00:00:01.000Z",
              operationId: OP,
              transactionAttemptNo: 1,
            },
            executed: false,
            recordedOutcome: null,
          },
        },
      }),
      reconcileAndLand: async () => ({ ok: false, reason: "n/a", holdReconcile: true }),
    };

    const result = await advanceMoveInternalMoneyWorker(ports, OP, {});
    // Isthmus of lies: ok:true executed:false but durable claim never written → FAILED.
    expect(result.kind).toBe("FAILED");
    if (result.kind === "FAILED") {
      expect(result.reason).toMatch(/durable submit claim missing/i);
    }
    expect(progress.submitClaimed).toBe(false);
  });

  it("lost submit mint with durable claim → HOLD_RECONCILE without executed exchange (No-blind-retry)", async () => {
    const harness = createOfflinePorts({ loseMint: true });
    const { terminal } = await runMoveInternalMoneyWorker(harness.ports, OP);
    expect(terminal.kind).toBe("HOLD_RECONCILE");
    if (terminal.kind === "HOLD_RECONCILE") {
      expect(terminal.submitClaimed).toBe(true);
      expect(terminal.reason).toMatch(/mint lost|reconcile-first/i);
    }
    expect(harness.submitCalls).toBe(1);
  });

  it("LAND with AMBIGUOUS claim invokes identical-byte redelivery before reconcile (ZTR-1244)", async () => {
    const progress = emptyProgress({
      bothLeasesHeld: true,
      baselinesBound: true,
      innerPreimagePersisted: true,
      signaturesComplete: true,
      submitClaimed: true,
      submitOutcome: "AMBIGUOUS",
    });
    let redeliverCalls = 0;
    let landCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => ({ signed: fakeSigned() }),
      submitOnce: async () => {
        throw new Error("must not re-enter SUBMIT after claim");
      },
      redeliverIdenticalSubmit: async () => {
        redeliverCalls += 1;
        return { ok: true, redelivered: true };
      },
      reconcileAndLand: async () => {
        landCalls += 1;
        progress.landDualPathVerified = true;
        progress.operationStatus = "INTERNAL_MOVE_LANDED";
        progress.landed = true;
        progress.rowVersion = 2;
        return {
          ok: true,
          land: {
            outcome: dualPathLandedOutcome(),
            persist: { kind: "PERSISTED", state: "INTERNAL_MOVE_LANDED", rowVersion: 2 },
          },
        };
      },
    };
    const result = await advanceMoveInternalMoneyWorker(ports, OP, {});
    expect(redeliverCalls).toBe(1);
    expect(landCalls).toBe(1);
    expect(result.kind).toBe("TERMINAL");
  });

  it("LAND skips redelivery port when submitOutcome is not AMBIGUOUS", async () => {
    const progress = emptyProgress({
      bothLeasesHeld: true,
      baselinesBound: true,
      innerPreimagePersisted: true,
      signaturesComplete: true,
      submitClaimed: true,
      submitOutcome: "ACK",
    });
    let redeliverCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => ({ signed: fakeSigned() }),
      submitOnce: async () => {
        throw new Error("must not submit");
      },
      redeliverIdenticalSubmit: async () => {
        redeliverCalls += 1;
        return { ok: true, redelivered: true };
      },
      reconcileAndLand: async () => {
        progress.landDualPathVerified = true;
        progress.operationStatus = "INTERNAL_MOVE_LANDED";
        progress.landed = true;
        return {
          ok: true,
          land: {
            outcome: dualPathLandedOutcome(),
            persist: { kind: "PERSISTED", state: "INTERNAL_MOVE_LANDED", rowVersion: 2 },
          },
        };
      },
    };
    await advanceMoveInternalMoneyWorker(ports, OP, {});
    expect(redeliverCalls).toBe(0);
  });

  it("post-submit indeterminate land holds with claim set (no resubmit path)", async () => {
    const harness = createOfflinePorts({ landFail: true });
    const { terminal, trail } = await runMoveInternalMoneyWorker(harness.ports, OP);
    expect(terminal.kind).toBe("HOLD_RECONCILE");
    expect(trail.some((t) => t.kind === "ADVANCED" && t.step === "SUBMIT")).toBe(true);
    expect(harness.submitCalls).toBe(1);

    await advanceMoveInternalMoneyWorker(harness.ports, OP, {});
    expect(harness.submitCalls).toBe(1);
  });

  it("refuses TERMINAL when loadProgress shows landed status without dual-path proof", async () => {
    const progress = emptyProgress({
      operationStatus: "INTERNAL_MOVE_LANDED",
      landed: true,
      landDualPathVerified: false,
      bothLeasesHeld: true,
      baselinesBound: true,
      innerPreimagePersisted: true,
      signaturesComplete: true,
      submitClaimed: true,
    });
    let landCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => null,
      submitOnce: async () => ({ ok: false, reason: "must not submit" }),
      reconcileAndLand: async () => {
        landCalls += 1;
        return { ok: false, reason: "still proving dual path", holdReconcile: true };
      },
    };
    const result = await advanceMoveInternalMoneyWorker(ports, OP, {});
    expect(result.kind).not.toBe("TERMINAL");
    expect(result.kind === "HOLD_RECONCILE" || result.kind === "FAILED" || result.kind === "WAITING").toBe(
      true,
    );
    // Must enter LAND to re-proof — not DONE on status alone.
    if (result.kind === "HOLD_RECONCILE") {
      expect(landCalls).toBe(1);
    }
  });

  it("crash-resume: durable baselinesBound + empty scratch reloads via loadBaselineBound (not FAILED)", async () => {
    const progress = emptyProgress({
      bothLeasesHeld: true,
      baselinesBound: true,
      innerPreimagePersisted: false,
    });
    const bound: MoveBaselineBound = {
      capture: fakeCapture(),
      sourceT0ObservationId: SRC_T0,
      destinationT0ObservationId: DST_T0,
      artifact: fakeArtifact(),
    };
    let reloadCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => {
        reloadCalls += 1;
        return bound;
      },
      formInner: async () => {
        progress.innerPreimagePersisted = true;
        return { ok: true, formed: { durable: fakeDurableInner() } };
      },
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => null,
      submitOnce: async () => ({ ok: false, reason: "n/a" }),
      reconcileAndLand: async () => ({ ok: false, reason: "n/a" }),
    };

    const result = await advanceMoveInternalMoneyWorker(ports, OP, {});
    expect(result.kind).toBe("ADVANCED");
    if (result.kind === "ADVANCED") expect(result.step).toBe("FORM");
    expect(reloadCalls).toBe(1);
  });

  it(
    "crash-resume: loadBaselineBound throwing on unreconstructable T0 evidence propagates " +
      "(never collapses to WAITING, never calls formInner)",
    async () => {
      const progress = emptyProgress({
        bothLeasesHeld: true,
        baselinesBound: true,
        innerPreimagePersisted: false,
      });
      let formInnerCalls = 0;
      const ports: MoveInternalMoneyWorkerPorts = {
        loadProgress: async () => ({ ...progress }),
        acquireDualLeases: async () => ({
          ok: true,
          leases: {
            sourceWalletId: SRC,
            sourceLeaseEpoch: 1n,
            destinationWalletId: DST,
            destinationLeaseEpoch: 1n,
          },
        }),
        captureBaselines: async () => ({ ok: false, reason: "n/a" }),
        loadBaselineBound: async () => {
          throw new Error(
            "move baseline reload: T0 observation evidence present but unreconstructable (parse_result=TRANSPORT_ERROR)",
          );
        },
        formInner: async () => {
          formInnerCalls += 1;
          return { ok: true, formed: { durable: fakeDurableInner() } };
        },
        signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
        loadSignedMaterial: async () => null,
        submitOnce: async () => ({ ok: false, reason: "n/a" }),
        reconcileAndLand: async () => ({ ok: false, reason: "n/a" }),
      };

      // No try/catch wraps the FORM case's loadBaselineBound reload (move-internal-money-
      // worker.ts) — a throw must reach the caller so the tick loop's own catch can convert
      // it into a typed FAILED terminal (apps/generic-node money-workers/move-internal-
      // worker.ts). Collapsing it to `{kind:"WAITING"}` here would retry forever under an
      // unproven baseline while both leases stay held (One-in-flight).
      await expect(advanceMoveInternalMoneyWorker(ports, OP, {})).rejects.toThrow(/unreconstructable/);
      expect(formInnerCalls).toBe(0);
    },
  );

  it("crash-resume: signaturesComplete + empty scratch reloads signed material (not FAILED)", async () => {
    const progress = progressReadyToSubmit();
    let reloadCalls = 0;
    let submitCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => {
        reloadCalls += 1;
        return { signed: fakeSigned() };
      },
      submitOnce: async () => {
        submitCalls += 1;
        progress.submitClaimed = true;
        progress.submitOutcome = "ACK";
        return {
          ok: true,
          submitted: {
            result: {
              claim: {
                attemptId: randomUUID(),
                claimedAt: "2026-07-29T00:00:01.000Z",
                operationId: OP,
                transactionAttemptNo: 1,
              },
              executed: true,
              recordedOutcome: {
                status: "ACK",
                capture: null,
                recordedAttempt: {
                  decisionId: randomUUID(),
                  operationId: OP,
                  attemptNo: 1,
                  transactionAttemptNo: 1,
                  requestBytes: new Uint8Array(),
                  requestSha256: BODY_SHA,
                  responseBytes: null,
                  responseSha256: null,
                  transportOutcome: "ACK",
                  startedAt: "2026-07-29T00:00:01.000Z",
                  completedAt: "2026-07-29T00:00:02.000Z",
                },
              },
            },
          },
        };
      },
      reconcileAndLand: async () => ({ ok: false, reason: "n/a" }),
    };

    const result = await advanceMoveInternalMoneyWorker(ports, OP, {});
    expect(reloadCalls).toBe(1);
    expect(submitCalls).toBe(1);
    expect(result.kind).toBe("ADVANCED");
    if (result.kind === "ADVANCED") expect(result.step).toBe("SUBMIT");
  });

  it("ensureLeases revalidates every call (does not trust scratch forever)", async () => {
    const progress = emptyProgress({
      bothLeasesHeld: true,
      baselinesBound: true,
      innerPreimagePersisted: true,
      signaturesComplete: false,
    });
    let acquireCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => {
        acquireCalls += 1;
        // First call succeeds, second fails (stolen / expired epoch) — even with scratch.
        if (acquireCalls === 1) {
          return {
            ok: true,
            leases: {
              sourceWalletId: SRC,
              sourceLeaseEpoch: 1n,
              destinationWalletId: DST,
              destinationLeaseEpoch: 1n,
            },
          };
        }
        return { ok: false, reason: "lease stolen" };
      },
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({
        ok: true,
        signed: { signed: fakeSigned() },
      }),
      loadSignedMaterial: async () => null,
      submitOnce: async () => ({ ok: false, reason: "n/a" }),
      reconcileAndLand: async () => ({ ok: false, reason: "n/a" }),
    };

    const scratch = {
      leases: {
        sourceWalletId: SRC,
        sourceLeaseEpoch: 1n,
        destinationWalletId: DST,
        destinationLeaseEpoch: 1n,
      },
    };
    // Seed scratch as if prior advance cached leases — must still call acquire.
    const first = await advanceMoveInternalMoneyWorker(ports, OP, scratch);
    expect(first.kind).toBe("ADVANCED");
    expect(acquireCalls).toBe(1);

    progress.signaturesComplete = false;
    // SIGN again: scratch still populated; acquire must be hit and fail → WAITING.
    const second = await advanceMoveInternalMoneyWorker(ports, OP, scratch);
    expect(acquireCalls).toBe(2);
    expect(second.kind).toBe("WAITING");
    expect(scratch.leases).toBeUndefined();
  });

  it("D1: lying persist + dual-path obs without durable INTERNAL_MOVE_LANDED → not TERMINAL", async () => {
    // Reproduces FAIL#2 D1: TERMINAL gated only on landDualPathVerified while status stays CREATED.
    const progress = emptyProgress({
      bothLeasesHeld: true,
      baselinesBound: true,
      innerPreimagePersisted: true,
      signaturesComplete: true,
      submitClaimed: true,
      submitOutcome: "ACK",
      landDualPathVerified: false,
      landed: false,
      operationStatus: "CREATED",
    });
    let landCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => null,
      submitOnce: async () => ({ ok: false, reason: "must not submit" }),
      reconcileAndLand: async () => {
        landCalls += 1;
        // Durable truth: dual-path obs written, but operations.status NEVER lands.
        progress.landDualPathVerified = true;
        // status stays CREATED / landed stays false — lying about persist.state alone.
        return {
          ok: true,
          land: {
            outcome: dualPathLandedOutcome(),
            persist: {
              kind: "PERSISTED",
              state: "INTERNAL_MOVE_LANDED",
              rowVersion: 2,
            },
          },
        };
      },
    };

    const result = await advanceMoveInternalMoneyWorker(ports, OP, {});
    expect(landCalls).toBe(1);
    expect(result.kind).not.toBe("TERMINAL");
    expect(result.kind).toBe("HOLD_RECONCILE");
    if (result.kind === "HOLD_RECONCILE") {
      expect(result.reason).toMatch(/durable operation status not INTERNAL_MOVE_LANDED/i);
    }
    expect(progress.operationStatus).toBe("CREATED");
    expect(progress.landed).toBe(false);
  });

  it("Fake LANDED residual: landed:true + CREATED + dual-path → not TERMINAL", async () => {
    // Break@37fe5284: DONE used (landed || status===LANDED); landed:true + CREATED + dual-path
    // emitted TERMINAL{INTERNAL_MOVE_LANDED} while durable status stayed CREATED.
    const progress = emptyProgress({
      bothLeasesHeld: true,
      baselinesBound: true,
      innerPreimagePersisted: true,
      signaturesComplete: true,
      submitClaimed: true,
      submitOutcome: "ACK",
      landDualPathVerified: true,
      landed: true,
      operationStatus: "CREATED",
    });
    let landCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => ({
        ok: true,
        leases: {
          sourceWalletId: SRC,
          sourceLeaseEpoch: 1n,
          destinationWalletId: DST,
          destinationLeaseEpoch: 1n,
        },
      }),
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => null,
      submitOnce: async () => ({ ok: false, reason: "must not submit" }),
      reconcileAndLand: async () => {
        landCalls += 1;
        // Durable status stays CREATED even if convenience landed stays true.
        progress.landDualPathVerified = true;
        progress.landed = true;
        progress.operationStatus = "CREATED";
        return {
          ok: true,
          land: {
            outcome: dualPathLandedOutcome(),
            persist: {
              kind: "PERSISTED",
              state: "INTERNAL_MOVE_LANDED",
              rowVersion: 2,
            },
          },
        };
      },
    };

    const result = await advanceMoveInternalMoneyWorker(ports, OP, {});
    expect(result.kind).not.toBe("TERMINAL");
    expect(result.kind === "HOLD_RECONCILE" || result.kind === "WAITING" || result.kind === "ADVANCED").toBe(
      true,
    );
    if (result.kind === "HOLD_RECONCILE") {
      expect(result.reason).toMatch(/INTERNAL_MOVE_LANDED|dual-path/i);
    }
    // If land was reached, durable status must still read CREATED (no fake TERMINAL).
    if (landCalls > 0) {
      expect(progress.operationStatus).toBe("CREATED");
    }
    expect(progress.operationStatus).toBe("CREATED");
  });

  it("D2: stolen leases before SUBMIT → WAITING, never submitOnce", async () => {
    const progress = progressReadyToSubmit();
    let acquireCalls = 0;
    let submitCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => {
        acquireCalls += 1;
        return { ok: false, reason: "lease stolen by peer" };
      },
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => ({ signed: fakeSigned() }),
      submitOnce: async () => {
        submitCalls += 1;
        return { ok: false, reason: "must not reach submit with stolen leases" };
      },
      reconcileAndLand: async () => ({ ok: false, reason: "n/a" }),
    };

    // Stale bothLeasesHeld + scratch leases must not authorize submit.
    const scratch = {
      leases: {
        sourceWalletId: SRC,
        sourceLeaseEpoch: 1n,
        destinationWalletId: DST,
        destinationLeaseEpoch: 1n,
      },
      signed: { signed: fakeSigned() },
    };
    const result = await advanceMoveInternalMoneyWorker(ports, OP, scratch);
    expect(acquireCalls).toBe(1);
    expect(submitCalls).toBe(0);
    expect(result.kind).toBe("WAITING");
    if (result.kind === "WAITING") {
      expect(result.reason).toMatch(/submit:.*lease/i);
    }
    expect(scratch.leases).toBeUndefined();
  });

  it("D2: stolen leases before LAND → WAITING, never reconcileAndLand", async () => {
    const progress = emptyProgress({
      bothLeasesHeld: true,
      baselinesBound: true,
      innerPreimagePersisted: true,
      signaturesComplete: true,
      submitClaimed: true,
      submitOutcome: "ACK",
    });
    let acquireCalls = 0;
    let landCalls = 0;
    const ports: MoveInternalMoneyWorkerPorts = {
      loadProgress: async () => ({ ...progress }),
      acquireDualLeases: async () => {
        acquireCalls += 1;
        return { ok: false, reason: "lease stolen by peer" };
      },
      captureBaselines: async () => ({ ok: false, reason: "n/a" }),
      loadBaselineBound: async () => null,
      formInner: async () => ({ ok: false, reason: "n/a" }),
      signUnderLeases: async () => ({ ok: false, reason: "n/a" }),
      loadSignedMaterial: async () => null,
      submitOnce: async () => ({ ok: false, reason: "must not submit" }),
      reconcileAndLand: async () => {
        landCalls += 1;
        return { ok: false, reason: "must not land with stolen leases" };
      },
    };

    const scratch = {
      leases: {
        sourceWalletId: SRC,
        sourceLeaseEpoch: 1n,
        destinationWalletId: DST,
        destinationLeaseEpoch: 1n,
      },
    };
    const result = await advanceMoveInternalMoneyWorker(ports, OP, scratch);
    expect(acquireCalls).toBe(1);
    expect(landCalls).toBe(0);
    expect(result.kind).toBe("WAITING");
    if (result.kind === "WAITING") {
      expect(result.reason).toMatch(/land:.*lease/i);
    }
    expect(scratch.leases).toBeUndefined();
  });
});
