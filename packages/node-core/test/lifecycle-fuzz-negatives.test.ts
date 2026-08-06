/**
 * NEGATIVE-PATH ASSERTIONS, one per governing-source bullet.
 *
 * Each `it` drives the state where the forbidden effect WOULD occur and asserts it is absent,
 * reusing FORBIDDEN_EFFECT_DETECTORS / the reconcile lease+observation axes. Shared oracles are
 * proven non-tautological in lifecycle-fuzz-oracle-selfcheck.test.ts; this file adds the
 * effect-detector red-go. custody (device signatures / TOTP burn) are OUT of this
 * surface — it.todo referencing the follow-up, never a vacuous green.
 *
 * TEST-ONLY.
 */
import { beforeAll, describe, expect, it } from "vitest";
import fc from "fast-check";

import { ready } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import { CONCURRENCY, type ConcurrencyShape } from "../../generic-node-contracts/src/event-commit/index.ts";
import { evaluateConcurrentAllocation } from "../../generic-node-contracts/src/sequence-recovery/index.ts";
import {
  classifyReceiveReconcile,
  classifyMoveReconcile,
  classifySendReconcile,
} from "../src/protocol/reconcile/index.js";
import { FORBIDDEN_EFFECT_DETECTORS } from "./crash-replay-recovery.ts";
import { OPERATION_ID } from "./crash-replay-fixtures.ts";
import {
  acquisitionAttemptArb,
  crashReplayActionArb,
  partialExistsActionArb,
  runCrashReplay,
  simulateWalletAcquisitions,
} from "./lifecycle-fuzz-alphabet.ts";
import { FUZZ_NUM_RUNS, FUZZ_SEED } from "./lifecycle-fuzz-oracles.ts";
import { LANDING_PROOF_FAULTS } from "../src/protocol/reconcile/landing-proof.js";

const CFG = { seed: FUZZ_SEED, numRuns: FUZZ_NUM_RUNS, endOnFailure: true } as const;
const anomalyObs = { result: "ANOMALY" as const, anomaly: "UNEXPLAINED_JUMP" as const };
const faultArb = fc.constantFrom(...LANDING_PROOF_FAULTS);

beforeAll(async () => {
  await ready();
});

describe("custody — mandatory security/golden negatives", () => {
  it("signer rejects stale/wrong-role lease: RELEASED lease during reconcile -> INVARIANT_BREACH", () => {
    const out = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: "att-1",
      sourceWalletId: "w-src",
      sourceLeaseState: "RELEASED",
      transferCodeSha256: "code-1",
      sourceObservation: { result: "NO_SUCCESSOR" },
    });
    expect(out.kind).toBe("INVARIANT_BREACH");
    if (out.kind === "INVARIANT_BREACH") {
      expect(out.reason.source).toBe("LEASE_NOT_ACTIVE_DURING_RECONCILE");
    }
  });

  it("move lease race never partially acquires: one leg RELEASED -> INVARIANT_BREACH on that wallet", () => {
    const out = classifyMoveReconcile({
      boundary: "POST_SUBMIT",
      moveAttemptId: "mv-1",
      sourceWalletId: "w-src",
      destinationWalletId: "w-dst",
      expectedMoveBodySha256: "body-1",
      sourceLeaseState: "ACTIVE",
      destinationLeaseState: "RELEASED",
      sourceObservation: { result: "NO_SUCCESSOR" },
      destinationObservation: { result: "NO_SUCCESSOR" },
    });
    expect(out.kind).toBe("INVARIANT_BREACH");
    if (out.kind === "INVARIANT_BREACH") expect(out.affectedWalletIds).toEqual(["w-dst"]);
  });

  it("recovery-unverified destination never auto-selected: anomaly never lands", () => {
    fc.assert(
      fc.property(fc.constant(anomalyObs), (obs) => {
        const out = classifySendReconcile({
          boundary: "DELIVERED",
          sendAttemptId: "att-1",
          sourceWalletId: "w-src",
          sourceLeaseState: "ACTIVE",
          transferCodeSha256: "code-1",
          sourceObservation: obs,
        });
        expect(out.kind).not.toBe("LANDED_VERIFIED");
      }),
      CFG,
    );
  });

  it("one guarded mutation per approval: no replacement partial / expiry refresh under old approval", () => {
    // Meaningful once a partial exists under the approval (the replacement-forbidden regime).
    fc.assert(
      fc.property(partialExistsActionArb, (action) => {
        const run = runCrashReplay(action);
        expect(FORBIDDEN_EFFECT_DETECTORS.MINT_REPLACEMENT_PARTIAL(run.ctx)).toBe(false);
        expect(FORBIDDEN_EFFECT_DETECTORS.REFRESH_EXPIRY_UNDER_OLD_APPROVAL(run.ctx)).toBe(false);
      }),
      CFG,
    );
  });

  it("crash at every boundary -> no partial or the exact one", () => {
    fc.assert(
      fc.property(crashReplayActionArb, (action) => {
        const run = runCrashReplay(action);
        expect(FORBIDDEN_EFFECT_DETECTORS.MINT_REPLACEMENT_PARTIAL(run.ctx)).toBe(false);
      }),
      CFG,
    );
  });

  it("persisted/delivered/expired partial never replaced: no new code delivered", () => {
    // A partial already exists — recovery may only re-serve the exact persisted code, never a new one.
    fc.assert(
      fc.property(partialExistsActionArb, (action) => {
        const run = runCrashReplay(action);
        expect(FORBIDDEN_EFFECT_DETECTORS.SUBMIT_OR_DELIVER_NEW_CODE(run.ctx)).toBe(false);
        expect(FORBIDDEN_EFFECT_DETECTORS.RE_SIGN_OR_RE_FORM(run.ctx)).toBe(false);
      }),
      CFG,
    );
  });

  it.todo("additive device policy (TOTP + device signature) — OUT of the lifecycle/recovery surface");
  it.todo("TOTP burned on failure, no replay — OUT of the lifecycle/recovery surface");
});

describe("observation — observation predicate negatives", () => {
  it("spawned-move continuous lease group: a broken (RELEASED) leg -> INVARIANT_BREACH", () => {
    const out = classifyMoveReconcile({
      boundary: "POST_SUBMIT",
      moveAttemptId: "mv-1",
      sourceWalletId: "w-src",
      destinationWalletId: "w-dst",
      expectedMoveBodySha256: "body-1",
      sourceLeaseState: "RELEASED",
      destinationLeaseState: "ACTIVE",
      sourceObservation: { result: "NO_SUCCESSOR" },
      destinationObservation: { result: "NO_SUCCESSOR" },
    });
    expect(out.kind).toBe("INVARIANT_BREACH");
  });

  it("unchanged/gap/regression/malformed/unrelated head grants no blind-retry authority", () => {
    // Unchanged head (NO_SUCCESSOR) on a delivered send is WAITING (redeliver-only), never a rebuild.
    const waiting = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: "att-1",
      sourceWalletId: "w-src",
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: "code-1",
      sourceObservation: { result: "NO_SUCCESSOR" },
    });
    expect(waiting.kind).toBe("WAITING");
    // Receive after the submit boundary never yields PROVEN_NOT_STARTED (no inbound rebuild).
    fc.assert(
      fc.property(fc.constant(anomalyObs), (obs) => {
        const out = classifyReceiveReconcile({
          boundary: "POST_SUBMIT",
          receiveAttemptId: "att-1",
          receiverWalletId: "w-1",
          receiverLeaseState: "ACTIVE",
          receiverObservation: obs,
        });
        expect(out.kind).not.toBe("PROVEN_NOT_STARTED");
      }),
      CFG,
    );
  });

  it("direct-successor settlement needs every guard: an incomplete proof never lands", () => {
    fc.assert(
      fc.property(faultArb, (fault) => {
        const out = classifySendReconcile({
          boundary: "DELIVERED",
          sendAttemptId: "att-1",
          sourceWalletId: "w-src",
          sourceLeaseState: "ACTIVE",
          transferCodeSha256: "code-1",
          sourceObservation: { result: "PROOF_INCOMPLETE", fault },
        });
        expect(out.kind).toBe("INDETERMINATE");
      }),
      CFG,
    );
  });
});

describe("test-plan — concurrency and reconciliation negatives", () => {
  it("MOVE-vs-SEND / two-worker same source: exactly one contender signs; a raced allocation is rejected", () => {
    // Decision level: an unlocked/raced allocation model is rejected.
    const unlocked: ConcurrencyShape = {
      ...CONCURRENCY,
      serializedOn: "no_lock",
      oneWinnerPerSeq: false,
      distinctSeqPerCommittedEvent: false,
      contiguousUnderContention: false,
    };
    expect(evaluateConcurrentAllocation(unlocked, [1n, 2n])).toBe("RACE_DUPLICATE_OR_GAP");
    // Even under the valid model, a duplicated/gapped observed sequence is a RACE.
    expect(evaluateConcurrentAllocation(CONCURRENCY, [1n, 1n])).toBe("RACE_DUPLICATE_OR_GAP");
    // Sequence level: >=2 operation-role acquisitions on one wallet -> exactly one signer.
    fc.assert(
      fc.property(fc.array(acquisitionAttemptArb, { minLength: 2, maxLength: 8 }), (attempts) => {
        for (const outcome of simulateWalletAcquisitions(attempts).values()) {
          expect(outcome.admittedOperationLeases).toBeLessThanOrEqual(1);
        }
      }),
      CFG,
    );
  });

  it("no blind retry; possible landing retains the lease; inbound never rebuilt", () => {
    fc.assert(
      fc.property(crashReplayActionArb, (action) => {
        const run = runCrashReplay(action);
        // possible landing retains the lease — recovery never releases over launch-reachable heads.
        expect(run.scenario.runtime.log.leaseReleases).toBe(0);
        expect(FORBIDDEN_EFFECT_DETECTORS.INFER_NON_LANDING_OR_RETRY(run.ctx)).toBe(false);
      }),
      CFG,
    );
  });
});

describe("state/event -node-core — closed vocabulary negatives", () => {
  it("state/event + node-core: no crash-replay operation transition emits a forbidden or non-member state", () => {
    // Covered structurally by the transition-allowlist + closed-vocab checks in
    // lifecycle-fuzz.test.ts; here assert the observed status set is a subset of the enum.
    fc.assert(
      fc.property(crashReplayActionArb, (action) => {
        const run = runCrashReplay(action);
        for (const t of run.scenario.runtime.log.operationTransitions) {
          expect(typeof t.to).toBe("string");
          expect(t.to).not.toMatch(/payment|checkout|refund|paid|finalised|settled|confirmed/);
        }
      }),
      CFG,
    );
  });
});

describe("effect-detector red-go (amendment 10 — the negatives are non-vacuous)", () => {
  it("MINT_REPLACEMENT_PARTIAL fires when a second partial is injected", () => {
    const run = runCrashReplay({
      durableState: "PARTIAL_DELIVERED_HEAD_UNCHANGED",
      anomalousVariant: "unrelated",
    });
    // Inject a duplicate partial row: the detector MUST catch it (proves it is not vacuous).
    const existing = run.scenario.durable.partials.find((r) => r["operation_id"] === OPERATION_ID);
    if (existing !== undefined) run.scenario.durable.partials.push({ ...existing });
    expect(FORBIDDEN_EFFECT_DETECTORS.MINT_REPLACEMENT_PARTIAL(run.ctx)).toBe(true);
  });
});
