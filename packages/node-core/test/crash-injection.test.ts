/**
 * Phase-by-phase crash-injection tests.
 *
 * A crash is injected at every durable phase boundary of all three operation kinds; the
 * recovery pass is then run over the surviving durable store and asserted to resume from the
 * correct phase. Each crash point verifies the four required properties:
 *   1. no data corruption         — every byte that survived the crash is unchanged after recovery
 *   2. resumes from correct state — the recovery classification matches the durable residue
 *   3. no duplicate operations    — one operation, one attempt, at most one submit, one partial
 *   4. leases maintained          — the source lease is held through ambiguity, released on landing
 *
 * Property 1 compares EVERY persisted byte column, including the step-2 preimage and
 * signature: a recovery that discards the persisted step-2 preimage and signs divergent bytes
 * is the exact action recovery and custody forbid, and it is only detectable if those
 * columns are inside the comparison aperture. The never-blind-retry rule (never blind-retry a submit) is
 * the other load-bearing assertion: once a submit claim is durable, recovery reconciles by
 * observation and the submit port is never invoked again — and an external send never reaches
 * a submit port on any path. Offline fixtures only — no custody surface, never live ZKZ.
 */
import { beforeAll, describe, expect, it } from "vitest";

import { ready } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  crashAt,
  crashAndRecover,
  CRASH_POINTS,
  LANDED_EVENT,
  runLifecycle,
  STEP_DELIVER_PARTIAL,
  STEP_INNER_PREIMAGE,
  STEP_SIGN_STEP1,
  STEP_SIGN_STEP2,
  STEP_STEP2_PREIMAGE,
  STEP_SUBMIT,
  type CrashPoint,
} from "./crash-injection-lifecycle.ts";
import {
  buildInnerPreimage,
  buildPartialCode,
  createRuntime,
  KEY_SEED_BYTE,
  OPERATION_IDS,
  PAYER_SEED_BYTE,
  signWithSeed,
  type OperationKind,
  type Scenario,
  type SubmitPort,
} from "./crash-injection-model.ts";
import {
  crashThenRecover,
  recoverOperation,
  snapshotDurable,
  type LandingObservation,
  type RecoveryClassification,
} from "./crash-injection-recovery.ts";

beforeAll(async () => {
  await ready();
});

const LANDED: LandingObservation = { kind: "LANDED_VERIFIED" };
const NOT_LANDED: LandingObservation = { kind: "NOT_LANDED_YET" };

/** The payer's step-1 signature on the inbound receive — produced with a key the node does
 *  not hold, so "the node never signed step 1 of a receive" is checkable, not merely asserted. */
const payerStep1Signature = (): string =>
  signWithSeed(buildInnerPreimage("RECEIVE_EXTERNAL"), PAYER_SEED_BYTE);

const freshScenario = (kind: OperationKind): Scenario => ({
  durable: {
    operations: [
      {
        operationId: OPERATION_IDS[kind],
        kind,
        status: "CREATED",
        leaseHeld: false,
        needsAttention: false,
        terminal: false,
      },
    ],
    attempts: [],
    signerAudit: [],
    externalPartials: [],
    events: [],
  },
  runtime: createRuntime(
    "worker-1",
    KEY_SEED_BYTE,
    kind === "RECEIVE_EXTERNAL" ? payerStep1Signature() : undefined,
  ),
});

/** A submit port that records every invocation so a blind-retry is observable. */
const countingSubmit = (): { port: SubmitPort; calls: number[] } => {
  const calls: number[] = [];
  const port: SubmitPort = (request) => {
    calls.push(request.attemptNo);
    return { kind: "ACCEPTED", gatewayRef: "gw-ref-0001" };
  };
  return { port, calls };
};

interface MatrixRow {
  crashPoint: CrashPoint;
  classification: RecoveryClassification;
  resumedFromStep: number;
}

/** Crash point -> the recovery classification its durable residue must produce, per kind. Only
 *  the phase boundaries a kind actually crosses appear: a receive never forms inner bytes and
 *  an external send has no step-2 or submit phase. */
const CRASH_MATRIX: Record<OperationKind, readonly MatrixRow[]> = {
  MOVE_INTERNAL: [
    { crashPoint: "AFTER_CREATE", classification: "NO_ATTEMPT_RESUME_FORMATION", resumedFromStep: STEP_INNER_PREIMAGE },
    { crashPoint: "AFTER_INNER_PREIMAGE", classification: "INNER_PERSISTED_RESIGN_STEP1", resumedFromStep: STEP_SIGN_STEP1 },
    { crashPoint: "AFTER_SIGN_STEP1", classification: "STEP1_SIGNED_BUILD_STEP2", resumedFromStep: STEP_STEP2_PREIMAGE },
    { crashPoint: "AFTER_STEP2_PREIMAGE", classification: "STEP2_PERSISTED_RESIGN_STEP2", resumedFromStep: STEP_SIGN_STEP2 },
    { crashPoint: "AFTER_SIGN_STEP2", classification: "SIGNED_SUBMIT_ONCE", resumedFromStep: STEP_SUBMIT },
    { crashPoint: "AFTER_SUBMIT", classification: "SUBMITTED_RECONCILE", resumedFromStep: STEP_SUBMIT + 1 },
  ],
  RECEIVE_EXTERNAL: [
    // The payer bytes are durable from acceptance, so the earliest receive residue is already
    // step-1-signed. The node never occupies a "no inner preimage" state for a receive.
    { crashPoint: "AFTER_CREATE", classification: "STEP1_SIGNED_BUILD_STEP2", resumedFromStep: STEP_STEP2_PREIMAGE },
    { crashPoint: "AFTER_STEP2_PREIMAGE", classification: "STEP2_PERSISTED_RESIGN_STEP2", resumedFromStep: STEP_SIGN_STEP2 },
    { crashPoint: "AFTER_SIGN_STEP2", classification: "SIGNED_SUBMIT_ONCE", resumedFromStep: STEP_SUBMIT },
    { crashPoint: "AFTER_SUBMIT", classification: "SUBMITTED_RECONCILE", resumedFromStep: STEP_SUBMIT + 1 },
  ],
  SEND_EXTERNAL: [
    { crashPoint: "AFTER_CREATE", classification: "NO_ATTEMPT_RESUME_FORMATION", resumedFromStep: STEP_INNER_PREIMAGE },
    { crashPoint: "AFTER_INNER_PREIMAGE", classification: "INNER_PERSISTED_RESIGN_STEP1", resumedFromStep: STEP_SIGN_STEP1 },
    { crashPoint: "AFTER_SIGN_STEP1", classification: "SIGNING_CLAIMED_FORM_PARTIAL_ONCE", resumedFromStep: STEP_DELIVER_PARTIAL },
    { crashPoint: "AFTER_DELIVER_PARTIAL", classification: "PARTIAL_DELIVERED_REDELIVER_ONLY", resumedFromStep: STEP_DELIVER_PARTIAL },
  ],
};

const KINDS = Object.keys(CRASH_MATRIX) as OperationKind[];

/** Every (kind, crash point) pair, flattened for `it.each`. */
const ALL_CRASH_CASES = KINDS.flatMap((kind) =>
  CRASH_MATRIX[kind].map((row) => ({ kind, ...row })),
);

/** Kinds that submit. SEND_EXTERNAL is deliberately absent — it has no submit port. */
const SUBMITTING_KINDS: OperationKind[] = ["MOVE_INTERNAL", "RECEIVE_EXTERNAL"];

describe("crash injection — happy path", () => {
  it.each(SUBMITTING_KINDS)(
    "%s: no crash drives creation -> signing -> submit -> landing with one submit call",
    (kind) => {
      const scenario = freshScenario(kind);
      const { port, calls } = countingSubmit();
      runLifecycle(scenario, port);
      const snap = snapshotDurable(scenario.durable);
      expect(snap.operations).toBe(1);
      expect(snap.attempts).toBe(1);
      expect(snap.submitClaimed).toBe(true);
      expect(snap.terminal).toBe(true);
      expect(snap.leaseHeld).toBe(false);
      expect(snap.events).toBe(1);
      expect(snap.attemptPhase).toBe("SETTLED_BODY_PERSISTED");
      expect(calls).toHaveLength(1);
    },
  );

  it("SEND_EXTERNAL: no crash forms exactly one partial, delivers it, and never submits", () => {
    const scenario = freshScenario("SEND_EXTERNAL");
    const { port, calls } = countingSubmit();
    runLifecycle(scenario, port);
    const snap = snapshotDurable(scenario.durable);
    expect(snap.partials).toBe(1);
    expect(snap.partialDeliveries).toBe(1);
    expect(snap.submitClaimed).toBe(false);
    expect(calls).toHaveLength(0);
    expect(snap.partialCode).toBe(
      buildPartialCode(snap.innerPreimageText as string, snap.step1Signature as string),
    );
  });
});

describe("crash injection — recovery resumes from the correct phase", () => {
  it.each(ALL_CRASH_CASES)(
    "$kind/$crashPoint -> $classification (resume at step $resumedFromStep)",
    ({ kind, crashPoint, classification, resumedFromStep }) => {
      const { port, calls } = countingSubmit();
      const crashed = crashAt(freshScenario(kind), port, crashPoint);
      const { scenario, outcome } = crashThenRecover(crashed, port, LANDED);

      expect(outcome.classification).toBe(classification);
      expect(outcome.resumedFromStep).toBe(resumedFromStep);
      expect(outcome.landed).toBe(true);

      const snap = snapshotDurable(scenario.durable);
      expect(snap.operations).toBe(1);
      expect(snap.attempts).toBe(1);
      expect(snap.terminal).toBe(true);
      expect(snap.leaseHeld).toBe(false);
      // Landing is an irreversible boundary crossing: one landed event, one landing, one lease
      // release — at EVERY residue of every kind, not just the ones that skip the lifecycle.
      expect(snap.events).toBe(1);
      expect(scenario.runtime.log.landings).toHaveLength(1);
      expect(scenario.runtime.log.leaseReleases).toBe(1);
      if (kind === "SEND_EXTERNAL") {
        // Never a second partial and never a submit, at any residue.
        expect(snap.partials).toBe(1);
        expect(calls).toHaveLength(0);
      } else {
        // Exactly one submit call across crash + recovery, always for attempt 1.
        expect(calls).toHaveLength(1);
        expect(calls[0]).toBe(1);
      }
    },
  );
});

describe("crash injection — no data corruption", () => {
  it.each(ALL_CRASH_CASES)(
    "$kind/$crashPoint: surviving bytes are byte-identical after recovery",
    ({ kind, crashPoint }) => {
      const { port } = countingSubmit();
      const crashed = crashAt(freshScenario(kind), port, crashPoint);
      const before = snapshotDurable(crashed.durable);

      const { scenario } = crashThenRecover(crashed, port, LANDED);
      const after = snapshotDurable(scenario.durable);

      // Every persisted byte column is compared. A column omitted here is a column a divergent
      // re-formation could rewrite unobserved — the aperture IS the assertion.
      if (before.innerPreimageText !== undefined) {
        expect(after.innerPreimageText).toBe(before.innerPreimageText);
        expect(after.innerSha256).toBe(before.innerSha256);
      }
      if (before.step1Signature !== undefined) {
        expect(after.step1Signature).toBe(before.step1Signature);
      }
      if (before.step2PreimageText !== undefined) {
        expect(after.step2PreimageText).toBe(before.step2PreimageText);
        expect(after.step2PreimageSha256).toBe(before.step2PreimageSha256);
      }
      if (before.step2Signature !== undefined) {
        expect(after.step2Signature).toBe(before.step2Signature);
      }
      if (before.completedTransactionText !== undefined) {
        expect(after.completedTransactionText).toBe(before.completedTransactionText);
        expect(after.completedTransactionSha256).toBe(before.completedTransactionSha256);
      }
      if (before.partialCode !== undefined) {
        expect(after.partialCode).toBe(before.partialCode);
        expect(after.partialCodeSha256).toBe(before.partialCodeSha256);
      }
    },
  );

  it("re-signing the persisted inner preimage reproduces the deterministic signature", () => {
    const { port } = countingSubmit();
    const crashed = crashAt(freshScenario("MOVE_INTERNAL"), port, "AFTER_INNER_PREIMAGE");
    const persistedInner = snapshotDurable(crashed.durable).innerPreimageText as string;
    expect(persistedInner).toBe(buildInnerPreimage("MOVE_INTERNAL"));

    const { scenario } = crashThenRecover(crashed, port, LANDED);
    expect(snapshotDurable(scenario.durable).step1Signature).toBe(
      signWithSeed(persistedInner, KEY_SEED_BYTE),
    );
  });

  /** recovery: "Re-sign only the identical persisted step-2 preimage. Ed25519 output must match
   *  any signer audit digest." Checked by computing the expected signature independently from
   *  the persisted bytes, not by asserting that some signature exists. */
  it.each(SUBMITTING_KINDS)(
    "%s: recovery re-signs the IDENTICAL persisted step-2 preimage, byte for byte",
    (kind) => {
      const { port } = countingSubmit();
      const crashed = crashAt(freshScenario(kind), port, "AFTER_STEP2_PREIMAGE");
      const beforeSnap = snapshotDurable(crashed.durable);
      const persistedStep2 = beforeSnap.step2PreimageText as string;
      expect(persistedStep2).toBeDefined();
      expect(beforeSnap.step2Signature).toBeUndefined();

      const { scenario } = crashThenRecover(crashed, port, LANDED);
      const after = snapshotDurable(scenario.durable);

      // The preimage that was signed is still the persisted one, unchanged...
      expect(after.step2PreimageText).toBe(persistedStep2);
      expect(after.step2PreimageSha256).toBe(beforeSnap.step2PreimageSha256);
      // ...and the signature is exactly the deterministic Ed25519 output over THOSE bytes.
      expect(after.step2Signature).toBe(signWithSeed(persistedStep2, KEY_SEED_BYTE));
      // The completed transaction embeds the persisted inner bytes verbatim.
      expect(after.completedTransactionText).toContain(beforeSnap.innerPreimageText as string);
    },
  );

  it("SEND_EXTERNAL: re-delivery carries the exact persisted code and mints no replacement", () => {
    const { port } = countingSubmit();
    const crashed = crashAt(freshScenario("SEND_EXTERNAL"), port, "AFTER_DELIVER_PARTIAL");
    const persistedCode = snapshotDurable(crashed.durable).partialCode as string;
    expect(persistedCode).toBeDefined();

    const { scenario } = crashThenRecover(crashed, port, LANDED);
    const after = snapshotDurable(scenario.durable);
    expect(after.partialCode).toBe(persistedCode);
    expect(after.partials).toBe(1);
    // The bytes handed to the delivery path are the persisted bytes, not re-formed ones.
    expect(scenario.runtime.log.partialDeliveries.map((entry) => entry.code)).toEqual([
      persistedCode,
    ]);
    expect(scenario.runtime.log.partialMints).toHaveLength(0);
  });
});

describe("crash injection — never blind-retry a submit (the never-blind-retry rule)", () => {
  it.each(SUBMITTING_KINDS)(
    "%s: a durable submit claim is reconciled by observation, never resubmitted",
    (kind) => {
      const { port, calls } = countingSubmit();
      const crashed = crashAt(freshScenario(kind), port, "AFTER_SUBMIT");
      expect(snapshotDurable(crashed.durable).submitClaimed).toBe(true);
      expect(calls).toHaveLength(1);

      // Not yet observed landed: parks in needs-attention, lease held, no second submit.
      const parked = crashThenRecover(crashed, port, NOT_LANDED);
      expect(parked.outcome.classification).toBe("SUBMITTED_RECONCILE");
      expect(parked.outcome.landed).toBe(false);
      expect(calls).toHaveLength(1);
      const parkedSnap = snapshotDurable(parked.scenario.durable);
      expect(parkedSnap.leaseHeld).toBe(true);
      expect(parkedSnap.needsAttention).toBe(true);
      expect(parkedSnap.terminal).toBe(false);

      // A verified observation lands the already-submitted operation — still no resubmit.
      const landed = crashThenRecover(crashed, port, LANDED);
      expect(landed.outcome.landed).toBe(true);
      expect(calls).toHaveLength(1);
      const landedSnap = snapshotDurable(landed.scenario.durable);
      expect(landedSnap.terminal).toBe(true);
      expect(landedSnap.leaseHeld).toBe(false);
    },
  );

  it("repeated recovery over a submit-claimed store never invokes the port again", () => {
    const { port, calls } = countingSubmit();
    const crashed = crashAt(freshScenario("MOVE_INTERNAL"), port, "AFTER_SUBMIT");
    const recovered = crashThenRecover(crashed, port, { kind: "ANOMALOUS" }).scenario;
    recoverOperation(recovered, port, { kind: "ANOMALOUS" });
    recoverOperation(recovered, port, NOT_LANDED);
    expect(calls).toHaveLength(1);
  });

  /** 1.5: "For SEND_EXTERNAL, prove the node never calls submit and re-delivery never
   *  rebuilds bytes." Proven over every send residue, including repeated recovery. */
  it("SEND_EXTERNAL never invokes a submit port at any residue, however often recovery runs", () => {
    const { port, calls } = countingSubmit();
    for (const crashPoint of Object.keys(CRASH_POINTS) as CrashPoint[]) {
      if (crashPoint === "AFTER_STEP2_PREIMAGE" || crashPoint === "AFTER_SIGN_STEP2" || crashPoint === "AFTER_SUBMIT") {
        continue; // phases an external send never crosses
      }
      const crashed = crashAt(freshScenario("SEND_EXTERNAL"), port, crashPoint);
      const { scenario } = crashThenRecover(crashed, port, NOT_LANDED);
      recoverOperation(crashAndRecover(scenario), port, NOT_LANDED);
      expect(snapshotDurable(scenario.durable).partials).toBe(1);
    }
    expect(calls).toHaveLength(0);
  });
});

describe("crash injection — wallet lease is maintained through ambiguity, released on landing", () => {
  it.each(SUBMITTING_KINDS)(
    "%s: an anomalous head after submit parks the operation and keeps the lease held",
    (kind) => {
      const { port, calls } = countingSubmit();
      const crashed = crashAt(freshScenario(kind), port, "AFTER_SUBMIT");
      const { scenario, outcome } = crashThenRecover(crashed, port, { kind: "ANOMALOUS" });
      expect(outcome.landed).toBe(false);
      const snap = snapshotDurable(scenario.durable);
      expect(snap.leaseHeld).toBe(true);
      expect(snap.terminal).toBe(false);
      expect(snap.needsAttention).toBe(true);
      expect(calls).toHaveLength(1);
    },
  );

  /** Pinned to a PRE-SUBMIT residue: that is the recovery path which resumes the lifecycle, so
   *  it is the only one where a resumed landing step could release the lease a second time.
   *  An AFTER_SUBMIT residue reconciles without re-entering the lifecycle at all and therefore
   *  cannot exhibit the fault this test is named for. */
  it.each(SUBMITTING_KINDS)(
    "%s: the lease is released exactly once, only on a verified landing",
    (kind) => {
      const { port } = countingSubmit();
      const crashed = crashAt(freshScenario(kind), port, "AFTER_STEP2_PREIMAGE");
      const { scenario, outcome } = crashThenRecover(crashed, port, LANDED);
      expect(outcome.landed).toBe(true);
      expect(snapshotDurable(scenario.durable).leaseHeld).toBe(false);
      expect(scenario.runtime.log.leaseReleases).toBe(1);
      expect(scenario.runtime.log.eventsEmitted).toEqual([LANDED_EVENT[kind]]);
    },
  );

  /** Landing is gated by a verified settlement observation on EVERY recovery path. A resumed
   *  lifecycle must stop short of its landing step: acknowledgement is not settlement
   *, so an unobserved landing keeps the lease and emits nothing. */
  it.each(SUBMITTING_KINDS)(
    "%s: a pre-submit residue with no verified landing submits once, then holds the lease",
    (kind) => {
      const { port, calls } = countingSubmit();
      const crashed = crashAt(freshScenario(kind), port, "AFTER_STEP2_PREIMAGE");
      const { scenario, outcome } = crashThenRecover(crashed, port, NOT_LANDED);
      expect(outcome.landed).toBe(false);
      const snap = snapshotDurable(scenario.durable);
      // The initial submit is first submission, not a retry — it runs; the landing does not.
      expect(snap.submitClaimed).toBe(true);
      expect(calls).toHaveLength(1);
      expect(snap.terminal).toBe(false);
      expect(snap.leaseHeld).toBe(true);
      expect(snap.needsAttention).toBe(true);
      expect(snap.events).toBe(0);
      expect(scenario.runtime.log.leaseReleases).toBe(0);
    },
  );
});

describe("crash injection — invariant breach fails closed", () => {
  it("a step-1 signer-audit record that cannot be reproduced from persisted bytes is INVARIANT_BREACH", () => {
    const { port, calls } = countingSubmit();
    const crashed = crashAt(freshScenario("MOVE_INTERNAL"), port, "AFTER_INNER_PREIMAGE");
    // Corrupt the residue: a step-1 signer-audit entry whose digest contradicts the persisted
    // inner preimage. Recovery must fail closed, never re-form, never submit, never land.
    crashed.durable.signerAudit.push({
      operationId: OPERATION_IDS.MOVE_INTERNAL,
      step: 1,
      preimageSha256: "f".repeat(64),
      signature: "forged-signature",
    });

    const { scenario, outcome } = crashThenRecover(crashed, port, LANDED);
    expect(outcome.classification).toBe("INVARIANT_BREACH");
    expect(outcome.landed).toBe(false);
    const snap = snapshotDurable(scenario.durable);
    expect(snap.needsAttention).toBe(true);
    expect(snap.terminal).toBe(false);
    expect(snap.leaseHeld).toBe(true);
    expect(calls).toHaveLength(0);
  });

  /** The step-2 mirror: signer-audit evidence that a step-2 call occurred over bytes that are
   * not the persisted step-2 preimage. recovery: "If exactness cannot be established,
   *  INVARIANT_BREACH" — never a re-formation over different bytes. */
  it.each(SUBMITTING_KINDS)(
    "%s: a step-2 signer-audit record contradicting the persisted step-2 preimage is INVARIANT_BREACH",
    (kind) => {
      const { port, calls } = countingSubmit();
      const crashed = crashAt(freshScenario(kind), port, "AFTER_STEP2_PREIMAGE");
      const persistedStep2 = snapshotDurable(crashed.durable).step2PreimageText as string;
      crashed.durable.signerAudit.push({
        operationId: OPERATION_IDS[kind],
        step: 2,
        preimageSha256: "e".repeat(64),
        signature: "signature-over-other-bytes",
      });

      const { scenario, outcome } = crashThenRecover(crashed, port, LANDED);
      expect(outcome.classification).toBe("INVARIANT_BREACH");
      expect(outcome.landed).toBe(false);
      const snap = snapshotDurable(scenario.durable);
      expect(snap.needsAttention).toBe(true);
      expect(snap.terminal).toBe(false);
      expect(snap.leaseHeld).toBe(true);
      expect(calls).toHaveLength(0);
      // Failing closed leaves the persisted bytes untouched — no re-formation, no overwrite.
      expect(snap.step2PreimageText).toBe(persistedStep2);
      expect(snap.step2Signature).toBeUndefined();
    },
  );
});

describe("crash injection — receive has no rebuild path", () => {
  it("a receive residue missing the payer bytes is INVARIANT_BREACH, never a re-formation", () => {
    const { port, calls } = countingSubmit();
    const crashed = crashAt(freshScenario("RECEIVE_EXTERNAL"), port, "AFTER_CREATE");
    // Simulate the attempt row not surviving: the node now holds no payer-signed inner bytes.
    crashed.durable.attempts = [];

    const { scenario, outcome } = crashThenRecover(crashed, port, LANDED);
    expect(outcome.classification).toBe("INVARIANT_BREACH");
    expect(outcome.landed).toBe(false);
    const snap = snapshotDurable(scenario.durable);
    // The node did NOT invent replacement inner bytes to continue with.
    expect(snap.attempts).toBe(0);
    expect(snap.needsAttention).toBe(true);
    expect(snap.leaseHeld).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("a receive residue with the payer bytes but no step-1 signature is INVARIANT_BREACH", () => {
    const { port, calls } = countingSubmit();
    const crashed = crashAt(freshScenario("RECEIVE_EXTERNAL"), port, "AFTER_CREATE");
    const attempt = crashed.durable.attempts[0];
    expect(attempt).toBeDefined();
    if (attempt !== undefined) {
      attempt.step1Signature = null;
    }

    const { outcome } = crashThenRecover(crashed, port, LANDED);
    expect(outcome.classification).toBe("INVARIANT_BREACH");
    expect(calls).toHaveLength(0);
  });

  it("the node's signer is never invoked for step 1 of a receive", () => {
    const scenario = freshScenario("RECEIVE_EXTERNAL");
    const { port } = countingSubmit();
    runLifecycle(scenario, port);

    const steps = scenario.runtime.log.signerCalls.map((call) => call.step);
    expect(steps).toEqual([2]);
    // The persisted step-1 signature is the payer's — not reproducible from the node's key.
    const snap = snapshotDurable(scenario.durable);
    const inner = snap.innerPreimageText as string;
    expect(snap.step1Signature).toBe(signWithSeed(inner, PAYER_SEED_BYTE));
    expect(snap.step1Signature).not.toBe(signWithSeed(inner, KEY_SEED_BYTE));
  });
});
