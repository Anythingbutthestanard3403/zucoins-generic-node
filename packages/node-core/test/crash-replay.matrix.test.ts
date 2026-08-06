// Residual — category (a): the crash matrix, driven from the frozen
// data. Every case is a durable-state fixture + recovery pass (never a bare "kill"):
// CRASH AXIOM — all volatile state lost, all committed writes survive, all uncommitted
// writes discarded; a kill inside DB-TX-N ≡ end of DB-TX-(N-1). The axiom is enforced
// mechanically by crashAndRecover (JSON round-trip of the durable store + brand-new
// runtime) and is itself recorded in CRASH_REPLAY_PERSISTENCE_OBLIGATIONS.
import { beforeAll, describe, expect, it } from "vitest";

import {
  digestPreimage,
  ready,
} from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD,
  CRASH_DURABLE_STATES,
  CRASH_MATRIX,
  INVARIANT_BREACH_PREDICATE,
} from "../../generic-node-contracts/src/approval/crash-recovery.contract.ts";
import {
  APPROVAL_ID,
  baselinePlan,
  BASELINE_PREIMAGE_TEXT,
  FORMATION_CLOCK_SECS,
  freshObservationPlan,
  KEY_SEED_BYTE,
  OPERATION_ID,
  signFixture,
  T2_SECS,
  type FormationPlan,
} from "./crash-replay-fixtures.ts";
import {
  addSecs,
  createRuntime,
  type Scenario,
  type UnixSecsString,
} from "./crash-replay-model.ts";
import {
  classifyDurableState,
  crashAndRecover,
  driveFormation,
  driveToDurableState,
  notLaunchReachableProvenNotLanded,
  type HeadObservation,
} from "./crash-replay-driver.ts";
import {
  FORBIDDEN_EFFECT_DETECTORS,
  PRESCRIBED_EFFECT_ASSERTERS,
  recoverOperation,
  snapshotDurable,
  type OracleContext,
} from "./crash-replay-recovery.ts";

const HEALTHY_NOW: UnixSecsString = addSecs(FORMATION_CLOCK_SECS, 60);
const HEAD_UNCHANGED: HeadObservation = { kind: "HEAD_UNCHANGED" };

const freshScenario = (approvalConsumed: boolean): Scenario => ({
  durable: {
    operations: [
      {
        operationId: OPERATION_ID,
        kind: "SEND_EXTERNAL",
        status: approvalConsumed ? "APPROVED" : "CREATED",
        formationState: approvalConsumed ? "APPROVED_UNSIGNED" : "APPROVAL_PENDING",
        needsAttention: false,
        terminal: false,
        leaseHeld: false,
        approvalConsumed,
        approvalId: APPROVAL_ID,
      },
    ],
    signIntents: [],
    attempts: [],
    partials: [],
    signerAudit: [],
    deliveries: [],
  },
  runtime: createRuntime("formation-worker", KEY_SEED_BYTE),
});

interface RecoveryRun {
  readonly scenario: Scenario;
  readonly ctx: OracleContext;
  readonly outcome: ReturnType<typeof recoverOperation>;
}

const runRecoveryPass = (options: {
  durableState: string;
  approvalConsumed?: boolean;
  observation?: HeadObservation;
  nowSecs?: UnixSecsString;
  preCrash?: (scenario: Scenario) => void;
  recoveryPlan?: FormationPlan;
}): RecoveryRun => {
  const approvalConsumed =
    options.approvalConsumed ?? options.durableState !== "APPROVAL_PENDING_NO_SIGN_INTENT";
  const driven = freshScenario(approvalConsumed);
  driveToDurableState(driven, baselinePlan(), options.durableState);
  options.preCrash?.(driven);
  const before = snapshotDurable(driven.durable, OPERATION_ID);
  const scenario = crashAndRecover(driven);
  const observation = options.observation ?? HEAD_UNCHANGED;
  const nowSecs = options.nowSecs ?? HEALTHY_NOW;
  const plan = options.recoveryPlan ?? freshObservationPlan();
  const outcome = recoverOperation(scenario, plan, OPERATION_ID, nowSecs, observation);
  return {
    scenario,
    outcome,
    ctx: {
      scenario,
      operationId: OPERATION_ID,
      before,
      observation,
      nowSecs,
      classification: outcome.classification,
    },
  };
};

const assertCardinality = (scenario: Scenario): void => {
  const counts = snapshotDurable(scenario.durable, OPERATION_ID);
  expect(counts.intents).toBeLessThanOrEqual(1);
  expect(counts.partials).toBeLessThanOrEqual(1);
  expect(counts.attempts).toBeLessThanOrEqual(1);
  for (const row of scenario.durable.attempts) {
    expect(row["attempt_no"]).toBe(1);
  }
};

const injectSignerAuditEvidence = (scenario: Scenario): void => {
  scenario.durable.signerAudit.push({
    operationId: OPERATION_ID,
    preimageSha256: digestPreimage(BASELINE_PREIMAGE_TEXT),
    signature: signFixture(BASELINE_PREIMAGE_TEXT),
  });
};

beforeAll(async () => {
  await ready();
});

describe("a crash matrix — durable-state fixture + recovery pass", () => {
  it.each(CRASH_MATRIX)(
    "durable-state fixture $durableState + recovery pass -> $recovery, never $forbidden",
    (row) => {
      const observation: HeadObservation =
        row.durableState === "PARTIAL_DELIVERED_EXPECTED_AT_HEAD"
          ? { kind: "EXPECTED_AT_HEAD" }
          : row.durableState === "PARTIAL_DELIVERED_HEAD_ANOMALOUS"
            ? { kind: "HEAD_ANOMALOUS", variant: "unrelated" }
            : row.durableState === "PARTIAL_EXPIRED"
              ? { kind: "NO_POSITIVE_PROOF" }
              : HEAD_UNCHANGED;
      const nowSecs =
        row.durableState === "PARTIAL_EXPIRED" ? addSecs(T2_SECS, 3600) : HEALTHY_NOW;
      const run = runRecoveryPass({ durableState: row.durableState, observation, nowSecs });
      expect(run.outcome.classification).toBe(row.durableState);
      expect(
        PRESCRIBED_EFFECT_ASSERTERS[row.recovery](run.ctx),
        `prescribed ${row.recovery} must hold`,
      ).toBe(true);
      expect(
        FORBIDDEN_EFFECT_DETECTORS[row.forbidden](run.ctx),
        `forbidden ${row.forbidden} must not occur`,
      ).toBe(false);
      assertCardinality(run.scenario);
    },
  );

  it("the anomalous-head cell feeds ALL THREE sub-variants (unrelated / regressed / unverifiable)", () => {
    const row = CRASH_MATRIX.find(
      (candidate) => candidate.durableState === "PARTIAL_DELIVERED_HEAD_ANOMALOUS",
    );
    if (row === undefined) {
      throw new Error("frozen matrix lost its anomalous-head row");
    }
    for (const variant of ["unrelated", "regressed", "unverifiable"] as const) {
      const observation: HeadObservation = { kind: "HEAD_ANOMALOUS", variant };
      const run = runRecoveryPass({
        durableState: row.durableState,
        observation,
        nowSecs: HEALTHY_NOW,
      });
      expect(PRESCRIBED_EFFECT_ASSERTERS[row.recovery](run.ctx), variant).toBe(true);
      expect(FORBIDDEN_EFFECT_DETECTORS[row.forbidden](run.ctx), variant).toBe(false);
      assertCardinality(run.scenario);
    }
  });

  it("the expired cell: no terminalization without positive proof; PERMITTED with proof at margin; refused before margin", () => {
    const row = CRASH_MATRIX.find((candidate) => candidate.durableState === "PARTIAL_EXPIRED");
    if (row === undefined) {
      throw new Error("frozen matrix lost its expired row");
    }
    const noProof = runRecoveryPass({
      durableState: row.durableState,
      observation: { kind: "NO_POSITIVE_PROOF" },
      nowSecs: addSecs(T2_SECS, 3600),
    });
    expect(PRESCRIBED_EFFECT_ASSERTERS[row.recovery](noProof.ctx)).toBe(true);
    expect(FORBIDDEN_EFFECT_DETECTORS[row.forbidden](noProof.ctx)).toBe(false);

    // PROVEN_NOT_LANDED is not launch-reachable. The matrix still
    // documents the RESERVED NEEDS_ATTENTION→REJECTED semantics, but only via the
    // explicitly branded constructor (notLaunchReachableProvenNotLanded) — never a bare
    // unbranded object literal of that kind.
    const provenAtMargin = runRecoveryPass({
      durableState: row.durableState,
      observation: notLaunchReachableProvenNotLanded(),
      nowSecs: addSecs(T2_SECS, 3600),
    });
    expect(PRESCRIBED_EFFECT_ASSERTERS[row.recovery](provenAtMargin.ctx)).toBe(true);
    expect(provenAtMargin.scenario.runtime.log.terminalizations).toHaveLength(1);
    expect(FORBIDDEN_EFFECT_DETECTORS[row.forbidden](provenAtMargin.ctx)).toBe(false);

    const provenBeforeMargin = runRecoveryPass({
      durableState: row.durableState,
      observation: notLaunchReachableProvenNotLanded(),
      nowSecs: addSecs(T2_SECS, 3599),
    });
    expect(PRESCRIBED_EFFECT_ASSERTERS[row.recovery](provenBeforeMargin.ctx)).toBe(true);
    expect(provenBeforeMargin.scenario.runtime.log.terminalizations).toHaveLength(0);
    expect(FORBIDDEN_EFFECT_DETECTORS[row.forbidden](provenBeforeMargin.ctx)).toBe(false);
  });

  it("crash injection at every step boundary of the custody ten-step formation lands in exactly one censused durable state", () => {
    for (let stopAfterStep = 0; stopAfterStep <= 10; stopAfterStep += 1) {
      const driven = freshScenario(true);
      driveFormation(driven, baselinePlan(), stopAfterStep);
      const classification = classifyDurableState(
        driven.durable,
        OPERATION_ID,
        HEALTHY_NOW,
        HEAD_UNCHANGED,
      );
      expect(
        (CRASH_DURABLE_STATES as readonly string[]).includes(classification),
        `boundary ${stopAfterStep} residue ${classification} must be censused`,
      ).toBe(true);
      const row = CRASH_MATRIX.find((candidate) => candidate.durableState === classification);
      if (row === undefined) {
        throw new Error(`no frozen row for ${classification}`);
      }
      const before = snapshotDurable(driven.durable, OPERATION_ID);
      const scenario = crashAndRecover(driven);
      const outcome = recoverOperation(
        scenario,
        freshObservationPlan(),
        OPERATION_ID,
        HEALTHY_NOW,
        HEAD_UNCHANGED,
      );
      const ctx: OracleContext = {
        scenario,
        operationId: OPERATION_ID,
        before,
        observation: HEAD_UNCHANGED,
        nowSecs: HEALTHY_NOW,
        classification: outcome.classification,
      };
      expect(PRESCRIBED_EFFECT_ASSERTERS[row.recovery](ctx), `boundary ${stopAfterStep}`).toBe(true);
      expect(FORBIDDEN_EFFECT_DETECTORS[row.forbidden](ctx), `boundary ${stopAfterStep}`).toBe(false);
      assertCardinality(scenario);
    }
  });

  it("recovery reads only durable rows: the JSON clone and the live store produce identical effect logs", () => {
    const driven = freshScenario(true);
    driveFormation(driven, baselinePlan(), 5);
    const plan = freshObservationPlan();
    const recoveredOverClone = crashAndRecover(driven);
    const outcomeClone = recoverOperation(
      recoveredOverClone,
      plan,
      OPERATION_ID,
      HEALTHY_NOW,
      HEAD_UNCHANGED,
    );
    const recoveredOverLive: Scenario = {
      durable: driven.durable,
      runtime: createRuntime("worker-1", KEY_SEED_BYTE),
    };
    const outcomeLive = recoverOperation(
      recoveredOverLive,
      plan,
      OPERATION_ID,
      HEALTHY_NOW,
      HEAD_UNCHANGED,
    );
    expect(JSON.stringify(recoveredOverClone.runtime.log)).toBe(
      JSON.stringify(recoveredOverLive.runtime.log),
    );
    expect(outcomeClone.action).toBe(outcomeLive.action);
  });

  it("INVARIANT_BREACH: signer-audit call with no persisted sign intent -> NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE; no first formation, no re-sign, no lease release", () => {
    const run = runRecoveryPass({
      durableState: "APPROVAL_CONSUMED_NO_SIGN_INTENT",
      preCrash: injectSignerAuditEvidence,
    });
    expect(run.outcome.action).toBe("NEEDS_ATTENTION");
    expect(PRESCRIBED_EFFECT_ASSERTERS.NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE(run.ctx)).toBe(true);
    const after = snapshotDurable(run.scenario.durable, OPERATION_ID);
    expect(after.intents).toBe(0);
    expect(after.partials).toBe(0);
    expect(after.auditEntries).toBe(1);
    expect(run.scenario.runtime.log.signerCalls).toHaveLength(0);
    expect(run.scenario.runtime.log.leaseReleases).toBe(0);
    expect(INVARIANT_BREACH_PREDICATE.permitsFirstFormation).toBe(false);
    expect(INVARIANT_BREACH_PREDICATE.permitsReSign).toBe(false);
    expect(INVARIANT_BREACH_PREDICATE.permitsLeaseRelease).toBe(false);
  });

  it.each(INVARIANT_BREACH_PREDICATE.triggeredBy)(
    "INVARIANT_BREACH trigger %s routes to NEEDS_ATTENTION, never formation",
    (trigger) => {
      const run =
        trigger === "no_persisted_sign_intent_row_but_signer_audit_shows_a_signing_call"
          ? runRecoveryPass({
              durableState: "APPROVAL_CONSUMED_NO_SIGN_INTENT",
              preCrash: injectSignerAuditEvidence,
            })
          : runRecoveryPass({
              durableState: "SIGNING_CLAIMED_NO_PARTIAL",
              preCrash: (scenario) => {
                const intent = scenario.durable.signIntents[0];
                if (intent === undefined) {
                  throw new Error("fixture lost its intent row");
                }
                intent["inner_sha256"] = "0".repeat(64);
              },
            });
      expect(run.outcome.action).toBe("NEEDS_ATTENTION");
      expect(PRESCRIBED_EFFECT_ASSERTERS.NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE(run.ctx)).toBe(true);
      expect(run.scenario.runtime.log.signerCalls).toHaveLength(0);
      expect(snapshotDurable(run.scenario.durable, OPERATION_ID).partials).toBe(0);
    },
  );

  it("APPROVAL_CONSUMED_NO_SIGN_INTENT ordinary case first-forms only after proving the signer was never called (APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD)", () => {
    expect(APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD.row).toBe("APPROVAL_CONSUMED_NO_SIGN_INTENT");
    expect(APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD.guard).toBe(
      "first_formation_permitted_only_after_proving_signer_never_called",
    );
    const driven = freshScenario(true);
    driveFormation(driven, baselinePlan(), 1);
    expect(driven.durable.signerAudit).toHaveLength(0); // the guard's premise, as a fixture
    const before = snapshotDurable(driven.durable, OPERATION_ID);
    const scenario = crashAndRecover(driven);
    const outcome = recoverOperation(
      scenario,
      freshObservationPlan(),
      OPERATION_ID,
      HEALTHY_NOW,
      HEAD_UNCHANGED,
    );
    const ctx: OracleContext = {
      scenario,
      operationId: OPERATION_ID,
      before,
      observation: HEAD_UNCHANGED,
      nowSecs: HEALTHY_NOW,
      classification: outcome.classification,
    };
    expect(outcome.action).toBe("FIRST_FORMATION_COMPLETED");
    expect(PRESCRIBED_EFFECT_ASSERTERS.ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT(ctx)).toBe(true);
    expect(FORBIDDEN_EFFECT_DETECTORS.CREATE_SECOND_SIGN_INTENT(ctx)).toBe(false);
  });

  it("crash after signature computation but before persistence recovers to the SAME signature — completion, not new authorization (custody; DETERMINISTIC_RESIGN)", () => {
    const driven = freshScenario(true);
    driveFormation(driven, baselinePlan(), 7); // signer-audit durable, no partial
    const auditSignature = driven.durable.signerAudit[0]?.signature;
    if (auditSignature === undefined) {
      throw new Error("fixture lost its signer-audit entry");
    }
    const before = snapshotDurable(driven.durable, OPERATION_ID);
    const scenario = crashAndRecover(driven);
    recoverOperation(scenario, freshObservationPlan(), OPERATION_ID, HEALTHY_NOW, HEAD_UNCHANGED);
    const after = snapshotDurable(scenario.durable, OPERATION_ID);
    expect(after.partials).toBe(1);
    expect(after.auditEntries).toBe(1);
    expect(scenario.durable.partials[0]?.["step_1_signature"]).toBe(auditSignature);
    expect(scenario.runtime.log.signerCalls).toHaveLength(1);
    expect(scenario.runtime.log.signerCalls[0]?.signature).toBe(auditSignature);
    expect(after.attempts).toBe(1);
    const ctx: OracleContext = {
      scenario,
      operationId: OPERATION_ID,
      before,
      observation: HEAD_UNCHANGED,
      nowSecs: HEALTHY_NOW,
      classification: "SIGNING_CLAIMED_NO_PARTIAL",
    };
    expect(
      PRESCRIBED_EFFECT_ASSERTERS.REVALIDATE_SAME_PREIMAGE_COMPLETE_FIRST_FORMATION(ctx),
    ).toBe(true);
  });

  it("a re-sign/signer-audit mismatch before delivery is INVARIANT_BREACH and is never delivered (DETERMINISTIC_RESIGN.recoveryByteComparesAgainstPriorSignerAuditSignatureBeforeDelivery)", () => {
    const run = runRecoveryPass({
      durableState: "SIGNING_CLAIMED_NO_PARTIAL",
      preCrash: (scenario) => {
        scenario.durable.signerAudit.push({
          operationId: OPERATION_ID,
          preimageSha256: digestPreimage(BASELINE_PREIMAGE_TEXT),
          signature: `${"B".repeat(86)}==`,
        });
      },
    });
    expect(run.outcome.action).toBe("NEEDS_ATTENTION");
    expect(run.scenario.runtime.log.needsAttentionMarks[0]).toContain("INVARIANT_BREACH");
    expect(run.scenario.runtime.log.deliveriesServed).toHaveLength(0);
    expect(snapshotDurable(run.scenario.durable, OPERATION_ID).partials).toBe(0);
    expect(run.scenario.runtime.log.leaseReleases).toBe(0);
  });
});
