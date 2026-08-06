// Residual — category (b): the compare-and-swap race on the shared
// operations.formation_state cell. CRASH AXIOM as recorded in the matrix suite. Claims
// here are scoped "per enumerated schedule over the parsed store" — the live-DB
// discharge is the test plan ("real database concurrency tests, not only
// mocked unit tests"), recorded in CRASH_REPLAY_PERSISTENCE_OBLIGATIONS. Never
// claimed: "the database enforces one contender". Losers receive the harness-local typed
// refusal SIGNING_CLAIM_CAS_LOST and produce zero side effects.
import { beforeAll, describe, expect, it } from "vitest";

import { ready } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import { FORMATION_STATES } from "../../generic-node-contracts/src/approval/sign-intent.contract.ts";
import {
  APPROVAL_ID,
  baselinePlan,
  FORMATION_CLOCK_SECS,
  freshObservationPlan,
  KEY_SEED_BYTE,
  makeSignIntentRow,
  OPERATION_ID,
} from "./crash-replay-fixtures.ts";
import {
  addSecs,
  commitInsert,
  createRuntime,
  findOperation,
  REFUSAL_CAS_LOST,
  type Runtime,
  type Scenario,
} from "./crash-replay-model.ts";
import {
  compareAndSwapFormationState,
  commitClaim,
  tryClaimTentative,
} from "./crash-replay-cas.ts";
import { crashAndRecover, driveFormation, type HeadObservation } from "./crash-replay-driver.ts";
import {
  recoverOperation,
  snapshotDurable,
} from "./crash-replay-recovery.ts";
import {
  FORMATION_ENUM_MEMBERS,
  SEND_EXTERNAL_STATUSES,
  SIGN_INTENTS_TABLE,
  SIGN_INTENTS_TABLE_NAME,
} from "./crash-replay-surfaces.ts";

const withRuntime = (scenario: Scenario, runtime: Runtime): Scenario => ({
  durable: scenario.durable,
  runtime,
});

/** Durable store with the sign intent already persisted (custody steps 1-4 done), ready
 *  for the CAS contention of step 5. */
const contendedStore = (): Scenario => {
  const scenario: Scenario = {
    durable: {
      operations: [
        {
          operationId: OPERATION_ID,
          kind: "SEND_EXTERNAL",
          status: "APPROVED",
          formationState: "APPROVED_UNSIGNED",
          needsAttention: false,
          terminal: false,
          leaseHeld: true,
          approvalConsumed: true,
          approvalId: APPROVAL_ID,
        },
      ],
      signIntents: [],
      attempts: [],
      partials: [],
      signerAudit: [],
      deliveries: [],
    },
    runtime: createRuntime("setup", KEY_SEED_BYTE),
  };
  driveFormation(scenario, baselinePlan(), 4);
  return scenario;
};

const loserHadNoSideEffects = (runtime: Runtime): void => {
  expect(runtime.log.signerCalls).toHaveLength(0);
  expect(runtime.log.insertAttempts).toHaveLength(0);
  expect(runtime.log.deliveriesServed).toHaveLength(0);
  expect(runtime.log.formationTransitions).toHaveLength(0);
  expect(runtime.log.leaseReleases).toBe(0);
  expect(runtime.log.terminalizations).toHaveLength(0);
};

/** Every interleaving of two 2-statement workers ([OBSERVE, CAS] each), exhaustive by
 *  construction: choosing A's two positions among four yields all C(4,2) schedules. */
const twoWorkerSchedules = (): string[][] => {
  const schedules: string[][] = [];
  for (let first = 0; first < 4; first += 1) {
    for (let second = first + 1; second < 4; second += 1) {
      const schedule = ["B1", "B1", "B1", "B1"];
      schedule[first] = "A1";
      schedule[second] = "A2";
      let bIndex = 0;
      schedules.push(
        schedule.map((token) => {
          if (token === "A1" || token === "A2") {
            return token;
          }
          bIndex += 1;
          return `B${bIndex}`;
        }),
      );
    }
  }
  return schedules;
};

beforeAll(async () => {
  await ready();
});

describe("b CAS race over the parsed store (formation step 5)", () => {
  it("the enum / FORMATION_STATES mapping is asserted, not assumed (6 members vs 5)", () => {
    expect(FORMATION_ENUM_MEMBERS).toHaveLength(6);
    expect(FORMATION_STATES).toHaveLength(5);
    const enumLadder = FORMATION_ENUM_MEMBERS.filter(
      (member) => member !== "NOT_REQUIRED" && member !== "APPROVAL_PENDING",
    );
    const contractLadder = FORMATION_STATES.filter((member) => member !== "AWAITING_REDEMPTION");
    expect(enumLadder).toEqual([...contractLadder]);
    expect(FORMATION_ENUM_MEMBERS).not.toContain("AWAITING_REDEMPTION");
    expect(SEND_EXTERNAL_STATUSES).toContain("AWAITING_REDEMPTION");
    expect(FORMATION_ENUM_MEMBERS).toContain("APPROVED_UNSIGNED");
    expect(FORMATION_ENUM_MEMBERS).toContain("SIGNING_CLAIMED");
  });

  it("all statement-order permutations of two racing workers yield exactly one winner — exhaustive by construction", () => {
    const schedules = twoWorkerSchedules();
    expect(schedules).toHaveLength(6); // C(4,2): the construction is the exhaustiveness proof
    expect(new Set(schedules.map((schedule) => schedule.join(","))).size).toBe(6);
    for (const schedule of schedules) {
      const scenario = contendedStore();
      const runtimeA = createRuntime("worker-A", KEY_SEED_BYTE);
      const runtimeB = createRuntime("worker-B", KEY_SEED_BYTE);
      const observed: Record<string, string> = {};
      const casResult: Record<string, boolean> = {};
      for (const token of schedule) {
        const worker = token[0] === "A" ? "A" : "B";
        const runtime = worker === "A" ? runtimeA : runtimeB;
        if (token.endsWith("1")) {
          observed[worker] = findOperation(scenario.durable, OPERATION_ID).formationState;
        } else {
          casResult[worker] = compareAndSwapFormationState(
            withRuntime(scenario, runtime),
            OPERATION_ID,
          );
        }
      }
      expect(casResult.A !== casResult.B, `${schedule.join("")}: exactly one winner`).toBe(true);
      const loser = casResult.A ? runtimeB : runtimeA;
      const winner = casResult.A ? runtimeA : runtimeB;
      expect(loser.log.refusals).toContain(REFUSAL_CAS_LOST);
      loserHadNoSideEffects(loser);
      expect(winner.log.formationTransitions).toHaveLength(1);
      expect(findOperation(scenario.durable, OPERATION_ID).formationState).toBe("SIGNING_CLAIMED");
      // Predicate recheck: whenever the loser OBSERVED before the winner's write, its stale
      // APPROVED_UNSIGNED read did NOT let its CAS through — the guarded write re-evaluated
      // the predicate against the winner's committed value.
      const loserStaleRead = observed[casResult.A ? "B" : "A"] === "APPROVED_UNSIGNED";
      if (schedule.indexOf(`${casResult.A ? "B" : "A"}1`) < schedule.indexOf(casResult.A ? "A2" : "B2")) {
        expect(loserStaleRead).toBe(true);
        expect(casResult[casResult.A ? "B" : "A"]).toBe(false);
      }
    }
  });

  it("N=8 barrier-released race: all workers observe, then race in a seeded order — one winner, seven typed refusals", () => {
    const scenario = contendedStore();
    const seededOrder = [5, 3, 8, 1, 7, 2, 6, 4];
    const runtimes = new Map<number, Runtime>();
    for (const id of seededOrder) {
      runtimes.set(id, createRuntime(`worker-${id}`, KEY_SEED_BYTE));
      expect(findOperation(scenario.durable, OPERATION_ID).formationState).toBe("APPROVED_UNSIGNED");
    }
    const results = new Map<number, boolean>();
    for (const id of seededOrder) {
      const runtime = runtimes.get(id);
      if (runtime === undefined) {
        throw new Error(`missing runtime for worker ${id}`);
      }
      results.set(id, compareAndSwapFormationState(withRuntime(scenario, runtime), OPERATION_ID));
    }
    const winners = seededOrder.filter((id) => results.get(id) === true);
    expect(winners).toEqual([5]);
    for (const id of seededOrder.filter((loser) => loser !== 5)) {
      const runtime = runtimes.get(id);
      if (runtime === undefined) {
        throw new Error(`missing runtime for worker ${id}`);
      }
      expect(runtime.log.refusals).toContain(REFUSAL_CAS_LOST);
      loserHadNoSideEffects(runtime);
    }
  });

  it("no two workers reach the signer: the winner completes; total signer-audit entries == 1 and committed partials == 1", () => {
    const scenario = contendedStore();
    const runtimeA = createRuntime("worker-A", KEY_SEED_BYTE);
    const runtimeB = createRuntime("worker-B", KEY_SEED_BYTE);
    expect(compareAndSwapFormationState(withRuntime(scenario, runtimeA), OPERATION_ID)).toBe(true);
    expect(compareAndSwapFormationState(withRuntime(scenario, runtimeB), OPERATION_ID)).toBe(false);
    const observation: HeadObservation = { kind: "HEAD_UNCHANGED" };
    const outcome = recoverOperation(
      withRuntime(scenario, runtimeA),
      freshObservationPlan(),
      OPERATION_ID,
      addSecs(FORMATION_CLOCK_SECS, 60),
      observation,
    );
    expect(outcome.action).toBe("COMPLETED_FIRST_FORMATION");
    const counts = snapshotDurable(scenario.durable, OPERATION_ID);
    expect(counts.auditEntries).toBe(1);
    expect(counts.partials).toBe(1);
    expect(counts.intents).toBe(1);
  });

  it("a concurrent sign-intent insert loses on the parsed PRIMARY KEY before any CAS (data-model, structural layer)", () => {
    for (const order of ["AB", "BA"] as const) {
      const scenario = contendedStore();
      scenario.durable.signIntents.length = 0; // both workers race the persist itself
      const runtimeA = createRuntime(`worker-A-${order}`, KEY_SEED_BYTE);
      const runtimeB = createRuntime(`worker-B-${order}`, KEY_SEED_BYTE);
      const [first, second] =
        order === "AB" ? [runtimeA, runtimeB] : [runtimeB, runtimeA];
      const firstVerdict = commitInsert(
        withRuntime(scenario, first),
        SIGN_INTENTS_TABLE,
        scenario.durable.signIntents,
        makeSignIntentRow(baselinePlan()),
        SIGN_INTENTS_TABLE_NAME,
        OPERATION_ID,
      );
      const secondVerdict = commitInsert(
        withRuntime(scenario, second),
        SIGN_INTENTS_TABLE,
        scenario.durable.signIntents,
        makeSignIntentRow(baselinePlan()),
        SIGN_INTENTS_TABLE_NAME,
        OPERATION_ID,
      );
      expect(firstVerdict.committed).toBe(true);
      expect(secondVerdict.committed).toBe(false);
      expect(secondVerdict.rejectedByKey?.kind).toBe("PRIMARY KEY");
      expect(secondVerdict.rejectedByKey?.columns).toEqual(["operation_id"]);
      expect(scenario.durable.signIntents).toHaveLength(1);
    }
  });

  it("a loser retrying after the typed refusal observes the persisted intent and forms nothing new (the never-blind-retry rule — never blind-retry)", () => {
    const scenario = contendedStore();
    const runtimeA = createRuntime("worker-A", KEY_SEED_BYTE);
    const runtimeB = createRuntime("worker-B", KEY_SEED_BYTE);
    compareAndSwapFormationState(withRuntime(scenario, runtimeA), OPERATION_ID);
    compareAndSwapFormationState(withRuntime(scenario, runtimeB), OPERATION_ID);
    recoverOperation(
      withRuntime(scenario, runtimeA),
      freshObservationPlan(),
      OPERATION_ID,
      addSecs(FORMATION_CLOCK_SECS, 60),
      { kind: "HEAD_UNCHANGED" },
    );
    const countsBefore = snapshotDurable(scenario.durable, OPERATION_ID);
    const retryOutcome = recoverOperation(
      withRuntime(scenario, runtimeB),
      freshObservationPlan(),
      OPERATION_ID,
      addSecs(FORMATION_CLOCK_SECS, 120),
      { kind: "HEAD_UNCHANGED" },
    );
    expect(retryOutcome.action).toBe("REDELIVERED");
    expect(runtimeB.log.signerCalls).toHaveLength(0);
    expect(runtimeB.log.insertAttempts).toHaveLength(0);
    const countsAfter = snapshotDurable(scenario.durable, OPERATION_ID);
    expect(countsAfter.intents).toBe(countsBefore.intents);
    expect(countsAfter.partials).toBe(countsBefore.partials);
    expect(runtimeB.log.deliveriesServed[0]?.transferCodeText).toBe(countsBefore.codeText);
  });

  it("abort path: a worker blocked behind the winner's UNCOMMITTED claim proceeds after the winner aborts (not permanently excluded)", () => {
    // The tentative-claim ledger is the shared database row-lock: both workers contend on the
    // SAME scenario (one volatile ledger), distinguished by workerId — a separate runtime per
    // worker would hide A's open claim from B and could never produce BLOCKED.
    const scenario = contendedStore();
    expect(tryClaimTentative(scenario, OPERATION_ID, "worker-A")).toBe("CLAIMED");
    expect(tryClaimTentative(scenario, OPERATION_ID, "worker-B")).toBe("BLOCKED");
    // A crashes mid-claim: the uncommitted claim rolls back (crash axiom), B rechecks.
    const recovered = crashAndRecover(scenario);
    expect(findOperation(recovered.durable, OPERATION_ID).formationState).toBe("APPROVED_UNSIGNED");
    expect(tryClaimTentative(recovered, OPERATION_ID, "worker-B")).toBe("CLAIMED");
    commitClaim(recovered, OPERATION_ID, "worker-B");
    const outcome = recoverOperation(
      recovered,
      freshObservationPlan(),
      OPERATION_ID,
      addSecs(FORMATION_CLOCK_SECS, 60),
      { kind: "HEAD_UNCHANGED" },
    );
    expect(outcome.action).toBe("COMPLETED_FIRST_FORMATION");
    const counts = snapshotDurable(recovered.durable, OPERATION_ID);
    expect(counts.intents).toBe(1);
    expect(counts.partials).toBe(1);
    expect(counts.auditEntries).toBe(1);
  });
});
