// The network-call-counting proof for MOVE_INTERNAL. Governing:
// the test plan (race scenarios) and
// 1.5 (crash-injection matrix); the recovery rules (boot recovery),
// (actions that do not exist); step 9; the launch gate
// C-04 ("submit-attempt audit proving at most one submit call for each exact attempt");
// the never-blind-retry rule (never blind-retry a submit).
//
// What this file measures and why it is separate from every sibling suite: it counts at the
// WIRE, not at the classifier and not at the exchange seam. The move service is driven through
// the real single-shot submit primitive over the fake gateway's GatewayFetchFn, so the number
// asserted is the number of outbound POSTs the gateway actually observed. A second call
// injected ANYWHERE below executeMoveSubmitClaim — a re-POST inside submitGatewayRequestOnce,
// a second exchange transport, a recovery pass that re-submits — is counted here, because the
// counter sits underneath all of them. That is the falsification test launch-gate C-04 asks for: it
// inspects observable external behaviour only, never internal state.
//
// Division of proof (no suite here restates another):
//   - test/submit-decision-claim-store.pg.test.ts proves the DATABASE arbitrates the
//     single-shot claim under genuinely concurrent workers, against the frozen DDL.
//   - test/pg-concurrency.test.ts proves operation_transactions structurally admits no second
//     attempt row, and wallet_active_leases no second lease.
//   - test/move-no-second-attempt.test.ts proves the RECONCILE CLASSIFIER emits no retry,
//     rebuild or non-landing authority on any observation.
// - THIS file proves the wire count, across the crash matrix and the races.
// The claim store here is in-memory ON PURPOSE: its arbitration is not what is under test, it
// is the fixture that lets the wire count be observed. The durable arbitration is discharged
// by the two real-PostgreSQL suites named above.
//
// Not proven here, and not claimed anywhere in this file: the non-actions are checked
// against the closed catalog only — no MOVE operator-action service exists yet to reject
// them at a request boundary (own that surface).

import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  executeMoveSubmitClaim,
  type MoveSubmitClaim,
  type MoveSubmitClaimStore,
} from "../src/core/move-submit-claim.js";
import { createGatewayExchangeTransport } from "../src/gateway/capture.js";
import type { SubmitAuthorization } from "../src/gateway/submit.js";
import type { GatewayLimits } from "../src/gateway/types.js";
import { LIMITS, PRIMARY, TX, WALLET_KEY, submitRecorder } from "../src/testkit/gateway-fake-fixtures.js";
import {
  SUBMIT_ACK_ENVELOPE,
  SUBMIT_CRASH_HOLD_POINTS,
  createFakeGateway,
  type FakeGateway,
  type SubmitCrashHoldPoint,
} from "../src/testkit/gateway-fake.js";

import { OPERATOR_RECOVERY_ACTIONS } from "../../generic-node-contracts/src/operator-halt/halt.contract.ts";

// A bare `timeout` outcome resolves only when the exchange's own deadline fires, so the
// timeout scenario runs on a short deadline rather than the fixture's 1s.
const SHORT_TIMEOUT: GatewayLimits = { readTimeoutMs: 20, maxRequestBytes: 4_096, maxResponseBytes: 4_096 };

// The recovery rules' "Actions that do not exist", quoted in their listed order.
const NONEXISTENT_OPERATOR_ACTIONS = [
  "RETRY_SUBMIT",
  "FORCE_LANDED",
  "FORCE_RELEASE",
  "EDIT_TRANSACTION",
  "CHANGE_DESTINATION",
  "CHANGE_AMOUNT",
  "REFORM_EXTERNAL_SEND",
  "NODE_SUBMIT_EXTERNAL_SEND",
  "DELETE_EVIDENCE",
  "SKIP_VERIFICATION",
] as const;

// The test-plan hold points at which the process dies BEFORE the request reaches the wire.
const PRE_SUBMIT_HOLD_POINTS: readonly SubmitCrashHoldPoint[] = [
  "before-signed-bytes-persist",
  "after-persist-before-submit",
];

// Every scenario's gateway-side count, keyed by scenario, so the census at the foot of this
// file can assert over the WHOLE run rather than only scenario-by-scenario.
const wireLedger = new Map<string, number>();

// The one assertion every scenario funnels through. It fails in the scenario that made the
// extra call, not only in the census — a second POST must redden where it happened.
function countWire(scenario: string, fake: FakeGateway): number {
  const posts = fake.totalSubmitAttempts;
  wireLedger.set(scenario, posts);
  expect(posts).toBeLessThanOrEqual(1);
  expect(fake.submitAttemptCountForKey(WALLET_KEY)).toBeLessThanOrEqual(1);
  return posts;
}

// In-memory stand-in for submit_decisions UNIQUE (operation_id, transaction_attempt_no); the
// suspension point sits after the decision, where the round trip would be, so no caller can
// observe a half-decided claim. Real arbitration: submit-decision-claim-store.pg.test.ts.
function makeClaimStore(): MoveSubmitClaimStore & { readonly mints: number } {
  const claims = new Map<string, MoveSubmitClaim>();
  let mints = 0;
  return {
    get mints() {
      return mints;
    },
    claimSubmitOnce: async (claim) => {
      const key = `${claim.operationId}#${claim.transactionAttemptNo}`;
      const existing = claims.get(key);
      if (existing !== undefined) {
        await Promise.resolve();
        return { claim: existing, minted: false };
      }
      claims.set(key, claim);
      mints += 1;
      await Promise.resolve();
      return { claim, minted: true };
    },
  };
}

interface MoveRun {
  readonly fake: FakeGateway;
  readonly store: MoveSubmitClaimStore & { readonly mints: number };
  readonly authorization: SubmitAuthorization;
}

function newRun(): MoveRun {
  return {
    fake: createFakeGateway(),
    store: makeClaimStore(),
    authorization: {
      submitDecisionId: randomUUID(),
      operationId: randomUUID(),
      transactionAttemptNo: 1,
    },
  };
}

// One pass of the move service over the fake's wire. A restart is modelled by calling this
// again with the SAME run: the durable claim survives, the process does not.
async function move(run: MoveRun, limits: GatewayLimits = LIMITS): Promise<boolean> {
  const result = await executeMoveSubmitClaim({
    authorization: run.authorization,
    signedTransaction: TX,
    claimStore: run.store,
    submit: {
      endpoint: PRIMARY,
      limits,
      recorder: submitRecorder(),
      exchange: createGatewayExchangeTransport({ limits, fetchFn: run.fake.fetch }),
    },
  });
  return result.executed;
}

const ackOnce = (fake: FakeGateway): void => {
  fake.scriptSubmit({ kind: "envelope", envelope: SUBMIT_ACK_ENVELOPE });
};

describe("MOVE_INTERNAL — the gateway counts one POST per operation, every outcome", () => {
  it("an ACK is one POST (receipt only, never a settlement verdict)", async () => {
    const run = newRun();
    ackOnce(run.fake);

    expect(await move(run)).toBe(true);

    expect(countWire("outcome:ack", run.fake)).toBe(1);
  });

  it("a definite 4xx REJECT is one POST and is never repeated", async () => {
    const run = newRun();
    run.fake.scriptSubmit({
      kind: "envelope",
      httpStatus: 400,
      envelope: { status: false, code: "rejected", message: "rejected", data: {} },
    });

    expect(await move(run)).toBe(true);

    expect(countWire("outcome:reject", run.fake)).toBe(1);
  });

  it("a 5xx INDETERMINATE is one POST — ambiguity authorizes no second call", async () => {
    const run = newRun();
    run.fake.scriptSubmit({
      kind: "envelope",
      httpStatus: 503,
      envelope: { status: false, code: "unavailable", message: "unavailable", data: {} },
    });

    await move(run);

    expect(countWire("outcome:5xx", run.fake)).toBe(1);
  });

  it("a severed connection is one POST — a missing response does not prove the POST did not land", async () => {
    const run = newRun();
    run.fake.scriptSubmit({ kind: "drop" });

    await move(run);

    expect(countWire("outcome:drop", run.fake)).toBe(1);
  });

  it("a timeout is one POST — the deadline expiring is not evidence of non-landing", async () => {
    const run = newRun();
    run.fake.scriptSubmit({ kind: "timeout" });

    await move(run, SHORT_TIMEOUT);

    expect(countWire("outcome:timeout", run.fake)).toBe(1);
  });

  it("a lagging gateway is one POST, not one per elapsed deadline", async () => {
    const run = newRun();
    run.fake.scriptSubmit({
      kind: "lag",
      delayMs: 5,
      then: { kind: "envelope", envelope: SUBMIT_ACK_ENVELOPE },
    });

    await move(run);

    expect(countWire("outcome:lag", run.fake)).toBe(1);
  });
});

describe("test-plan crash matrix — recovery after a crash at any hold point adds no POST", () => {
  // Runs the pass that crashed (where one happened), then re-enters the SAME attempt as boot
  // recovery would, and reports what the gateway saw across BOTH passes.
  async function crashThenRecover(point: SubmitCrashHoldPoint): Promise<number> {
    const run = newRun();
    const reachedTheWire = !PRE_SUBMIT_HOLD_POINTS.includes(point);

    if (reachedTheWire) {
      run.fake.scriptSubmitHoldPoint(point);
      if (point === "during-reconciliation") {
        // The hold point scripts the READ surface; the submit that preceded it still needs its
        // gateway-side answer.
        ackOnce(run.fake);
      }
      await move(run);
    } else if (point === "after-persist-before-submit") {
      // The durable claim was minted, then the process died before the exchange. Recovery
      // inherits a consumed claim and must never spend it.
      await run.store.claimSubmitOnce({
        attemptId: run.authorization.submitDecisionId,
        claimedAt: "2026-07-25T00:00:00.000Z",
        operationId: run.authorization.operationId,
        transactionAttemptNo: run.authorization.transactionAttemptNo,
      });
    }

    // Boot recovery re-enters the attempt. The gateway is willing; the node must not be.
    ackOnce(run.fake);
    await move(run);

    return countWire(`crash:${point}`, run.fake);
  }

  it("before-signed-bytes-persist — nothing was claimed or sent, so recovery makes the ONE shot", async () => {
    expect(await crashThenRecover("before-signed-bytes-persist")).toBe(1);
  });

  it("after-persist-before-submit — the claim is spent, so recovery sends NOTHING", async () => {
    expect(await crashThenRecover("after-persist-before-submit")).toBe(0);
  });

  it.each([
    "during-submit-no-response",
    "after-acceptance-before-local-ack",
    "after-local-ack-before-event-emission",
    "during-reconciliation",
    "before-outbox-delivery",
    "after-outbox-delivery",
  ] as const)("%s — the shot already happened, and recovery never repeats it", async (point) => {
    expect(await crashThenRecover(point)).toBe(1);
  });
});

describe("test-plan races — exactly one contender may reach the wire", () => {
  it("eight workers racing one attempt produce exactly ONE POST", async () => {
    const run = newRun();
    ackOnce(run.fake);

    const executed = await Promise.all(Array.from({ length: 8 }, () => move(run)));

    expect(executed.filter(Boolean)).toHaveLength(1);
    expect(run.store.mints).toBe(1);
    expect(countWire("race:eight-workers", run.fake)).toBe(1);
  });

  it("a worker that lost the claim never touches the transport at all", async () => {
    const run = newRun();
    ackOnce(run.fake);
    await move(run);
    const afterWinner = run.fake.totalSubmitAttempts;

    expect(await move(run)).toBe(false);

    expect(run.fake.totalSubmitAttempts).toBe(afterWinner);
    expect(countWire("race:loser", run.fake)).toBe(1);
  });

  it("two different operations proceed concurrently without either being suppressed", async () => {
    const first = newRun();
    const second = newRun();
    ackOnce(first.fake);
    ackOnce(second.fake);

    await Promise.all([move(first), move(second)]);

    expect(countWire("race:distinct-operation-a", first.fake)).toBe(1);
    expect(countWire("race:distinct-operation-b", second.fake)).toBe(1);
  });

  it("acknowledging attention across a restart submits nothing", async () => {
    const run = newRun();
    ackOnce(run.fake);
    await move(run);

    // ACKNOWLEDGE_KEEP_PINNED records operator awareness only — no state change, so a restart
    // that follows it re-enters the attempt with the same spent claim.
    expect(OPERATOR_RECOVERY_ACTIONS as readonly string[]).toContain("ACKNOWLEDGE_KEEP_PINNED");
    expect(await move(run)).toBe(false);

    expect(countWire("restart:after-acknowledge", run.fake)).toBe(1);
  });
});

describe("recovery — the non-actions are not dispatchable", () => {
  it("no token is a member of the closed operator-action catalog", () => {
    for (const nonAction of NONEXISTENT_OPERATOR_ACTIONS) {
      expect(OPERATOR_RECOVERY_ACTIONS as readonly string[]).not.toContain(nonAction);
    }
  });
});

describe("the whole run — launch-gate C-04 submit-attempt audit", () => {
  it("every hold point is on the ledger and no operation ever exceeded one POST", () => {
    for (const point of SUBMIT_CRASH_HOLD_POINTS) {
      expect(wireLedger.has(`crash:${point}`)).toBe(true);
    }
    expect(wireLedger.size).toBeGreaterThan(SUBMIT_CRASH_HOLD_POINTS.length);
    expect(Math.max(...wireLedger.values())).toBe(1);
  });
});
