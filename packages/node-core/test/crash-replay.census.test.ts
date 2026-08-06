// Residual crash/replay census — closes the two rigor-integrity gaps
// the harness's proof surface left open, plus pins one previously-untested divergence.
//
//   D1  Canon binding. SEND_REDEMPTION_WINDOW_SECS and SEND_PARTIAL_AGING_MARGIN_SECS are
//       bound to frozen pins committed in this file, independent of the model
//       source. A pin<->source drift of either expiry constant reddens here. This is the
//       mechanism the claim comment at crash-replay-model.ts references.
//   D2  Count-exact coverage. assertCountExactCoverage (previously defined but never called)
// is WIRED: it asserts the frozen custody crash matrix is a bijection onto each frozen
//       closed set, and a mutation meta-test proves the checker actually goes RED when a cell
//       is dropped, duplicated, or overwritten with a forbidden-column value (a prescribed ->
//       forbidden swap). The oracle is falsifiable, not tautological.
//   F4  Conservative divergence pin. classifyDurableState evaluates expiry BEFORE the head-
//       observation switch: a past-T2 partial observed EXPECTED_AT_HEAD classifies as
//       PARTIAL_EXPIRED (-> NEEDS_ATTENTION), never PARTIAL_DELIVERED_EXPECTED_AT_HEAD
//       (-> MARK_LANDED). Custody-safe ("past-expiry delivered = NEEDS_ATTENTION +
//       reconcile-first"); this pins it so the ordering can never change silently.
//
// Invariants: byte-exact signing / no blind retry / one in-flight transaction per wallet
// per wallet are unaffected — this file reads bytes and counts sets; it signs nothing.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import { ready } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  CRASH_DURABLE_STATES,
  CRASH_MATRIX,
  FORBIDDEN_RECOVERY_ACTIONS,
  RECOVERY_ACTIONS,
} from "../../generic-node-contracts/src/approval/crash-recovery.contract.ts";
import {
  addSecs,
  assertCountExactCoverage,
  createRuntime,
  SEND_PARTIAL_AGING_MARGIN_SECS,
  SEND_REDEMPTION_WINDOW_SECS,
  type Scenario,
} from "./crash-replay-model.ts";
import {
  APPROVAL_ID,
  baselinePlan,
  freshObservationPlan,
  KEY_SEED_BYTE,
  OPERATION_ID,
  T2_SECS,
} from "./crash-replay-fixtures.ts";
import {
  classifyDurableState,
  crashAndRecover,
  driveToDurableState,
  isLaunchReachableHeadObservation,
  LAUNCH_REACHABLE_HEAD_OBSERVATION_KINDS,
  notLaunchReachableProvenNotLanded,
  type HeadObservation,
} from "./crash-replay-driver.ts";
import { recoverOperation } from "./crash-replay-recovery.ts";

// ---------------------------------------------------------------------------
// D1 — canon binding to the frozen pins.
// ---------------------------------------------------------------------------

// Frozen expiry constants, inlined as committed pins. A source edit to
// either model constant that departs from the frozen value reddens here.
const FROZEN_SEND_REDEMPTION_WINDOW_SECS = 300;
const FROZEN_SEND_PARTIAL_AGING_MARGIN_SECS = 3600;

beforeAll(async () => {
  await ready();
});

describe("census — D1 expiry constants are bound to the frozen pins", () => {
  it("SEND_REDEMPTION_WINDOW_SECS equals the frozen pin (drift reddens here)", () => {
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(FROZEN_SEND_REDEMPTION_WINDOW_SECS);
  });

  it("SEND_PARTIAL_AGING_MARGIN_SECS equals the frozen pin (drift reddens here)", () => {
    expect(SEND_PARTIAL_AGING_MARGIN_SECS).toBe(FROZEN_SEND_PARTIAL_AGING_MARGIN_SECS);
  });
});

// ---------------------------------------------------------------------------
// D2 — assertCountExactCoverage wired into a red-going closed-set census.
// ---------------------------------------------------------------------------

const durableStatesOf = (): string[] => CRASH_MATRIX.map((row) => row.durableState);
const recoveriesOf = (): string[] => CRASH_MATRIX.map((row) => row.recovery);
const forbiddensOf = (): string[] => CRASH_MATRIX.map((row) => row.forbidden);

describe("census — D2 the frozen crash matrix is a count-exact bijection onto the closed sets", () => {
  it("every censused durable state / recovery action / forbidden action appears exactly once", () => {
    // Load-bearing: these throw if the matrix ever drops or duplicates a row against the frozen
    // closed sets. assertCountExactCoverage is the checker; here it does real coverage work.
    expect(() =>
      assertCountExactCoverage(durableStatesOf(), CRASH_DURABLE_STATES, "durable-state coverage"),
    ).not.toThrow();
    expect(() =>
      assertCountExactCoverage(recoveriesOf(), RECOVERY_ACTIONS, "recovery-action coverage"),
    ).not.toThrow();
    expect(() =>
      assertCountExactCoverage(forbiddensOf(), FORBIDDEN_RECOVERY_ACTIONS, "forbidden-action coverage"),
    ).not.toThrow();
  });

  it("goes RED when a member is dropped (the self-checking mutant feeds a dropped set)", () => {
    const dropped = recoveriesOf().slice(1);
    expect(() =>
      assertCountExactCoverage(dropped, RECOVERY_ACTIONS, "dropped recovery action"),
    ).toThrow(/coverage mismatch — missing=\[[^\]]+\]/);
  });

  it("goes RED when a member is duplicated (extra / length mismatch)", () => {
    const duplicated = [...recoveriesOf(), RECOVERY_ACTIONS[0]];
    expect(() =>
      assertCountExactCoverage(duplicated, RECOVERY_ACTIONS, "duplicated recovery action"),
    ).toThrow(/coverage mismatch/);
  });

  it("goes RED under a prescribed -> forbidden swap on a representative row", () => {
    // Overwrite one row's PRESCRIBED (recovery) cell with a value from the FORBIDDEN column.
    // The census reddens because that value is not a member of RECOVERY_ACTIONS (extra) and the
    // real recovery action it displaced is now missing — exactly the transcription error the
    // oracle must be able to catch, mechanized.
    const swapped = recoveriesOf();
    const representative = 3; // PARTIAL_COMMITTED_UNDELIVERED -> DELIVER_EXACT_PERSISTED_CODE
    swapped[representative] = FORBIDDEN_RECOVERY_ACTIONS[0]; // "ACQUIRE_OR_SIGN"
    expect(() =>
      assertCountExactCoverage(swapped, RECOVERY_ACTIONS, "prescribed<-forbidden swap"),
    ).toThrow(/coverage mismatch/);
  });
});

// ---------------------------------------------------------------------------
// F4 — conservative expiry-before-head-observation ordering, pinned.
// ---------------------------------------------------------------------------

const deliveredScenario = (): Scenario => {
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
          leaseHeld: false,
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
    runtime: createRuntime("formation-worker", KEY_SEED_BYTE),
  };
  driveToDurableState(scenario, baselinePlan(), "PARTIAL_DELIVERED_EXPECTED_AT_HEAD");
  return scenario;
};

const EXPECTED_AT_HEAD: HeadObservation = { kind: "EXPECTED_AT_HEAD" };

describe("census — F4 classifyDurableState checks expiry before the head-observation switch", () => {
  it("pre-T2 + EXPECTED_AT_HEAD classifies as PARTIAL_DELIVERED_EXPECTED_AT_HEAD (head switch wins)", () => {
    const scenario = deliveredScenario();
    const beforeExpiry = addSecs(T2_SECS, -1);
    expect(
      classifyDurableState(scenario.durable, OPERATION_ID, beforeExpiry, EXPECTED_AT_HEAD),
    ).toBe("PARTIAL_DELIVERED_EXPECTED_AT_HEAD");
  });

  it("past-T2 + EXPECTED_AT_HEAD classifies as PARTIAL_EXPIRED (expiry wins — the conservative divergence)", () => {
    const scenario = deliveredScenario();
    const afterExpiry = addSecs(T2_SECS, 1);
    expect(
      classifyDurableState(scenario.durable, OPERATION_ID, afterExpiry, EXPECTED_AT_HEAD),
    ).toBe("PARTIAL_EXPIRED");
  });

  it("a past-T2 EXPECTED_AT_HEAD partial recovers to NEEDS_ATTENTION, never MARK_LANDED (reconcile-first)", () => {
    const scenario = crashAndRecover(deliveredScenario());
    const afterExpiry = addSecs(T2_SECS, 1);
    const outcome = recoverOperation(
      scenario,
      freshObservationPlan(),
      OPERATION_ID,
      afterExpiry,
      EXPECTED_AT_HEAD,
    );
    expect(outcome.classification).toBe("PARTIAL_EXPIRED");
    expect(outcome.action).toBe("NEEDS_ATTENTION");
    // Custody-safe: no lease release, no terminalization on expiry-plus-landing alone.
    expect(scenario.runtime.log.leaseReleases).toBe(0);
    expect(scenario.runtime.log.terminalizations).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// PROVEN_NOT_LANDED is not launch-reachable; harness brands it.
// ---------------------------------------------------------------------------

describe("census — PROVEN_NOT_LANDED is branded not-launch-reachable", () => {
  it("LAUNCH_REACHABLE_HEAD_OBSERVATION_KINDS is a closed 4-member set excluding PROVEN_NOT_LANDED", () => {
    expect([...LAUNCH_REACHABLE_HEAD_OBSERVATION_KINDS]).toEqual([
      "HEAD_UNCHANGED",
      "EXPECTED_AT_HEAD",
      "HEAD_ANOMALOUS",
      "NO_POSITIVE_PROOF",
    ]);
    expect(LAUNCH_REACHABLE_HEAD_OBSERVATION_KINDS).not.toContain("PROVEN_NOT_LANDED");
  });

  it("notLaunchReachableProvenNotLanded() is the only constructor and carries the brand", () => {
    const observation = notLaunchReachableProvenNotLanded();
    expect(observation.kind).toBe("PROVEN_NOT_LANDED");
    expect(observation.notLaunchReachable).toBe(true);
    expect(isLaunchReachableHeadObservation(observation)).toBe(false);
    expect(isLaunchReachableHeadObservation({ kind: "NO_POSITIVE_PROOF" })).toBe(true);
  });

  it("harness sources never feed an unbranded PROVEN_NOT_LANDED object literal (constructor-only)", () => {
    // Source pin: a single-field object literal of that kind (no brand) would reintroduce
    // the earlier ambiguity this suite closes. Multi-line branded constructor body in
    // crash-replay-driver.ts is allowed (has notLaunchReachable on a sibling field).
    // Pattern is assembled from parts so THIS file does not itself contain a match.
    const harnessDir = dirname(fileURLToPath(import.meta.url));
    const harnessFiles = [
      "crash-replay-driver.ts",
      "crash-replay-recovery.ts",
      "crash-replay.matrix.test.ts",
      "crash-replay.census.test.ts",
      "crash-replay.cas-race.test.ts",
      "crash-replay.exactness.test.ts",
      "lifecycle-fuzz-alphabet.ts",
    ];
    const kind = "PROVEN" + "_NOT_LANDED";
    const bareLiteral = new RegExp("\\{\\s*kind:\\s*[\"']" + kind + "[\"']\\s*\\}");
    for (const file of harnessFiles) {
      const source = readFileSync(resolve(harnessDir, file), "utf8");
      expect(
        bareLiteral.test(source),
        `${file} must not contain an unbranded PROVEN_NOT_LANDED object literal`,
      ).toBe(false);
    }
  });
});
