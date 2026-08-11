import { describe, expect, it } from "vitest";

import { GATING_CHECK_IDS, type ReadinessCheckId } from "./readiness-checks.contract.ts";
import {
  type NodeReadinessState,
  GATING_CHECK_EVALUATORS,
  evaluateReadiness,
  hasSignerLeadership,
  maySign,
  assertSigningPermitted,
} from "./predicates.ts";

const READY_LEADER: NodeReadinessState = {
  schemaMigrated: true,
  databaseReachable: true,
  vaultKeyRingLoaded: true,
  vaultCensusVerified: true,
  observationReadCapable: true,
  restoreHoldClear: true,
  leadershipLockHeld: true,
};

/**
 * One row per gating STATE field, not per check id: `vault_available` reads two fields
 * (`vaultKeyRingLoaded` AND `vaultCensusVerified`), so it needs a row per conjunct to catch a
 * mutant that drops either half of the AND (e.g. the census conjunct). Every other gating check
 * reads exactly one field, so it gets exactly one row.
 */
const GATING_FIELD_CASES: readonly {
  readonly checkId: ReadinessCheckId;
  readonly field: keyof NodeReadinessState;
}[] = [
  { checkId: "schema_migrated", field: "schemaMigrated" },
  { checkId: "database_reachable", field: "databaseReachable" },
  { checkId: "vault_available", field: "vaultKeyRingLoaded" },
  { checkId: "vault_available", field: "vaultCensusVerified" },
  { checkId: "observation_read_capable", field: "observationReadCapable" },
  { checkId: "restore_hold_clear", field: "restoreHoldClear" },
];

describe("readiness / leadership predicate split (the readiness concern)", () => {
  it("a node is READY without leadership (the decoupling)", () => {
    const readyNotLeader: NodeReadinessState = { ...READY_LEADER, leadershipLockHeld: false };
    expect(evaluateReadiness(readyNotLeader).ready).toBe(true);
    expect(hasSignerLeadership(readyNotLeader)).toBe(false);
    expect(maySign(readyNotLeader)).toBe(false);
  });

  it("a leader may not sign while a gating readiness dependency has failed (readiness-gated signing)", () => {
    const leaderDbDown: NodeReadinessState = { ...READY_LEADER, databaseReachable: false };
    expect(hasSignerLeadership(leaderDbDown)).toBe(true);
    expect(evaluateReadiness(leaderDbDown).ready).toBe(false);
    expect(maySign(leaderDbDown)).toBe(false);
  });

  it("leadership also requires the loaded key-ring, not merely the census (vault availability)", () => {
    const censusNoKeyRing: NodeReadinessState = { ...READY_LEADER, vaultKeyRingLoaded: false };
    expect(censusNoKeyRing.leadershipLockHeld).toBe(true);
    expect(censusNoKeyRing.vaultCensusVerified).toBe(true);
    expect(hasSignerLeadership(censusNoKeyRing)).toBe(false);
    expect(maySign(censusNoKeyRing)).toBe(false);
  });

  it.each(GATING_FIELD_CASES)(
    "readiness fails closed and blocks signing when $field is false (check $checkId)",
    ({ checkId, field }) => {
      const state: NodeReadinessState = { ...READY_LEADER, [field]: false };
      const verdict = evaluateReadiness(state);
      expect(verdict.ready).toBe(false);
      expect(verdict.failing).toContain(checkId);
      expect(maySign(state)).toBe(false);
    },
  );

  it("the gating field case table covers every gating check id", () => {
    const coveredCheckIds = new Set(GATING_FIELD_CASES.map((testCase) => testCase.checkId));
    for (const id of GATING_CHECK_IDS) {
      expect(coveredCheckIds.has(id)).toBe(true);
    }
  });

  it("leadership requires the vault census, not merely the lock (NO_LEADERSHIP_WITHOUT_VAULT_CENSUS)", () => {
    const lockNoCensus: NodeReadinessState = { ...READY_LEADER, vaultCensusVerified: false };
    expect(lockNoCensus.leadershipLockHeld).toBe(true);
    expect(hasSignerLeadership(lockNoCensus)).toBe(false);
    expect(maySign(lockNoCensus)).toBe(false);
  });

  it("signing is permitted only for a ready leader", () => {
    expect(maySign(READY_LEADER)).toBe(true);
  });

  it("the gating evaluator map covers exactly the gating checks", () => {
    for (const id of GATING_CHECK_IDS) {
      expect(typeof GATING_CHECK_EVALUATORS[id]).toBe("function");
    }
    expect(GATING_CHECK_EVALUATORS.signer_leadership).toBeUndefined();
  });

  it("signing without leadership is rejected (negative path)", () => {
    const nonLeader: NodeReadinessState = { ...READY_LEADER, leadershipLockHeld: false };
    expect(() => assertSigningPermitted(nonLeader)).toThrow("SIGNING_WITHOUT_LEADERSHIP_REJECTED");
  });

  it("signing without readiness is rejected with a distinguishing identifier (LEADER_NOT_READY;)", () => {
    const leaderNotReady: NodeReadinessState = { ...READY_LEADER, databaseReachable: false };
    expect(hasSignerLeadership(leaderNotReady)).toBe(true);
    expect(evaluateReadiness(leaderNotReady).ready).toBe(false);
    expect(() => assertSigningPermitted(leaderNotReady)).toThrow("SIGNING_WITHOUT_READINESS_REJECTED");
  });
});
