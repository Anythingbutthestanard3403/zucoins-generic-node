import { describe, expect, it } from "vitest";

import { type NodeReadinessState } from "../readiness/index.ts";
import { ENGINE_REGISTRY, type NodeEngine } from "./engines.contract.ts";
import {
  engineMayRun,
  engineMayEconomicWrite,
  assertEngineEconomicWritePermitted,
  assertEconomicWriteSitePermitted,
} from "./predicates.ts";

const LEADER: NodeReadinessState = {
  schemaMigrated: true,
  databaseReachable: true,
  vaultKeyRingLoaded: true,
  vaultCensusVerified: true,
  observationReadCapable: true,
    restoreHoldClear: true,
  leadershipLockHeld: true,
};
const FOLLOWER: NodeReadinessState = { ...LEADER, leadershipLockHeld: false };

const engine = (id: string): NodeEngine => {
  const found = ENGINE_REGISTRY.find((candidate) => candidate.id === id);
  if (found === undefined) throw new Error(`no engine ${id}`);
  return found;
};

const SIGNER = engine("SIGNER");
const OBSERVATION = engine("OBSERVATION_SERVICE");

describe("engine-startup predicates gate the money path on leadership (the named concern; the frozen rule)", () => {
  it("a leader-gated engine runs only on the leader; a follower-safe engine runs on either", () => {
    expect(engineMayRun(SIGNER, LEADER)).toBe(true);
    expect(engineMayRun(SIGNER, FOLLOWER)).toBe(false);
    expect(engineMayRun(OBSERVATION, LEADER)).toBe(true);
    expect(engineMayRun(OBSERVATION, FOLLOWER)).toBe(true);
  });

  it("an economic-state write needs an economic-writer engine AND leadership", () => {
    expect(engineMayEconomicWrite(SIGNER, LEADER)).toBe(true);
    expect(engineMayEconomicWrite(SIGNER, FOLLOWER)).toBe(false);
    expect(engineMayEconomicWrite(OBSERVATION, LEADER)).toBe(false);
    expect(engineMayEconomicWrite(OBSERVATION, FOLLOWER)).toBe(false);
  });

  it("a leader-gated engine writing on a follower is rejected (negative path)", () => {
    expect(() => assertEngineEconomicWritePermitted(SIGNER, FOLLOWER)).toThrow(
      "FOLLOWER_ECONOMIC_WRITE_REJECTED",
    );
  });

  it("a follower-safe engine never counts as an economic writer even on the leader (negative path)", () => {
    expect(() => assertEngineEconomicWritePermitted(OBSERVATION, LEADER)).toThrow(
      "FOLLOWER_ECONOMIC_WRITE_REJECTED",
    );
  });
});

describe("assertEconomicWriteSitePermitted composes readiness AND leadership (; the frozen rule)", () => {
  it("full leader with economic-writer engine does not throw", () => {
    expect(() => assertEconomicWriteSitePermitted(SIGNER, LEADER)).not.toThrow();
  });

  it("leader with databaseReachable:false is rejected on readiness (binding AC)", () => {
    const degraded = { ...LEADER, databaseReachable: false };
    expect(() => assertEconomicWriteSitePermitted(SIGNER, degraded)).toThrow(
      "SIGNING_WITHOUT_READINESS_REJECTED",
    );
  });

  it("leader with schemaMigrated:false is rejected on readiness", () => {
    const degraded = { ...LEADER, schemaMigrated: false };
    expect(() => assertEconomicWriteSitePermitted(SIGNER, degraded)).toThrow(
      "SIGNING_WITHOUT_READINESS_REJECTED",
    );
  });

  it("follower (leadershipLockHeld:false) is rejected on leadership", () => {
    expect(() => assertEconomicWriteSitePermitted(SIGNER, FOLLOWER)).toThrow(
      "SIGNING_WITHOUT_LEADERSHIP_REJECTED",
    );
  });

  it("non-economic-writer engine on full leader is rejected", () => {
    expect(() => assertEconomicWriteSitePermitted(OBSERVATION, LEADER)).toThrow(
      "FOLLOWER_ECONOMIC_WRITE_REJECTED",
    );
  });
});
