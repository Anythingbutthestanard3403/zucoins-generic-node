import { describe, expect, it } from "vitest";

import { assertClosedSet } from "../testkit/freeze.ts";
import {
  SCENARIO_CLASSES,
  SCENARIO_MATRIX,
  type ScenarioCell,
} from "./scenario-matrix.contract.ts";
import { evaluateCell, verifyCell } from "./proof.ts";

const cell = (id: string): ScenarioCell => {
  const found = SCENARIO_MATRIX.find((candidate) => candidate.id === id);
  if (found === undefined) throw new Error(`no cell ${id}`);
  return found;
};

describe("two-instance handoff proof matrix drives the real contracts (the named concern; the frozen rule)", () => {
  it("covers every scenario class", () => {
    const classes = SCENARIO_MATRIX.map((scenarioCell) => scenarioCell.scenarioClass);
    assertClosedSet([...new Set(classes)], [...SCENARIO_CLASSES]);
  });

  it("every cell's actual outcome (from the real the named concern/.2 predicates) matches its expectation", () => {
    for (const scenarioCell of SCENARIO_MATRIX) {
      expect(verifyCell(scenarioCell)).toEqual([]);
    }
  });

  it("the no-concurrent-double-write theorem holds for every cell", () => {
    for (const scenarioCell of SCENARIO_MATRIX) {
      expect(evaluateCell(scenarioCell).noConcurrentDoubleWrite).toBe(true);
    }
  });

  it("overlap deploy: the ready standby holds no leadership and cannot write the shared wallet", () => {
    const overlap = evaluateCell(cell("overlap-deploy-standby"));
    expect(overlap.readyB).toBe(true);
    expect(overlap.leaderB).toBe(false);
    expect(overlap.bSharedWriteAdmitted).toBe(false);
  });

  it("readiness truth: a booting instance reports not-ready and not-leader", () => {
    const booting = evaluateCell(cell("new-instance-booting"));
    expect(booting.readyB).toBe(false);
    expect(booting.leaderB).toBe(false);
  });

  it("rejects a cell whose expected leadership is falsified (negative path)", () => {
    const good = cell("overlap-deploy-standby");
    const tampered: ScenarioCell = {
      ...good,
      expected: { ...good.expected, leaderB: true },
    };
    expect(verifyCell(tampered)).toContain("LEADER_B_MISMATCH");
  });

  it("rejects a cell claiming the follower may write the shared wallet (negative path)", () => {
    const good = cell("overlap-deploy-standby");
    const tampered: ScenarioCell = {
      ...good,
      expected: { ...good.expected, bSharedWriteAdmitted: true },
    };
    expect(verifyCell(tampered)).toContain("B_SHARED_WRITE_MISMATCH");
  });
});
