import { describe, expect, it } from "vitest";

import { assertClosedSet } from "../testkit/freeze.ts";
import {
  NODE_OPERATION_CLASSES,
  LEADER_ONLY_OPERATION_CLASSES,
  NODE_MODES,
  type NodeMode,
} from "./degraded-modes.contract.ts";
import { classifyMode } from "./verifiers.ts";

const LEADER_ONLY = new Set<string>(LEADER_ONLY_OPERATION_CLASSES);
const LEADER_ONLY_CLASSES: readonly string[] = LEADER_ONLY_OPERATION_CLASSES;
const MODES: readonly NodeMode[] = NODE_MODES;

/** A mode leaks the money path if it allows a leader-only class while it is not the leader. */
const leaksLeaderOnly = (mode: NodeMode): boolean =>
  !mode.leader && mode.allowed.some((op) => LEADER_ONLY.has(op));

describe("degraded modes partition operations and gate the money path (the readiness concern)", () => {
  it("every mode partitions the whole operation vocabulary (disjoint and total)", () => {
    for (const mode of MODES) {
      const overlap = mode.allowed.filter((op) => mode.forbidden.includes(op));
      expect(overlap).toEqual([]);
      assertClosedSet([...mode.allowed, ...mode.forbidden], [...NODE_OPERATION_CLASSES]);
    }
  });

  it("classifyMode maps every readiness x leadership pair onto exactly one mode", () => {
    expect(classifyMode(true, true)).toBe("READY_AND_LEADER");
    expect(classifyMode(true, false)).toBe("READY_NOT_LEADER");
    expect(classifyMode(false, true)).toBe("LEADER_NOT_READY");
    expect(classifyMode(false, false)).toBe("NOT_READY_NOT_LEADER");
  });

  it("the money path is allowed only in the nominal ready-and-leader mode", () => {
    for (const mode of MODES) {
      const allowed: readonly string[] = mode.allowed;
      const runsMoneyPath = LEADER_ONLY_CLASSES.every((op) => allowed.includes(op));
      expect(runsMoneyPath).toBe(mode.id === "READY_AND_LEADER");
    }
  });

  it("SIGN is forbidden in every mode that is not ready-and-leader", () => {
    for (const mode of MODES) {
      if (mode.id === "READY_AND_LEADER") continue;
      const forbidden: readonly string[] = mode.forbidden;
      expect(forbidden.includes("SIGN")).toBe(true);
    }
  });

  it("no real mode leaks a leader-only operation while not the leader", () => {
    for (const mode of MODES) {
      expect(leaksLeaderOnly(mode)).toBe(false);
    }
  });

  it("a mode allowing SIGN without leadership is rejected by the leak check (negative path)", () => {
    const bad: NodeMode = {
      id: "ROGUE",
      ready: true,
      leader: false,
      degraded: true,
      allowed: ["SIGN"],
      forbidden: [],
    };
    expect(leaksLeaderOnly(bad)).toBe(true);
  });
});
