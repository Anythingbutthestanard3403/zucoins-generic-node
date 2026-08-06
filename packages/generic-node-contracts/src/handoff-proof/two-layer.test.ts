import { describe, expect, it } from "vitest";

import { hasSignerLeadership, verifyBootSequence, BOOT_SEQUENCE } from "../readiness/index.ts";
import {
  verifyTakeover,
  verifyStartupSequence,
  ENGINE_STARTUP_SEQUENCE,
  TAKEOVER_BOUNDARY,
} from "../engine-startup/index.ts";
import { SCENARIO_MATRIX, type ScenarioCell } from "./scenario-matrix.contract.ts";
import {
  leadershipGateBlocksSharedWrite,
  c02LeaseBlocksSharedWrite,
  bMayWriteSharedWallet,
  aWritesSharedInFlight,
  noConcurrentDoubleWrite,
  verifyCell,
} from "./proof.ts";

const cell = (id: string): ScenarioCell => {
  const found = SCENARIO_MATRIX.find((candidate) => candidate.id === id);
  if (found === undefined) throw new Error(`no cell ${id}`);
  return found;
};

describe("split-brain two-layer independence (leadership gate + wallet-lease backstop)", () => {
  it("the leadership gate is bypassed yet the C-02 lease still blocks the phantom leader", () => {
    const splitBrain = cell("split-brain-window");
    const b = splitBrain.instanceB.state;
    expect(hasSignerLeadership(b)).toBe(true);
    expect(leadershipGateBlocksSharedWrite(b)).toBe(false);
    expect(aWritesSharedInFlight(splitBrain.sharedWallet)).toBe(true);
    expect(c02LeaseBlocksSharedWrite(splitBrain.sharedWallet)).toBe(true);
    expect(bMayWriteSharedWallet(b, splitBrain.sharedWallet)).toBe(false);
    expect(noConcurrentDoubleWrite(splitBrain)).toBe(true);
  });

  it("removing layer 2 makes the theorem FALSE and fires the hard guard — layer 2 is load-bearing (negative path)", () => {
    const splitBrain = cell("split-brain-window");
    // Counterfactually strip the wallet-sequencing authority while A's write is still unresolved —
    // the exact state the backstop invariant `aWriteUnresolved → walletSequencingHeld` forbids. The
    // "both instances write wallet W" state is now REPRESENTABLE (it was unreachable pre-fix).
    const layerTwoRemoved: ScenarioCell = {
      ...splitBrain,
      sharedWallet: { ...splitBrain.sharedWallet, walletSequencingHeld: false },
    };
    expect(aWritesSharedInFlight(layerTwoRemoved.sharedWallet)).toBe(true);
    expect(
      bMayWriteSharedWallet(layerTwoRemoved.instanceB.state, layerTwoRemoved.sharedWallet),
    ).toBe(true);
    expect(noConcurrentDoubleWrite(layerTwoRemoved)).toBe(false);
    expect(verifyCell(layerTwoRemoved)).toContain("DOUBLE_WRITE_SAFETY_BREACH");
    // The frozen matrix cell itself stays safe: layer 2 present ⇒ single-writer holds.
    expect(noConcurrentDoubleWrite(splitBrain)).toBe(true);
  });
});

describe("crash failover and graceful handoff boundary", () => {
  it("the recovered leader follows the frozen boot and startup sequences", () => {
    expect(verifyBootSequence([...BOOT_SEQUENCE])).toEqual([]);
    expect(verifyStartupSequence([...ENGINE_STARTUP_SEQUENCE])).toEqual([]);
  });

  it("the residual TCP-death-window backstop is the crash-failover proof cell — proven, not a bare literal", () => {
    const failover = cell("crash-failover-inflight");
    // The classic failover: A crashed (holds NO leadership) but its write may still land.
    expect(hasSignerLeadership(failover.instanceA.state)).toBe(false);
    expect(aWritesSharedInFlight(failover.sharedWallet)).toBe(true);
    // The wallet's lease/in-flight row survives the crash (no time-based deletion at boot) and is
    // what blocks B — the DB single-in-flight backstop, not a still-live leader.
    expect(c02LeaseBlocksSharedWrite(failover.sharedWallet)).toBe(true);
    expect(bMayWriteSharedWallet(failover.instanceB.state, failover.sharedWallet)).toBe(false);
    expect(noConcurrentDoubleWrite(failover)).toBe(true);
    // Exactly the fact engine-startup's TAKEOVER_BOUNDARY freezes — now demonstrated by this cell.
    expect(TAKEOVER_BOUNDARY.residual_tcp_death_window_backstopped_by_c02).toBe(true);

    // Negative: strip the surviving backstop and the failover becomes a real double-write.
    const backstopRemoved: ScenarioCell = {
      ...failover,
      sharedWallet: { ...failover.sharedWallet, walletSequencingHeld: false },
    };
    expect(noConcurrentDoubleWrite(backstopRemoved)).toBe(false);
    expect(verifyCell(backstopRemoved)).toContain("DOUBLE_WRITE_SAFETY_BREACH");
  });

  it("a graceful handoff accepts quiesce-before-arm", () => {
    expect(verifyTakeover(true, true)).toEqual([]);
  });

  it("arming the new leader before the old quiesces is rejected (negative path)", () => {
    expect(verifyTakeover(false, true)).toContain("NEW_LEADER_ARMED_BEFORE_OLD_QUIESCED");
  });
});
