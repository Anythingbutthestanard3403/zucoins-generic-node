/**
 * SOURCE: derived from the named concern scenario matrix by driving the REAL the named concern readiness
 * predicates and the named concern takeover verifier. Pure functions only — the proof computes each cell's
 * actual outcome from the frozen contracts and compares it to the cell's frozen expectation.
 */

import {
  type NodeReadinessState,
  evaluateReadiness,
  hasSignerLeadership,
} from "../readiness/index.ts";
import { verifyTakeover } from "../engine-startup/index.ts";
import {
  type ScenarioCell,
  type ScenarioExpectation,
  type SharedWalletWrite,
} from "./scenario-matrix.contract.ts";

/** Layer 1 — the leadership gate blocks B's shared-wallet write unless B holds leadership. */
export const leadershipGateBlocksSharedWrite = (bState: NodeReadinessState): boolean =>
  !hasSignerLeadership(bState);

/**
 * Layer 2 — the C-02 lease / DB single-in-flight-per-wallet row blocks B while the shared wallet's
 * sequencing authority is held. This is the sole wallet-sequencing authority (the vault-storage rule guard 4) and
 * in the TCP-death window, the ultimate DB in-flight-uniqueness backstop (the frozen rule residual).
 */
export const c02LeaseBlocksSharedWrite = (wallet: SharedWalletWrite): boolean =>
  wallet.walletSequencingHeld;

/** B may write the shared wallet only when NEITHER layer blocks it. */
export const bMayWriteSharedWallet = (
  bState: NodeReadinessState,
  wallet: SharedWalletWrite,
): boolean => !leadershipGateBlocksSharedWrite(bState) && !c02LeaseBlocksSharedWrite(wallet);

/**
 * A is mid-write on the shared wallet when its economic write is still unresolved. This is a
 * PHYSICAL fact independent of A's current leadership: A's submit can still land after A has
 * crashed and lost leadership — exactly the failover hazard the theorem must weigh — so it is read
 * from the wallet observation, not recomputed from A's readiness.
 */
export const aWritesSharedInFlight = (wallet: SharedWalletWrite): boolean =>
  wallet.aWriteUnresolved;

/**
 * The safety theorem: A and B never both write the shared wallet. It is NON-vacuous — A writing
 * (`aWriteUnresolved`) and B being admitted (B holds leadership AND the wallet's sequencing
 * authority is free) are INDEPENDENT observations, so the "both writing wallet W" state is
 * representable. The theorem holds for every cell in which the C-02 + DB backstop is intact
 * (`aWriteUnresolved → walletSequencingHeld`); a cell that violates that backstop is a real
 * concurrent double-write and trips DOUBLE_WRITE_SAFETY_BREACH in verifyCell.
 */
export const noConcurrentDoubleWrite = (cell: ScenarioCell): boolean =>
  !(
    aWritesSharedInFlight(cell.sharedWallet) &&
    bMayWriteSharedWallet(cell.instanceB.state, cell.sharedWallet)
  );

/** The actual outcome of a cell, computed entirely from the real the named concern / the named concern contracts.*/
export const evaluateCell = (cell: ScenarioCell): ScenarioExpectation => ({
  readyA: evaluateReadiness(cell.instanceA.state).ready,
  leaderA: hasSignerLeadership(cell.instanceA.state),
  readyB: evaluateReadiness(cell.instanceB.state).ready,
  leaderB: hasSignerLeadership(cell.instanceB.state),
  bSharedWriteAdmitted: bMayWriteSharedWallet(cell.instanceB.state, cell.sharedWallet),
  noConcurrentDoubleWrite: noConcurrentDoubleWrite(cell),
  takeoverAccepted: verifyTakeover(cell.takeover.oldQuiesced, cell.takeover.newArmed).length === 0,
});

/**
 * Returns the frozen violation ids a cell commits — each field whose actual outcome differs from
 * the frozen expectation, plus a hard DOUBLE_WRITE_SAFETY_BREACH whenever the actual safety
 * theorem is false (a real concurrent double-write) regardless of what the cell claims to expect.
 */
export const verifyCell = (cell: ScenarioCell): readonly string[] => {
  const actual = evaluateCell(cell);
  const expected = cell.expected;
  const violations: string[] = [];
  const compare = (key: keyof ScenarioExpectation, id: string): void => {
    if (actual[key] !== expected[key]) violations.push(id);
  };
  compare("readyA", "READY_A_MISMATCH");
  compare("leaderA", "LEADER_A_MISMATCH");
  compare("readyB", "READY_B_MISMATCH");
  compare("leaderB", "LEADER_B_MISMATCH");
  compare("bSharedWriteAdmitted", "B_SHARED_WRITE_MISMATCH");
  compare("noConcurrentDoubleWrite", "NO_DOUBLE_WRITE_MISMATCH");
  compare("takeoverAccepted", "TAKEOVER_MISMATCH");
  if (!actual.noConcurrentDoubleWrite) violations.push("DOUBLE_WRITE_SAFETY_BREACH");
  return violations;
};
