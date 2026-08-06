/**
 * Two-instance handoff safety (overlap deploy, lock loss, single-signer backstop): one active
 * lease per wallet, one leadership lock, and boot recovery that never time-deletes a lease.
 * This concern freezes the two-instance handoff PROOF MATRIX: each scenario cell carries two
 * instance states and the frozen expected outcome, and the proof tests drive the REAL
 * readiness / engine-startup predicates against every cell. CONTRACT_FREEZE:
 * frozen data + pure functions only; no runtime, no two live processes, no ZKZ.
 */

import { type NodeReadinessState } from "../readiness/index.ts";

export const SCENARIO_CLASSES = [
  "OVERLAP_DEPLOY",
  "GRACEFUL_HANDOFF",
  "CRASH_FAILOVER",
  "SPLIT_BRAIN_ATTEMPT",
  "READINESS_TRUTH",
] as const;

export type ScenarioClass = (typeof SCENARIO_CLASSES)[number];

const STATE_READY_LEADER: NodeReadinessState = {
  schemaMigrated: true,
  databaseReachable: true,
  vaultKeyRingLoaded: true,
  vaultCensusVerified: true,
  observationReadCapable: true,
  leadershipLockHeld: true,
};
const STATE_READY_FOLLOWER: NodeReadinessState = { ...STATE_READY_LEADER, leadershipLockHeld: false };
const STATE_BOOTING: NodeReadinessState = {
  schemaMigrated: true,
  databaseReachable: true,
  vaultKeyRingLoaded: false,
  vaultCensusVerified: false,
  observationReadCapable: false,
  leadershipLockHeld: false,
};
const STATE_DEAD: NodeReadinessState = {
  schemaMigrated: false,
  databaseReachable: false,
  vaultKeyRingLoaded: false,
  vaultCensusVerified: false,
  observationReadCapable: false,
  leadershipLockHeld: false,
};

export interface InstanceView {
  readonly role: string;
  readonly state: NodeReadinessState;
}

export interface TakeoverStep {
  readonly oldQuiesced: boolean;
  readonly newArmed: boolean;
}

/**
 * The shared wallet's two INDEPENDENT economic-write facts. They are split apart on purpose: the
 * earlier single `sharedWalletInFlightOnA` boolean conflated "A is mid-write" with "the lease is
 * held", so a cell could never express the classic failover double-spend (A's write still unresolved
 * while the wallet is writable by B) and the safety theorem was a vacuous `held ∧ ¬held`.
 *
 * - `aWriteUnresolved` — A launched an economic write on the shared wallet that is not yet
 *   definitively resolved; its submit may still land on chain. This is a PHYSICAL fact that survives
 *   A's crash and loss of leadership (acknowledgement is not settlement), so it is deliberately
 *   NOT a function of A's current readiness/leadership.
 * - `walletSequencingHeld` — the shared wallet's single C-02 lease / DB single-in-flight-per-wallet
 *   row is currently held. The database enforces at most one active lease row per `wallet_id`,
 *   and boot recovery does NOT delete a stale lease based on time, so the row SURVIVES A's
 *   crash. This is the sole wallet-sequencing authority and the ultimate DB
 *   in-flight-uniqueness backstop.
 *
 * The C-02 + DB backstop guarantees the invariant `aWriteUnresolved → walletSequencingHeld`: while
 * A's write on the wallet is unresolved, the wallet's lease/in-flight row is held and cannot be
 * duplicated. The proof leans on exactly this invariant and claims nothing beyond it.
 */
export interface SharedWalletWrite {
  readonly aWriteUnresolved: boolean;
  readonly walletSequencingHeld: boolean;
}

/**
 * The frozen expected outcome of a cell. `bSharedWriteAdmitted` is whether instance B may perform
 * an economic write on the wallet A holds in-flight — it encodes BOTH safety layers (B holds
 * leadership AND the shared wallet's sequencing authority is free). `noConcurrentDoubleWrite` is the
 * safety theorem: A and B never both write the shared wallet.
 */
export interface ScenarioExpectation {
  readonly readyA: boolean;
  readonly leaderA: boolean;
  readonly readyB: boolean;
  readonly leaderB: boolean;
  readonly bSharedWriteAdmitted: boolean;
  readonly noConcurrentDoubleWrite: boolean;
  readonly takeoverAccepted: boolean;
}

export interface ScenarioCell {
  readonly id: string;
  readonly scenarioClass: ScenarioClass;
  readonly instanceA: InstanceView;
  readonly instanceB: InstanceView;
  readonly sharedWallet: SharedWalletWrite;
  readonly takeover: TakeoverStep;
  readonly expected: ScenarioExpectation;
}

export const SCENARIO_MATRIX = [
  {
    id: "overlap-deploy-standby",
    scenarioClass: "OVERLAP_DEPLOY",
    instanceA: { role: "INCUMBENT_LEADER", state: STATE_READY_LEADER },
    instanceB: { role: "NEW_STANDBY", state: STATE_READY_FOLLOWER },
    // A is mid-write and holds the wallet's lease; B is blocked by layer 1 (no leadership).
    sharedWallet: { aWriteUnresolved: true, walletSequencingHeld: true },
    takeover: { oldQuiesced: true, newArmed: false },
    expected: {
      readyA: true,
      leaderA: true,
      readyB: true,
      leaderB: false,
      bSharedWriteAdmitted: false,
      noConcurrentDoubleWrite: true,
      takeoverAccepted: true,
    },
  },
  {
    id: "graceful-handoff-complete",
    scenarioClass: "GRACEFUL_HANDOFF",
    instanceA: { role: "OUTGOING_QUIESCED", state: STATE_READY_FOLLOWER },
    instanceB: { role: "NEW_LEADER", state: STATE_READY_LEADER },
    // A quiesced and released before the handoff: no unresolved write, lease free. B may write.
    sharedWallet: { aWriteUnresolved: false, walletSequencingHeld: false },
    takeover: { oldQuiesced: true, newArmed: true },
    expected: {
      readyA: true,
      leaderA: false,
      readyB: true,
      leaderB: true,
      bSharedWriteAdmitted: true,
      noConcurrentDoubleWrite: true,
      takeoverAccepted: true,
    },
  },
  {
    id: "crash-failover-inflight",
    scenarioClass: "CRASH_FAILOVER",
    instanceA: { role: "CRASHED_INCUMBENT", state: STATE_DEAD },
    instanceB: { role: "RECOVERED_LEADER", state: STATE_READY_LEADER },
    // The classic failover: A crashed mid-submit (no leadership) but its write may still land, and
    // the wallet's lease/in-flight row SURVIVES the crash (no time-based lease deletion at boot),
    // so the DB single-in-flight backstop — not a still-live leader — blocks B. This is the cell
    // that proves the residual TCP-death-window claim in engine-startup's TAKEOVER_BOUNDARY.
    sharedWallet: { aWriteUnresolved: true, walletSequencingHeld: true },
    takeover: { oldQuiesced: true, newArmed: true },
    expected: {
      readyA: false,
      leaderA: false,
      readyB: true,
      leaderB: true,
      bSharedWriteAdmitted: false,
      noConcurrentDoubleWrite: true,
      takeoverAccepted: true,
    },
  },
  {
    id: "split-brain-window",
    scenarioClass: "SPLIT_BRAIN_ATTEMPT",
    instanceA: { role: "REAL_LEADER", state: STATE_READY_LEADER },
    instanceB: { role: "PHANTOM_LEADER", state: STATE_READY_LEADER },
    // Both believe they lead (layer 1 bypassed); A is mid-write and holds the lease, so layer 2
    // alone blocks the phantom leader.
    sharedWallet: { aWriteUnresolved: true, walletSequencingHeld: true },
    takeover: { oldQuiesced: true, newArmed: false },
    expected: {
      readyA: true,
      leaderA: true,
      readyB: true,
      leaderB: true,
      bSharedWriteAdmitted: false,
      noConcurrentDoubleWrite: true,
      takeoverAccepted: true,
    },
  },
  {
    id: "new-instance-booting",
    scenarioClass: "READINESS_TRUTH",
    instanceA: { role: "INCUMBENT_LEADER", state: STATE_READY_LEADER },
    instanceB: { role: "BOOTING", state: STATE_BOOTING },
    // A is mid-write and holds the lease; B is not-ready and holds no leadership.
    sharedWallet: { aWriteUnresolved: true, walletSequencingHeld: true },
    takeover: { oldQuiesced: true, newArmed: false },
    expected: {
      readyA: true,
      leaderA: true,
      readyB: false,
      leaderB: false,
      bSharedWriteAdmitted: false,
      noConcurrentDoubleWrite: true,
      takeoverAccepted: true,
    },
  },
] as const satisfies readonly ScenarioCell[];

export type ScenarioCellId = (typeof SCENARIO_MATRIX)[number]["id"];
