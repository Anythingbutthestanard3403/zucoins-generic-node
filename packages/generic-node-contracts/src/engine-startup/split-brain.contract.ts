/**
 * SOURCE: the node-core runtime model (one process-wide leadership lock; leadership and wallet leases do
 * not replace one another) + the startup-sequence decision (a dropped lock frees it, markLost, then
 * graceful restart; the DB single-in-flight-per-wallet constraint is the ultimate backstop in the
 * TCP-death window) + the vault-storage rule guard 4 (C-02 is the sole wallet-sequencing authority). Consumes the
 * the named concern wallet-sequencing authority so this concern introduces no second authority.
 *
 * the named concern freezes the no-split-brain invariant and the takeover boundary as data. the named concern
 * proves the two-instance scenario empirically; the proof matrix is out of this slice's scope.
 */

import { WALLET_SEQUENCING_AUTHORITY } from "../readiness/index.ts";

/**
 * Two safety layers. The leadership gate: at most one instance holds the lock, and a non-leader's
 * leader-gated engines cannot write economic state. The physical backstop: the C-02 lease plus the
 * DB single-in-flight-per-wallet constraint make two in-flight transactions on one wallet
 * impossible even inside a brief dual-leader detection window.
 */
export const NO_SPLIT_BRAIN_INVARIANT = {
  at_most_one_leader_holds_lock: true,
  follower_leader_gated_engines_cannot_economic_write: true,
  db_single_in_flight_per_wallet_backstop: true,
  wallet_sequencing_authority: WALLET_SEQUENCING_AUTHORITY,
} as const;

/**
 * The takeover boundary. The old leader must quiesce (stop new work, mark lost, release/lose the
 * lock) before the new leader can acquire it; the lock is the single serialisation point. The new
 * leader runs boot recovery over the in-flight left under its C-02 leases, then starts engines,
 * then arms authority last.
 *
 * `residual_tcp_death_window_backstopped_by_c02`: in the window between an incumbent's TCP death and
 * the connection-scoped leadership lock being observed free, two instances may transiently believe
 * they lead. What still forbids a second write on an in-flight wallet is NOT the leadership lock but
 * the C-02 wallet lease — a DB row the database keeps single per `wallet_id` — and
 * one that boot recovery does NOT delete on a timer, so it SURVIVES the
 * crash. This is the DB single-in-flight-per-wallet uniqueness backstop of the frozen rule's residual. The
 * claim is not a bare literal: the named concern handoff proof demonstrates it in the
 * `crash-failover-inflight` cell (A crashed and holds no leadership, yet its unresolved write is
 * blocked by the surviving lease) and proves it load-bearing by firing DOUBLE_WRITE_SAFETY_BREACH on
 * the negative where that backstop is removed (`handoff-proof/two-layer.test.ts`).
 */
export const TAKEOVER_BOUNDARY = {
  old_leader_quiesces_before_new_acquires_lock: true,
  lock_is_the_single_serialisation_point: true,
  new_leader_runs_boot_recovery_before_engines: true,
  new_leader_arms_authority_last: true,
  residual_tcp_death_window_backstopped_by_c02: true,
} as const;
