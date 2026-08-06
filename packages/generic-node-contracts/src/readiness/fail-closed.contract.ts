/**
 * SOURCE: the node-core spec (one active lease per wallet; the C-02 lease is the wallet
 * sequencing authority; leadership and wallet leases do not replace one another) +
 * the readiness-leadership decoupling rule (leadership loss quiesces signing; the DB in-flight uniqueness
 * constraint is the ultimate single-signer backstop) and the wallet-vault envelope freeze guard 4. This module CONSUMES
 * the vault concern vault leadership facts rather than restating them (vault wins on conflict).
 */

import { LEADERSHIP_RULES, SIGNING_CONCURRENCY } from "../vault/index.ts";

/**
 * The wallet sequencing authority is NOT a readiness or leadership concept. It is the C-02
 * universal per-wallet lease, frozen by the vault concern vault contract. Binding to the vault's own
 * value here is the structural guarantee that the named concern introduces no second sequencing authority:
 * if the vault fact ever changed, this binding — and its census test — would have to change too.
 */
export const WALLET_SEQUENCING_AUTHORITY = LEADERSHIP_RULES.wallet_ordering_authority;

/** Re-exposed vault facts this concern depends on, so the dependency is explicit in the manifest. */
export const CONSUMED_VAULT_LEADERSHIP = {
  mutations_single_writer: LEADERSHIP_RULES.mutations_single_writer,
  rotation_is_sole_all_envelope_writer: LEADERSHIP_RULES.rotation_is_sole_all_envelope_writer,
  no_hybrid_fallback: LEADERSHIP_RULES.no_hybrid_fallback,
  vault_row_lock_held_across_signing: SIGNING_CONCURRENCY.vault_row_lock_held_across_signing,
} as const;

/**
 * The fail-closed rules as frozen data. Each is enforced by a pure verifier or predicate and a
 * negative test. LEADERSHIP_IS_NODE_LEVEL_NOT_WALLET_SEQUENCING is the load-bearing separation:
 * leadership is a node-wide single-writer role; the wallet sequencing authority stays C-02.
 */
export const FAIL_CLOSED_RULES = [
  {
    id: "NO_SIGNING_WITHOUT_LEADERSHIP",
    rule: "a signing path is permitted only when this instance holds signer leadership",
  },
  {
    id: "NO_LEADERSHIP_WITHOUT_VAULT_CENSUS",
    rule: "a leadership claim is permitted only after the vault census has verified",
  },
  {
    id: "LEADERSHIP_LOSS_QUIESCES_SIGNING",
    rule: "losing leadership mid-operation quiesces signing and engines and never releases or re-sequences wallet leases",
  },
  {
    id: "LEADERSHIP_IS_NODE_LEVEL_NOT_WALLET_SEQUENCING",
    rule: "leadership is a node-level writer role; the wallet sequencing authority remains the C-02 universal lease",
  },
  {
    id: "LEADERSHIP_LOCK_RELEASED_ON_GRACEFUL_SHUTDOWN",
    rule: "graceful shutdown withdraws signer authority and quiesces engines and in-flight signing before releasing the leadership lock, releasing it last so a successor never signs concurrently",
  },
  {
    id: "INVOLUNTARY_LEADERSHIP_LOSS_FAILS_CLOSED",
    rule: "a leadership lock lost involuntarily (connection loss or database failover) stops signing and money engines immediately and restarts to re-acquire; it never continues signing after loss",
  },
] as const;

export type FailClosedRuleId = (typeof FAIL_CLOSED_RULES)[number]["id"];

/**
 * Leadership loss handling as frozen booleans. On loss the node stops signing but the C-02 lease
 * plus the DB single-in-flight-per-wallet constraint keep single-signer safety — leadership loss
 * is never allowed to become a lease-release or re-sequencing authority.
 */
export const LEADERSHIP_LOSS_HANDLING = {
  quiesces_signing: true,
  quiesces_money_engines: true,
  releases_wallet_leases: false,
  re_sequences_wallet_leases: false,
  db_single_in_flight_is_backstop: true,
} as const;

/**
 * The leadership LOCK exit facts — the node-wide signer lock itself, distinct from the per-wallet
 * C-02 leases covered by LEADERSHIP_LOSS_HANDLING. On graceful shutdown the lock is released last,
 * after signing has quiesced (SHUTDOWN_SEQUENCE), so the READY standby successor acquires an idle
 * lock; the readiness-leadership decoupling rule overlap-deploy handover is exactly this release. A lock lost involuntarily — a
 * connection-scoped advisory lock silently freed by a dropped connection or DB failover — fails
 * closed: stop signing, restart, re-acquire. Neither path releases or re-sequences wallet leases;
 * the DB single-in-flight-per-wallet constraint backstops the loss-detection window (the readiness-leadership decoupling rule
 * residual). SOURCE: the readiness-leadership decoupling rule (the v2 anchor for this frozen structure) + the readiness-leadership decoupling rule
 * split-brain guard (the v1 precedent, not itself the anchor — see the readiness-leadership decoupling rule) +
 * the operations-recovery spec.
 */
export const LEADERSHIP_LOCK_EXIT = {
  released_on_graceful_shutdown: true,
  released_after_signing_quiesced: true,
  freed_by_connection_loss_or_failover: true,
  continues_signing_after_loss: false,
  restarts_to_reacquire_after_loss: true,
  releases_or_resequences_wallet_leases_on_exit: false,
  db_single_in_flight_backstops_loss_window: true,
} as const;
