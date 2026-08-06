/**
 * SOURCE: the node-core leadership section + the readiness-leadership decoupling rule. Pure predicates over a frozen node
 * state snapshot. No I/O, no time, no randomness — the same inputs always give the same verdict.
 * These are the predicate split the named concern freezes: a node can be READY without leadership; every
 * signing path REQUIRES leadership. See also the readiness-leadership decoupling rule, the anchor for this concern's shutdown-side
 * sibling facts (SHUTDOWN_SEQUENCE / LEADERSHIP_LOCK_EXIT in boot-sequence.contract.ts and
 * fail-closed.contract.ts).
 */

import { GATING_CHECK_IDS, type ReadinessCheckId } from "./readiness-checks.contract.ts";

/** The frozen state inputs the readiness and leadership predicates read. */
export interface NodeReadinessState {
  readonly schemaMigrated: boolean;
  readonly databaseReachable: boolean;
  readonly vaultKeyRingLoaded: boolean;
  readonly vaultCensusVerified: boolean;
  readonly observationReadCapable: boolean;
  readonly leadershipLockHeld: boolean;
}

/**
 * Maps each gating readiness check id to the pure extractor that reads its truth from state.
 * The census test asserts this covers exactly GATING_CHECK_IDS, so a new gating check without an
 * extractor — a check nothing can ever stamp — fails the build.
 */
export const GATING_CHECK_EVALUATORS: Readonly<
  Record<ReadinessCheckId, ((state: NodeReadinessState) => boolean) | undefined>
> = {
  schema_migrated: (state) => state.schemaMigrated,
  database_reachable: (state) => state.databaseReachable,
  vault_available: (state) => state.vaultKeyRingLoaded && state.vaultCensusVerified,
  observation_read_capable: (state) => state.observationReadCapable,
  signer_leadership: undefined,
};

export interface ReadinessVerdict {
  readonly ready: boolean;
  readonly failing: readonly ReadinessCheckId[];
}

/** Ready iff every gating check passes. Leadership is deliberately not consulted (the readiness-leadership decoupling rule).*/
export const evaluateReadiness = (state: NodeReadinessState): ReadinessVerdict => {
  const failing = GATING_CHECK_IDS.filter((id) => {
    const evaluate = GATING_CHECK_EVALUATORS[id];
    return evaluate === undefined || !evaluate(state);
  });
  return { ready: failing.length === 0, failing };
};

/**
 * Leadership is held only when the leadership lock is held AND the vault is fully available (the
 * boot key-ring is loaded AND the census has verified). The census conjunct enforces fail-closed
 * rule NO_LEADERSHIP_WITHOUT_VAULT_CENSUS; the key-ring conjunct closes the representable-but-
 * incoherent "leader with an unloaded key-ring" state — the boot sequence loads the key-ring
 * strictly before the census, so in every reachable state this conjunct is a no-op and only fails
 * closed a corrupt one — and keeps leadership's vault requirement identical to the gating
 * `vault_available` check.
 */
export const hasSignerLeadership = (state: NodeReadinessState): boolean =>
  state.leadershipLockHeld && state.vaultKeyRingLoaded && state.vaultCensusVerified;

/**
 * Node-level signing authorization: signing is permitted only when the node is READY (every gating
 * dependency healthy) AND holds signer leadership — exactly the frozen READY_AND_LEADER mode.
 * Leadership alone is insufficient: a leader with a failed gating dependency is LEADER_NOT_READY,
 * whose frozen table forbids SIGN, and with `databaseReachable:false` the DB
 * single-in-flight-per-wallet uniqueness constraint (the ultimate One-in-flight backstop, the readiness-leadership decoupling rule) cannot be
 * enforced, so permitting a sign would open a two-in-flight window. The wallet-specific C-02 lease
 * is a separate authority checked elsewhere and is intentionally NOT duplicated here.
 */
export const maySign = (state: NodeReadinessState): boolean =>
  evaluateReadiness(state).ready && hasSignerLeadership(state);

/**
 * Fail-closed guard: throws unless signing is permitted, with an identifier that distinguishes WHY
 * . A non-ready instance (a failed gating dependency) throws
 * SIGNING_WITHOUT_READINESS_REJECTED; a ready instance that merely lacks leadership throws the
 * pre-existing SIGNING_WITHOUT_LEADERSHIP_REJECTED — downstream consumers still key on that string
 * unchanged. The checks mirror maySign's own readiness-then-leadership sequence, so the set of
 * states this permits or rejects is identical to before; only the rejection identifier gained
 * precision.
 */
export const assertSigningPermitted = (state: NodeReadinessState): void => {
  if (!evaluateReadiness(state).ready) {
    throw new Error("SIGNING_WITHOUT_READINESS_REJECTED");
  }
  if (!hasSignerLeadership(state)) {
    throw new Error("SIGNING_WITHOUT_LEADERSHIP_REJECTED");
  }
};
