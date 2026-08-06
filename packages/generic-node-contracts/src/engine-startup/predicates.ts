/**
 * SOURCE: the startup-sequence decision + the node-core runtime component table. Pure predicates over a node engine and
 * the frozen the named concern NodeReadinessState. They consume the named concern's hasSignerLeadership so a single
 * definition of "this instance is the leader" governs both readiness and engine startup.
 */

import { type NodeReadinessState, assertSigningPermitted, hasSignerLeadership } from "../readiness/index.ts";
import { type NodeEngine } from "./engines.contract.ts";

/**
 * A leader-gated engine runs only on the leader; a follower-safe engine runs on any instance.
 * Leadership is read through the named concern's predicate (lock held AND vault census verified).
 */
export const engineMayRun = (engine: NodeEngine, state: NodeReadinessState): boolean =>
  engine.leadershipRequirement === "FOLLOWER_SAFE" || hasSignerLeadership(state);

/**
 * This predicate enforces ONLY the leadership/split-brain conjunct: an economic-state write is
 * permitted only when the engine is an economic-state writer AND this instance holds leadership.
 * A follower-safe engine is never an economic-state writer, so this is false for it regardless; a
 * leader-gated engine on a non-leader is false — the split-brain guard.
 *
 * Readiness (`schema_migrated` / `database_reachable` — the DB one-in-flight-per-wallet backstop
 * precondition, the frozen rule) is a SEPARATE conjunct this predicate does NOT check. It MUST be composed
 * at every real economic-write site, alongside this predicate — compose with `maySign(state)` /
 * `assertSigningPermitted` (../readiness/predicates.ts). The frozen authority for "no economic
 * write when not ready" is the LEADER_NOT_READY mode row in degraded-modes.contract.ts, which
 * forbids MUTATE_ECONOMIC_STATE while leader but not ready.
 */
export const engineMayEconomicWrite = (engine: NodeEngine, state: NodeReadinessState): boolean =>
  engine.economicStateWriter && hasSignerLeadership(state);

/**
 * Fail-closed guard: throws unless the engine may economic-write per the leadership/split-brain
 * conjunct above. The rejection path for a follower. As with `engineMayEconomicWrite`, this does
 * NOT check readiness — callers MUST separately compose `assertSigningPermitted` (or `maySign`)
 * at the real write site (the frozen rule; LEADER_NOT_READY in degraded-modes.contract.ts).
 */
export const assertEngineEconomicWritePermitted = (
  engine: NodeEngine,
  state: NodeReadinessState,
): void => {
  if (!engineMayEconomicWrite(engine, state)) {
    throw new Error("FOLLOWER_ECONOMIC_WRITE_REJECTED");
  }
};

// Composed write-site guard: readiness AND leadership (the frozen rule; LEADER_NOT_READY forbids MUTATE_ECONOMIC_STATE).
export const assertEconomicWriteSitePermitted = (
  engine: NodeEngine,
  state: NodeReadinessState,
): void => {
  assertSigningPermitted(state);
  assertEngineEconomicWritePermitted(engine, state);
};
