/**
 * Residual crash/replay proof harness — the compare-and-swap cell.
 *
 * The shared cell is operations.formation_state (data-model; no shipped.sql artifact — the
 * vocabulary is doc-extracted in crash-replay-surfaces.ts). The CAS stands in for the
 * single-statement UPDATE... WHERE formation_state = 'APPROVED_UNSIGNED' of custody
 * step 5. Claims proven here are scoped "per enumerated schedule over the parsed store";
 * the live-DB discharge is the test plan ("real database concurrency tests,
 * not only mocked unit tests"), recorded as a persistence obligation. Never claimed: "the
 * database enforces one contender."
 */
import {
  findOperation,
  REFUSAL_CAS_BLOCKED,
  REFUSAL_CAS_LOST,
  signIntentFor,
  transitionFormation,
  type DurableStore,
  type Scenario,
  type VolatileDb,
} from "./crash-replay-model.ts";

/** Single atomic guarded write: the predicate is re-evaluated against the cell's CURRENT
 *  value at write time (EvalPlanQual-style recheck against a winner's write). The frozen
 *  guard is enforced structurally: no CAS fires before a sign intent is durably persisted
 * (custody steps 4-5: persist_sign_intent_before_signer_then_compare_and_swap). */
export const compareAndSwapFormationState = (
  scenario: Scenario,
  operationId: string,
): boolean => {
  if (signIntentFor(scenario.durable, operationId) === undefined) {
    throw new Error(
      "crash-replay cas: CAS guard violated — no persisted sign intent (custody steps 4-5)",
    );
  }
  const row = findOperation(scenario.durable, operationId);
  if (row.formationState !== "APPROVED_UNSIGNED") {
    scenario.runtime.log.refusals.push(REFUSAL_CAS_LOST);
    return false;
  }
  transitionFormation(scenario, operationId, "SIGNING_CLAIMED");
  return true;
};

export type TentativeClaimOutcome = "CLAIMED" | "BLOCKED" | "LOST";

/** Transactional (uncommitted) claim for the crash-vs-race interplay: the tentative write
 *  is visible but rolls back on abort. A second worker is BLOCKED behind the open claim —
 *  never permanently excluded; it rechecks once the claim resolves (Postgres row-lock
 *  blocking + post-resolution predicate recheck, at model level). */
export const tryClaimTentative = (
  scenario: Scenario,
  operationId: string,
  workerId: string,
): TentativeClaimOutcome => {
  const pending = scenario.runtime.volatileDb.pendingClaims.find(
    (claim) => claim.operationId === operationId && claim.workerId !== workerId,
  );
  if (pending !== undefined) {
    scenario.runtime.log.refusals.push(REFUSAL_CAS_BLOCKED);
    return "BLOCKED";
  }
  const row = findOperation(scenario.durable, operationId);
  if (row.formationState !== "APPROVED_UNSIGNED") {
    scenario.runtime.log.refusals.push(REFUSAL_CAS_LOST);
    return "LOST";
  }
  scenario.runtime.volatileDb.pendingClaims.push({
    workerId,
    operationId,
    previousFormationState: row.formationState,
  });
  row.formationState = "SIGNING_CLAIMED";
  return "CLAIMED";
};

export const commitClaim = (scenario: Scenario, operationId: string, workerId: string): void => {
  const claims = scenario.runtime.volatileDb.pendingClaims;
  const index = claims.findIndex(
    (claim) => claim.operationId === operationId && claim.workerId === workerId,
  );
  if (index === -1) {
    throw new Error(`crash-replay cas: no pending claim for ${workerId} on ${operationId}`);
  }
  claims.splice(index, 1);
  scenario.runtime.log.formationTransitions.push({
    operationId,
    from: "APPROVED_UNSIGNED",
    to: "SIGNING_CLAIMED",
  });
};

/** Rolls every uncommitted claim back (crash axiom: uncommitted writes are discarded). */
export const rollbackPendingClaims = (durable: DurableStore, volatileDb: VolatileDb): void => {
  for (const claim of volatileDb.pendingClaims) {
    findOperation(durable, claim.operationId).formationState = claim.previousFormationState;
  }
  volatileDb.pendingClaims = [];
};
