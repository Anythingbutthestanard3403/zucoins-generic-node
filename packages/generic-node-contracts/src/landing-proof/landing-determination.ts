/**
 * SOURCE: the complete-path landing-proof rule (canonical), the observation-verification spec,
 * and the incomplete-ancestor-proof note. the landing-proof e2e — the pure, total landing
 * determination classifier: map an already-computed evidence bundle to a landing outcome, failing
 * closed to a taxonomised INDETERMINATE on anything short of a clean, fresh-head-anchored, complete,
 * re-verified proof.
 *
 * Pure and stateless: no storage, no network, no worker, no keys, no clock, not even a hash. It
 * consumes the landing-proof index/walk's `WalkOutcome` and the landing-proof manifest builder's `ReverifyVerdict` and re-freezes neither. The
 * return type's outcome is `LandingDeterminationOutcome` (three members, none non-landing), so the
 * function CANNOT construct a `PROVEN_NOT_LANDED` — there is no such value to return.
 */

import { type WalkOutcome } from "./linkage.contract.ts";
import { type AncestryIndex, type WalkResult, collisionOnPath } from "./ancestry-index.ts";
import { type ReverifyVerdict } from "./proof-manifest.contract.ts";
import {
  DETERMINATION_AUTHORITY,
  type DeterminationAuthorityGrant,
  type FreshHeadStatus,
  type IndeterminateCause,
  type LandingDeterminationOutcome,
} from "./fail-closed.contract.ts";

/**
 * The already-computed evidence a landing determination is made from. Every field is produced by an
 * upstream lane (the observation concern observation, the landing-proof index/walk/index, the landing-proof manifest builder re-verify, the runtime
 * signature/economic lane); this slice performs no I/O and only classifies. Construct it from real
 * upstreams via `buildLandingEvidence`, which is the sole sanctioned producer — it DERIVES the
 * walk-sourced and index-sourced signals rather than accepting them hand-supplied.
 *
 * `walkOutcome` carries the walk's total termination outcome, including `INCOMPLETE_BUDGET_EXHAUSTED`
 * (an over-budget walk) and `INCOMPLETE_CYCLE` (a cyclic/self-looping index) — there is deliberately no
 * separate `workBudgetExhausted` boolean, because budget exhaustion is a termination mode of the walk,
 * not an independent axis, and a second encoding of the same fact would admit contradictory evidence.
 * `indexCollisionOnPath` is derived by `collisionOnPath(index, walk.chain)` (a hop on the path shares a
 * key with a surfaced, unmerged collision — orthogonal to `walkOutcome`, since a COMPLETE_CONTIGUOUS
 * walk can still traverse a collided key). `reverify === null` means no proof manifest could be
 * constructed for the expected body from the completed walk (the expected body is not on the
 * reconstructable path).
 */
export interface LandingEvidence {
  readonly freshHead: FreshHeadStatus;
  readonly invariantAnomaly: boolean;
  readonly indexCollisionOnPath: boolean;
  readonly walkOutcome: WalkOutcome;
  readonly reverify: ReverifyVerdict | null;
  readonly attestedPredicatesEstablished: boolean;
}

/** A landing determination: the outcome, its INDETERMINATE cause (null iff a positive landing), and the frozen authority the caller may derive. */
export interface LandingDetermination {
  readonly outcome: LandingDeterminationOutcome;
  readonly cause: IndeterminateCause | null;
  readonly authority: DeterminationAuthorityGrant;
}

const decide = (
  outcome: LandingDeterminationOutcome,
  cause: IndeterminateCause | null,
): LandingDetermination => ({ outcome, cause, authority: DETERMINATION_AUTHORITY[outcome] });

const indeterminate = (cause: IndeterminateCause): LandingDetermination =>
  decide("INDETERMINATE", cause);

/**
 * Classify a landing attempt, failing closed. The precedence is fixed so the function is total and
 * deterministic (re-running on identical evidence yields the identical result): anchor problems
 * first, then the walk's termination modes (over-budget, then cycle), then a collision on the path,
 * then walk incompleteness (ambiguous, then missing), then the expected body's presence, then the
 * re-verify verdict and the attested predicates. The ONLY positive exits require an authoritative
 * fresh head, no anomaly, no budget exhaustion, no cycle, no collision, a COMPLETE_CONTIGUOUS walk, a
 * clean standalone re-verify, and established attested predicates — exactly the complete-path landing-proof rule's positive
 * conditions. Every other path is INDETERMINATE with a cause; none is ever non-landing. A clean
 * STRUCTURALLY re-verified manifest with the attested predicates NOT established is
 * `PREDICATE_UNVERIFIABLE`, never a landing (the crypto gate is not yet satisfied).
 */
export const classifyLanding = (evidence: LandingEvidence): LandingDetermination => {
  if (evidence.invariantAnomaly) return indeterminate("INVARIANT_ANOMALY");
  if (evidence.freshHead === "ENDPOINT_CONFLICT") return indeterminate("ENDPOINT_CONFLICT");
  if (evidence.freshHead === "STALE_OR_UNVERIFIED") return indeterminate("FRESH_HEAD_UNAVAILABLE");
  if (evidence.walkOutcome === "INCOMPLETE_BUDGET_EXHAUSTED") return indeterminate("WORK_BUDGET_EXHAUSTED");
  if (evidence.walkOutcome === "INCOMPLETE_CYCLE") return indeterminate("WALK_CYCLE");
  if (evidence.indexCollisionOnPath) return indeterminate("INDEX_COLLISION");
  if (evidence.walkOutcome === "INCOMPLETE_AMBIGUOUS_HOP") return indeterminate("WALK_AMBIGUOUS_HOP");
  if (evidence.walkOutcome === "INCOMPLETE_MISSING_HOP") return indeterminate("WALK_MISSING_HOP");

  // walkOutcome === "COMPLETE_CONTIGUOUS" from here.
  if (evidence.reverify === null) return indeterminate("EXPECTED_BODY_ABSENT_FROM_PATH");
  if (evidence.reverify === "REJECTED") return indeterminate("REVERIFY_REJECTED");
  if (!evidence.attestedPredicatesEstablished) return indeterminate("PREDICATE_UNVERIFIABLE");
  if (evidence.reverify === "STRUCTURALLY_REVERIFIED_LANDED_EXACT") return decide("LANDED_EXACT", null);
  return decide("LANDED_COMPLETE_PATH", null);
};

/**
 * The sole sanctioned producer of a `LandingEvidence` bundle from real upstreams. It DERIVES the
 * walk-sourced and index-sourced signals — `walkOutcome` from the (total) walk, `indexCollisionOnPath`
 * from `collisionOnPath(index, walk.chain)` — closing the "free hand-supplied boolean with no producer"
 * gap: a cyclic index now reaches `classifyLanding` as `walkOutcome === "INCOMPLETE_CYCLE"`, an
 * over-budget walk as `"INCOMPLETE_BUDGET_EXHAUSTED"`, and a collision on the claimed head as
 * `indexCollisionOnPath === true`, each failing closed to its INDETERMINATE cause. The remaining fields
 * are genuinely external to the landing-proof index/walk's index/walk: `freshHead` (the head-read/anchor lane)
 * `invariantAnomaly` (the custody-invariant lane), `reverify` (the landing-proof manifest builder's standalone re-verify, or null
 * when the expected body is absent from the reconstructable path), and `attestedPredicatesEstablished`
 * (the runtime Ed25519 / economic verification lane). Pure: no I/O, no keys, no clock.
 */
export const buildLandingEvidence = (inputs: {
  readonly freshHead: FreshHeadStatus;
  readonly invariantAnomaly: boolean;
  readonly index: AncestryIndex;
  readonly walk: WalkResult;
  readonly reverify: ReverifyVerdict | null;
  readonly attestedPredicatesEstablished: boolean;
}): LandingEvidence => ({
  freshHead: inputs.freshHead,
  invariantAnomaly: inputs.invariantAnomaly,
  indexCollisionOnPath: collisionOnPath(inputs.index, inputs.walk.chain),
  walkOutcome: inputs.walk.outcome,
  reverify: inputs.reverify,
  attestedPredicatesEstablished: inputs.attestedPredicatesEstablished,
});
