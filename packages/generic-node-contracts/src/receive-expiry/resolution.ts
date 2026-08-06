// the named concern — post-boundary resolution contract. A receive held past the durable-candidate boundary
// reconciles ONLY to RECEIVE_LANDED (the landing-proof complete-path rule) or INDETERMINATE (indefinitely). There is NO
// EXPIRED -> RECEIVE_LANDED transition and NO the frozen rule 30-minute fold-out (the landing-proof complete-path rule has no
// PROVEN_NOT_LANDED; folding + freeing the lease reopens the landed-into-released-wallet loss).
// Data + pure predicates; no DB code.

export const POST_BOUNDARY_RESOLUTIONS = ["RECEIVE_LANDED", "INDETERMINATE"] as const;
export type PostBoundaryResolution = (typeof POST_BOUNDARY_RESOLUTIONS)[number];

// The frozen rule fold-out (free the lease after ~30 min as PROVEN_NOT_LANDED) is forbidden here.
export const FOLD_OUT_ALLOWED = false;

export function isPostBoundaryResolutionLegal(resolution: string): boolean {
  return (POST_BOUNDARY_RESOLUTIONS as readonly string[]).includes(resolution);
}

// The unattributed-deep-successor disposition: a deep chain successor observed on the receiver that
// cannot be attributed to this op is an invariant breach -> quarantine (never adopted as landing).
export const UNATTRIBUTED_SUCCESSOR_DISPOSITION = "INVARIANT_BREACH_QUARANTINE" as const;

export function isInvariantBreach(deepSuccessorObserved: boolean, attributed: boolean): boolean {
  return deepSuccessorObserved && !attributed;
}
