/**
 * SOURCE: the complete-path landing-proof rule (canonical) and the observation-verification
 * spec: relationship anomaly classes, "the result is indeterminate—not not-landed", fail-closed
 * anomaly actions, threats/limitations, and the incomplete-ancestor-proof note.
 * the landing-proof e2e — the fail-closed side of the any-depth landing proof.
 *
 * This slice freezes what an incomplete or bounded landing attempt CONCLUDES: the closed
 * INDETERMINATE cause taxonomy (every way evidence is insufficient to prove landing WITHOUT being a
 * structural defect of a supplied artifact), the rule that such an outcome confers ZERO authority,
 * and the fact that there is no `PROVEN_NOT_LANDED` — none can be expressed. It CONSUMES the landing-proof index/walk's
 * walk/completeness distinction and the landing-proof manifest builder's re-verify vocabulary and re-freezes neither (.1/.2
 * win on any conflict). The determination classifier is in landing-determination.ts.
 */

import {
  type LandingClassification,
  MANIFEST_REVERIFY_FAILURES,
} from "./proof-manifest.contract.ts";

/**
 * The landing-determination outcome space. The two POSITIVE members are exactly the manifest builder's
 * `LANDING_CLASSIFICATIONS`; the only addition is `INDETERMINATE`. There is deliberately NO member
 * expressing non-landing: the rule has no generic `PROVEN_NOT_LANDED` oracle and canon fixes an absent
 * back-link as "indeterminate—not not-landed". The type space itself cannot name a not-landed
 * outcome — that impossibility is the point, and fail-closed.census.test.ts proves it holds.
 */
export const LANDING_DETERMINATIONS = [
  "LANDED_EXACT",
  "LANDED_COMPLETE_PATH",
  "INDETERMINATE",
] as const;
export type LandingDeterminationOutcome = (typeof LANDING_DETERMINATIONS)[number];

/** Compile-time proof the positive determinations ARE exactly the landing-proof manifest builder's classifications.*/
export type _PositivesAreClassifications = LandingClassification extends LandingDeterminationOutcome
  ? true
  : never;

/**
 * The closed INDETERMINATE cause taxonomy — every construction-time reason a landing attempt fails to
 * prove landing through EVIDENCE INSUFFICIENCY (or contradiction), as opposed to the landing-proof manifest builder's
 * `MANIFEST_REVERIFY_FAILURES`, which are structural defects of an already-SUPPLIED manifest artifact.
 * The two vocabularies are disjoint by construction (see `FAIL_CLOSED_INVARIANTS` and the census);
 * `REVERIFY_REJECTED` is the single bridge that maps the landing-proof manifest builder structural `REJECTED` up to a
 * determination-layer INDETERMINATE (a rejected proof proves nothing, and nothing is not-landing).
 */
export const INDETERMINATE_CAUSES = [
  "FRESH_HEAD_UNAVAILABLE",
  "ENDPOINT_CONFLICT",
  "WORK_BUDGET_EXHAUSTED",
  "INDEX_COLLISION",
  "WALK_AMBIGUOUS_HOP",
  "WALK_MISSING_HOP",
  "WALK_CYCLE",
  "EXPECTED_BODY_ABSENT_FROM_PATH",
  "REVERIFY_REJECTED",
  "PREDICATE_UNVERIFIABLE",
  "INVARIANT_ANOMALY",
] as const;
export type IndeterminateCause = (typeof INDETERMINATE_CAUSES)[number];

/**
 * The fresh-head anchor status the determination is built on. A landing can only be anchored on an
 * AUTHORITATIVE, signature-verified fresh head. A stale/unread/unverifiable head or two
 * disagreeing endpoints can anchor nothing and each yields its own INDETERMINATE cause.
 */
export const FRESH_HEAD_STATUSES = [
  "AUTHORITATIVE",
  "STALE_OR_UNVERIFIED",
  "ENDPOINT_CONFLICT",
] as const;
export type FreshHeadStatus = (typeof FRESH_HEAD_STATUSES)[number];

/**
 * The traceability taxonomy: each INDETERMINATE cause, the upstream signal that produces it, and its
 * governing spec citation. `layer` is uniformly EVIDENCE_INSUFFICIENCY to contrast with the landing-proof manifest builder's
 * ARTIFACT_STRUCTURAL re-verify failures — the two never share a member. The census asserts this list
 * covers `INDETERMINATE_CAUSES` exactly (no orphan, no gap).
 */
export const INDETERMINATE_CAUSE_TAXONOMY = [
  {
    cause: "FRESH_HEAD_UNAVAILABLE",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "no fresh authoritative signature-verified head to anchor at depth 0 (read failure / stale / unverifiable)",
    source: "the landing-proof rule; anomaly actions (transport/read failure -> keep lease, verification indeterminate)",
  },
  {
    cause: "ENDPOINT_CONFLICT",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "two independently configured gateway endpoints disagree on the wallet head",
    source: "the landing-proof rule (conflict / contradictory wallet path); anomaly actions (endpoints disagree -> INDETERMINATE, oracle incident)",
  },
  {
    cause: "WORK_BUDGET_EXHAUSTED",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "the walk hit its bounded step budget before reaching genesis (the index/walk INCOMPLETE_BUDGET_EXHAUSTED) — a pathologically long or over-budget chain, never silently truncated to a shorter 'complete' path",
    source: "the landing-proof rule (verifier resource/budget exhaustion); bounded read; over-budget evidence; the index/walk WALK_OUTCOMES",
  },
  {
    cause: "INDEX_COLLISION",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "a hop's (wallet, step-2 signature) key holds two conflicting exact bodies (a surfaced index collision)",
    source: "the landing-proof rule (conflict); SIGNATURE_COLLISION anomaly -> fail closed",
  },
  {
    cause: "WALK_AMBIGUOUS_HOP",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "a predecessor state signature resolves to more than one candidate body (the index/walk INCOMPLETE_AMBIGUOUS_HOP)",
    source: "the landing-proof rule (conflict/anomaly); relationship anomaly classes; the index/walk WALK_OUTCOMES",
  },
  {
    cause: "WALK_MISSING_HOP",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "a body needed to extend the contiguous chain is absent from the index (unobserved body / missed poll / gap / index gap / unknown completed send) (the index/walk INCOMPLETE_MISSING_HOP)",
    source: "the landing-proof rule (missing bodies / gap); absent back-link; omission -> indeterminate; the index/walk WALK_OUTCOMES",
  },
  {
    cause: "WALK_CYCLE",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "a predecessor pointer resolves back to an entry already on the walk (a state-signature cycle or self-loop) so no genesis-terminating chain exists (the index/walk INCOMPLETE_CYCLE)",
    source: "the landing-proof rule (duplicate/cycle yields INDETERMINATE); cycle anomaly -> fail closed; the index/walk WALK_OUTCOMES",
  },
  {
    cause: "EXPECTED_BODY_ABSENT_FROM_PATH",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "the reconstructable/contiguous path does not contain the expected body as its terminal; absence is not evidence of non-landing (a stale head or a sibling branch remains possible)",
    source: "the landing-proof rule (no PROVEN_NOT_LANDED); indeterminate—not not-landed",
  },
  {
    cause: "REVERIFY_REJECTED",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "a manifest was constructed but the manifest builder's standalone re-verifier returned REJECTED (corrupt/tampered body, broken back-link, gap, duplicate/cycle, wrong claim, ...); a rejected proof proves nothing",
    source: "the landing-proof rule (invalid preimage/back-link, duplicate/cycle); bridges MANIFEST_REVERIFY_FAILURES",
  },
  {
    cause: "PREDICATE_UNVERIFIABLE",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "an attested per-body predicate the standalone re-verifier cannot itself re-run (both Ed25519 signatures, strict scalar/role, operation-artifact + economic against T0) could not be established at construction",
    source: "the landing-proof rule (invalid signature/role/economic predicate); the observation verification predicates",
  },
  {
    cause: "INVARIANT_ANOMALY",
    layer: "EVIDENCE_INSUFFICIENCY",
    producedBy: "a custody/invariant anomaly incompatible with a clean determination (unexplained jump, regression, genesis-after-history, or an unattributed deep successor while the wallet remains actively leased)",
    source: "the landing-proof rule (anomaly; unattributed deep successor = invariant/custody breach); do not infer landing/non-landing",
  },
] as const;

/** The authority a caller may derive from a determination — the consumer contract, as data. */
export interface DeterminationAuthorityGrant {
  readonly mayConcludeLanded: boolean;
  readonly mayConcludeNotLanded: boolean;
  readonly mayRetryRebuildResubmit: boolean;
  readonly mayReleaseLeaseOrReuse: boolean;
  readonly mustHoldLeaseAndAwaitNewObservations: boolean;
}

/**
 * The consumer contract keyed by outcome (the incomplete-ancestor-proof note). `INDETERMINATE`
 * confers ZERO authority: it authorizes no landing, no non-landing, no retry/rebuild/resubmit, and no
 * lease/reuse release — the lease is HELD and the attempt waits for new observations (the one-in-flight-per-wallet rule).
 * A positive landing authorizes concluding landed only; it never authorizes retry or lease release,
 * and — like every outcome — never authorizes concluding not-landed (`mayConcludeNotLanded` is false
 * across the entire space: there is no PROVEN_NOT_LANDED).
 */
export const DETERMINATION_AUTHORITY = {
  LANDED_EXACT: {
    mayConcludeLanded: true,
    mayConcludeNotLanded: false,
    mayRetryRebuildResubmit: false,
    mayReleaseLeaseOrReuse: false,
    mustHoldLeaseAndAwaitNewObservations: false,
  },
  LANDED_COMPLETE_PATH: {
    mayConcludeLanded: true,
    mayConcludeNotLanded: false,
    mayRetryRebuildResubmit: false,
    mayReleaseLeaseOrReuse: false,
    mustHoldLeaseAndAwaitNewObservations: false,
  },
  INDETERMINATE: {
    mayConcludeLanded: false,
    mayConcludeNotLanded: false,
    mayRetryRebuildResubmit: false,
    mayReleaseLeaseOrReuse: false,
    mustHoldLeaseAndAwaitNewObservations: true,
  },
} as const satisfies Record<LandingDeterminationOutcome, DeterminationAuthorityGrant>;

/**
 * Re-walk semantics. An INDETERMINATE is not terminal, but re-interpreting the SAME
 * evidence must yield the SAME outcome — only genuinely NEW observations (a newly retained body, a
 * fresh head read) may change it. It never defaults to landed or to not-landed, and never folds to a
 * terminal verdict on a timer.
 */
export const REWALK_SEMANTICS = {
  indeterminateIsNotTerminal: true,
  onlyNewObservationsCanChangeOutcome: true,
  identicalEvidenceYieldsIdenticalOutcome: true,
  indeterminateNeverDefaultsToLanded: true,
  indeterminateNeverDefaultsToNotLanded: true,
  noTimeBasedFoldToTerminal: true,
  source: "the landing-proof rule and the receive-expiry prevention rule (no PROVEN_NOT_LANDED, no fold-out)",
} as const;

/**
 * The frozen invariants this slice enforces, as a reviewable data record. `provenNotLandedExists` is
 * false and is proven structurally: the outcome type space is three members, none of which names a
 * non-landing. The cause vocabulary is disjoint from the landing-proof manifest builder's re-verify failures, meeting at the
 * single bridge cause `REVERIFY_REJECTED`.
 */
export const FAIL_CLOSED_INVARIANTS = {
  provenNotLandedExists: false,
  determinationSpaceSize: LANDING_DETERMINATIONS.length,
  positiveMembersAreClassifications: true,
  indeterminateConfersZeroAuthority: true,
  noOutcomeAuthorizesConcludingNotLanded: true,
  causeVocabularyDisjointFromReverifyFailures: true,
  reverifyRejectedIsTheSoleBridge: true,
  reverifyFailureVocabularySize: MANIFEST_REVERIFY_FAILURES.length,
  source: "the landing-proof rule; the landing wire-vocabulary correction; the observation-verification completeness/anomaly rules; the api contract landing fields",
} as const;

/**
 * Wire positive landing classifications on verification-complete / verification-material
 * (the api contract's landing fields). Distinct from the three-member determination space: the wire carries only
 * the two positive shapes, and an incomplete attempt is a top-level `INDETERMINATE` verdict with
 * no landing classification (the wire-vocabulary freeze).
 */
export const LANDING_WIRE_CLASSIFICATIONS = ["EXPECTED_AT_HEAD", "EXPECTED_ANCESTOR"] as const;
export type LandingWireClassification = (typeof LANDING_WIRE_CLASSIFICATIONS)[number];

/**
 * Positive determination → wire classification at the ack/material boundary (the wire-vocabulary freeze).
 * Depth-1 is NOT a distinct determination: the historical prose label `LANDED_DIRECT_SUCCESSOR`
 * is a descriptive synonym for `LANDED_COMPLETE_PATH` at hop_count === 1 and maps to
 * `EXPECTED_ANCESTOR` the same way any deeper complete path does. hop_count (0 vs ≥1)
 * distinguishes exact-head from buried landing on the wire material shape.
 */
export const LANDING_DETERMINATION_TO_WIRE = {
  LANDED_EXACT: "EXPECTED_AT_HEAD",
  LANDED_COMPLETE_PATH: "EXPECTED_ANCESTOR",
} as const satisfies Record<
  Exclude<LandingDeterminationOutcome, "INDETERMINATE">,
  LandingWireClassification
>;

/** Explicit fold flag: depth-1 is not a fourth determination (the wire-vocabulary freeze).*/
export const DEPTH_ONE_LANDING_IS_LANDED_COMPLETE_PATH = true as const;

/**
 * Public wire `indeterminate_reason` codes on ancestor_proofs / verification-material
 * (the api contract's landing fields) — five values. The eleven-value `INDETERMINATE_CAUSES` taxonomy is the
 * determination-layer cause space; every cause projects to exactly one wire code below.
 */
export const WIRE_INDETERMINATE_REASONS = [
  "MISSING_BODY",
  "LINK_GAP",
  "ANOMALY",
  "FRESH_HEAD_MISMATCH",
  "BUDGET_EXCEEDED",
] as const;
export type WireIndeterminateReason = (typeof WIRE_INDETERMINATE_REASONS)[number];

/**
 * Total cause → wire-reason mapping (the wire-vocabulary freeze). Surjective onto `WIRE_INDETERMINATE_REASONS`
 * (every wire code is produced by ≥1 cause). Not injective: several causes collapse to ANOMALY.
 * A consumer that only sees wire codes must treat ANOMALY as a bucket and must not invent a
 * sixth wire code for an unknown cause — unknown determination causes fail closed as
 * INDETERMINATE with wire reason ANOMALY when projected for material, never as a landing.
 */
export const INDETERMINATE_CAUSE_TO_WIRE_REASON = {
  FRESH_HEAD_UNAVAILABLE: "FRESH_HEAD_MISMATCH",
  ENDPOINT_CONFLICT: "ANOMALY",
  WORK_BUDGET_EXHAUSTED: "BUDGET_EXCEEDED",
  INDEX_COLLISION: "ANOMALY",
  WALK_AMBIGUOUS_HOP: "LINK_GAP",
  WALK_MISSING_HOP: "LINK_GAP",
  WALK_CYCLE: "ANOMALY",
  EXPECTED_BODY_ABSENT_FROM_PATH: "MISSING_BODY",
  REVERIFY_REJECTED: "ANOMALY",
  PREDICATE_UNVERIFIABLE: "ANOMALY",
  INVARIANT_ANOMALY: "ANOMALY",
} as const satisfies Record<IndeterminateCause, WireIndeterminateReason>;
