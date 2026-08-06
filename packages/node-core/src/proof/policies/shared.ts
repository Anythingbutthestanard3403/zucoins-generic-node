// internals shared by the three operation proof policies.
//
// (the per-operation predicate lists) and the verdict rule each section repeats:
// every predicate true → VERIFIED; a cryptographically determinate mismatch → REJECTED
// while retaining evidence; a read failure, anomaly, gap, regression, or contradiction →
// INDETERMINATE with no business promotion. Canonical override:.md
// (exactly three operation kinds, so exactly three policies) and canonical ZKZ amount contract (the ZKZ amount
// domain every delta check is held to). All amounts here are ZKZ.
//
// This module holds no predicate logic of its own: it is the vocabulary the three policy
// files use to say "held", "determinate mismatch", or "not decided", the shared finish
// that sequences evaluated predicates and hands them to `evaluateProof`, plus the attribution
// of one `DeltaEvaluation` onto the several frozen predicates it answers for.
import type {
  DeltaEvaluation,
  DeltaRejectionReason,
} from "../../protocol/economic-predicates.js";
import type { InnerShapeRejection } from "../../verifier/inner-shape.js";
import type { PreimageEncodingRejection } from "../../verifier/transaction-verify.js";
import { evaluateProof } from "../evaluate.js";
import type {
  EvidenceKind,
  OperationType,
  PredicateId,
  PredicateResult,
  ProofVerdict,
} from "../types.js";

/**
 * A `PredicateResult` carrying the reason the policy reached it. `detail` is
 * evidence for the operator and for proof serialization; the verdict itself is
 * decided from `passed`/`determinate` alone by `evaluateProof`.
 */
export interface EvaluatedPredicate {
  readonly predicate: PredicateId;
  readonly passed: boolean;
  readonly determinate: boolean;
  readonly detail: string;
}

export interface OperationProofResult {
  readonly verdict: ProofVerdict;
  readonly predicates: readonly EvaluatedPredicate[];
}

/** The predicate held on the evidence presented. */
export function held(predicate: PredicateId, detail: string): EvaluatedPredicate {
  return { predicate, passed: true, determinate: true, detail };
}

/** A cryptographically determinate mismatch — the operation is REJECTED, evidence retained. */
export function mismatch(predicate: PredicateId, detail: string): EvaluatedPredicate {
  return { predicate, passed: false, determinate: true, detail };
}

/**
 * The predicate could not be decided from the evidence held — a read failure, gap, or
 * contradiction. Never REJECTED on this alone: `evaluateProof` folds it to INDETERMINATE.
 */
export function undecided(predicate: PredicateId, detail: string): EvaluatedPredicate {
  return { predicate, passed: false, determinate: false, detail };
}

export function decide(
  predicate: PredicateId,
  ok: boolean,
  detail: string,
): EvaluatedPredicate {
  return ok ? held(predicate, detail) : mismatch(predicate, detail);
}

/**
 * Half 1 — the expected-artifact envelope verdict produced by the artifact concern's
 * `verifyExpectedArtifact` (crypto-owning, async, dependency-injected). The policies consume
 * its typed outcome and check the independent second half: that the artifact's bound values
 * match the chain. Structurally assignable from that function's `VerifyResult`.
 */
export type ArtifactVerification =
  | { readonly ok: true; readonly purpose: string; readonly digest: string }
  | { readonly ok: false; readonly reason: string; readonly detail?: string };

export function describeArtifactRejection(
  verification: Extract<ArtifactVerification, { ok: false }>,
): string {
  return verification.detail === undefined
    ? verification.reason
    : `${verification.reason} (${verification.detail})`;
}

export function describeTransactionRejection(
  rejection: InnerShapeRejection | PreimageEncodingRejection,
): string {
  return rejection.reason === "invalid_scalar"
    ? `invalid_scalar ${rejection.scalarKind}/${rejection.scalarReason}`
    : `${rejection.reason}: ${rejection.detail}`;
}

/**
 * A `checkExactDelta` rejection detail always opens with the caller's own label for the
 * delta it was computing. labels the two MOVE legs "source …" / "destination …",
 * which is how one `evaluateInternalMoveDelta` rejection is attributed to the right leg.
 * `move.delta-attribution.test.ts` pins this prefix so a relabel there breaks a test here
 * instead of silently mislabelling a proof record.
 */
export const DESTINATION_DELTA_DETAIL_PREFIX = "destination";

/** Rejection reasons produced by the exact-decimal delta check itself (amount domain). */
export const AMOUNT_DELTA_REASONS: readonly DeltaRejectionReason[] = [
  "invalid_operation_amount",
  "invalid_balance_scalar",
  "balance_delta_mismatch",
];

export interface DeltaRejection {
  readonly reason: DeltaRejectionReason;
  readonly detail: string;
}

/**
 * One frozen predicate and the test for "this rejection is the one I answer for". A
 * rejection no owner claims means short-circuited before reaching any of these
 * predicates, so all of them are left undecided — never a determinate mismatch asserted on
 * a check that was not run.
 */
export interface DeltaPredicateOwner {
  readonly predicate: PredicateId;
  readonly owns: (rejection: DeltaRejection) => boolean;
}

export function attributeDelta(
  evaluation: DeltaEvaluation,
  owners: readonly DeltaPredicateOwner[],
): EvaluatedPredicate[] {
  if (evaluation.ok) {
    return owners.map((owner) =>
      held(owner.predicate, "exact-decimal economic predicate held (ZKZ)"),
    );
  }
  const rejection: DeltaRejection = { reason: evaluation.reason, detail: evaluation.detail };
  const owner = owners.find((candidate) => candidate.owns(rejection));
  return owners.map((candidate) =>
    candidate === owner
      ? mismatch(candidate.predicate, evaluation.detail)
      : undecided(candidate.predicate, `not decided: delta stopped at ${evaluation.reason}`),
  );
}

/**
 * Shared finalizer for all three operation policies (three public money operations). Sequences evaluated predicates by
 * the caller's frozen policy step list, projects them to `PredicateResult`, and returns the
 * `evaluateProof` verdict. Predicate logic and step-sequence declarations stay in each policy
 * module; only the finish shape is shared. `as const` step tuples and `OperationType` keep the
 * frozen step list and evidence kinds compile-time constrained.
 */
export function finalizeOperationProof<const TSteps extends readonly PredicateId[]>(
  operationType: OperationType,
  predicateSteps: TSteps,
  predicates: readonly EvaluatedPredicate[],
  evidencePresent: readonly EvidenceKind[],
): OperationProofResult {
  const sequenced = predicateSteps.flatMap((predicate) =>
    predicates.filter((evaluated) => evaluated.predicate === predicate),
  );
  const predicateResults: PredicateResult[] = sequenced.map(({ predicate, passed, determinate }) => ({
    predicate,
    passed,
    determinate,
  }));
  return {
    verdict: evaluateProof({
      operationType,
      predicateResults,
      evidencePresent,
    }),
    predicates: sequenced,
  };
}
