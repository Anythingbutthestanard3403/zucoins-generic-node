import { type PostBoundaryResolution } from "./resolution.js";

// the named concern — the expiry -> reconcile -> release sequencing contract. On a post-boundary expiry the
// node keeps the lease and ALL evidence, and reconciles FIRST via a fresh verified chain read
// (the landing-proof complete-path rule-style oracle). Per the receive-expiry rule's stricter branch there is NO release post-boundary at any proof
// level — a head-unchanged read is a snapshot, not proof a signed, durable tx will never land — so
// the post-boundary output domain is exactly RECEIVE_LANDED or INDETERMINATE (held indefinitely).
// Dispositions wire to .1's resolution contract (.1 wins). Data + pure verifiers; no DB code, no
// reconcile/release runtime.

// The sequenced steps; never reorder (resolution must never precede reconcile).
export const EXPIRY_RECONCILE_RELEASE_ORDER = [
  "hold_lease",
  "retain_evidence",
  "reconcile_first",
  "resolve_or_release",
] as const;

export type PostBoundaryDisposition =
  | { readonly kind: "resolved"; readonly resolution: PostBoundaryResolution }
  | { readonly kind: "held"; readonly attentionReason: "POST_EXPIRY_RECONCILING" };

// The disposition of a post-boundary expiry, wired to .1's resolution contract. Reconcile FIRST: no
// disposition before a fresh verified read. A landing wins (RECEIVE_LANDED). There is no release
// branch here (the receive-expiry rule): a durably inconclusive reconcile resolves to INDETERMINATE (held
// indefinitely); anything else — including a head-unchanged, fully-acked read that is not (yet)
// durably inconclusive — stays held and keeps reconciling.
// t0Unchanged and groupAcknowledgementsComplete are carried on the input for the reconcile oracle's
// observability (the DB-domains concern/the named concern) but no longer gate the disposition: neither, nor both together
// constitutes no-landing proof post-boundary (that belief was the defect this contract now forbids).
export function postBoundaryExpiryDisposition(input: {
  readonly reconcileCompleted: boolean;
  readonly landingObserved: boolean;
  readonly t0Unchanged: boolean;
  readonly groupAcknowledgementsComplete: boolean;
  readonly durablyInconclusive: boolean;
}): PostBoundaryDisposition {
  if (!input.reconcileCompleted) return { kind: "held", attentionReason: "POST_EXPIRY_RECONCILING" };
  if (input.landingObserved) return { kind: "resolved", resolution: "RECEIVE_LANDED" };
  if (input.durablyInconclusive) return { kind: "resolved", resolution: "INDETERMINATE" };
  return { kind: "held", attentionReason: "POST_EXPIRY_RECONCILING" };
}

// The lease may be dropped ONLY after a landing. It is NEVER dropped while held or INDETERMINATE
// (held indefinitely — the receive-expiry rule has no release post-boundary), and never before any disposition.
export function leaseDropAllowed(disposition: PostBoundaryDisposition): boolean {
  if (disposition.kind === "resolved") return disposition.resolution === "RECEIVE_LANDED";
  return false;
}
