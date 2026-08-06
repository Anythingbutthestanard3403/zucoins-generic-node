// The forbidden shortcuts around post-boundary expiry, frozen as data + detection
// verifiers. Each of these reopens the late-landing loss the boundary rule closes. No DB code.
//
// post_boundary_release_on_reconcile subsumes the seemingly-safe release paths: a
// sufficiently-proven release (reconcile-first + T0 unchanged + complete acks) is NOT safe
// post-boundary. There is no release disposition post-boundary at any proof level, because a
// head-unchanged read cannot prove a signed, durable tx will never land. The exact "fully
// proven" combination that looks safe is the shortcut itself.

export const FORBIDDEN_SHORTCUTS = {
  post_boundary_release_on_reconcile:
    "Releasing a post-boundary receive at all, even on a reconcile-first, T0-unchanged, fully-acked read — no post-boundary release is permitted; a head-unchanged snapshot is not proof a signed tx will never land.",
  evidence_disposal_on_expiry:
    "Discarding persisted evidence when a receive expires (post-boundary must retain all evidence).",
  lease_drop_before_disposition:
    "Dropping the lease before a disposition (RECEIVE_LANDED / INDETERMINATE) is reached.",
} as const;
export type ForbiddenShortcut = keyof typeof FORBIDDEN_SHORTCUTS;

// Detect the post-boundary release shortcut: the exact "fully proven" combination (reconcile-first,
// T0 unchanged, complete acks) that is forbidden from ever producing a release, regardless of how
// complete the proof looks. Returns null only when the read is not even that combination (i.e.
// nothing resembling a release is being attempted).
export function releaseShortcutViolation(input: {
  readonly reconcileCompleted: boolean;
  readonly t0Unchanged: boolean;
  readonly groupAcknowledgementsComplete: boolean;
}): ForbiddenShortcut | null {
  if (input.reconcileCompleted && input.t0Unchanged && input.groupAcknowledgementsComplete) {
    return "post_boundary_release_on_reconcile";
  }
  return null;
}

// Post-boundary, evidence is NEVER disposed on expiry — disposing it is a forbidden shortcut.
export const EVIDENCE_DISPOSAL_ON_EXPIRY_ALLOWED = false;

export function evidenceDisposalViolation(disposeAttempted: boolean): ForbiddenShortcut | null {
  return disposeAttempted ? "evidence_disposal_on_expiry" : null;
}

// The lease is never dropped before a disposition is reached — a premature drop is a forbidden shortcut.
export function leaseDropViolation(
  dropAttempted: boolean,
  dispositionReached: boolean,
): ForbiddenShortcut | null {
  return dropAttempted && !dispositionReached ? "lease_drop_before_disposition" : null;
}
