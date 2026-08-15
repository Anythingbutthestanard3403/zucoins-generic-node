// Distinct lease-release proof kind for CLOSE_LANDED_UNACKNOWLEDGED (ZTR-1316).
// Extends lease-foundation + send-proven-not-landed-close so an overdue
// INDEPENDENT land never mints EXTERNAL_SEND_LANDED into lease_release_proofs.

export const SEND_LANDED_UNACKNOWLEDGED_CLOSE_SCHEMA_FILE =
  "send-landed-unacknowledged-close.sql" as const;

export const SEND_LANDED_UNACKNOWLEDGED_CLOSE_EXTENDS = [
  "lease-foundation.sql",
  "send-proven-not-landed-close.sql",
] as const;

export const SEND_LANDED_UNACKNOWLEDGED_CLOSE_PROOF_KIND =
  "SEND_LANDED_UNACKNOWLEDGED_CLOSE" as const;

export const SEND_LANDED_UNACKNOWLEDGED_CLOSE_INVARIANTS = [
  {
    id: "DISTINCT_LEASE_PROOF_KIND",
    sqlAnchor: "SEND_LANDED_UNACKNOWLEDGED_CLOSE",
    rule:
      "lease_release_proofs.proof_kind admits SEND_LANDED_UNACKNOWLEDGED_CLOSE so CLOSE_LANDED_UNACKNOWLEDGED membership close evidence is not EXTERNAL_SEND_LANDED.",
  },
  {
    id: "RETAINS_PRIOR_KINDS",
    sqlAnchor: "SEND_PROVEN_NOT_LANDED_CLOSE",
    rule:
      "The CHECK rewrite retains SEND_PROVEN_NOT_LANDED_CLOSE and the prior landing/expiry/quarantine kinds; it only adds the landed-unacknowledged close kind.",
  },
] as const;

export type SendLandedUnacknowledgedCloseInvariant =
  (typeof SEND_LANDED_UNACKNOWLEDGED_CLOSE_INVARIANTS)[number];

export const SCHEMA_SEND_LANDED_UNACKNOWLEDGED_CLOSE_OBLIGATIONS = [
  "apply after lease-foundation.sql and send-proven-not-landed-close.sql",
  "[pg] CLOSE_LANDED_UNACKNOWLEDGED mints SEND_LANDED_UNACKNOWLEDGED_CLOSE, never EXTERNAL_SEND_LANDED",
  "[pg] genuine NODE_VERIFIED send landing still mints EXTERNAL_SEND_LANDED",
] as const;

export const SEND_LANDED_UNACKNOWLEDGED_CLOSE_SOURCE =
  "ZTR-1316 landed INDEPENDENT send with overdue verification-complete; operations recovery" as const;
