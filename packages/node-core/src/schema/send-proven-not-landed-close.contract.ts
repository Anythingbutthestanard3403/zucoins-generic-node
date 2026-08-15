// Distinct lease-release proof kind for CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED (ZTR-1318).
// Extends lease-foundation + operator-accepted-risk-release so a send proven NOT
// landed never mints EXTERNAL_SEND_LANDED into lease_release_proofs.proof_kind.

export const SEND_PROVEN_NOT_LANDED_CLOSE_SCHEMA_FILE =
  "send-proven-not-landed-close.sql" as const;

export const SEND_PROVEN_NOT_LANDED_CLOSE_EXTENDS = [
  "lease-foundation.sql",
  "operator-accepted-risk-release.sql",
] as const;

export const SEND_PROVEN_NOT_LANDED_CLOSE_PROOF_KIND =
  "SEND_PROVEN_NOT_LANDED_CLOSE" as const;

export const SEND_PROVEN_NOT_LANDED_CLOSE_INVARIANTS = [
  {
    id: "DISTINCT_LEASE_PROOF_KIND",
    sqlAnchor: "SEND_PROVEN_NOT_LANDED_CLOSE",
    rule:
      "lease_release_proofs.proof_kind admits SEND_PROVEN_NOT_LANDED_CLOSE so CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED membership close evidence is not EXTERNAL_SEND_LANDED.",
  },
  {
    id: "RETAINS_PRIOR_KINDS",
    sqlAnchor: "RECEIVE_OPERATOR_ACCEPTED_RISK",
    rule:
      "The CHECK rewrite retains RECEIVE_OPERATOR_ACCEPTED_RISK and the prior landing/expiry/quarantine kinds; it only adds the send non-landing close kind.",
  },
] as const;

export type SendProvenNotLandedCloseInvariant =
  (typeof SEND_PROVEN_NOT_LANDED_CLOSE_INVARIANTS)[number];

export const SCHEMA_SEND_PROVEN_NOT_LANDED_CLOSE_OBLIGATIONS = [
  "apply after lease-foundation.sql and operator-accepted-risk-release.sql",
  "[pg] CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED mints SEND_PROVEN_NOT_LANDED_CLOSE, never EXTERNAL_SEND_LANDED",
  "[pg] genuine NODE_VERIFIED send landing still mints EXTERNAL_SEND_LANDED",
] as const;

export const SEND_PROVEN_NOT_LANDED_CLOSE_SOURCE =
  "ZTR-1318 send proven-not-landed close proof kind; operations recovery" as const;
