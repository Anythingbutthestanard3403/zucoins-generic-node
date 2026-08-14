// Operator-accepted-risk receive release (ZTR-1280).
// Extends receive-expiry-release + lease-foundation with a distinct non-proof
// release kind so the catalogue has a lawful pressure valve that can never mint
// EXPIRED_T0_UNCHANGED.

export const OPERATOR_ACCEPTED_RISK_RELEASE_SCHEMA_FILE =
  "operator-accepted-risk-release.sql" as const;

export const OPERATOR_ACCEPTED_RISK_RELEASE_EXTENDS = [
  "receive-expiry-release.sql",
  "lease-foundation.sql",
] as const;

export const OPERATOR_ACCEPTED_RISK_RELEASE_KIND = "OPERATOR_ACCEPTED_RISK" as const;
export const OPERATOR_ACCEPTED_RISK_RELEASE_STATUS =
  "RELEASED_OPERATOR_ACCEPTED_RISK" as const;
export const OPERATOR_ACCEPTED_RISK_LEASE_PROOF_KIND =
  "RECEIVE_OPERATOR_ACCEPTED_RISK" as const;

export const OPERATOR_ACCEPTED_RISK_RELEASE_INVARIANTS = [
  {
    id: "DISTINCT_RELEASE_KIND",
    sqlAnchor: "OPERATOR_ACCEPTED_RISK",
    rule:
      "receive_release_proofs admits release_kind OPERATOR_ACCEPTED_RISK with null verification ack; observations optional. Distinct from EXPIRED_T0_UNCHANGED.",
  },
  {
    id: "DISTINCT_RELEASE_STATUS",
    sqlAnchor: "RELEASED_OPERATOR_ACCEPTED_RISK",
    rule:
      "operations.receive_release_status admits RELEASED_OPERATOR_ACCEPTED_RISK so the override is never misread as RELEASED_T0_UNCHANGED.",
  },
  {
    id: "DISTINCT_LEASE_PROOF_KIND",
    sqlAnchor: "RECEIVE_OPERATOR_ACCEPTED_RISK",
    rule:
      "lease_release_proofs.proof_kind admits RECEIVE_OPERATOR_ACCEPTED_RISK so membership close evidence is not RECEIVE_EXPIRED_T0.",
  },
] as const;

export type OperatorAcceptedRiskReleaseInvariant =
  (typeof OPERATOR_ACCEPTED_RISK_RELEASE_INVARIANTS)[number];

export const SCHEMA_OPERATOR_ACCEPTED_RISK_RELEASE_OBLIGATIONS = [
  "apply after receive-expiry-release.sql and lease-foundation.sql",
  "[pg] OPERATOR_ACCEPTED_RISK never requires T0/fresh observation equality — the manifest records failed predicates instead",
  "[pg] EXPIRED_T0_UNCHANGED remains unreachable from the operator-risk recovery path",
] as const;

export const OPERATOR_ACCEPTED_RISK_RELEASE_SOURCE =
  "ZTR-1280 audited operator override release; operations recovery" as const;
