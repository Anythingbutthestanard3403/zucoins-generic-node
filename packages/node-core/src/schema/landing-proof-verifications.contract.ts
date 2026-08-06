/**
 * Contract for landing-proof-verifications.sql — operation_landing_proofs and
 * operation_verifications.
 */

export const LANDING_PROOF_VERIFICATIONS_SCHEMA_FILE = "landing-proof-verifications.sql";

export const LANDING_PROOF_VERIFICATIONS_TABLES = [
  "operation_landing_proofs",
  "operation_verifications",
] as const;

export const LANDING_PROOF_VERIFICATIONS_ENUMS = [
  "lineage_proof_verdict",
  "verification_verdict",
] as const;

interface LandingProofVerificationInvariant {
  id: string;
  sqlAnchor: string;
  rule: string;
}

export const LANDING_PROOF_VERIFICATION_INVARIANTS: readonly LandingProofVerificationInvariant[] = [
  {
    id: "attempt-no-pinned",
    sqlAnchor: "expected_transaction_attempt_no integer NOT NULL CHECK",
    rule: "operation_landing_proofs pins the verified attempt to attempt_no = 1 (the one-in-flight-per-wallet rule: one in-flight transaction per wallet).",
  },
  {
    id: "landed-verdict-requires-timestamp",
    sqlAnchor: "CHECK ((verdict IN ('LANDED_EXACT','LANDED_COMPLETE_PATH')) = (verified_at IS NOT NULL))",
    rule: "operation_landing_proofs.verified_at is set iff the verdict is a landed verdict.",
  },
  {
    id: "landing-proof-fk-triple",
    sqlAnchor: "REFERENCES operation_landing_proofs(id, operation_id, verifier_observer_id)",
    rule: "operation_verifications.landing_proof_id, when set, must resolve to a landing proof for the same operation and verifier (no cross-operation proof reuse).",
  },
  {
    id: "verified-verdict-requires-landing-proof",
    sqlAnchor: "CHECK (verdict <> 'VERIFIED' OR landing_proof_id IS NOT NULL)",
    rule: "operation_verifications cannot record a VERIFIED verdict without a backing landing proof.",
  },
] as const;

export const LANDING_PROOF_VERIFICATIONS_SCHEMA_SOURCE =
  "data-model: landing proofs and operation verifications; verification-proofs.sql (operation_verifications, verbatim)";
