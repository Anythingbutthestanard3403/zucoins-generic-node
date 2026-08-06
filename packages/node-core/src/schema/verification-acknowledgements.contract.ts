/**
 * Contract for verification-acknowledgements.sql — the acknowledgement tables and the
 * deferred mutation correlation behind the live verification-complete mount.
 */

export const VERIFICATION_ACKNOWLEDGEMENTS_SCHEMA_FILE =
  "verification-acknowledgements.sql";

export const VERIFICATION_ACKNOWLEDGEMENTS_TABLES = [
  "verification_acknowledgements",
  "verification_ack_wallet_evidence",
] as const;

interface VerificationAckInvariant {
  id: string;
  sqlAnchor: string;
  rule: string;
}

export const VERIFICATION_ACK_INVARIANTS: readonly VerificationAckInvariant[] = [
  {
    id: "one-ack-per-operation",
    sqlAnchor: "operation_id uuid NOT NULL UNIQUE REFERENCES operations(id)",
    rule: "At most one verification_acknowledgements row per operation.",
  },
  {
    id: "verdict-not-pending",
    sqlAnchor: "verdict verification_verdict NOT NULL CHECK (verdict <> 'PENDING')",
    rule: "An acknowledgement is terminal — PENDING is not a lawful ACK verdict.",
  },
  {
    id: "ack-wallet-evidence-roles",
    sqlAnchor: "('SOURCE','RECEIVER','DESTINATION')",
    rule: "Ack wallet evidence roles are exactly the three lease-holding roles.",
  },
  {
    id: "ack-immutable",
    sqlAnchor: "reporting_acks_immutable",
    rule: "verification_acknowledgements rows are insert-only evidence.",
  },
] as const;

export const VERIFICATION_ACKNOWLEDGEMENTS_SCHEMA_SOURCE =
  "data-model: operation verification acknowledgements; verification-proofs.sql (ack surface)";
