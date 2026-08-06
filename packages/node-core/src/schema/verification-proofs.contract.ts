/**
 * Frozen contract census for operation verification acknowledgements. The SQL is contract
 * text: its forward references into the separately owned landing-proof tables are
 * deliberate.
 */
import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

export const VERIFICATION_PROOFS_SCHEMA_FILE = "verification-proofs.sql" as const;
export const VERIFICATION_PROOFS_SCHEMA_SOURCE =
  "data-model: enumerations and operation verification acknowledgements" as const;

export interface VerificationProofInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const VERIFICATION_PROOF_INVARIANTS: readonly VerificationProofInvariant[] = [
  {
    id: "VERIFIED_REQUIRES_LANDING_PROOF",
    sqlAnchor: "CHECK (verdict <> 'VERIFIED' OR landing_proof_id IS NOT NULL)",
    rule: "A transport acknowledgement can never establish landing; VERIFIED requires a landing proof.",
  },
  {
    id: "ACK_LOGICAL_FINGERPRINT",
    sqlAnchor:
      "logical_fingerprint sha256_hex GENERATED ALWAYS AS\n    (reporting_logical_fingerprint(method, raw_target, request_body_sha256)) STORED",
    rule: "Acknowledgement idempotency binds method, opaque raw target, and exact request-body digest.",
  },
  {
    id: "ACK_NONCE_UNIQUE",
    sqlAnchor: "reporting_nonce_id uuid NOT NULL UNIQUE",
    rule: "A reporting nonce authenticates exactly one acknowledgement.",
  },
  {
    id: "ACK_IDEMPOTENCY_UNIQUE",
    sqlAnchor: "mutation_idempotency_id uuid NOT NULL UNIQUE",
    rule: "A completed reporting mutation correlates to exactly one child acknowledgement.",
  },
  {
    id: "ACK_APPEND_ONLY",
    sqlAnchor: "CREATE TRIGGER reporting_acks_immutable",
    rule: "Acknowledgements are append-only and reject UPDATE or DELETE.",
  },
  {
    id: "ACK_NO_TRUNCATE",
    sqlAnchor: "CREATE TRIGGER reporting_acks_no_truncate",
    rule: "Acknowledgement evidence cannot be truncated.",
  },
  {
    id: "ACK_PRIVILEGE_REVOKE",
    sqlAnchor: "REVOKE UPDATE, DELETE, TRUNCATE ON",
    rule: "The node runtime lacks mutation privileges over acknowledgement evidence.",
  },
  {
    id: "ACK_EVIDENCE_ROLE_CARDINALITY",
    sqlAnchor: "PRIMARY KEY (acknowledgement_id, evidence_role)",
    rule: "Row uniqueness supports the operation-kind validator: RECEIVE needs RECEIVER, SEND needs SOURCE, and MOVE needs distinct SOURCE and DESTINATION rows.",
  },
  {
    id: "ACK_EVIDENCE_WALLET_UNIQUE",
    sqlAnchor: "UNIQUE (acknowledgement_id, wallet_public_key)",
    rule: "One wallet cannot masquerade as two evidence roles in one acknowledgement.",
  },
  {
    id: "RELEASE_PROOF_ACK_FK",
    sqlAnchor: "ADD FOREIGN KEY (verification_acknowledgement_id)",
    rule: "Receive release is structurally bound to a durable verification acknowledgement.",
  },
] as const;

export const VERIFICATION_PROOF_TABLES = [
  "operation_verifications",
  "verification_acknowledgements",
  "verification_ack_wallet_evidence",
] as const;

export const VERIFICATION_PROOF_ENUMS = {
  lineage_proof_verdict: [
    "LANDED_EXACT",
    "LANDED_COMPLETE_PATH",
    "INDETERMINATE",
    "INVARIANT_BREACH",
  ],
  verification_verdict: ["PENDING", "VERIFIED", "REJECTED", "INDETERMINATE"],
  reporting_request_class: ["READ", "MUTATION"],
} as const;

export type VerificationAckEvidenceRole = "SOURCE" | "RECEIVER" | "DESTINATION";

const REQUIRED_ACK_EVIDENCE_ROLES: Readonly<
  Record<OperationKind, readonly VerificationAckEvidenceRole[]>
> = {
  RECEIVE_EXTERNAL: ["RECEIVER"],
  MOVE_INTERNAL: ["SOURCE", "DESTINATION"],
  SEND_EXTERNAL: ["SOURCE"],
};

/**
 * Enforces the operation-kind cardinality that cannot be expressed by the frozen
 * row-local keys alone. Callers must validate the complete evidence set, in a stable
 * sequence, before persisting an acknowledgement and its child rows.
 */
export function assertVerificationAckEvidenceRoles(
  operationKind: OperationKind,
  evidenceRoles: readonly VerificationAckEvidenceRole[],
): void {
  const required = REQUIRED_ACK_EVIDENCE_ROLES[operationKind];
  const actual = [...evidenceRoles].sort();
  const expected = [...required].sort();
  if (
    actual.length !== expected.length ||
    actual.some((role, index) => role !== expected[index])
  ) {
    throw new Error(
      `${operationKind} requires exactly ${required.join("+")} acknowledgement evidence`,
    );
  }
}

export const SCHEMA_VERIFICATION_PROOF_OBLIGATIONS: readonly string[] = [
  "Apply after operations, gateway observations, transaction attempts, reporting stores, receive release proofs, and the separately owned landing-proof tables exist.",
  "Verify proof_manifest_text and all signed or authoritative text by byte comparison against the exact stored text; never reconstruct authoritative bytes from parsed projections (the byte-exact signing rule).",
  "A VERIFIED operation_verifications row must cite an operation_landing_proofs row; a transport acknowledgement is never a landing oracle.",
  "RECEIVE and SEND acknowledgements require one exact evidence role; MOVE_INTERNAL requires independently complete SOURCE and DESTINATION evidence anchored to the same expected body.",
  "Depth coverage: must cover zero-depth and arbitrary-depth round trips while ensuring bounded chunks never become partially authoritative.",
  "Indeterminacy coverage: must prove gap, cycle, duplicate, conflicting body, missing SEND body, inconsistent counts, MOVE disagreement, anomaly, and budget exhaustion remain INDETERMINATE.",
  "Adjudication coverage: must prove UNEXPLAINED_JUMP remains immutable and COMPLETE_PATH_SUCCESSOR is effective only through adjudication.",
  "A conflicting replay must fail closed and cannot release a receive wallet; immutable acknowledgement and wallet-evidence rows remain durable audit evidence.",
] as const;
