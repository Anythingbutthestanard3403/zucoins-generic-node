// frozen proof-body intake envelope types.
//
// These mirror the `lineage_path_bodies` column set and the INDETERMINATE reason taxonomy,
// under the exact-byte rules, read-stream identity, non-authority, and retention
// disciplines, and the changed-response observation ledger.
//
// Non-authority principle (landing-path oracle): a supplied candidate
// body is untrusted evidence until it is verified and fresh-head-anchored. Intake never
// promotes a supplied field to authoritative chain state; a rejected parse produces no
// projection fields at all.

// The wallet role a body is supplied for. Mirrors
// lineage_path_bodies.wallet_role CHECK (wallet_role IN ('sender','receiver')).
export const PROOF_BODY_WALLET_ROLES = ["sender", "receiver"] as const;

export type ProofBodyWalletRole = (typeof PROOF_BODY_WALLET_ROLES)[number];

// The single provenance value a caller-supplied proof body carries. The other
// lineage_path_bodies.source_kind values (EXPECTED_OPERATION, CANONICAL_LEDGER,
// FRESH_GATEWAY_HEAD) are node-derived and never arrive through this intake surface.
export const PROOF_BODY_SOURCE_KIND = "PROOF_CHANNEL";

export type ProofBodySourceKind = typeof PROOF_BODY_SOURCE_KIND;

// The validated proof body — the frozen lineage_path_bodies column set this envelope
// populates, minus the node-assigned path_proof_id primary-key
// component. Field sequence is the frozen insertion sequence; the byte-exact signing rule means these
// bytes are never reformatted, resequenced, or re-serialized after capture.
export interface ValidatedProofBody {
  readonly path_index: number;
  readonly source_kind: ProofBodySourceKind;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly completed_transaction_octets: number;
  readonly wallet_role: ProofBodyWalletRole;
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
  readonly verification_manifest_text: string;
  readonly verification_manifest_sha256: string;
}

// The authenticated request identity, re-derived from the verified caller credential —
// never from a client-asserted body field alone (the implementer
// ID is never accepted from a request body; the universal signing lease supplies the
// tenant/operation/role binding this envelope mirrors at intake).
export interface AuthenticatedRequestIdentity {
  readonly tenant_id: string;
  readonly operation_id: string;
  readonly wallet_role: ProofBodyWalletRole;
}

// The expected identity the authenticated context must bind to, re-derived by the node
// from its own durable records for the target operation (binding discipline: each
// observation's owning key and required domain are verified, not trusted).
export interface ExpectedIdentityBinding {
  readonly tenant_id: string;
  readonly operation_id: string;
  readonly wallet_role: ProofBodyWalletRole;
}

// Transport metadata captured alongside the raw bytes, keeping raw response evidence
// separate from HTTP status, endpoint
// fingerprint, request id, and timestamps. The claimed signature is supplied evidence
// only; it is never verified or trusted at this layer.
export interface ProofBodyTransportMetadata {
  readonly claimed_signature: string;
  readonly content_length: number;
  readonly media_type: string;
  readonly request_id: string;
  readonly provenance: string;
}

// One authenticated proof-body intake request: the verified identity, the expected
// binding, the transport metadata, and the exact raw body bytes exactly as received.
export interface ProofBodyIntakeRequest {
  readonly authenticated: AuthenticatedRequestIdentity;
  readonly expected: ExpectedIdentityBinding;
  readonly transport: ProofBodyTransportMetadata;
  readonly rawBytes: Uint8Array;
}

// Coarse rejection taxonomy aligned with the served reason set rather than inventing a
// parallel one: BUDGET_EXCEEDED is reused verbatim for an oversize body; MALFORMED_ENVELOPE
// and IDENTITY_MISMATCH are the two intake-surface additions the verifier-level set
// (MISSING_BODY / LINK_GAP / ANOMALY / FRESH_HEAD_MISMATCH / BUDGET_EXCEEDED) does not
// cover, because a single supplied body has no path/link/fresh-head to fail on.
export const PROOF_BODY_REJECTION_REASONS = [
  "MALFORMED_ENVELOPE",
  "IDENTITY_MISMATCH",
  "BUDGET_EXCEEDED",
] as const;

export type ProofBodyRejectionReason = (typeof PROOF_BODY_REJECTION_REASONS)[number];

// Fine-grained, independently testable rejection codes (review indicator: the
// duplicate-key, ambiguous-encoding, and wrong-role/operation/tenant fixtures each fail
// closed with a distinct reason). Each maps onto exactly one coarse reason above.
export const PROOF_BODY_REJECTION_CODES = [
  "AMBIGUOUS_ENCODING",
  "DUPLICATE_JSON_KEY",
  "INVALID_JSON",
  "SCHEMA_VIOLATION",
  "TENANT_MISMATCH",
  "OPERATION_MISMATCH",
  "ROLE_MISMATCH",
  "OVERSIZE",
] as const;

export type ProofBodyRejectionCode = (typeof PROOF_BODY_REJECTION_CODES)[number];

// The accepted branch: parsed fields plus the byte-exact capture evidence. The raw bytes
// and digest are the authoritative record of what was submitted (capture-before-parse);
// the parsed body is derived evidence only and never overrides a node-canonical projection.
export interface ProofBodyAccepted {
  readonly accepted: true;
  readonly body: ValidatedProofBody;
  readonly rawBytes: Uint8Array;
  readonly rawSha256: string;
}

// The rejected branch: coarse reason + distinct code + diagnostic detail, with the raw
// bytes and digest still captured (a decode or parse failure never discards the original
// bytes — they remain authoritative evidence). Carries no parsed/projection fields, so a
// rejected body can never leak a derived field to a downstream verifier.
export interface ProofBodyRejected {
  readonly accepted: false;
  readonly reason: ProofBodyRejectionReason;
  readonly code: ProofBodyRejectionCode;
  readonly detail: string;
  readonly rawBytes: Uint8Array;
  readonly rawSha256: string;
}

// The intake result discriminated union. intakeProofBody never throws; it always returns
// one of these two branches.
export type ProofBodyIntakeResult = ProofBodyAccepted | ProofBodyRejected;
