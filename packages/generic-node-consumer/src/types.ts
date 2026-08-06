/**
 * Product-neutral consumer integration types (part of the installable SDK).
 *
 * Composition vocabulary is only the three public operations. No product-layer
 * states (no PAID / fulfilment / webhook vocabulary). `node_claim` and
 * `operation_verified` are separate fields.
 */

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";
import type {
  OperationProofKind,
  OperationProofVerdict,
  OperationProofVerdictKind,
} from "@zucoins/node-core/verifier/consumer";
import type { CachedIdentityPin } from "@zucoins/node-core/verifier/consumer/pinning";

/** The three public money operations — the only composition units. */
export const PUBLIC_OPERATION_KINDS = ["receive", "move", "send"] as const;
export type PublicOperationKind = (typeof PUBLIC_OPERATION_KINDS)[number];

/**
 * Non-normative composition labels. These name the *example*
 * flow; they are never node states and never become settlement match keys.
 */
export const COMPOSITION_LABELS = [
  "deposit",
  "internal_allocation",
  "external_distribution",
] as const;
export type CompositionLabel = (typeof COMPOSITION_LABELS)[number];

export const COMPOSITION_TO_KIND: Readonly<Record<CompositionLabel, PublicOperationKind>> = {
  deposit: "receive",
  internal_allocation: "move",
  external_distribution: "send",
};

/** Closed consumer-side lifecycle. Never copies a node claim into verified. */
export const CONSUMER_OPERATION_STATUSES = [
  "OPEN",
  "AWAITING_TRIGGER",
  "VERIFYING",
  "VERIFIED",
  "REJECTED",
  "INDETERMINATE",
  "ACKNOWLEDGED",
] as const;
export type ConsumerOperationStatus = (typeof CONSUMER_OPERATION_STATUSES)[number];

/** How the consumer learned an operation may need attention (never authority). */
export const TRIGGER_SOURCES = [
  "events_poll",
  "events_stream",
  "subscribe_handle",
  "manual",
] as const;
export type TriggerSource = (typeof TRIGGER_SOURCES)[number];

/**
 * Browser-facing subscribe projection. Emits only lifecycle fields —
 * no raw evidence. Server-facing consumers must not treat this as proof.
 */
export interface SubscribeLifecycleProjection {
  readonly operation_id: string;
  readonly operation_type: OperationKind;
  readonly state: string;
  readonly row_version: number;
  readonly attention_required: boolean;
  readonly updated_at: string;
}

/**
 * Signed reporting-credential event envelope fields the consumer authenticates.
 * Sequence is used only to wake; never as settlement authority.
 */
export interface NodeEventWake {
  readonly event_id: string;
  readonly implementer_seq: string;
  readonly operation_id: string;
  readonly event_type: string;
  /** Node's claimed generic state — advisory only. */
  readonly node_claim_state: string;
  readonly artifact: {
    readonly key_id: string;
    readonly preimage_text: string;
    readonly preimage_sha256: string;
    readonly signature: string;
  };
}

/** Node claim retained separately from the consumer's own verdict. */
export interface NodeClaimRecord {
  readonly state: string;
  readonly eventType: string;
  readonly authenticated: boolean;
  readonly source: TriggerSource;
  readonly implementerSeq: string | null;
  readonly observedAtUnixMs: number;
}

/** One verification-material `attempts[]` entry — attempt-specific T0/evidence and settled transaction text. */
export interface VerificationMaterialAttempt {
  readonly attempt_no: number;
  readonly classification: string;
  readonly transaction: {
    readonly inner_preimage_text: string;
    readonly inner_sha256: string;
    readonly step_1_signature: string;
    readonly step_2_preimage_text: string;
    readonly step_2_signature: string;
    readonly settled_transaction_text: string;
  };
}

/** Closed `evidence_role` vocabulary — wider than `wallet_evidence[].role`,
 * which is only the 3 node-controlled-wallet roles. */
export type EvidenceRole =
  | "RECEIVER"
  | "SOURCE"
  | "DESTINATION"
  | "EXTERNAL_SENDER_PREFLIGHT"
  | "EXTERNAL_DESTINATION_PARTIAL";

/** Closed `indeterminate_reason` vocabulary (mirrors the frozen `WIRE_INDETERMINATE_REASONS` set). */
export type WireIndeterminateReason =
  | "MISSING_BODY"
  | "LINK_GAP"
  | "ANOMALY"
  | "FRESH_HEAD_MISMATCH"
  | "BUDGET_EXCEEDED";

/** One `ancestor_proofs[]` entry. `path_manifest`/`transaction_bodies` nest per-entry — never top-level. */
export interface VerificationMaterialAncestorProof {
  readonly evidence_role: EvidenceRole;
  readonly wallet_public_key: string;
  readonly classification: "EXPECTED_AT_HEAD" | "EXPECTED_ANCESTOR" | "INDETERMINATE";
  readonly expected_step_2_signature: string;
  readonly fresh_head_step_2_signature: string;
  readonly fresh_head_transaction_sha256: string;
  readonly hop_count: number;
  readonly path_manifest_sha256: string;
  readonly path_manifest: readonly {
    readonly position: number;
    readonly step_2_signature: string;
    readonly queried_wallet_previous_signature: string;
    readonly transaction_sha256: string;
    readonly body_index: number;
  }[];
  readonly transaction_bodies: readonly {
    readonly body_index: number;
    readonly transaction_sha256: string;
    readonly settled_transaction_text: string;
  }[];
  readonly indeterminate_reason: WireIndeterminateReason | null;
}

/** Wire shape of GET /v1/operations/:id/verification-material. */
export interface VerificationMaterialWire {
  readonly operation_id: string;
  readonly operation_type: OperationKind;
  readonly state: string;
  /** Present once the served operation reaches its kind's landed-terminal status. */
  readonly landed_attempt_no?: number;
  readonly expected_artifact: {
    readonly key_id: string;
    readonly preimage_text: string;
    readonly preimage_sha256: string;
    readonly signature: string;
  };
  readonly observation_evidence: readonly {
    readonly evidence_role: EvidenceRole;
    /** Null for an externally owned public key — never a node-controlled wallet. */
    readonly wallet_id: string | null;
    readonly wallet_public_key: string;
    readonly t0: {
      readonly observation_id: string;
      readonly projection: { readonly s: string; readonly p: string; readonly b_zkz: string };
    };
    readonly terminal: {
      readonly observation_id: string;
      readonly projection: { readonly s: string; readonly p: string; readonly b_zkz: string };
    } | null;
    /** Node-relayed raw body — never treated as the consumer's own observation. */
    readonly node_observation_raw_body_base64: string | null;
  }[];
  readonly attempts?: readonly VerificationMaterialAttempt[];
  readonly ancestor_proofs?: readonly VerificationMaterialAncestorProof[];
  /** Verification-material access expiry (`operations.verification_material_available_until`). */
  readonly available_until?: string;
}

/**
 * Direct gateway observation the consumer configured itself (verification step 3).
 * Endpoint fingerprint is pinned by the consumer — never taken from the node.
 */
export interface DirectGatewayObservation {
  readonly walletPublicKey: string;
  readonly role: "RECEIVER" | "SOURCE" | "DESTINATION";
  /** Exact captured response bytes from the consumer's own SplitChain read. */
  readonly rawResponseBytes: Uint8Array;
  /** Consumer-pinned gateway endpoint fingerprint. */
  readonly endpointFingerprint: string;
}

/**
 * `wallet_evidence[].landing_proof`. Required by the server's `.strict()`
 * `WalletEvidence` schema on every entry — the consumer supplies `fresh_head_step_2_signature`
 * and `path_manifest_sha256` only after independently reading a fresh gateway head and
 * verifying every manifest hop; see `deriveLandingProof` in `landing-proof.ts`.
 */
export interface LandingProofWire {
  readonly classification: "EXPECTED_AT_HEAD" | "EXPECTED_ANCESTOR";
  readonly fresh_head_step_2_signature: string;
  readonly fresh_head_transaction_sha256: string;
  readonly path_manifest_sha256: string;
}

/** POST /v1/operations/:id/verification-complete request body. */
export interface VerificationCompleteRequest {
  readonly expected_row_version: number;
  readonly consumed_cursor: string;
  readonly verdict: OperationProofVerdictKind;
  readonly wallet_evidence: readonly {
    readonly wallet_id: string;
    readonly role: "RECEIVER" | "SOURCE" | "DESTINATION";
    readonly t0: {
      readonly observation_id: string;
      readonly projection: { readonly s: string; readonly p: string; readonly b_zkz: string };
    };
    readonly terminal: {
      readonly observation_id: string;
      readonly projection: { readonly s: string; readonly p: string; readonly b_zkz: string };
    };
    readonly landing_proof: LandingProofWire;
  }[];
}

/** POST /v1/operations/:id/verification-complete success body. */
export interface VerificationCompleteResponse {
  readonly operation_id: string;
  readonly acknowledgement_id: string;
  readonly verdict: OperationProofVerdictKind;
  readonly lease_release_status: "RELEASED" | "PINNED_GROUP_PENDING" | "PINNED_FOR_ATTENTION";
  readonly acknowledged_at: string;
}

/**
 * One consumer-tracked operation. Holds both `node_claim` and `operation_verified`
 * so a landed node claim can coexist with INDETERMINATE.
 */
export interface ConsumerOperation {
  readonly operationId: string;
  readonly kind: PublicOperationKind;
  /** Non-normative composition label for the example flow only. */
  readonly compositionLabel: CompositionLabel;
  readonly status: ConsumerOperationStatus;
  readonly rowVersion: number;
  /** Advisory only — never a settlement match key. */
  readonly clientReference: string | null;
  readonly nodeClaim: NodeClaimRecord | null;
  /** Consumer's own independent verdict — never silently copied from nodeClaim. */
  readonly operationVerified: OperationProofVerdict | null;
  readonly lastTriggerSource: TriggerSource | null;
  readonly acknowledgementId: string | null;
  readonly leaseReleaseStatus: VerificationCompleteResponse["lease_release_status"] | null;
}

/** Durable consumer cursor — owned by the consumer, never a node-supplied cache. */
export interface ConsumerCursorState {
  /** Exclusive resume position for GET /v1/events. */
  readonly watermarkSeq: string;
  readonly lastPersistedAtUnixMs: number;
}

/** Snapshot of consumer-owned durable state (restart resume surface). */
export interface ConsumerSnapshot {
  readonly watermarkSeq: string;
  readonly operations: readonly ConsumerOperation[];
  readonly identityPin: CachedIdentityPin;
  /** Consumer-pinned SplitChain gateway fingerprint. */
  readonly pinnedGatewayFingerprint: string;
  readonly capturedAtUnixMs: number;
}

export interface TrustAssumptions {
  readonly node: "claim_authentication_only";
  readonly configuredGateway: "independent_read_authority";
  readonly independentGatewayRead: "required_for_verdict";
  readonly signedInstructionOrigin: "node_or_merchant_controlled";
  readonly secondApplicationOrLedger: "none_in_this_example";
  readonly statement: string;
}

export const DEFAULT_TRUST_ASSUMPTIONS: TrustAssumptions = {
  node: "claim_authentication_only",
  configuredGateway: "independent_read_authority",
  independentGatewayRead: "required_for_verdict",
  signedInstructionOrigin: "node_or_merchant_controlled",
  secondApplicationOrLedger: "none_in_this_example",
  statement:
    "This example authenticates node events only as a wake signal, pins the node " +
    "identity key through a channel independent of hosted ZuPayments, reads wallet " +
    "heads from a consumer-configured SplitChain endpoint, and records its own " +
    "operation_verified verdict separately from node_claim. A node claim is never " +
    "sufficient for a business transition.",
};

export type { OperationProofKind, OperationProofVerdict, OperationProofVerdictKind };
