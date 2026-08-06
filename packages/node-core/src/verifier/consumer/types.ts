// consumer verifier kit — public proof structures.
//
// This is the consumer-facing surface for platform-independent verification: a third party imports these types and
// the verify functions (verify.ts) to check an operation proof against the node's published
// signing key and its own wallet-head observations. It composes the internal pipeline stages
// (gateway-envelope, transaction-verify, economic-predicates, suite verify) and never
// re-implements their byte logic.
//
// Non-authority principle: a proof bundle is supplied evidence. Verification yields a
// verdict; it never promotes a supplied field to authoritative chain state.
import type { WalletStateProjection } from "../../protocol/wallet-role.js";
import type { SignedSuiteTupleEnvelope } from "../../protocol/suite/verify.js";

// The node signing key a consumer publishes for artifact and node-event authentication: the
// resolved key id plus the Ed25519 public key (canonical padded base64url). The key class is
// fixed by the artifact purpose (node_identity / node_event), so the consumer supplies only
// id + key. `liveChain` (default false) enables A.9 vector 16: refusal of A.8 golden/seed keys.
export interface NodeVerificationKey {
  readonly keyId: string;
  readonly publicKey: string;
  /** When true, A.8 fixture keys/node_id are refused (A.9 item 16). Default: false (test mode). */
  readonly liveChain?: boolean;
}

// The signed expected-artifact envelope as carried over the wire (the suite tuple):
// the declared signing key id, the exact preimage text, its digest, and the Ed25519 signature.
export type ArtifactEnvelope = SignedSuiteTupleEnvelope;

export const OPERATION_PROOF_KINDS = ["receive", "move", "send"] as const;

export type OperationProofKind = (typeof OPERATION_PROOF_KINDS)[number];

// Wire encoding of one raw gateway head observation: canonical padded base64url of the exact
// captured response bytes (never a re-encoding). Decoded to bytes at parse time.
export interface ResponseBytesWire {
  readonly base64url: string;
}

// Wire encoding of a proof bundle (untrusted input to parseProofBundle). `baseline` is
// optional and defaults to genesis at verify time.
export interface WireProofBundle {
  readonly kind: OperationProofKind;
  readonly artifact: ArtifactEnvelope;
  readonly response?: ResponseBytesWire;
  readonly sourceResponse?: ResponseBytesWire;
  readonly destinationResponse?: ResponseBytesWire;
  readonly baseline?: WalletStateProjection;
  readonly sourceBaseline?: WalletStateProjection;
  readonly destinationBaseline?: WalletStateProjection;
  readonly spawnedFromReceive?: { readonly receiveTransactionStepTwoSignature: string };
}

interface ProofBundleBase {
  readonly artifact: ArtifactEnvelope;
}

// RECEIVE: one inbound head observation for the reserved receiver wallet.
export interface ReceiveProofBundle extends ProofBundleBase {
  readonly kind: "receive";
  readonly receiverResponse: Uint8Array;
  readonly receiverBaseline?: WalletStateProjection;
}

// MOVE: one dual-signed transaction observed independently from the source and destination
// wallets; an optional parent-receive link for a spawned auto-move.
export interface MoveProofBundle extends ProofBundleBase {
  readonly kind: "move";
  readonly sourceResponse: Uint8Array;
  readonly destinationResponse: Uint8Array;
  readonly sourceBaseline?: WalletStateProjection;
  readonly destinationBaseline?: WalletStateProjection;
  readonly spawnedFromReceive?: { readonly receiveTransactionStepTwoSignature: string };
}

// SEND: the completed transaction observed from the node-controlled source wallet.
export interface SendProofBundle extends ProofBundleBase {
  readonly kind: "send";
  readonly sourceResponse: Uint8Array;
  readonly sourceBaseline?: WalletStateProjection;
}

export type ProofBundle = ReceiveProofBundle | MoveProofBundle | SendProofBundle;

export const PROOF_BUNDLE_REJECTION_REASONS = [
  "INVALID_ENVELOPE",
  "MALFORMED_BUNDLE",
  "INVALID_RESPONSE_ENCODING",
] as const;

export type ProofBundleRejectionReason = (typeof PROOF_BUNDLE_REJECTION_REASONS)[number];

export type ProofBundleParseResult =
  | { readonly ok: true; readonly bundle: ProofBundle }
  | { readonly ok: false; readonly reason: ProofBundleRejectionReason; readonly detail: string };

// The pipeline stage a verdict originates from.
export const OPERATION_PROOF_STAGES = [
  "artifact",
  "envelope",
  "transaction",
  "delta",
] as const;

export type OperationProofStage = (typeof OPERATION_PROOF_STAGES)[number];

export const OPERATION_PROOF_VERDICTS = ["VERIFIED", "REJECTED", "INDETERMINATE"] as const;

export type OperationProofVerdictKind = (typeof OPERATION_PROOF_VERDICTS)[number];

// Verdict taxonomy: every predicate true → VERIFIED; a cryptographically determinate
// mismatch → REJECTED; malformed/unavailable evidence / anomaly / backlink jump that cannot be
// evaluated to a landing or non-landing → INDETERMINATE (landing-path oracle).
export type OperationProofVerdict =
  | {
      readonly verdict: "VERIFIED";
      readonly kind: OperationProofKind;
      readonly projection: WalletStateProjection;
      readonly semanticFingerprint: string;
      readonly completedTransactionSha256: string;
      // "move" only: the destination wallet's own independently-observed head, discarded
      // by earlier verifyMoveProof revisions. A move binds two separate wallet histories
      // (source, destination) to the same shared transaction; a caller building per-wallet
      // landing evidence (`wallet_evidence[]`) needs both sides' own S/P/B and
      // completed-transaction digest, not just the primary (source) head this verdict
      // already carried.
      readonly secondaryProjection?: WalletStateProjection;
      readonly secondaryCompletedTransactionSha256?: string;
    }
  | {
      readonly verdict: "REJECTED";
      readonly kind: OperationProofKind;
      readonly stage: OperationProofStage;
      readonly reason: string;
    }
  | {
      readonly verdict: "INDETERMINATE";
      readonly kind: OperationProofKind;
      readonly stage: OperationProofStage;
      readonly reason: string;
    };

// Result of authenticating a node-signed artifact or node event against the node key.
export type NodeArtifactResult =
  | { readonly authenticated: true }
  | { readonly authenticated: false; readonly reason: string };
