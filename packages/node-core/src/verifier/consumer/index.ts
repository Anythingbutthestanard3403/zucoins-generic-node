// consumer-facing verifier kit for third-party integrators.
//
// Import via `@zucoins/node-core/verifier/consumer`. Provides:
// - Typed proof-bundle structures for the three public operations (receive, move, send)
// - parseProofBundle: structural validation of untrusted wire bundles
// - verifyOperationProof / verifyReceiveProof / verifyMoveProof / verifySendProof:
// full pipeline verification (artifact signature → envelope → transaction → economic delta)
// - authenticateArtifact / authenticateNodeEvent / authenticateImplementerEvent: standalone node-key signature checks
// - deriveBaseline: derive a wallet baseline projection from a raw T0 gateway observation
// - assertNotGoldenKey: A.9 item 16 live-chain golden-key refusal
// pinning workflow: import `@zucoins/node-core/verifier/consumer/pinning`
export {
  OPERATION_PROOF_KINDS,
  OPERATION_PROOF_STAGES,
  OPERATION_PROOF_VERDICTS,
  PROOF_BUNDLE_REJECTION_REASONS,
  type ArtifactEnvelope,
  type MoveProofBundle,
  type NodeArtifactResult,
  type NodeVerificationKey,
  type OperationProofKind,
  type OperationProofStage,
  type OperationProofVerdict,
  type OperationProofVerdictKind,
  type ProofBundle,
  type ProofBundleParseResult,
  type ProofBundleRejectionReason,
  type ReceiveProofBundle,
  type ResponseBytesWire,
  type SendProofBundle,
  type WireProofBundle,
} from "./types.js";

export { parseProofBundle } from "./parse.js";

export {
  A8_GOLDEN_NODE_ID,
  A8_GOLDEN_PUBLIC_KEYS,
  assertNotGoldenKey,
  authenticateArtifact,
  authenticateImplementerEvent,
  authenticateNodeEvent,
  deriveBaseline,
  isA8GoldenKey,
  verifyMoveProof,
  verifyOperationProof,
  verifyReceiveProof,
  verifySendProof,
} from "./verify.js";
