export interface Verifier<Input = unknown, Result = unknown> {
  verify(input: Input): Promise<Result>;
}

// the strict `get_transaction__v1` envelope stage of the verification pipeline:
// pure bytes-in/verdict-out, no signature verification or role logic (those are later
// stages).
export {
  ENVELOPE_REJECTION_REASONS,
  GATEWAY_ENVELOPE_CLASSIFICATIONS,
  GATEWAY_RESPONSE_FIELDS,
  GENESIS_ACCOUNT_NOT_FOUND_CODE,
  GET_TRANSACTION_ACTION_NAME,
  SETTLED_TRANSACTION_FIELDS,
  SUPPORTED_TRANSACTION_VERSION,
  parseGatewayEnvelope,
  type EnvelopeRejectionReason,
  type GatewayEnvelopeClassification,
  type GatewayEnvelopeVerdict,
  type GenesisEnvelopeVerdict,
  type HeadEnvelopeVerdict,
  type MalformedEnvelopeVerdict,
  type ParsedSettledTransaction,
  type ParsedTransactionInner,
} from "./gateway-envelope.js";

// the transaction verification stage consuming the
// HEAD verdict above: exact inner shape + dual Ed25519, role-relative state
//, and the A.7 wallet-head semantic fingerprint. The inner-shape
// narrowing is an internal step of verifySettledTransaction, not barrel surface.
export {
  TRANSACTION_VERIFY_OUTCOMES,
  WALLET_HEAD_FINGERPRINT_FIELDS,
  WALLET_HEAD_FINGERPRINT_PURPOSE,
  buildWalletHeadFingerprintPreimage,
  computeWalletHeadFingerprint,
  verifySettledTransaction,
  type MalformedTransactionVerdict,
  type TransactionVerifyOutcome,
  type TransactionVerifyVerdict,
  type UnverifiedSignatureVerdict,
  type VerifiedTransactionVerdict,
  type WalletHeadFingerprintMaterial,
  type WalletRoleInvalidVerdict,
} from "./transaction-verify.js";

// the landing-path oracle any-depth complete-path landing oracle: the only producer of a
// positive LandingPathProof, anchored on a live confirm-read of the authoritative head.
export {
  DEFAULT_MAX_PATH_DEPTH,
  landingProofToPathObservation,
  proveExactHeadLanding,
  proveReceiveLanding,
  proveSendLanding,
  type ExactHeadLandingInput,
  type FreshHeadRead,
  type ReadFreshHead,
  type ReceiveLandingOracleInput,
  type SendLandingOracleInput,
} from "./landing-path-oracle.js";

// MOVE_INTERNAL dual-path verification: both source (debit) and destination
// (credit) paths must independently confirm for the move to land.
export {
  MOVE_PATH_REJECTION_REASONS,
  MOVE_PATH_VERIFY_OUTCOMES,
  verifyMoveDualPath,
  type MoveArtifact,
  type MovePathEvidence,
  type MovePathRejectionReason,
  type MovePathVerifyOutcome,
  type MovePathVerifyVerdict,
  type PathObservation,
  type PathVerificationFailure,
} from "./move-path-verify.js";

// the any-depth ancestry walker: the landing-path oracle proof-CONSTRUCTION half. Resolves each
// hop from retained storage through the backlink index, verifies every body in full,
// and persists the lineage_path_proofs row with its ordered lineage_path_bodies.
export {
  DEFAULT_MAX_PATH_BODY_OCTETS,
  resolvePathBudget,
  InMemoryLineagePathProofStore,
  InMemoryRetainedPathBodySource,
  LINEAGE_PATH_BODY_SOURCE_KINDS,
  LINEAGE_PATH_ROLES,
  walkAncestryPath,
  type AncestryWalkInput,
  type AncestryWalkOutcome,
  type LineagePathBodyRow,
  type LineagePathBodySourceKind,
  type LineagePathProofRow,
  type LineagePathProofStore,
  type LineagePathRole,
  type PathBaseline,
  type RetainedPathBody,
  type RetainedPathBodySource,
  type SuccessorResolution,
  type WalkOperation,
} from "./ancestry-walker.js";

// production RetainedPathBodySource against the observation ledger
// (gateway_observations); the first real adapter for the port above.
export {
  createSqlRetainedPathBodySource,
  fetchRetainedBodyByObservationId,
  fetchRetainedBodyByStepOneSignature,
  type SqlQueryPort,
  type SqlRetainedPathBodySourceDeps,
} from "./retained-path-body-source-sql.js";
