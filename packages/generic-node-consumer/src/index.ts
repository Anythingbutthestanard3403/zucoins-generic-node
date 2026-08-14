/**
 * @zucoins/generic-node-consumer — consumer SDK surface for a self-hosted generic
 * SplitChain treasury node.
 *
 * Wraps:
 *   - RECEIVE_EXTERNAL / MOVE_INTERNAL / SEND_EXTERNAL initiation (implementer bearer);
 *   - arm (`POST /v1/operations/:id/armed`, signed reporting);
 *   - the browser-facing operation subscribe stream (`GET /v1/operations/:id/subscribe`,
 *     subscription handle);
 *   - the signed-reporting event/verification-material/verification-complete routes
 *     (`GET /v1/events`, `GET .../verification-material`, `POST .../verification-complete`);
 *   - the independent verification pipeline built on `@zucoins/node-core/verifier/consumer`
 *     (originally shipped inline in `@zucoins/consumer-example`).
 */

export {
  COMPOSITION_LABELS,
  COMPOSITION_TO_KIND,
  CONSUMER_OPERATION_STATUSES,
  DEFAULT_TRUST_ASSUMPTIONS,
  PUBLIC_OPERATION_KINDS,
  TRIGGER_SOURCES,
  type CompositionLabel,
  type ConsumerCursorState,
  type ConsumerOperation,
  type ConsumerOperationStatus,
  type ConsumerSnapshot,
  type DirectGatewayObservation,
  type EvidenceRole,
  type LandingProofWire,
  type NodeClaimRecord,
  type NodeEventWake,
  type PublicOperationKind,
  type SubscribeLifecycleProjection,
  type TriggerSource,
  type TrustAssumptions,
  type VerificationCompleteRequest,
  type VerificationCompleteResponse,
  type VerificationMaterialAncestorProof,
  type VerificationMaterialAttempt,
  type VerificationMaterialWire,
  type WireIndeterminateReason,
} from "./types.js";

export {
  LANDING_PROOF_DERIVATION_FAILURES,
  deriveLandingProof,
  type IndependentHeadForRole,
  type LandingProofDerivationFailure,
  type LandingProofDerivationResult,
} from "./landing-proof.js";

export {
  advanceWatermark,
  createInMemoryConsumerStore,
  resumeAfterSeq,
  type ConsumerStore,
} from "./cursor-store.js";

export {
  classifyIndependentStream,
  projectionsAgree,
  readIndependentHead,
  type HeadReadOutcome,
  type IndependentHeadRead,
  type StreamClassifyInput,
  type StreamClassifyOutcome,
  type VerifiedSemanticState,
} from "./observation.js";

export {
  applyVerificationComplete,
  asDirectObservation,
  buildVerificationCompleteRequest,
  gateAnomalousObservation,
  ingestEventWake,
  ingestSubscribeProjection,
  openConsumerOperation,
  verifyOperationIndependently,
  type TriggerResult,
  type VerifyOperationInput,
  type VerifyOperationResult,
} from "./pipeline.js";

// Consumer-side verifier for the GET /v1/events purpose actually served
// (zp-implementer-event-v1 / zp-implementer-checkpoint-v1). Re-exported so an
// integrator gets it from the SDK, not only from node-core internals.
export {
  authenticateImplementerEvent,
  authenticateNodeEvent,
  type ArtifactEnvelope,
  type NodeArtifactResult,
  type NodeVerificationKey,
} from "@zucoins/node-core/verifier/consumer";

// Gate: every purpose served by a tenant route has a consumer verifier. Used by
// route-purpose-verifier.gate.test.ts so a green test cannot pin fiction.
export {
  ROUTE_SERVED_PURPOSES,
  CONSUMER_VERIFIER_BY_PURPOSE,
} from "./route-purpose-verifiers.js";

// Merchant-hosted payment-instruction origin: instructions shown on a
// merchant-controlled surface are verified against an independently pinned node identity
// before anything is displayed.
export {
  DISCOVERY_PATH,
  verifyReceiveInstructionOrigin,
  type InstructionOriginInput,
  type InstructionOriginResult,
  type VerifiedReceiveInstruction,
} from "./instruction-origin.js";

// ---------------------------------------------------------------------------
// Changed-response ledger + node-state vocabulary
// ---------------------------------------------------------------------------

export {
  createInMemoryChangedResponseLedger,
  type ChangedResponseAppendInput,
  type ChangedResponseAppendResult,
  type ChangedResponseLedger,
  type ChangedResponseRecord,
  type ChangedResponseRecordKind,
} from "./changed-response-ledger.js";
export {
  KNOWN_NODE_CLAIM_STATES,
  NodeStateDriftError,
  isKnownNodeClaimState,
  parseNodeClaimState,
  type KnownNodeClaimState,
} from "./node-state.js";

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------

export {
  NodeApiError,
  readNodeApiError,
  assertOk,
  assignCapacityReason,
  ASSIGN_CAPACITY_REASONS,
  type NodeApiErrorBody,
  type AssignCapacityReason,
} from "./http/errors.js";
export {
  resolveFetch,
  resolveUrl,
  type FetchLike,
  type NodeClientConfig,
} from "./http/client-types.js";
export {
  bodySha256Hex,
  buildSignedReportingHeaders,
  ReportingRequestInvalidError,
  type BuildSignedReportingHeadersInput,
  type ReportingCredential,
  type ReportingSigner,
} from "./http/reporting-signer.js";
export {
  createReceive,
  generateIdempotencyKey,
  getReceive,
  type AfterLanding,
  type CommonOperationView,
  type CreateReceiveInput,
  type CreateReceiveRequest,
  type CreateReceiveResponse,
  type GetReceiveInput,
  type ReceiveOperationView,
} from "./http/receives.js";
export {
  subscribeToOperation,
  type SubscribeToOperationInput,
} from "./http/subscribe.js";
export {
  buildEventsRawTarget,
  getEvents,
  type GetEventsInput,
  type GetEventsQuery,
  type GetEventsResponse,
} from "./http/events.js";
export {
  getVerificationMaterial,
  postVerificationComplete,
  type GetVerificationMaterialInput,
  type PostVerificationCompleteInput,
} from "./http/verification.js";
export {
  armOperation,
  type ArmOperationInput,
  type ArmRequest,
  type ArmSuccessResponse,
} from "./http/arm.js";
export {
  createInternalMove,
  getInternalMove,
  type CreateInternalMoveInput,
  type CreateInternalMoveRequest,
  type GetInternalMoveInput,
  type InternalMoveOperationView,
} from "./http/moves.js";
export {
  createExternalSend,
  getExternalSend,
  type CreateExternalSendInput,
  type CreateExternalSendRequest,
  type ExternalSendOperationView,
  type GetExternalSendInput,
} from "./http/sends.js";
