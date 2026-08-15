// Public surface of the API validation and error-handling layer.
// Governing spec: Phase 5.

export interface ApiPort<Request = unknown, Response = unknown> {
  handle(request: Request): Promise<Response>;
}

export {
  UUID_PATTERN,
  UuidSchema,
  WalletPublicKeySchema,
  Ed25519SignatureSchema,
  ZkzAmountSchema,
  PositiveZkzAmountSchema,
  Sha256HexSchema,
  UnixTimeSecsV2Schema,
  OpaqueReferenceSchema,
  AnchorSchema,
  IdempotencyKeySchema,
  Rfc3339MsSchema,
  DecimalSeqStringSchema,
} from "./scalars.js";

export {
  API_ERROR_CODES,
  ASSIGN_CAPACITY_REASONS,
  isAssignCapacityReason,
  ApiErrorCodeSchema,
  ApiErrorDetailsSchema,
  ApiErrorEnvelopeSchema,
  HTTP_STATUS_BY_CODE,
  buildApiErrorBody,
  apiErrorResponse,
  scopeDenialResponse,
  type ApiErrorCode,
  type ApiErrorDetails,
  type ApiErrorResponse,
  type ApiErrorEnvelope,
  type AssignCapacityReason,
} from "./error-envelope.js";

export {
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_NESTING_DEPTH,
  parseStrictJson,
  type StrictJsonConfig,
  type StrictJsonOutcome,
  type StrictJsonSuccess,
  type StrictJsonFailure,
  type StrictJsonRejectionCode,
} from "./strict-json.js";

export {
  CreateReceiveBody,
  CreateInternalMoveBody,
  CreateExternalSendBody,
  CreateDestinationBody,
  CreateIntegrationRequestBody,
  ListDestinationsQuery,
  ListEventsQuery,
  EventStreamQuery,
  ArmBody,
  VerificationCompleteBody,
  ApproveBody,
  RejectBody,
  RecoveryActionsBody,
  BlessBody,
  RetireBody,
  ROUTE_SCHEMAS,
  findRouteSchema,
  type RouteSchema,
} from "./route-schemas.js";

export {
  runValidationPipeline,
  type PipelineRequest,
  type PipelineContext,
  type PipelineOutcome,
  type PipelineConfig,
} from "./pipeline.js";
export {
  bindTenant,
  credentialResolverFromService,
  enforceScope,
  extractImplementerBearer,
  runTenantScopeGate,
  type AuthPrincipal,
  type CredentialResolver,
  type CredentialValidationService,
  type TenantGateOutcome,
} from "./tenant-middleware.js";
export { hasScope, parseScope, scopeMatches } from "./scope.js";

export {
  handleCreateReceive,
  handleGetReceive,
  handleCreateInternalMove,
  handleGetInternalMove,
  handleCreateExternalSend,
  handleGetExternalSend,
  WalletBusyError,
  ReceiveQueueFullError,
  IdempotencyConflictError,
  IdempotencyKeyReusedError,
  IdempotencyInProgressError,
  ReceiveAdmissionError,
  SendAdmissionError,
  type OperationObject,
  type ExpectedArtifact,
  type ReceiveResponse,
  type InternalMoveResponse,
  // Keep ExternalSendResponse on the api barrel: packages/node-core/src/index.ts pins
  // the package surface to this export (not./send) so TS2308 stays resolved.
  type ExternalSendResponse,
  type RouteHandlerResult,
  type OperationRouteStore,
  type CreateReceiveInput,
  type CreateInternalMoveInput,
  type CreateExternalSendInput,
  // action routes — arm + verification-complete (+ pure predicates / store errors).
  // handleGetVerificationMaterial / VerificationMaterialResponse are owned solely by
  //./verification-material.js (access gate). Action-routes twin retired.
  handleArm,
  handleVerificationComplete,
  compareT0Evidence,
  leaseReleaseStatusForVerdict,
  classifyAncestorProof,
  isOperationKind,
  ACTION_EVIDENCE_ROLES,
  OperationVersionConflictError,
  T0MismatchError,
  OperationNotArmableError,
  VerificationMaterialNotReadyError,
  VerificationMaterialExpiredError,
  ProtocolPredicateFailedError,
  type T0ProjectionWire,
  type T0EvidenceWire,
  type ArmInput,
  type ArmSuccessResponse,
  type VerificationVerdict,
  type LeaseReleaseStatus,
  type LandingProofWire,
  type WalletEvidenceWire,
  type VerificationCompleteInput,
  type VerificationCompleteSuccessResponse,
  type IndeterminateReason,
  type AncestorProofClassification,
  type PathManifestEntry,
  type TransactionBodyEntry,
  type AncestorProof,
  type ObservationEvidence,
  type AttemptTransaction,
  type AttemptEntry,
  type ActionEvidenceRole,
  type ActionRouteStore,
  type AncestorProofCompletenessFlags,
  type T0MismatchField,
} from "./routes/index.js";

// verification-material transport edge. The pure assembler lives in
// observation/verification; this is the 409/200/410 HTTP binder that consumes it.
export {
  handleGetVerificationMaterial,
  VERIFICATION_MATERIAL_FIELD_KEYS,
  type VerificationMaterialFieldKey,
  type VerificationMaterialRow,
  type VerificationMaterialSource,
  type VerificationMaterialRequest,
  type VerificationMaterialOk,
  type VerificationMaterialResponse,
} from "./verification-material.js";

// durable-table → VerificationMaterialSource adapters.
export {
  createGatedTableVerificationMaterialSource,
  createTableBackedVerificationMaterialSource,
  type AssembleFromTablesFn,
  type LoadOperationFn,
} from "./verification-material-source.js";

// verification-material access-window RECORD (not a bearer scheme).
// Auth remains the signed reporting credential; this is the per-operation availability gate.
// Pure 409/200/410 gate primitives stay on the core/data barrel (retention.ts); this surface
// is the durable window record + issue/authorize/revoke + read-audit.
export {
  VERIFICATION_ACCESS_WINDOW_STATUSES,
  VERIFICATION_MATERIAL_READ_AUDIT_ACTION,
  InMemoryVerificationAccessWindowStore,
  VerificationAccessWindowError,
  auditVerificationMaterialAccessRead,
  authorizeVerificationAccessWindow,
  gatedVerificationAccessRead,
  hashAccessWindowNonce,
  issueVerificationAccessWindow,
  markVerificationAccessWindowExpired,
  mintAccessWindowNoncePlaintext,
  revokeVerificationAccessWindow,
  type AccessWindowDecision,
  type AccessWindowDecisionReason,
  type AuthorizeAccessWindowInput,
  type GatedAccessReadInput,
  type IssueAccessWindowRequest,
  type IssuedAccessWindow,
  type VerificationAccessWindowRecord,
  type VerificationAccessWindowStatus,
  type VerificationAccessWindowStore,
} from "./verification-access.js";

// GET /v1/events transport edge + reporting-registry binder.
export {
  EVENTS_LIST_CURSOR_FIELDS,
  EVENTS_LIST_PATH,
  EVENTS_LIST_ROUTE_ID,
  EVENTS_WAIT_SECONDS_DEFAULT,
  EVENTS_WAIT_SECONDS_MAX,
  EVENTS_WAIT_SECONDS_MIN,
  LONG_POLL_INTERVAL_MS,
  createEventsListRouteHandler,
  eventsListHandlerEntry,
  handleGetEvents,
  parseEventsListQueryFromTarget,
  type EventsListOk,
  type EventsListQueryParse,
  type EventsListRequest,
  type EventsListResponse,
  type EventsListRouteDeps,
  type EventsListRouteQuery,
} from "./events.js";

export {
  createOperationRouter,
  type OperationRouter,
  type OperationRouterDeps,
  type RouterResponse,
} from "./operation-router.js";

export {
  OperationRouterCompositionError,
  createFailClosedOperationStore,
  createRejectAllOperationAuth,
  createImplementerBearerAuth,
  createImplementerBearerAuthFromService,
  assertOperationAuthComposition,
  isOperationAuthBinding,
  isFailClosedOperationStore,
  pipelineHooksFromAuth,
  type OperationAuthBinding,
  type OperationAuthKind,
  type RejectAllOperationAuth,
  type ImplementerBearerOperationAuth,
  type ImplementerBearerKey,
  type ImplementerBearerAuthOptions,
  type FailClosedOperationStore,
} from "./operation-auth.js";

export {
  KeyValidityIntervalSchema,
  DiscoveryPublicKeySchema,
  DiscoveryKeyEntrySchema,
  NodeIdentityDocumentSchema,
  buildNodeIdentityDocument,
  buildHealthResponse,
  type KeyValidityInterval,
  type DiscoveryPublicKey,
  type DiscoveryKeyEntry,
  type NodeIdentityDocument,
  type DiscoveryKeyConfig,
  type DiscoveryConfig,
  type HealthStatus,
} from "./discovery.js";

export {
  handleWellKnown,
  wellKnownFromDiscoveryConfig,
  type WellKnownDeps,
  type WellKnownHttpResponse,
} from "./well-known.js";

export {
  DEFERRED_HALT_ROUTE,
  LIVE_HALT_ROUTES,
  LIVE_ATTENTION_RETRACTION_ROUTES,
  LIVE_OPERATOR_PARK_ROUTES,
  LIVE_IMPLEMENTER_ROUTES,
  LIVE_AUTO_APPROVE_POLICY_ROUTES,
  LIVE_ALLOW_NODE_VERIFIED_POLICY_ROUTES,
  LIVE_INTEGRATION_REQUEST_ROUTES,
  OPERATIONAL_PROBE_PATHS,
  OPTIONAL_METRICS_ROUTE,
  adminRouteKeys,
  operationalProbeKeys,
  publicRouteKeys,
  requiredProductionRouteKeys,
  routeKeyOf,
  routeManifestParityFindings,
  routePolicyKeys,
  type RouteKey,
} from "./production-route-census.js";

export {
  DEFAULT_DB_PING_TTL_MS,
  DEFAULT_DB_PING_TIMEOUT_MS,
  GATING_READINESS_CHECK_IDS,
  REPORTED_READINESS_CHECK_IDS,
  buildLivenessResponse,
  buildReadinessResponse,
  livenessHttp,
  readinessHttp,
  evaluateReadinessFromProbes,
  CachedDbProbe,
  createHealthHandlers,
  type GatingReadinessCheckId,
  type ReportedReadinessCheckId,
  type LivenessResponse,
  type ReadinessCheckEntry,
  type ReadinessStatus,
  type ReadinessResponse,
  type HealthHttpResult,
  type ReadinessVerdict,
  type ReadinessHandlerDeps,
  type HealthRouteHandlers,
} from "./health.js";

// GET /v1/events/stream + GET /v1/state/snapshot.
export {
  EVENTS_STREAM_PATH,
  EVENTS_STREAM_ROUTE_ID,
  createEventsStreamRouteHandler,
  eventsStreamHandlerEntry,
  lastEventIdFromHeaders,
  openEventsStream,
  parseEventsStreamQueryFromTarget,
  type EventsStreamQueryParse,
  type EventsStreamRouteDeps,
  type EventsStreamRouteQuery,
} from "./event-stream.js";
export {
  DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS,
  STATE_SNAPSHOT_PATH,
  STATE_SNAPSHOT_ROUTE_ID,
  createStateSnapshotRouteHandler,
  handleGetStateSnapshot,
  stateSnapshotHandlerEntry,
  type StateSnapshotOk,
  type StateSnapshotResponse,
  type StateSnapshotRouteDeps,
} from "./state-snapshot.js";

// GET /v1/operations/:operation_id/subscribe (subscription handle).
export {
  DEFAULT_SUBSCRIPTION_HANDLE_POST_TERMINAL_TTL_MS,
  NONTERMINAL_OPERATION_STATES,
  OPERATION_LIFECYCLE_FIELD_KEYS,
  SUBSCRIPTION_HANDLE_PREFIX,
  TERMINAL_OPERATION_STATES,
  assertLifecycleFieldAllowlist,
  authorizeOperationSubscribe,
  extractSubscriptionHandle,
  hashSubscriptionHandle,
  isKnownOperationState,
  isTerminalOperationState,
  mintSubscriptionHandlePlaintext,
  projectOperationLifecycle,
  renderOperationLifecycleBody,
  safeEqualHex,
  type OperationLifecycleFieldKey,
  type OperationLifecycleRow,
  type OperationLifecycleStore,
  type OperationState,
  type NonterminalOperationState,
  type SubscribeAuthorizeOutcome,
  type SubscriptionHandleRecord,
  type SubscriptionHandleStore,
  type TerminalOperationState,
} from "./subscription-handle.js";
export {
  OPERATION_SUBSCRIBE_SSE_EVENT,
  createOperationSubscribeAccelerator,
  type OperationSubscribeAccelerator,
  type OperationSubscribeSseConfig,
  type OperationSubscribeSseConnection,
} from "./operation-subscribe-sse.js";
export {
  OPERATION_SUBSCRIBE_METHOD,
  OPERATION_SUBSCRIBE_PATH_TEMPLATE,
  createOperationSubscribeHandler,
  handleOperationSubscribe,
  matchOperationSubscribeRoute,
  openOperationSubscribe,
  type OperationSubscribeHttpResponse,
  type OperationSubscribeMatch,
  type OperationSubscribeRequest,
  type OperationSubscribeRouteDeps,
} from "./operation-subscribe.js";
export {
  createSqlSubscriptionHandleStore,
  INSERT_SUBSCRIPTION_HANDLE,
  type SubscriptionHandleSqlExecutor,
} from "./sql-subscription-handle-store.js";
export {
  createSqlOperationLifecycleStore,
  type OperationLifecycleSqlExecutor,
} from "./sql-operation-lifecycle-store.js";

// destination registration, listing, blessing, retirement.
export {
  createDestinationService,
  deriveMoveEligibility,
  DestinationIdempotencyKeyClaimedError,
  isDestinationIdempotencyKeyClaimed,
  type BlessDestinationOutcome,
  type BlessDestinationRequest,
  type BlessingAuthorizer,
  type CustodyDenialReason,
  type DestinationClock,
  type DestinationFilter,
  type DestinationIdGenerator,
  type DestinationListItem,
  type DestinationPage,
  type DestinationRecord,
  type DestinationService,
  type DestinationState,
  type DestinationStore,
  type DestinationWalletFacts,
  type DestinationWalletKeyClaim,
  type DestinationWalletKeyGenerator,
  type NewDestination,
  type RegisterDestinationOutcome,
  type RegisterDestinationRequest,
  type RetireDestinationOutcome,
  type RetireDestinationRequest,
} from "./destination.js";

export {
  createDestinationsListRouteHandler,
  destinationToWire,
  handleCreateDestination,
  handleListDestinations,
  listDestinationsBody,
  parseListDestinationsQueryFromTarget,
  type DestinationHttpDeps,
  type DestinationsListRouteDeps,
  type ListDestinationsQueryParse,
} from "./destination-http.js";

export {
  createDestinationsRouter,
  createFailClosedDestinationService,
  type DestinationsRouter,
  type DestinationsRouterDeps,
} from "./destinations-router.js";

export {
  createSqlDestinationStore,
  type DestinationSqlExecutor,
} from "./sql-destination-store.js";

export {
  INSERT_NODE_GENERATED_WALLET_SQL,
  INSERT_PENDING_DESTINATION_FOR_WALLET_SQL,
  DELETE_PENDING_DESTINATION_FOR_WALLET_SQL,
  DELETE_NODE_GENERATED_WALLET_SQL,
  insertNodeGeneratedWalletWithPendingDestination,
  deleteNodeGeneratedWalletMint,
  type InsertNodeGeneratedWalletInput,
  type NodeGeneratedWalletSqlExecutor,
} from "./insert-node-generated-wallet.js";

// wallet custody administration: safe public metadata, recovery
// status/evidence exposure, and the direct quarantine transition. Retirement stays with
// above; this slice adds no route that could become an import path.
export {
  WALLET_CUSTODY_VIEW_FIELDS,
  WALLET_RECOVERY_EVIDENCE_FIELDS,
  buildWalletCustodyView,
  createWalletCustodyAdminService,
  type QuarantineWalletOutcome,
  type QuarantineWalletRequest,
  type WalletCustodyAdminService,
  type WalletCustodyRow,
  type WalletCustodyStore,
  type WalletCustodyView,
  type WalletRecoveryEvidenceView,
  type WalletRecoveryVerificationRow,
} from "./wallet-custody-admin.js";

// recovery inspection handlers (read-only). Pure
// classification symbols live on./operator (package barrel) to avoid TS2308.
export {
  NEEDS_ATTENTION_DEFAULT_LIMIT,
  NEEDS_ATTENTION_MAX_LIMIT,
  NEEDS_ATTENTION_PATH,
  NeedsAttentionQuerySchema,
  RECOVERY_DETAIL_PATH,
  handleGetRecovery,
  handleNeedsAttention,
  type GetRecoveryOutcome,
  type IssuedRecoveryNonce,
  type NeedsAttentionListItem,
  type NeedsAttentionQuery,
  type NeedsAttentionResponse,
  type NeedsAttentionStorePage,
  type RecoveryDetailResponse,
  type RecoveryInspectionStore,
} from "./recovery-inspection.js";

// recovery-actions POST (mutating; operator_session_totp).
// Pure evaluate/plan symbols live on./operator to avoid TS2308 with the barrel.
export {
  RECOVERY_ACTIONS_PATH,
  handleRecoveryAction,
  recoveryActionErrorEnvelope,
  type HandleRecoveryActionResult,
  type RecoveryActionAuthContext,
} from "./recovery-actions.js";

// TLS + request-transport hardening.
export {
  MIN_TLS_VERSION,
  MAX_TLS_VERSION,
  HARDENED_CIPHER_SUITES,
  buildHardenedTlsConfig,
  JSON_MEDIA_TYPE,
  JSON_CONTENT_TYPE_HEADER,
  MIN_HTTP_VERSION,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_HEADERS_TIMEOUT_MS,
  DEFAULT_MAX_HEADER_BYTES,
  buildTransportHardeningConfig,
  guardHttpVersion,
  guardContentType,
  guardRequestSize,
  guardHeaderSize,
  enforceTransportGuards,
  buildHardenedServerConfig,
  type HardenedTlsConfig,
  type TlsOverrides,
  type TransportHardeningConfig,
  type TransportOverrides,
  type TransportRejectionCode,
  type TransportGuardOutcome,
  type HardenedServerConfig,
  type HardenedServerOverrides,
} from "./transport-hardening.js";

export {
  createImplementerIdentityRouter,
  type ImplementerIdentityRouter,
  type ImplementerIdentityRouterDeps,
  type ImplementerIdentityLoaders,
} from "./implementer-identity-router.js";

