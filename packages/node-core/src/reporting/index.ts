// public surface of the node-core reporting runtime: the signed
// reporting request verifier pipeline, the post-burn idempotency/handler orchestration, the
// zp-node-event-v1 batch verification library, and the store seam with its in-memory
// reference adapter. Registered as the `reporting` module in test/boundaries.test.ts.

export { sha256Hex, sha256HexUtf8, reportingPublicKeyObject, verifyDetachedEd25519, computeNodeEventHash, computeReportingLogicalFingerprint } from "./ed25519.js";
export {
  REPORTING_REJECTION_CODES,
  REJECTION_STATUS,
  reportingErrorResponse,
  reportingJsonResponse,
  type ReportingRejectionCode,
  type ReportingHttpResponse,
} from "./errors.js";
export {
  REPORTING_HEADER_NAMES,
  readExactHeader,
  readReportingSignedHeaders,
  type ExactHeaderRead,
  type ReportingSignedHeaders,
  type ReportingSignedHeaderRead,
} from "./headers.js";
export {
  REPORTING_ROUTE_IDS,
  REPORTING_RETENTION_CLASSES,
  reportingRouteShapeMatches,
  classifyReportingRoute,
  type ReportingRouteId,
  type ReportingRetentionClass,
  type ReportingRouteClassification,
} from "./route-table.js";
export {
  COMPLETED_IDEMPOTENCY_UNIQUE_FIELDS,
  NODE_EVENT_SIGNING_KEY_PURPOSE,
  ReportingStoreError,
  isFingerprintGuardedRouteId,
  reportingKeyAdmissionEligible,
  type AppendNodeEventsOutcome,
  type BurnNonceEvidence,
  type BurnNonceOutcome,
  type BurnNonceRequest,
  type CommitMutationWithCompletedIdempotencyOutcome,
  type CompletedIdempotencyDraft,
  type CompletedIdempotencyRecord,
  type InsertCompletedIdempotencyOutcome,
  type NodeEventCursor,
  type NodeEventSigningKey,
  type NodeEventVerificationStore,
  type PersistCompletedMutationChild,
  type RecordedNodeEvent,
  type ReportingAdmissionSnapshot,
  type ReportingMutationTx,
  type ReportingNonceEvidence,
  type ReportingPresentedKeyState,
  type ReportingRateLimiter,
  type ReportingRegistration,
  type ReportingRequestStore,
} from "./store.js";
export {
  InMemoryReportingStore,
  type InMemoryKeyStateSeed,
  type InMemoryLifecycleHeadSeed,
} from "./in-memory-store.js";
export { InMemoryReportingRateLimiter } from "./in-memory-rate-limiter.js";
export {
  DEFAULT_MAX_BODY_BYTES,
  createReportingRequestVerifier,
  type CapturedReportRequest,
  type ReportingRejection,
  type ReportingRequestVerifier,
  type ReportingRequestVerifierConfig,
  type ReportingVerifyOutcome,
  type VerifiedReportRequest,
} from "./request-verifier.js";
export {
  createReportingRequestHandler,
  type ReportingHandlerRegistry,
  type ReportingHandlerResult,
  type ReportingRequestHandler,
  type ReportingRequestHandlerConfig,
  type ReportingRouteHandler,
  type ReportingTransportSideChannel,
} from "./request-handler.js";
export {
  createNodeEventVerifier,
  type NodeEventBatchOutcome,
  type NodeEventVerifier,
  type NodeEventVerifierConfig,
  type ServedNodeEvent,
} from "./event-verifier.js";
export {
  EVENTS_LIMIT_DEFAULT,
  EVENTS_LIMIT_MAX,
  EVENTS_LIMIT_MIN,
  InMemoryImplementerEventReadStore,
  clampEventsLimit,
  frameImplementerEventStream,
  listEvents,
  renderEventsListBody,
  resolveStreamCursor,
  type EventsListQuery,
  type EventsListResult,
  type ImplementerEventPage,
  type ImplementerEventReadStore,
  type ServedImplementerCheckpoint,
  type ServedImplementerEvent,
  type StreamCursorResolution,
} from "./events-read-service.js";

export {
  IMPLEMENTER_STREAM_EVENT_TYPES,
  InMemoryImplementerEventLog,
  ImplementerEventLogError,
  isImplementerStreamEventType,
  type ImplementerCheckpointAppendInput,
  type ImplementerEventAppendInput,
  type ImplementerEventLog,
  type ImplementerStreamEventType,
  type StoredImplementerCheckpoint,
  type StoredImplementerEvent,
} from "./implementer-event-log.js";
export {
  createPgImplementerEventLog,
  type PgImplementerEventLogConfig,
  type SqlQueryFn as ImplementerEventLogSqlQueryFn,
  type SqlTxFn as ImplementerEventLogSqlTxFn,
} from "./pg-implementer-event-log.js";
export {
  createSnapshotService,
  SnapshotCaptureTimeoutError,
  deriveActiveCounts,
  InMemorySnapshotStateReader,
  InMemorySnapshotStore,
  renderSnapshotBody,
  type ImplementerStateSnapshot,
  type SnapshotActiveCounts,
  type SnapshotAttentionItem,
  type SnapshotDestination,
  type SnapshotOperation,
  type SnapshotService,
  type SnapshotServiceConfig,
  type SnapshotStateReader,
  type SnapshotStore,
} from "./snapshot-service.js";
export {
  createPgSnapshotStore,
  serializeSnapshotRowBody,
  type PgSnapshotStoreConfig,
} from "./pg-snapshot-store.js";
export {
  createPgSnapshotStateReader,
  type PgSnapshotStateReaderConfig,
} from "./pg-snapshot-state-reader.js";
export {
  SSE_HEADERS,
  SSE_MEDIA_TYPE,
  createEventStreamAccelerator,
  formatSseFrame,
  formatSseHeartbeat,
  sseComment,
  type EventStreamAccelerator,
  type EventStreamAcceleratorConfig,
  type SseConnection,
  type SseOpenOutcome,
  type SseRejectCode,
  type SseSink,
  type SseStreamOpenRequest,
} from "./event-stream-sse.js";
