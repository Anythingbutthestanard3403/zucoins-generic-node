// Public surface of the durable event-log module.

export {
  EVENT_CURSOR_NAMES,
  EventLogError,
  type AdvanceCursorOutcome,
  type AppendEventsOutcome,
  type EventAppendInput,
  type EventCursorName,
  type EventCursorState,
  type EventCursorStore,
  type EventListStore,
  type EventRecord,
  type EventStreamTail,
} from "./store.js";

export {
  EventListService,
  computeEventLogNodeEventHash,
  type EventChainVerification,
  type EventListServiceConfig,
  type EventScanPage,
} from "./event-list.js";

export { CursorManager, type CursorManagerConfig } from "./cursor.js";

export { InMemoryEventStore } from "./in-memory-store.js";

export {
  createPgEventListStore,
  type PgEventListStoreConfig,
  type SqlQueryFn as EventLogSqlQueryFn,
  type SqlTxFn as EventLogSqlTxFn,
} from "./pg-event-store.js";

export {
  appendDurableDualChainEvent,
  appendImplementerEventLeg,
  appendTerminalLandedEvent,
  buildArtifactEnvelope,
  createDualChainEventAppender,
  implementerEventHashOf,
  DEFAULT_IMPLEMENTER_EVENT_QUOTA,
  TerminalEventNotAppendableError,
  type DualChainAppendInput,
  type DualChainAppendOutcome,
  type DualChainAppenderConfig,
  type DualChainEventAppender,
  type DualChainEventQuota,
  type DurableDualChainEventInput,
  type ImplementerEventLegInput,
  type ImplementerEventLegResult,
  type NodeEventSigner,
  type TerminalLandedEventInput,
} from "./dual-chain-appender.js";
