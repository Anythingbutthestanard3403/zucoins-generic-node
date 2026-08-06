// Durable neutral event stream and named-consumer cursor seam.
//
// Invariants:
// * Gapless monotonic seq from a dedicated per-node counter, never identity/serial (gapless per-node event counter).
// Counter advance shares the event insert's transaction so a rolled-back append burns no value.
// * Hash-linked chain is the sole authoritative gap/tamper detector (operator halt surface).
// * Insert-only — events are never edited or deleted.
// * Scan uses exclusive after_seq (CURSOR_CONTRACT.requestCursorExclusive).
//
// EventRecord carries every node_events column required to serve the zp-node-event-v1 envelope
// (purpose, canonical_version, preimage_text, preimage_sha256, signing_key_id, signature).

import type { NodeEventType } from "../protocol/suite/index.js";

// Caller-supplied fields for one append. `dataText` is the exact separately stored
// event-data JSON text; the service digests it, never reformats it (the byte-exact signing rule).
// Signed envelope fields are supplied by the caller (the signing path); this seam
// allocates seq, binds previous_event_hash, and persists.
export interface EventAppendInput {
  readonly eventId: string;
  readonly operationId: string | null;
  readonly walletId: string | null;
  readonly eventType: NodeEventType;
  readonly dataText: string;
  readonly dataSha256: string;
  readonly purpose: "zp-node-event-v1";
  readonly canonicalVersion: 1;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly signingKeyId: string;
  readonly signature: string;
  readonly createdAt: string;
}

// Full stored row matching node_events columns.
export interface EventRecord {
  readonly seq: bigint;
  readonly eventId: string;
  readonly purpose: "zp-node-event-v1";
  readonly canonicalVersion: 1;
  readonly nodeId: string;
  readonly operationId: string | null;
  readonly walletId: string | null;
  readonly eventType: NodeEventType;
  readonly dataText: string;
  readonly dataSha256: string;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly signingKeyId: string;
  readonly signature: string;
  readonly previousEventHash: string | null;
  readonly eventHash: string;
  readonly createdAt: string;
}

export interface EventStreamTail {
  readonly highWater: bigint;
  readonly lastEventHash: string | null;
}

export type AppendEventsOutcome =
  | { readonly kind: "APPENDED"; readonly records: readonly EventRecord[] }
  | { readonly kind: "STALE_TAIL" };

export interface EventListStore {
  readTail(nodeId: string): Promise<EventStreamTail>;
  // Atomically persist one contiguous batch whose first seq is highWater+1. expectedHighWater
  // is the optimistic-concurrency guard; STALE_TAIL means re-read and rebuild.
  appendBatch(
    nodeId: string,
    batch: readonly EventRecord[],
    expectedHighWater: bigint,
  ): Promise<AppendEventsOutcome>;
  // Forward scan: events with seq > afterSeq (exclusive), ascending, at most limit.
  // afterSeq null means from the beginning (equivalent to afterSeq = 0).
  scanAfter(
    nodeId: string,
    afterSeq: bigint | null,
    limit: number,
  ): Promise<readonly EventRecord[]>;
  find(nodeId: string, seq: bigint): Promise<EventRecord | null>;
}

// Named consumer cursors. Advance is idempotent monotonic max.
export const EVENT_CURSOR_NAMES = ["reporting", "observation", "sse"] as const;
export type EventCursorName = (typeof EVENT_CURSOR_NAMES)[number];

export interface EventCursorState {
  readonly nodeId: string;
  readonly name: EventCursorName;
  readonly position: bigint;
  readonly version: bigint;
  readonly updatedAt: string;
}

export type AdvanceCursorOutcome =
  | { readonly kind: "ADVANCED"; readonly state: EventCursorState; readonly moved: boolean }
  | { readonly kind: "STALE_VERSION" };

export interface EventCursorStore {
  readCursor(nodeId: string, name: EventCursorName): Promise<EventCursorState>;
  advanceCursor(
    nodeId: string,
    name: EventCursorName,
    toPosition: bigint,
    expectedVersion: bigint,
  ): Promise<AdvanceCursorOutcome>;
  listCursors(nodeId: string): Promise<readonly EventCursorState[]>;
}

export class EventLogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EventLogError";
  }
}
