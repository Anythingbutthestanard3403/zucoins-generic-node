// Single-process reference adapter for EventListStore + EventCursorStore.
// Critical sections are await-free so concurrent callers serialize on the JS event loop
// within each method body (single-threaded atomicity). This is NOT a durability proof —
// real durability is pg-event-store.ts exercised by event-log.pg.test.ts against the
// frozen event-ledger.sql DDL.

import {
  EventLogError,
  type AdvanceCursorOutcome,
  type AppendEventsOutcome,
  type EventCursorName,
  type EventCursorState,
  type EventCursorStore,
  type EventListStore,
  type EventRecord,
  type EventStreamTail,
  EVENT_CURSOR_NAMES,
} from "./store.js";

interface NodeStream {
  events: EventRecord[];
  bySeq: Map<string, EventRecord>;
  byEventId: Set<string>;
  highWater: bigint;
  lastEventHash: string | null;
}

function cursorKey(nodeId: string, name: EventCursorName): string {
  return `${nodeId}\0${name}`;
}

export class InMemoryEventStore implements EventListStore, EventCursorStore {
  private readonly streams = new Map<string, NodeStream>();
  private readonly cursors = new Map<string, EventCursorState>();

  private streamOf(nodeId: string): NodeStream {
    let stream = this.streams.get(nodeId);
    if (stream === undefined) {
      stream = {
        events: [],
        bySeq: new Map(),
        byEventId: new Set(),
        highWater: 0n,
        lastEventHash: null,
      };
      this.streams.set(nodeId, stream);
    }
    return stream;
  }

  readTail(nodeId: string): Promise<EventStreamTail> {
    const stream = this.streamOf(nodeId);
    return Promise.resolve({
      highWater: stream.highWater,
      lastEventHash: stream.lastEventHash,
    });
  }

  appendBatch(
    nodeId: string,
    batch: readonly EventRecord[],
    expectedHighWater: bigint,
  ): Promise<AppendEventsOutcome> {
    const stream = this.streamOf(nodeId);
    if (stream.highWater !== expectedHighWater) {
      return Promise.resolve({ kind: "STALE_TAIL" });
    }
    if (batch.length === 0) {
      return Promise.resolve({ kind: "APPENDED", records: [] });
    }
    let expectedSeq = expectedHighWater + 1n;
    let expectedPrev = stream.lastEventHash;
    for (const record of batch) {
      if (record.nodeId !== nodeId) {
        throw new EventLogError("append batch contains cross-node record");
      }
      if (record.seq !== expectedSeq) {
        throw new EventLogError(
          `append batch non-contiguous: expected seq ${expectedSeq.toString()} got ${record.seq.toString()}`,
        );
      }
      if (record.previousEventHash !== expectedPrev) {
        throw new EventLogError("append batch previousEventHash mismatch");
      }
      if (stream.byEventId.has(record.eventId)) {
        throw new EventLogError(`duplicate event_id ${record.eventId}`);
      }
      expectedSeq += 1n;
      expectedPrev = record.eventHash;
    }
    const frozen = batch.map((r) => Object.freeze({ ...r }));
    for (const record of frozen) {
      stream.events.push(record);
      stream.bySeq.set(record.seq.toString(), record);
      stream.byEventId.add(record.eventId);
    }
    const last = frozen[frozen.length - 1]!;
    stream.highWater = last.seq;
    stream.lastEventHash = last.eventHash;
    return Promise.resolve({ kind: "APPENDED", records: frozen });
  }

  scanAfter(
    nodeId: string,
    afterSeq: bigint | null,
    limit: number,
  ): Promise<readonly EventRecord[]> {
    const stream = this.streamOf(nodeId);
    const after = afterSeq ?? 0n;
    const out: EventRecord[] = [];
    for (const event of stream.events) {
      if (event.seq > after) {
        out.push(event);
        if (out.length >= limit) break;
      }
    }
    return Promise.resolve(out);
  }

  find(nodeId: string, seq: bigint): Promise<EventRecord | null> {
    const stream = this.streamOf(nodeId);
    return Promise.resolve(stream.bySeq.get(seq.toString()) ?? null);
  }

  readCursor(nodeId: string, name: EventCursorName): Promise<EventCursorState> {
    const existing = this.cursors.get(cursorKey(nodeId, name));
    if (existing !== undefined) return Promise.resolve(existing);
    const fresh: EventCursorState = Object.freeze({
      nodeId,
      name,
      position: 0n,
      version: 0n,
      updatedAt: new Date(0).toISOString(),
    });
    return Promise.resolve(fresh);
  }

  advanceCursor(
    nodeId: string,
    name: EventCursorName,
    toPosition: bigint,
    expectedVersion: bigint,
  ): Promise<AdvanceCursorOutcome> {
    const key = cursorKey(nodeId, name);
    const current = this.cursors.get(key) ?? {
      nodeId,
      name,
      position: 0n,
      version: 0n,
      updatedAt: new Date(0).toISOString(),
    };
    if (current.version !== expectedVersion) {
      return Promise.resolve({ kind: "STALE_VERSION" });
    }
    if (toPosition <= current.position) {
      const frozen = Object.freeze({ ...current });
      this.cursors.set(key, frozen);
      return Promise.resolve({ kind: "ADVANCED", state: frozen, moved: false });
    }
    const next: EventCursorState = Object.freeze({
      nodeId,
      name,
      position: toPosition,
      version: current.version + 1n,
      updatedAt: new Date().toISOString(),
    });
    this.cursors.set(key, next);
    return Promise.resolve({ kind: "ADVANCED", state: next, moved: true });
  }

  listCursors(nodeId: string): Promise<readonly EventCursorState[]> {
    const out: EventCursorState[] = [];
    for (const name of EVENT_CURSOR_NAMES) {
      const existing = this.cursors.get(cursorKey(nodeId, name));
      if (existing !== undefined) out.push(existing);
    }
    return Promise.resolve(out);
  }
}
