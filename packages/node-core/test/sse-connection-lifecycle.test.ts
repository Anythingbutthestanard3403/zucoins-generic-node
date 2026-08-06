// Shared SSE connection lifecycle.
// Fake timers throughout: setInterval/clearInterval are injected, so a tick only fires
// when a test fires it and a cleared handle is observable.
//
// The assertion that matters is the leak test: open a stream, disconnect, and prove both
// timer handles were cleared and the store listener released.
import { describe, expect, it } from "vitest";

import {
  createOperationSubscribeAccelerator,
  type OperationSubscribeSseConfig,
} from "../src/api/operation-subscribe-sse.ts";
import {
  createEventStreamAccelerator,
  type SseSink,
} from "../src/reporting/event-stream-sse.ts";
import { InMemoryImplementerEventLog } from "../src/reporting/implementer-event-log.ts";
import { startSseLifecycle } from "../src/reporting/sse-connection-lifecycle.ts";
import { IMPLEMENTER_ID } from "../src/reporting/test-fixtures.ts";
import type {
  OperationLifecycleRow,
  OperationLifecycleStore,
} from "../src/api/subscription-handle.ts";

const OP_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

/** Injected clock. Records every armed timer and every handle that gets cleared. */
class FakeTimers {
  readonly armed: Array<{ handle: number; fn: () => void; ms: number }> = [];
  readonly cleared: unknown[] = [];

  readonly setInterval = (fn: () => void, ms: number): unknown => {
    const handle = this.armed.length + 1;
    this.armed.push({ handle, fn, ms });
    return handle;
  };

  readonly clearInterval = (handle: unknown): void => {
    this.cleared.push(handle);
  };

  /** Fire every armed timer once, cleared or not — a leaked timer would still write. */
  fireAll(): void {
    for (const t of this.armed) t.fn();
  }

  get liveHandles(): number[] {
    return this.armed.filter((t) => !this.cleared.includes(t.handle)).map((t) => t.handle);
  }
}

class RecordingSink implements SseSink {
  readonly chunks: string[] = [];
  closed = false;
  write(chunk: string): void {
    this.chunks.push(chunk);
  }
  close(): void {
    this.closed = true;
  }
  get text(): string {
    return this.chunks.join("");
  }
  get eventFrames(): string[] {
    return this.chunks.filter((c) => c.startsWith("id:"));
  }
}

/** Lifecycle store with an observable listener count, so a leak is directly assertable. */
class CountingLifecycleStore implements OperationLifecycleStore {
  readonly rows = new Map<string, OperationLifecycleRow>();
  readonly listeners = new Map<string, Set<(row: OperationLifecycleRow) => void>>();
  getLifecycleCalls = 0;
  rejectPoll = false;

  async getLifecycle(operationId: string): Promise<OperationLifecycleRow | null> {
    this.getLifecycleCalls += 1;
    if (this.rejectPoll) throw new Error("poll failed");
    return this.rows.get(operationId) ?? null;
  }

  subscribe(operationId: string, listener: (row: OperationLifecycleRow) => void): () => void {
    let set = this.listeners.get(operationId);
    if (set === undefined) {
      set = new Set();
      this.listeners.set(operationId, set);
    }
    set.add(listener);
    return () => {
      set?.delete(listener);
    };
  }

  get listenerCount(): number {
    let total = 0;
    for (const set of this.listeners.values()) total += set.size;
    return total;
  }

  set(row: OperationLifecycleRow): void {
    this.rows.set(row.operationId, row);
  }

  advance(operationId: string, patch: Partial<OperationLifecycleRow>): void {
    const prev = this.rows.get(operationId);
    if (prev === undefined) throw new Error(`missing ${operationId}`);
    const next = { ...prev, ...patch };
    this.rows.set(operationId, next);
    for (const listener of [...(this.listeners.get(operationId) ?? [])]) listener(next);
  }
}

function lifecycleRow(
  operationId: string,
  overrides: Partial<OperationLifecycleRow> = {},
): OperationLifecycleRow {
  return {
    operationId,
    operationType: "RECEIVE_EXTERNAL",
    state: "READY",
    rowVersion: 1,
    attentionRequired: false,
    updatedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  };
}

function openSubscribe(
  store: CountingLifecycleStore,
  timers: FakeTimers,
  overrides: Partial<OperationSubscribeSseConfig> = {},
) {
  const row = lifecycleRow(OP_A);
  store.set(row);
  const accel = createOperationSubscribeAccelerator({
    lifecycleStore: store,
    pollMs: 10,
    heartbeatMs: 25,
    setInterval: timers.setInterval,
    clearInterval: timers.clearInterval,
    ...overrides,
  });
  const sink = new RecordingSink();
  return { conn: accel.open({ operationId: OP_A, initial: row }, sink), sink };
}

// --- the leak assertion -----------------------------------------------------------

describe("SSE lifecycle releases every resource on disconnect", () => {
  it("operation-subscribe: clears both timers and drops the store listener", async () => {
    const store = new CountingLifecycleStore();
    const timers = new FakeTimers();
    const { conn, sink } = openSubscribe(store, timers);

    expect(timers.armed.map((t) => t.ms)).toEqual([10, 25]);
    expect(store.listenerCount).toBe(1);

    conn.close();

    // Timers released.
    expect(timers.cleared).toEqual([1, 2]);
    expect(timers.liveHandles).toEqual([]);
    // Listener released.
    expect(store.listenerCount).toBe(0);
    expect(sink.closed).toBe(true);

    // Nothing the source does afterwards can reach the sink.
    const before = sink.chunks.length;
    store.advance(OP_A, { rowVersion: 9, state: "RECEIVE_LANDED" });
    timers.fireAll();
    await Promise.resolve();
    await Promise.resolve();
    expect(sink.chunks).toHaveLength(before);
  });

  it("event-stream: clears both timers and drops the log listener", async () => {
    const log = new InMemoryImplementerEventLog();
    const timers = new FakeTimers();
    const accel = createEventStreamAccelerator({
      log,
      pollMs: 10,
      heartbeatMs: 25,
      setInterval: timers.setInterval,
      clearInterval: timers.clearInterval,
    });
    const sink = new RecordingSink();
    const outcome = await accel.open(
      {
        requestId: "r1",
        implementerId: IMPLEMENTER_ID,
        afterImplementerSeq: null,
        lastEventId: null,
      },
      sink,
    );
    expect(outcome.kind).toBe("OPEN");
    if (outcome.kind !== "OPEN") return;

    expect(timers.armed.map((t) => t.ms)).toEqual([10, 25]);

    outcome.connection.close();

    expect(timers.cleared).toEqual([1, 2]);
    expect(timers.liveHandles).toEqual([]);
    expect(sink.closed).toBe(true);

    // A leaked log listener would frame this append into the closed sink.
    const before = sink.chunks.length;
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    timers.fireAll();
    await Promise.resolve();
    await Promise.resolve();
    expect(sink.chunks).toHaveLength(before);
  });
});

// --- helper unit tests ------------------------------------------------------------

describe("startSseLifecycle", () => {
  function spyOptions(timers: FakeTimers, overrides: Record<string, unknown> = {}) {
    const calls = { poll: 0, heartbeat: 0, unsubscribe: 0, closeSink: 0 };
    const gate = { closed: false };
    const lifecycle = startSseLifecycle({
      gate,
      pollMs: 10,
      heartbeatMs: 25,
      setInterval: timers.setInterval,
      clearInterval: timers.clearInterval,
      poll: async () => {
        calls.poll += 1;
      },
      heartbeat: () => {
        calls.heartbeat += 1;
      },
      unsubscribe: () => {
        calls.unsubscribe += 1;
      },
      closeSink: () => {
        calls.closeSink += 1;
      },
      ...overrides,
    });
    return { lifecycle, calls, gate };
  }

  it("does not poll or heartbeat when closed before the first tick", () => {
    const timers = new FakeTimers();
    const { lifecycle, calls } = spyOptions(timers);
    lifecycle.close();
    timers.fireAll();
    expect(calls).toEqual({ poll: 0, heartbeat: 0, unsubscribe: 1, closeSink: 1 });
  });

  it("is idempotent under double close", () => {
    const timers = new FakeTimers();
    const { lifecycle, calls, gate } = spyOptions(timers);
    lifecycle.close();
    lifecycle.close();
    lifecycle.close();
    expect(calls.unsubscribe).toBe(1);
    expect(calls.closeSink).toBe(1);
    // Each handle cleared exactly once.
    expect(timers.cleared).toEqual([1, 2]);
    expect(gate.closed).toBe(true);
  });

  it("swallows a rejected poll and keeps the connection open", async () => {
    const timers = new FakeTimers();
    let polls = 0;
    const { gate } = spyOptions(timers, {
      poll: async () => {
        polls += 1;
        throw new Error("poll failed");
      },
    });
    timers.fireAll();
    await Promise.resolve();
    await Promise.resolve();
    expect(polls).toBe(1);
    expect(gate.closed).toBe(false);

    // Still ticking after the rejection.
    timers.fireAll();
    await Promise.resolve();
    expect(polls).toBe(2);
  });

  it.each([
    ["undefined", undefined],
    ["zero", 0],
    ["negative", -1],
  ])("arms no heartbeat timer when heartbeatMs is %s", (_label, heartbeatMs) => {
    const timers = new FakeTimers();
    const { calls } = spyOptions(timers, { heartbeatMs });
    expect(timers.armed.map((t) => t.ms)).toEqual([10]);
    timers.fireAll();
    expect(calls.heartbeat).toBe(0);
  });

  it("arms a heartbeat timer when heartbeatMs is positive", () => {
    const timers = new FakeTimers();
    const { calls } = spyOptions(timers, { heartbeatMs: 25 });
    expect(timers.armed.map((t) => t.ms)).toEqual([10, 25]);
    timers.fireAll();
    expect(calls.heartbeat).toBe(1);
  });

  it.each([
    ["zero", 0],
    ["negative", -1],
  ])("arms no poll timer when pollMs is %s", (_label, pollMs) => {
    const timers = new FakeTimers();
    const { calls } = spyOptions(timers, { pollMs });
    expect(timers.armed.map((t) => t.ms)).toEqual([25]);
    timers.fireAll();
    expect(calls.poll).toBe(0);
  });

  it("clears only the timers it armed", () => {
    const timers = new FakeTimers();
    const { lifecycle } = spyOptions(timers, { pollMs: 0, heartbeatMs: 0 });
    expect(timers.armed).toEqual([]);
    lifecycle.close();
    expect(timers.cleared).toEqual([]);
  });
});

// --- per-call-site behaviour preserved ---------------------------------------------

describe("operation-subscribe lifecycle wiring", () => {
  it("stops emitting when close lands while a poll is in flight", async () => {
    const store = new CountingLifecycleStore();
    const timers = new FakeTimers();
    const { conn, sink } = openSubscribe(store, timers);
    const before = sink.eventFrames.length;

    // Fire the poll, then close before the getLifecycle promise settles.
    store.rows.set(OP_A, lifecycleRow(OP_A, { rowVersion: 7, state: "RECEIVE_LANDED" }));
    timers.armed[0]?.fn();
    conn.close();
    await Promise.resolve();
    await Promise.resolve();

    expect(sink.eventFrames).toHaveLength(before);
  });

  it("swallows a rejected getLifecycle without closing the connection", async () => {
    const store = new CountingLifecycleStore();
    const timers = new FakeTimers();
    const { conn, sink } = openSubscribe(store, timers);
    store.rejectPoll = true;
    timers.armed[0]?.fn();
    await Promise.resolve();
    await Promise.resolve();

    expect(sink.closed).toBe(false);
    expect(store.listenerCount).toBe(1);

    // Recovers on the next tick.
    store.rejectPoll = false;
    store.rows.set(OP_A, lifecycleRow(OP_A, { rowVersion: 4, state: "RECEIVE_LANDED" }));
    timers.armed[0]?.fn();
    await Promise.resolve();
    await Promise.resolve();
    expect(sink.text).toContain("RECEIVE_LANDED");
    conn.close();
  });

  it("unsubscribes exactly once across repeated close", () => {
    const store = new CountingLifecycleStore();
    const timers = new FakeTimers();
    const { conn } = openSubscribe(store, timers);
    expect(store.listenerCount).toBe(1);
    conn.close();
    conn.close();
    expect(store.listenerCount).toBe(0);
    expect(timers.cleared).toEqual([1, 2]);
  });
});

describe("event-stream lifecycle wiring", () => {
  it("does not arm a timer when the backlog read fails", async () => {
    const log = new InMemoryImplementerEventLog();
    const timers = new FakeTimers();
    const failing = {
      subscribe: log.subscribe.bind(log),
      readEvents: async () => {
        throw new Error("unavailable");
      },
      append: log.append.bind(log),
    } as unknown as InMemoryImplementerEventLog;

    const accel = createEventStreamAccelerator({
      log: failing,
      pollMs: 10,
      heartbeatMs: 25,
      setInterval: timers.setInterval,
      clearInterval: timers.clearInterval,
    });
    const sink = new RecordingSink();
    const outcome = await accel.open(
      {
        requestId: "r1",
        implementerId: IMPLEMENTER_ID,
        afterImplementerSeq: null,
        lastEventId: null,
      },
      sink,
    );

    expect(outcome).toEqual({
      kind: "REJECTED",
      code: "service_unavailable",
      requestId: "r1",
    });
    // Rejected before the lifecycle is armed: no timers to leak.
    expect(timers.armed).toEqual([]);
  });
});
