// GET /v1/operations/:operation_id/subscribe
// Covers field allowlist, cross-operation binding,
// non-oracular enumeration collapse, concurrent connections, reconnect/snapshot replay,
// and post-terminal handle expiry.

import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { apiErrorResponse } from "../src/api/error-envelope.ts";
import {
  createOperationSubscribeAccelerator,
  OPERATION_SUBSCRIBE_SSE_EVENT,
} from "../src/api/operation-subscribe-sse.ts";
import {
  createOperationSubscribeHandler,
  handleOperationSubscribe,
  matchOperationSubscribeRoute,
  openOperationSubscribe,
} from "../src/api/operation-subscribe.ts";
import {
  assertLifecycleFieldAllowlist,
  authorizeOperationSubscribe,
  DEFAULT_SUBSCRIPTION_HANDLE_POST_TERMINAL_TTL_MS,
  extractSubscriptionHandle,
  hashSubscriptionHandle,
  isTerminalOperationState,
  mintSubscriptionHandlePlaintext,
  OPERATION_LIFECYCLE_FIELD_KEYS,
  projectOperationLifecycle,
  renderOperationLifecycleBody,
  type OperationLifecycleRow,
  type OperationLifecycleStore,
  type SubscriptionHandleRecord,
  type SubscriptionHandleStore,
} from "../src/api/subscription-handle.ts";
import type { SseSink } from "../src/reporting/event-stream-sse.ts";

const OP_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OP_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const IMPLEMENTER = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const NODE = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const REQUEST_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

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
  parseEventData(): unknown[] {
    const out: unknown[] = [];
    for (const frame of this.eventFrames) {
      const dataLines = frame
        .split("\n")
        .filter((l) => l.startsWith("data: "))
        .map((l) => l.slice("data: ".length));
      out.push(JSON.parse(dataLines.join("\n")));
    }
    return out;
  }
}

class MemoryHandleStore implements SubscriptionHandleStore {
  readonly byHash = new Map<string, SubscriptionHandleRecord>();

  async lookupByHandleHash(handleHash: string): Promise<SubscriptionHandleRecord | null> {
    return this.byHash.get(handleHash) ?? null;
  }

  put(record: SubscriptionHandleRecord): void {
    this.byHash.set(record.handleHash, record);
  }
}

class MemoryLifecycleStore implements OperationLifecycleStore {
  readonly rows = new Map<string, OperationLifecycleRow>();
  private readonly listeners = new Map<string, Set<(row: OperationLifecycleRow) => void>>();

  async getLifecycle(operationId: string): Promise<OperationLifecycleRow | null> {
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

  set(row: OperationLifecycleRow): void {
    this.rows.set(row.operationId, row);
  }

  /** Advance row_version and notify subscribers (simulates DB-TX state transition). */
  advance(operationId: string, patch: Partial<OperationLifecycleRow>): OperationLifecycleRow {
    const prev = this.rows.get(operationId);
    if (prev === undefined) throw new Error(`missing ${operationId}`);
    const next: OperationLifecycleRow = {
      ...prev,
      ...patch,
      operationId,
      rowVersion: patch.rowVersion ?? prev.rowVersion + 1,
    };
    this.rows.set(operationId, next);
    for (const listener of this.listeners.get(operationId) ?? []) listener(next);
    return next;
  }
}

function lifecycle(
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

function issueHandle(
  handles: MemoryHandleStore,
  operationId: string,
  expiresAtMs: number,
  plaintext?: string,
): string {
  const plain = plaintext ?? mintSubscriptionHandlePlaintext();
  handles.put({
    operationId,
    handleHash: hashSubscriptionHandle(plain),
    expiresAtMs,
    implementerId: IMPLEMENTER,
    nodeId: NODE,
  });
  return plain;
}

function authHeaders(handle: string): Record<string, string> {
  return { authorization: `Bearer ${handle}` };
}

describe("subscription handle primitives", () => {
  it("hashes plaintext to 64-char lowercase hex and never equals plaintext", () => {
    const plain = mintSubscriptionHandlePlaintext();
    expect(plain.startsWith("sh_")).toBe(true);
    const hash = hashSubscriptionHandle(plain);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).toBe(createHash("sha256").update(plain, "utf8").digest("hex"));
    expect(hash).not.toContain(plain);
  });

  it("extractSubscriptionHandle accepts only Bearer sh_…", () => {
    expect(extractSubscriptionHandle({ authorization: "Bearer sh_abc" })).toBe("sh_abc");
    expect(extractSubscriptionHandle({ Authorization: "Bearer sh_abc" })).toBe("sh_abc");
    expect(extractSubscriptionHandle({ authorization: "Bearer ik_abc" })).toBeNull();
    expect(extractSubscriptionHandle({ authorization: "Basic sh_abc" })).toBeNull();
    expect(extractSubscriptionHandle({})).toBeNull();
    expect(extractSubscriptionHandle({ authorization: "Bearer sh_" })).toBeNull();
  });

  it("projects exactly the six fields in frozen order", () => {
    const row = lifecycle(OP_A, {
      state: "RECEIVE_LANDED",
      rowVersion: 4,
      attentionRequired: true,
      updatedAt: "2026-07-27T12:00:00.000Z",
    });
    const projected = projectOperationLifecycle(row);
    expect(Object.keys(projected)).toEqual([...OPERATION_LIFECYCLE_FIELD_KEYS]);
    const body = JSON.parse(renderOperationLifecycleBody(row)) as Record<string, unknown>;
    expect(assertLifecycleFieldAllowlist(body)).toBe(true);
    expect(body).toEqual({
      operation_id: OP_A,
      operation_type: "RECEIVE_EXTERNAL",
      state: "RECEIVE_LANDED",
      row_version: 4,
      attention_required: true,
      updated_at: "2026-07-27T12:00:00.000Z",
    });
    // Forbidden fields must never appear (data-minimization exit criterion).
    for (const forbidden of [
      "amount_zkz",
      "amount",
      "address",
      "destination_address",
      "transfer_code",
      "code",
      "artifact",
      "t0",
      "t0_observation_id",
      "raw",
      "lineage",
      "implementer_id",
      "subscription_handle",
      "receiver_pubkey",
      "expected_artifact",
    ]) {
      expect(forbidden in body).toBe(false);
    }
  });

  it("recognizes terminal states that start the post-terminal TTL", () => {
    expect(isTerminalOperationState("RECEIVE_LANDED")).toBe(true);
    expect(isTerminalOperationState("INTERNAL_MOVE_LANDED")).toBe(true);
    expect(isTerminalOperationState("EXTERNAL_SEND_LANDED")).toBe(true);
    expect(isTerminalOperationState("EXPIRED")).toBe(true);
    expect(isTerminalOperationState("REJECTED")).toBe(true);
    expect(isTerminalOperationState("READY")).toBe(false);
    expect(isTerminalOperationState("CREATED")).toBe(false);
  });

  it("default post-terminal TTL is 15 minutes", () => {
    expect(DEFAULT_SUBSCRIPTION_HANDLE_POST_TERMINAL_TTL_MS).toBe(15 * 60 * 1000);
  });
});

describe("authorizeOperationSubscribe", () => {
  it("authorizes a valid handle bound to the path operation", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A, { rowVersion: 2 }));
    const plain = issueHandle(handles, OP_A, Date.now() + 60_000);

    const outcome = await authorizeOperationSubscribe({
      requestId: REQUEST_ID,
      pathOperationId: OP_A,
      headers: authHeaders(plain),
      handleStore: handles,
      lifecycleStore,
      nowMs: () => Date.now(),
    });
    expect(outcome.kind).toBe("AUTHORIZED");
    if (outcome.kind !== "AUTHORIZED") return;
    expect(outcome.lifecycle.operationId).toBe(OP_A);
    expect(outcome.record.implementerId).toBe(IMPLEMENTER);
  });

  it("rejects a valid handle for operation A against path B (cross-operation)", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A));
    lifecycleStore.set(lifecycle(OP_B));
    const plain = issueHandle(handles, OP_A, Date.now() + 60_000);

    const outcome = await authorizeOperationSubscribe({
      requestId: REQUEST_ID,
      pathOperationId: OP_B,
      headers: authHeaders(plain),
      handleStore: handles,
      lifecycleStore,
      nowMs: () => Date.now(),
    });
    expect(outcome.kind).toBe("DENIED");
    if (outcome.kind !== "DENIED") return;
    expect(outcome.response).toEqual(apiErrorResponse("invalid_api_key", REQUEST_ID));
  });

  it("enumeration: invalid handle and nonexistent operation produce byte-identical errors", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    // OP_A exists with a real handle; OP_B does not.
    lifecycleStore.set(lifecycle(OP_A));
    const real = issueHandle(handles, OP_A, Date.now() + 60_000);

    const invalid = await authorizeOperationSubscribe({
      requestId: REQUEST_ID,
      pathOperationId: OP_A,
      headers: authHeaders("sh_totally_invalid_handle_value"),
      handleStore: handles,
      lifecycleStore,
      nowMs: () => Date.now(),
    });
    const missingOp = await authorizeOperationSubscribe({
      requestId: REQUEST_ID,
      pathOperationId: OP_B,
      headers: authHeaders(real), // valid handle but wrong path → same collapse
      handleStore: handles,
      lifecycleStore,
      nowMs: () => Date.now(),
    });
    const unknownHandleMissingOp = await authorizeOperationSubscribe({
      requestId: REQUEST_ID,
      pathOperationId: OP_B,
      headers: authHeaders("sh_another_unknown"),
      handleStore: handles,
      lifecycleStore,
      nowMs: () => Date.now(),
    });
    const absentAuth = await authorizeOperationSubscribe({
      requestId: REQUEST_ID,
      pathOperationId: OP_A,
      headers: {},
      handleStore: handles,
      lifecycleStore,
      nowMs: () => Date.now(),
    });

    expect(invalid.kind).toBe("DENIED");
    expect(missingOp.kind).toBe("DENIED");
    expect(unknownHandleMissingOp.kind).toBe("DENIED");
    expect(absentAuth.kind).toBe("DENIED");
    if (
      invalid.kind !== "DENIED" ||
      missingOp.kind !== "DENIED" ||
      unknownHandleMissingOp.kind !== "DENIED" ||
      absentAuth.kind !== "DENIED"
    ) {
      return;
    }
    // Byte-identical bodies for fixed request_id (non-oracular collapse).
    expect(invalid.response.body).toBe(missingOp.response.body);
    expect(invalid.response.body).toBe(unknownHandleMissingOp.response.body);
    expect(invalid.response.body).toBe(absentAuth.response.body);
    expect(invalid.response.status).toBe(401);
    expect(invalid.response.body).toBe(apiErrorResponse("invalid_api_key", REQUEST_ID).body);
  });

  it("expiry: handle past expiresAtMs is denied (not a stale subscription)", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A, { state: "RECEIVE_LANDED", rowVersion: 5 }));
    const now = 1_000_000;
    const plain = issueHandle(handles, OP_A, now); // expires exactly at `now`

    const expired = await authorizeOperationSubscribe({
      requestId: REQUEST_ID,
      pathOperationId: OP_A,
      headers: authHeaders(plain),
      handleStore: handles,
      lifecycleStore,
      nowMs: () => now,
    });
    expect(expired.kind).toBe("DENIED");
    if (expired.kind !== "DENIED") return;
    expect(expired.response.body).toBe(apiErrorResponse("invalid_api_key", REQUEST_ID).body);

    // Still valid one ms before expiry.
    const fresh = await authorizeOperationSubscribe({
      requestId: REQUEST_ID,
      pathOperationId: OP_A,
      headers: authHeaders(plain),
      handleStore: handles,
      lifecycleStore,
      nowMs: () => now - 1,
    });
    expect(fresh.kind).toBe("AUTHORIZED");
  });
});

describe("matchOperationSubscribeRoute", () => {
  it("matches GET with canonical uuid path", () => {
    expect(matchOperationSubscribeRoute("GET", `/v1/operations/${OP_A}/subscribe`)).toEqual({
      kind: "MATCH",
      operationId: OP_A,
    });
  });

  it("rejects wrong method, malformed uuid, trailing junk", () => {
    expect(matchOperationSubscribeRoute("POST", `/v1/operations/${OP_A}/subscribe`).kind).toBe(
      "NO_MATCH",
    );
    expect(matchOperationSubscribeRoute("GET", "/v1/operations/not-a-uuid/subscribe").kind).toBe(
      "NO_MATCH",
    );
    expect(
      matchOperationSubscribeRoute("GET", `/v1/operations/${OP_A}/subscribe/extra`).kind,
    ).toBe("NO_MATCH");
    expect(matchOperationSubscribeRoute("GET", "/v1/events/stream").kind).toBe("NO_MATCH");
  });
});

describe("operation subscribe SSE accelerator", () => {
  it("emits connected comment + current lifecycle snapshot with allowlisted data", async () => {
    const lifecycleStore = new MemoryLifecycleStore();
    const row = lifecycle(OP_A, { rowVersion: 3, state: "READY" });
    lifecycleStore.set(row);
    const accel = createOperationSubscribeAccelerator({ lifecycleStore, pollMs: 0 });
    const sink = new RecordingSink();
    const conn = accel.open({ operationId: OP_A, initial: row }, sink);

    expect(sink.chunks[0]).toBe(": connected\n\n");
    expect(sink.eventFrames).toHaveLength(1);
    expect(sink.eventFrames[0]).toContain(`event: ${OPERATION_SUBSCRIBE_SSE_EVENT}`);
    expect(sink.eventFrames[0]).toContain("id: 3");
    const data = sink.parseEventData()[0];
    expect(assertLifecycleFieldAllowlist(data)).toBe(true);
    expect(data).toEqual(JSON.parse(renderOperationLifecycleBody(row)));
    conn.close();
    expect(sink.closed).toBe(true);
  });

  it("pushes subsequent row_version advances to all concurrent subscribers", async () => {
    const lifecycleStore = new MemoryLifecycleStore();
    const row = lifecycle(OP_A, { rowVersion: 1 });
    lifecycleStore.set(row);
    const accel = createOperationSubscribeAccelerator({ lifecycleStore, pollMs: 0 });
    const sink1 = new RecordingSink();
    const sink2 = new RecordingSink();
    const c1 = accel.open({ operationId: OP_A, initial: row }, sink1);
    const c2 = accel.open({ operationId: OP_A, initial: row }, sink2);

    lifecycleStore.advance(OP_A, {
      state: "RECEIVE_LANDED",
      updatedAt: "2026-07-27T01:00:00.000Z",
    });

    expect(sink1.eventFrames).toHaveLength(2);
    expect(sink2.eventFrames).toHaveLength(2);
    const d1 = sink1.parseEventData()[1] as { state: string; row_version: number };
    const d2 = sink2.parseEventData()[1] as { state: string; row_version: number };
    expect(d1).toEqual(d2);
    expect(d1.state).toBe("RECEIVE_LANDED");
    expect(d1.row_version).toBe(2);
    expect(assertLifecycleFieldAllowlist(d1)).toBe(true);
    c1.close();
    c2.close();
  });

  it("reconnect / snapshot replay: dropped client receives current state on reopen", async () => {
    const lifecycleStore = new MemoryLifecycleStore();
    let row = lifecycle(OP_A, { rowVersion: 1, state: "CREATED" });
    lifecycleStore.set(row);
    const accel = createOperationSubscribeAccelerator({ lifecycleStore, pollMs: 0 });

    const first = new RecordingSink();
    const c1 = accel.open({ operationId: OP_A, initial: row }, first);
    c1.close();

    // Missed transition while disconnected.
    row = lifecycleStore.advance(OP_A, {
      state: "READY",
      updatedAt: "2026-07-27T02:00:00.000Z",
    });

    const second = new RecordingSink();
    const c2 = accel.open({ operationId: OP_A, initial: row }, second);
    const data = second.parseEventData();
    expect(data).toHaveLength(1);
    expect(data[0]).toEqual({
      operation_id: OP_A,
      operation_type: "RECEIVE_EXTERNAL",
      state: "READY",
      row_version: 2,
      attention_required: false,
      updated_at: "2026-07-27T02:00:00.000Z",
    });
    c2.close();
  });

  it("gap fill via poll when subscribe notification is missed", async () => {
    const lifecycleStore = new MemoryLifecycleStore();
    const row = lifecycle(OP_A, { rowVersion: 1 });
    lifecycleStore.set(row);

    const timers: Array<{ fn: () => void; ms: number }> = [];
    const accel = createOperationSubscribeAccelerator({
      lifecycleStore,
      pollMs: 10,
      setInterval: (fn, ms) => {
        timers.push({ fn: fn as () => void, ms });
        return timers.length;
      },
      clearInterval: () => {
        /* no-op */
      },
    });
    const sink = new RecordingSink();
    const conn = accel.open({ operationId: OP_A, initial: row }, sink);
    expect(sink.eventFrames).toHaveLength(1);

    // Mutate WITHOUT firing subscribe listeners (simulates missed notification / other process).
    lifecycleStore.rows.set(
      OP_A,
      lifecycle(OP_A, {
        rowVersion: 4,
        state: "RECEIVE_LANDED",
        updatedAt: "2026-07-27T03:00:00.000Z",
      }),
    );
    // Fire poll timers.
    for (const t of timers) t.fn();
    // Allow microtask for async getLifecycle.
    await Promise.resolve();
    await Promise.resolve();

    const versions = sink
      .parseEventData()
      .map((d) => (d as { row_version: number }).row_version);
    expect(versions).toContain(1);
    expect(versions).toContain(4);
    conn.close();
  });
});

describe("handleOperationSubscribe route", () => {
  it("returns 200 SSE headers on authorized open (empty bodyBytes)", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A));
    const plain = issueHandle(handles, OP_A, Date.now() + 60_000);
    const sink = new RecordingSink();

    const response = await handleOperationSubscribe(
      {
        handleStore: handles,
        lifecycleStore,
        nowMs: () => Date.now(),
        newRequestId: () => REQUEST_ID,
        pollMs: 0,
        openSink: () => sink,
      },
      {
        method: "GET",
        path: `/v1/operations/${OP_A}/subscribe`,
        headers: authHeaders(plain),
      },
    );

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toBe("text/event-stream");
    expect(response.bodyBytes.byteLength).toBe(0);
    expect(sink.eventFrames.length).toBeGreaterThanOrEqual(1);
    const data = sink.parseEventData()[0];
    expect(assertLifecycleFieldAllowlist(data)).toBe(true);
  });

  it("route-level expiry and cross-op rejections are 401 invalid_api_key", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A));
    const plain = issueHandle(handles, OP_A, 100);

    const expired = await handleOperationSubscribe(
      {
        handleStore: handles,
        lifecycleStore,
        nowMs: () => 100,
        newRequestId: () => REQUEST_ID,
        pollMs: 0,
      },
      {
        method: "GET",
        path: `/v1/operations/${OP_A}/subscribe`,
        headers: authHeaders(plain),
      },
    );
    const cross = await handleOperationSubscribe(
      {
        handleStore: handles,
        lifecycleStore,
        nowMs: () => 50,
        newRequestId: () => REQUEST_ID,
        pollMs: 0,
      },
      {
        method: "GET",
        path: `/v1/operations/${OP_B}/subscribe`,
        headers: authHeaders(plain),
      },
    );

    expect(expired.status).toBe(401);
    expect(cross.status).toBe(401);
    expect(expired.body).toBe(cross.body);
    expect(expired.body).toBe(apiErrorResponse("invalid_api_key", REQUEST_ID).body);
  });

  it("openOperationSubscribe rejects before writing lifecycle frames", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A));
    const sink = new RecordingSink();
    const outcome = await openOperationSubscribe(
      {
        handleStore: handles,
        lifecycleStore,
        nowMs: () => Date.now(),
        newRequestId: () => REQUEST_ID,
        pollMs: 0,
      },
      {
        requestId: REQUEST_ID,
        operationId: OP_A,
        headers: authHeaders("sh_nope"),
        sink,
      },
    );
    expect(outcome.kind).toBe("REJECTED");
    expect(sink.eventFrames).toHaveLength(0);
  });

  it("createOperationSubscribeHandler is a stable factory", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A, { rowVersion: 9 }));
    const plain = issueHandle(handles, OP_A, Date.now() + 60_000);
    const handler = createOperationSubscribeHandler({
      handleStore: handles,
      lifecycleStore,
      nowMs: () => Date.now(),
      newRequestId: () => randomUUID(),
      pollMs: 0,
    });
    const res = await handler({
      method: "GET",
      path: `/v1/operations/${OP_A}/subscribe`,
      headers: authHeaders(plain),
    });
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-cache");
  });

  it("r2: deny never calls openSink and returns 401 invalid_api_key", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A));
    const plain = issueHandle(handles, OP_A, 100);
    let openSinkCalls = 0;
    const sink = new RecordingSink();

    const expired = await handleOperationSubscribe(
      {
        handleStore: handles,
        lifecycleStore,
        nowMs: () => 100,
        newRequestId: () => REQUEST_ID,
        pollMs: 0,
        openSink: () => {
          openSinkCalls += 1;
          return sink;
        },
      },
      {
        method: "GET",
        path: `/v1/operations/${OP_A}/subscribe`,
        headers: authHeaders(plain),
      },
    );

    expect(openSinkCalls).toBe(0);
    expect(sink.chunks).toHaveLength(0);
    expect(expired.status).toBe(401);
    expect(expired.liveConnection).toBeUndefined();
    expect(expired.body).toBe(apiErrorResponse("invalid_api_key", REQUEST_ID).body);
  });

  it("r2: authorized openSink retains liveConnection; close stops poll", async () => {
    const handles = new MemoryHandleStore();
    const lifecycleStore = new MemoryLifecycleStore();
    lifecycleStore.set(lifecycle(OP_A));
    const plain = issueHandle(handles, OP_A, Date.now() + 60_000);
    const sink = new RecordingSink();
    const armed: Array<{ fn: () => void; handle: number }> = [];
    const cleared: number[] = [];
    let next = 1;

    const response = await handleOperationSubscribe(
      {
        handleStore: handles,
        lifecycleStore,
        nowMs: () => Date.now(),
        newRequestId: () => REQUEST_ID,
        pollMs: 50,
        heartbeatMs: 50,
        openSink: () => sink,
        accelerator: createOperationSubscribeAccelerator({
          lifecycleStore,
          pollMs: 50,
          heartbeatMs: 50,
          setInterval: (fn) => {
            const handle = next++;
            armed.push({ fn, handle });
            return handle;
          },
          clearInterval: (handle) => {
            cleared.push(handle as number);
          },
        }),
      },
      {
        method: "GET",
        path: `/v1/operations/${OP_A}/subscribe`,
        headers: authHeaders(plain),
      },
    );

    expect(response.status).toBe(200);
    expect(response.liveConnection).toBeDefined();
    expect(armed.length).toBeGreaterThan(0);

    response.liveConnection!.close();

    expect(cleared.length).toBe(armed.length);
    expect(sink.closed).toBe(true);
  });
});
