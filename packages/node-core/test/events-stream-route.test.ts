// GET /v1/events/stream transport edge.
import { describe, expect, it } from "vitest";

import { randomUUID } from "node:crypto";

import {
  createEventsStreamRouteHandler,
  EVENTS_STREAM_ROUTE_ID,
  lastEventIdFromHeaders,
  openEventsStream,
  parseEventsStreamQueryFromTarget,
} from "../src/api/event-stream.ts";
import { InMemoryImplementerEventLog } from "../src/reporting/implementer-event-log.ts";
import type { SseSink } from "../src/reporting/event-stream-sse.ts";
import type { VerifiedReportRequest } from "../src/reporting/request-verifier.ts";
import { REPORTING_ROUTE_IDS } from "../src/reporting/route-table.ts";
import { IMPLEMENTER_ID } from "../src/reporting/test-fixtures.ts";
import { REPORT_REQUEST_PURPOSE } from "@zucoins/generic-node-contracts";

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
}

describe("parseEventsStreamQueryFromTarget", () => {
  it("parses exclusive after_implementer_seq", () => {
    const parsed = parseEventsStreamQueryFromTarget("/v1/events/stream?after_implementer_seq=1043");
    expect(parsed).toEqual({ ok: true, query: { afterImplementerSeq: 1043n } });
  });

  it("rejects legacy after_seq", () => {
    const parsed = parseEventsStreamQueryFromTarget("/v1/events/stream?after_seq=1");
    expect(parsed.ok).toBe(false);
  });

  it("rejects unknown query keys", () => {
    const parsed = parseEventsStreamQueryFromTarget("/v1/events/stream?limit=1");
    expect(parsed.ok).toBe(false);
  });
});

describe("lastEventIdFromHeaders", () => {
  it("reads Last-Event-ID case-insensitively", () => {
    expect(lastEventIdFromHeaders({ "Last-Event-ID": "9" })).toBe("9");
    expect(lastEventIdFromHeaders({ "last-event-id": "9" })).toBe("9");
    expect(lastEventIdFromHeaders({})).toBeNull();
  });
});

describe("openEventsStream", () => {
  it("returns 400 cursor_mismatch when Last-Event-ID disagrees", async () => {
    const log = new InMemoryImplementerEventLog();
    const sink = new RecordingSink();
    const outcome = await openEventsStream(
      { log, nowMs: () => 0, newRequestId: () => "req", pollMs: 0 },
      {
        requestId: "req",
        implementerId: IMPLEMENTER_ID,
        rawTarget: "/v1/events/stream?after_implementer_seq=5",
        headers: { "Last-Event-ID": "6" },
        sink,
      },
    );
    expect(outcome.kind).toBe("REJECTED");
    if (outcome.kind !== "REJECTED") return;
    expect(outcome.response.status).toBe(400);
    expect(outcome.response.body).toContain("cursor_mismatch");
  });

  it("opens and replays committed events", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const sink = new RecordingSink();
    const outcome = await openEventsStream(
      { log, nowMs: () => 0, newRequestId: () => "req", pollMs: 0 },
      {
        requestId: "req",
        implementerId: IMPLEMENTER_ID,
        rawTarget: "/v1/events/stream",
        headers: {},
        sink,
      },
    );
    expect(outcome.kind).toBe("OPEN");
    if (outcome.kind !== "OPEN") return;
    expect(sink.text).toContain('id: 1\nevent: receive.ready\ndata: {"implementer_seq":"1"}');
    outcome.connection.close();
  });
});

function verifiedStreamRequest(input: {
  readonly rawTarget: string;
  readonly lastEventId: string | null;
}): VerifiedReportRequest {
  return {
    ok: true,
    binding: {
      reportingKeyId: "key-1",
      nodeId: "node-1",
      implementerId: IMPLEMENTER_ID,
      publicKeyEncoded: "pub",
    },
    route: {
      routeId: REPORTING_ROUTE_IDS.eventsStream,
      requestClass: "READ",
      retentionClass: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE",
    },
    nonceEvidence: {
      id: randomUUID(),
      nodeId: "node-1",
      implementerId: IMPLEMENTER_ID,
      nonce: randomUUID(),
      purpose: REPORT_REQUEST_PURPOSE,
      routeId: REPORTING_ROUTE_IDS.eventsStream,
      requestClass: "READ",
      reportingKeyId: "key-1",
      lifecycleEpoch: 0n,
      nonceBurnSequence: 1n,
      requestPreimageText: "pre",
      requestPreimageSha256: "00".repeat(32),
      requestSignature: `${"A".repeat(86)}==`,
      method: "GET",
      rawTarget: input.rawTarget,
      bodySha256: "00".repeat(32),
      logicalFingerprint: "fp",
      issuedAt: "2026-07-18T00:00:00.000Z",
      expiresAt: "2026-07-18T00:01:00.000Z",
      receivedAtMs: 0,
      consumedAtMs: 0,
      retentionClass: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE",
    },
    idempotencyKey: null,
    fingerprint: {
      method: "GET",
      rawTarget: input.rawTarget,
      bodySha256: "00".repeat(32),
    },
    bodyBytes: new Uint8Array(),
    lastEventId: input.lastEventId,
  };
}

describe("createEventsStreamRouteHandler", () => {
  it("registers under events_stream", () => {
    expect(EVENTS_STREAM_ROUTE_ID).toBe(REPORTING_ROUTE_IDS.eventsStream);
  });

  it("returns 400 cursor_mismatch when Last-Event-ID disagrees with after_implementer_seq", async () => {
    const log = new InMemoryImplementerEventLog();
    const handler = createEventsStreamRouteHandler({
      log,
      nowMs: () => 0,
      newRequestId: () => "req-binder-mismatch",
      pollMs: 0,
    });

    const result = await handler(
      verifiedStreamRequest({
        rawTarget: "/v1/events/stream?after_implementer_seq=5",
        lastEventId: "6",
      }),
    );

    expect(result.persistChild).toBeNull();
    expect(result.response.status).toBe(400);
    const body = new TextDecoder().decode(result.response.bodyBytes);
    expect(body).toContain("cursor_mismatch");
  });

  it("returns 400 cursor_mismatch when Last-Event-ID is supplied without after_implementer_seq", async () => {
    // Browser EventSource reconnect sends Last-Event-ID alone; requires equality
    // with the query cursor, so a lone header is a mismatch (not a silent full replay).
    const log = new InMemoryImplementerEventLog();
    const handler = createEventsStreamRouteHandler({
      log,
      nowMs: () => 0,
      newRequestId: () => "req-binder-lone-leid",
      pollMs: 0,
    });

    const result = await handler(
      verifiedStreamRequest({
        rawTarget: "/v1/events/stream",
        lastEventId: "99",
      }),
    );

    expect(result.response.status).toBe(400);
    const body = new TextDecoder().decode(result.response.bodyBytes);
    expect(body).toContain("cursor_mismatch");
  });

  it("opens 200 SSE when Last-Event-ID matches after_implementer_seq", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e2",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"2"}',
      createdAt: "2026-07-18T00:00:01.000Z",
    });

    const handler = createEventsStreamRouteHandler({
      log,
      nowMs: () => 0,
      newRequestId: () => "req-binder-match",
      pollMs: 0,
    });

    const result = await handler(
      verifiedStreamRequest({
        rawTarget: "/v1/events/stream?after_implementer_seq=1",
        lastEventId: "1",
      }),
    );

    expect(result.persistChild).toBeNull();
    expect(result.response.status).toBe(200);
    expect(result.response.headers["content-type"]).toMatch(/text\/event-stream/);
  });

  it("r2: cursor reject never calls openSink", async () => {
    const log = new InMemoryImplementerEventLog();
    let openSinkCalls = 0;
    const sink = new RecordingSink();
    const handler = createEventsStreamRouteHandler({
      log,
      nowMs: () => 0,
      newRequestId: () => "req-no-sink-on-deny",
      pollMs: 0,
    });

    const result = await handler(
      verifiedStreamRequest({
        rawTarget: "/v1/events/stream?after_implementer_seq=5",
        lastEventId: "6",
      }),
      {
        openSink: () => {
          openSinkCalls += 1;
          return sink;
        },
      },
    );

    expect(openSinkCalls).toBe(0);
    expect(result.response.status).toBe(400);
    expect(result.response.liveStream).toBeUndefined();
    expect(sink.chunks).toHaveLength(0);
  });

  it("r2: transport openSink holds liveStream and frames events", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const sink = new RecordingSink();
    const handler = createEventsStreamRouteHandler({
      log,
      nowMs: () => 0,
      newRequestId: () => "req-live-stream",
      pollMs: 0,
    });

    const result = await handler(
      verifiedStreamRequest({
        rawTarget: "/v1/events/stream",
        lastEventId: null,
      }),
      { openSink: () => sink },
    );

    expect(result.response.status).toBe(200);
    expect(result.response.liveStream).toBeDefined();
    expect(sink.text).toContain("connected");
    expect(sink.text).toContain('id: 1\nevent: receive.ready');
    result.response.liveStream!.close();
    expect(sink.closed).toBe(true);
  });
});
