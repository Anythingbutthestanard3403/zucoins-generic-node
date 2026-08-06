// GET /v1/events route handler tests.
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  EVENTS_LIST_CURSOR_FIELDS,
  EVENTS_LIST_ROUTE_ID,
  createEventsListRouteHandler,
  handleGetEvents,
  parseEventsListQueryFromTarget,
} from "../src/api/events.ts";
import {
  InMemoryImplementerEventReadStore,
  type ServedImplementerEvent,
} from "../src/reporting/events-read-service.ts";
import type { VerifiedReportRequest } from "../src/reporting/request-verifier.ts";
import { REPORTING_ROUTE_IDS } from "../src/reporting/route-table.ts";

const IMPLEMENTER_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const IMPLEMENTER_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const REQUEST_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const event = (seq: bigint, proof: string): ServedImplementerEvent => ({
  implementerSeq: seq,
  eventType: "receive.landed",
  proofRepresentation: proof,
});

function seed(store: InMemoryImplementerEventReadStore, implementerId: string, n: number): void {
  for (let i = 1; i <= n; i += 1) {
    store.seedEvent(
      implementerId,
      event(
        BigInt(i),
        `{"purpose":"zp-implementer-event-v1","implementer_seq":"${i}","key_id":"k${i}","data":{}}`,
      ),
    );
  }
}

describe("parseEventsListQueryFromTarget", () => {
  it("defaults limit=100 wait_seconds=0 and null cursor", () => {
    const parsed = parseEventsListQueryFromTarget("/v1/events");
    expect(parsed).toEqual({
      ok: true,
      query: { afterImplementerSeq: null, limit: 100, waitSeconds: 0 },
    });
  });

  it("parses exclusive after_implementer_seq + limit + wait_seconds", () => {
    const parsed = parseEventsListQueryFromTarget(
      "/v1/events?after_implementer_seq=1043&limit=50&wait_seconds=30",
    );
    expect(parsed).toEqual({
      ok: true,
      query: { afterImplementerSeq: 1043n, limit: 50, waitSeconds: 30 },
    });
  });

  it("rejects legacy after_seq (wrong cursor family)", () => {
    expect(parseEventsListQueryFromTarget("/v1/events?after_seq=5").ok).toBe(false);
  });

  it("rejects wait_seconds out of range", () => {
    expect(parseEventsListQueryFromTarget("/v1/events?wait_seconds=31").ok).toBe(false);
  });

  it("rejects unknown query keys", () => {
    expect(parseEventsListQueryFromTarget("/v1/events?foo=1").ok).toBe(false);
  });
});

describe("EVENTS_LIST_CURSOR_FIELDS ↔ CURSOR_CONTRACT", () => {
  it("preserves exclusive-after / watermark / next-after semantics under dual-continuity names", async () => {
    const { CURSOR_CONTRACT } = await import(
      "../../generic-node-contracts/src/event-sequencing/cursor.ts"
    );
    expect(EVENTS_LIST_CURSOR_FIELDS.requestCursorExclusive).toBe(
      CURSOR_CONTRACT.requestCursorExclusive,
    );
    expect(EVENTS_LIST_CURSOR_FIELDS.applyRule).toBe(CURSOR_CONTRACT.applyRule);
    expect(EVENTS_LIST_CURSOR_FIELDS.tracks).toBe(CURSOR_CONTRACT.tracks);
    expect(EVENTS_LIST_CURSOR_FIELDS.monotonic).toBe(CURSOR_CONTRACT.monotonic);
    expect(EVENTS_LIST_CURSOR_FIELDS.requestCursorField).toBe("after_implementer_seq");
    expect(EVENTS_LIST_CURSOR_FIELDS.responseWatermarkField).toBe("implementer_watermark_seq");
    expect(EVENTS_LIST_CURSOR_FIELDS.responseNextCursorField).toBe(
      "next_after_implementer_seq",
    );
  });
});

describe("handleGetEvents", () => {
  it("returns a page with implementer_watermark_seq and next_after_implementer_seq", async () => {
    const store = new InMemoryImplementerEventReadStore();
    seed(store, IMPLEMENTER_A, 5);
    const response = await handleGetEvents(
      {
        requestId: REQUEST_ID,
        implementerId: IMPLEMENTER_A,
        rawTarget: "/v1/events?limit=2",
        nowMs: () => 0,
      },
      store,
    );
    expect(response.status).toBe(200);
    if (response.status !== 200) return;
    const body = JSON.parse(response.body) as {
      events: unknown[];
      checkpoints: unknown[];
      implementer_watermark_seq: string;
      next_after_implementer_seq: string;
    };
    expect(body.events).toHaveLength(2);
    expect(body.checkpoints).toEqual([]);
    expect(body.implementer_watermark_seq).toBe("5");
    expect(body.next_after_implementer_seq).toBe("2");
  });

  it("delivers durable checkpoints on GET /v1/events (UP-07)", async () => {
    const store = new InMemoryImplementerEventReadStore();
    store.seedCheckpoint(IMPLEMENTER_A, {
      checkpointEpoch: 1n,
      implementerSeqHead: 2n,
      proofRepresentation: '{"purpose":"zp-implementer-checkpoint-v1","checkpoint_epoch":"1"}',
    });
    const response = await handleGetEvents(
      {
        requestId: REQUEST_ID,
        implementerId: IMPLEMENTER_A,
        rawTarget: "/v1/events",
        nowMs: () => 0,
      },
      store,
    );
    expect(response.status).toBe(200);
    if (response.status !== 200) return;
    expect(response.body).toContain('"checkpoints":[{"purpose":"zp-implementer-checkpoint-v1"');
    const body = JSON.parse(response.body) as { checkpoints: unknown[] };
    expect(body.checkpoints).toHaveLength(1);
  });

  it("idempotent resume: repeating after_implementer_seq returns the same page", async () => {
    const store = new InMemoryImplementerEventReadStore();
    seed(store, IMPLEMENTER_A, 5);
    const req = {
      requestId: REQUEST_ID,
      implementerId: IMPLEMENTER_A,
      rawTarget: "/v1/events?after_implementer_seq=2&limit=2",
      nowMs: () => 0,
    };
    const a = await handleGetEvents(req, store);
    const b = await handleGetEvents(req, store);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    if (a.status === 200 && b.status === 200) {
      expect(a.body).toBe(b.body);
    }
  });

  it("tenant scopes: implementer B never sees implementer A events", async () => {
    const store = new InMemoryImplementerEventReadStore();
    seed(store, IMPLEMENTER_A, 3);
    seed(store, IMPLEMENTER_B, 1);
    const response = await handleGetEvents(
      {
        requestId: REQUEST_ID,
        implementerId: IMPLEMENTER_B,
        rawTarget: "/v1/events",
        nowMs: () => 0,
      },
      store,
    );
    expect(response.status).toBe(200);
    if (response.status !== 200) return;
    const body = JSON.parse(response.body) as {
      events: unknown[];
      implementer_watermark_seq: string;
    };
    expect(body.events).toHaveLength(1);
    expect(body.implementer_watermark_seq).toBe("1");
    expect(response.body).not.toContain('"implementer_seq":"3"');
  });

  it("long-poll waits until an event appears or budget expires", async () => {
    const store = new InMemoryImplementerEventReadStore();
    let now = 0;
    const sleeps: number[] = [];
    const response = await handleGetEvents(
      {
        requestId: REQUEST_ID,
        implementerId: IMPLEMENTER_A,
        rawTarget: "/v1/events?wait_seconds=1",
        nowMs: () => now,
        sleepMs: async (ms) => {
          sleeps.push(ms);
          now += ms;
          if (sleeps.length === 2) {
            store.seedEvent(IMPLEMENTER_A, event(1n, '{"key_id":"late"}'));
          }
        },
      },
      store,
    );
    expect(response.status).toBe(200);
    if (response.status !== 200) return;
    expect(response.body).toContain("late");
    expect(sleeps.length).toBeGreaterThan(0);
  });

  it("long-poll returns empty page when budget expires with no events", async () => {
    const store = new InMemoryImplementerEventReadStore();
    let now = 0;
    const response = await handleGetEvents(
      {
        requestId: REQUEST_ID,
        implementerId: IMPLEMENTER_A,
        rawTarget: "/v1/events?wait_seconds=1",
        nowMs: () => now,
        sleepMs: async (ms) => {
          now += ms;
        },
      },
      store,
    );
    expect(response.status).toBe(200);
    if (response.status !== 200) return;
    expect(response.body).toBe(
      '{"events":[],"checkpoints":[],"implementer_watermark_seq":"0","next_after_implementer_seq":"0"}',
    );
  });

  it("rejects proofs that contain forbidden data-leak markers", async () => {
    const store = new InMemoryImplementerEventReadStore();
    store.seedEvent(IMPLEMENTER_A, event(1n, '{"private_key":"leak","key_id":"k1"}'));
    const response = await handleGetEvents(
      {
        requestId: REQUEST_ID,
        implementerId: IMPLEMENTER_A,
        rawTarget: "/v1/events",
        nowMs: () => 0,
      },
      store,
    );
    expect(response.status).toBe(503);
  });

  it("returns 400 invalid_scalar for malformed after_implementer_seq", async () => {
    const store = new InMemoryImplementerEventReadStore();
    const response = await handleGetEvents(
      {
        requestId: REQUEST_ID,
        implementerId: IMPLEMENTER_A,
        rawTarget: "/v1/events?after_implementer_seq=-1",
        nowMs: () => 0,
      },
      store,
    );
    expect(response.status).toBe(400);
    expect(response.body).toContain("invalid_scalar");
  });
});

describe("createEventsListRouteHandler", () => {
  it("registers under events_list and serves implementer-scoped body", async () => {
    expect(EVENTS_LIST_ROUTE_ID).toBe(REPORTING_ROUTE_IDS.eventsList);
    const store = new InMemoryImplementerEventReadStore();
    seed(store, IMPLEMENTER_A, 1);
    const handler = createEventsListRouteHandler({
      store,
      nowMs: () => 0,
      newRequestId: () => REQUEST_ID,
    });
    const request = {
      ok: true as const,
      binding: {
        reportingKeyId: "key-1",
        nodeId: "node-1",
        implementerId: IMPLEMENTER_A,
        publicKeyEncoded: "pub",
      },
      route: {
        routeId: REPORTING_ROUTE_IDS.eventsList,
        requestClass: "READ" as const,
        retentionClass: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE" as const,
      },
      nonceEvidence: {
        id: randomUUID(),
        nodeId: "node-1",
        implementerId: IMPLEMENTER_A,
        nonce: randomUUID(),
        purpose: "REPORT_REQUEST",
        routeId: REPORTING_ROUTE_IDS.eventsList,
        requestClass: "READ",
        reportingKeyId: "key-1",
        lifecycleEpoch: 0n,
        nonceBurnSequence: 1n,
        requestPreimageText: "pre",
        requestPreimageSha256: "00".repeat(32),
        requestSignature: `${"A".repeat(86)}==`,
        method: "GET",
        rawTarget: "/v1/events?limit=10",
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
        rawTarget: "/v1/events?limit=10",
        bodySha256: "00".repeat(32),
      },
      bodyBytes: new Uint8Array(),
      lastEventId: null,
    } as VerifiedReportRequest;

    const result = await handler(request);
    expect(result.persistChild).toBeNull();
    expect(result.response.status).toBe(200);
    const text = new TextDecoder().decode(result.response.bodyBytes);
    expect(text).toContain("implementer_watermark_seq");
    expect(text).toContain("key_id");
  });
});

describe("source guards", () => {
  it("api/events.ts never invents product projection fields", () => {
    const source = readFileSync(
      fileURLToPath(new URL("../src/api/events.ts", import.meta.url)),
      "utf8",
    );
    expect(source).not.toContain("payment_status");
    expect(source).not.toContain("checkout_id");
    expect(source).toContain("after_implementer_seq");
    expect(source).toContain("implementer_watermark_seq");
  });
});
