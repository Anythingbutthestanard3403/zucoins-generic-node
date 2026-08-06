// Tests for the read-only events read-service backing GET /v1/events and
// GET /v1/events/stream. Covers pagination, the exact
// envelope, SSE framing, the Last-Event-ID cursor guard, tenant scoping, byte-exact
// proof preservation, async error propagation, and a source guard that the node-global
// stream is never wired here.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  EVENTS_LIMIT_DEFAULT,
  EVENTS_LIMIT_MAX,
  EVENTS_LIMIT_MIN,
  InMemoryImplementerEventReadStore,
  clampEventsLimit,
  frameImplementerEventStream,
  listEvents,
  renderEventsListBody,
  resolveStreamCursor,
  type ImplementerEventReadStore,
  type ServedImplementerEvent,
} from "../src/reporting/events-read-service.ts";

const event = (seq: bigint, eventType: string, proof: string): ServedImplementerEvent => ({
  implementerSeq: seq,
  eventType,
  proofRepresentation: proof,
});

const seededStore = (implementerId: string, count: number): InMemoryImplementerEventReadStore => {
  const store = new InMemoryImplementerEventReadStore();
  for (let i = count; i >= 1; i -= 1) {
    store.seedEvent(implementerId, event(BigInt(i), "receive.landed", `{"key_id":"k${i}"}`));
  }
  return store;
};

describe("events read-service — limit bounds ", () => {
  it("clamps to [1, 500] with a default of 100", () => {
    expect(clampEventsLimit(undefined)).toBe(EVENTS_LIMIT_DEFAULT);
    expect(clampEventsLimit(0)).toBe(EVENTS_LIMIT_MIN);
    expect(clampEventsLimit(999)).toBe(EVENTS_LIMIT_MAX);
    expect(clampEventsLimit(5)).toBe(5);
  });
});

describe("events read-service — list + pagination ", () => {
  it("returns a bounded page and the next cursor is the last event's seq", async () => {
    const store = seededStore("impl-a", 5);
    const first = await listEvents(store, { implementerId: "impl-a", afterImplementerSeq: null, limit: 2 });
    expect(first.events.map((e) => e.implementerSeq)).toEqual([1n, 2n]);
    expect(first.watermarkSeq).toBe(5n);
    expect(first.nextAfterSeq).toBe(2n);

    const next = await listEvents(store, { implementerId: "impl-a", afterImplementerSeq: 2n, limit: 2 });
    expect(next.events.map((e) => e.implementerSeq)).toEqual([3n, 4n]);
    expect(next.nextAfterSeq).toBe(4n);
  });

  it("resumes at the watermark when the caller is caught up", async () => {
    const store = seededStore("impl-a", 5);
    const caughtUp = await listEvents(store, { implementerId: "impl-a", afterImplementerSeq: 5n });
    expect(caughtUp.events).toEqual([]);
    expect(caughtUp.watermarkSeq).toBe(5n);
    expect(caughtUp.nextAfterSeq).toBe(5n);
  });

  it("scopes strictly to the calling implementer", async () => {
    const store = seededStore("impl-a", 2);
    store.seedEvent("impl-b", event(1n, "receive.landed", '{"key_id":"other"}'));
    const result = await listEvents(store, { implementerId: "impl-a", afterImplementerSeq: null });
    expect(result.events.every((e) => e.proofRepresentation.includes("k"))).toBe(true);
    expect(result.events.some((e) => e.proofRepresentation.includes("other"))).toBe(false);
  });

  it("propagates a store read failure", async () => {
    const failing: ImplementerEventReadStore = {
      readEvents: () => Promise.reject(new Error("read failed")),
    };
    await expect(
      listEvents(failing, { implementerId: "impl-a", afterImplementerSeq: null }),
    ).rejects.toThrow("read failed");
  });
});

describe("events read-service — envelope render (byte-exact proofs)", () => {
  it("inserts proof representations verbatim and emits decimal cursors", () => {
    const body = renderEventsListBody({
      events: [event(7n, "receive.landed", '{"key_id":"k7","data":"a,b"}')],
      checkpoints: [],
      watermarkSeq: 7n,
      nextAfterSeq: 7n,
    });
    expect(body).toBe(
      '{"events":[{"key_id":"k7","data":"a,b"}],' +
        '"checkpoints":[],' +
        '"implementer_watermark_seq":"7","next_after_implementer_seq":"7"}',
    );
    const parsed = JSON.parse(body) as { events: Array<{ key_id: string }> };
    expect(parsed.events[0]?.key_id).toBe("k7");
  });

  it("renders an empty page with checkpoints channel present", () => {
    const body = renderEventsListBody({
      events: [],
      checkpoints: [],
      watermarkSeq: 1043n,
      nextAfterSeq: 1043n,
    });
    expect(body).toBe(
      '{"events":[],"checkpoints":[],"implementer_watermark_seq":"1043","next_after_implementer_seq":"1043"}',
    );
  });

  it("inserts checkpoint proofs verbatim on the delivery channel", () => {
    const body = renderEventsListBody({
      events: [],
      checkpoints: [
        {
          checkpointEpoch: 1n,
          implementerSeqHead: 2n,
          proofRepresentation: '{"purpose":"zp-implementer-checkpoint-v1","epoch":"1"}',
        },
      ],
      watermarkSeq: 2n,
      nextAfterSeq: 2n,
    });
    expect(body).toBe(
      '{"events":[],' +
        '"checkpoints":[{"purpose":"zp-implementer-checkpoint-v1","epoch":"1"}],' +
        '"implementer_watermark_seq":"2","next_after_implementer_seq":"2"}',
    );
  });
});

describe("events read-service — SSE ", () => {
  it("frames id/event/data with a terminating blank line", () => {
    const frames = frameImplementerEventStream([
      event(7n, "receive.landed", '{"key_id":"k7"}'),
      event(8n, "external_send.landed", '{"key_id":"k8"}'),
    ]);
    expect(frames).toBe(
      'id: 7\nevent: receive.landed\ndata: {"key_id":"k7"}\n\n' +
        'id: 8\nevent: external_send.landed\ndata: {"key_id":"k8"}\n\n',
    );
  });

  it("enforces the Last-Event-ID cursor equality (else cursor_mismatch)", () => {
    expect(resolveStreamCursor(null, null)).toEqual({ ok: true, afterImplementerSeq: null });
    expect(resolveStreamCursor(5n, null)).toEqual({ ok: true, afterImplementerSeq: 5n });
    expect(resolveStreamCursor(5n, "5")).toEqual({ ok: true, afterImplementerSeq: 5n });
    expect(resolveStreamCursor(5n, "6")).toEqual({ ok: false, code: "cursor_mismatch" });
    expect(resolveStreamCursor(null, "5")).toEqual({ ok: false, code: "cursor_mismatch" });
  });
});

describe("events read-service — stream scope guard", () => {
  it("never wires the operator/auditor-only node-global stream", () => {
    const source = readFileSync(
      fileURLToPath(new URL("../src/reporting/events-read-service.ts", import.meta.url)),
      "utf8",
    );
    expect(source).not.toContain("node_events");
    expect(source).not.toContain("zp-node-event");
    expect(source.toLowerCase()).toContain("read-only");
  });
});
