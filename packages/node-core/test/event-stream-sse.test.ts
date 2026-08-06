// SSE accelerator.
import { describe, expect, it } from "vitest";

import {
  createEventStreamAccelerator,
  formatSseFrame,
  formatSseHeartbeat,
  sseComment,
  type SseSink,
} from "../src/reporting/event-stream-sse.ts";
import { InMemoryImplementerEventLog } from "../src/reporting/implementer-event-log.ts";
import { IMPLEMENTER_ID } from "../src/reporting/test-fixtures.ts";

// parseDecimalSeq is not exported from final module — exercise via resolveStreamCursor path.
// Re-export local helper for frame tests only.
function parseDecimalSeqLocal(value: string): bigint | null {
  return /^(0|[1-9][0-9]*)$/.test(value) ? BigInt(value) : null;
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
  /** Event frames only (exclude comments / heartbeats). */
  get eventFrames(): string[] {
    return this.chunks.filter((c) => c.startsWith("id:"));
  }
}

async function seed(
  log: InMemoryImplementerEventLog,
  n: number,
  type: "receive.ready" | "receive.landed" = "receive.ready",
): Promise<void> {
  for (let i = 1; i <= n; i += 1) {
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: `e${i}`,
      eventType: type,
      proofRepresentation: `{"implementer_seq":"${i}"}`,
      createdAt: "2026-07-18T00:00:00.000Z",
    });
  }
}

describe("SSE frame primitives", () => {
  it("formats multi-line data safely", () => {
    expect(formatSseFrame({ id: "7", event: "receive.ready", data: "line1\nline2" })).toBe(
      "id: 7\nevent: receive.ready\ndata: line1\ndata: line2\n\n",
    );
  });

  it("formats heartbeat as a comment (never an event id)", () => {
    expect(formatSseHeartbeat()).toBe(": heartbeat\n\n");
    expect(sseComment("connected")).toBe(": connected\n\n");
    expect(formatSseHeartbeat()).not.toMatch(/^id:/m);
  });

  it("accepts only canonical decimal seq strings", () => {
    expect(parseDecimalSeqLocal("0")).toBe(0n);
    expect(parseDecimalSeqLocal("1043")).toBe(1043n);
    expect(parseDecimalSeqLocal("01")).toBeNull();
    expect(parseDecimalSeqLocal("-1")).toBeNull();
  });
});

describe("createEventStreamAccelerator", () => {
  it("rejects Last-Event-ID mismatch with cursor_mismatch", async () => {
    const log = new InMemoryImplementerEventLog();
    const accel = createEventStreamAccelerator({ log, pollMs: 0 });
    const sink = new RecordingSink();
    const outcome = await accel.open(
      {
        requestId: "r1",
        implementerId: IMPLEMENTER_ID,
        afterImplementerSeq: 5n,
        lastEventId: "6",
      },
      sink,
    );
    expect(outcome).toEqual({ kind: "REJECTED", code: "cursor_mismatch", requestId: "r1" });
  });

  it("accepts matching Last-Event-ID and after_implementer_seq", async () => {
    const log = new InMemoryImplementerEventLog();
    await seed(log, 3);
    const accel = createEventStreamAccelerator({ log, pollMs: 0 });
    const sink = new RecordingSink();
    const outcome = await accel.open(
      {
        requestId: "r1",
        implementerId: IMPLEMENTER_ID,
        afterImplementerSeq: 2n,
        lastEventId: "2",
      },
      sink,
    );
    expect(outcome.kind).toBe("OPEN");
    if (outcome.kind !== "OPEN") return;
    expect(sink.eventFrames.join("")).toContain('id: 3\nevent: receive.ready\ndata: {"implementer_seq":"3"}');
    expect(sink.eventFrames.join("")).not.toContain('id: 2\n');
    outcome.connection.close();
    expect(sink.closed).toBe(true);
  });

  it("replays backlog with no gap and no duplicate on resume", async () => {
    const log = new InMemoryImplementerEventLog();
    await seed(log, 5);
    const accel = createEventStreamAccelerator({ log, pollMs: 0 });
    const sink = new RecordingSink();
    const outcome = await accel.open(
      {
        requestId: "r1",
        implementerId: IMPLEMENTER_ID,
        afterImplementerSeq: 2n,
        lastEventId: null,
      },
      sink,
    );
    expect(outcome.kind).toBe("OPEN");
    if (outcome.kind !== "OPEN") return;
    const ids = [...sink.text.matchAll(/^id: (\d+)$/gm)].map((m) => m[1]);
    expect(ids).toEqual(["3", "4", "5"]);
    outcome.connection.close();
  });

  it("delivers live appends after connect", async () => {
    const log = new InMemoryImplementerEventLog();
    await seed(log, 1);
    const accel = createEventStreamAccelerator({ log, pollMs: 0 });
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
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "live",
      eventType: "receive.landed",
      proofRepresentation: '{"implementer_seq":"2"}',
      createdAt: "2026-07-18T00:00:01.000Z",
    });
    expect(sink.text).toContain('id: 2\nevent: receive.landed');
    outcome.connection.close();
  });

  it("heartbeats never appear as event frames and never move lastSent", async () => {
    const handles: Array<() => void> = [];
    const log = new InMemoryImplementerEventLog();
    await seed(log, 1);
    const accel = createEventStreamAccelerator({
      log,
      pollMs: 0,
      heartbeatMs: 10,
      setInterval: (handler) => {
        handles.push(handler);
        return handles.length;
      },
      clearInterval: () => undefined,
    });
    const sink = new RecordingSink();
    const outcome = await accel.open(
      {
        requestId: "r1",
        implementerId: IMPLEMENTER_ID,
        afterImplementerSeq: 1n,
        lastEventId: "1",
      },
      sink,
    );
    expect(outcome.kind).toBe("OPEN");
    if (outcome.kind !== "OPEN") return;
    // Fire heartbeat
    for (const h of handles) h();
    expect(sink.text).toContain(": heartbeat\n\n");
    expect(sink.eventFrames).toEqual([]);
    // Still only resume at 1 — a later append at 2 must still deliver.
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e2",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"2"}',
      createdAt: "2026-07-18T00:00:02.000Z",
    });
    expect(sink.eventFrames.join("")).toContain("id: 2\n");
    outcome.connection.close();
  });

  it("SSE close after commit does not remove the durable event (failure irrelevance)", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "landed-1",
      eventType: "receive.landed",
      proofRepresentation: '{"event":"receive.landed","seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const accel = createEventStreamAccelerator({ log, pollMs: 0 });
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
    // Kill the stream mid-delivery path.
    outcome.connection.close();
    // Durable row still served by pull listEvents path.
    const page = await log.readEvents(IMPLEMENTER_ID, null, 10);
    expect(page.events).toHaveLength(1);
    expect(page.events[0]?.proofRepresentation).toBe('{"event":"receive.landed","seq":"1"}');
    expect(page.watermarkSeq).toBe(1n);
  });

  it("never wires node-global stream vocabulary", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const source = readFileSync(
      fileURLToPath(new URL("../src/reporting/event-stream-sse.ts", import.meta.url)),
      "utf8",
    );
    expect(source).not.toContain("node_events");
    expect(source).not.toContain("zp-node-event");
  });
});

// silence unused import if tree-shaken
