import { describe, expect, it } from "vitest";

import { subscribeToOperation } from "./subscribe.js";
import type { FetchLike } from "./client-types.js";

const OP_ID = "55555555-5555-4555-8555-555555555540";

function sseStream(chunks: readonly string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

function fetchReturning(body: ReadableStream<Uint8Array>, status = 200): FetchLike {
  return async () => new Response(body, { status, headers: { "content-type": "text/event-stream" } });
}

async function collect<T>(gen: AsyncGenerator<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const item of gen) out.push(item);
  return out;
}

describe("subscribeToOperation", () => {
  it("yields one lifecycle projection per SSE frame, ignoring comment/heartbeat frames", async () => {
    const frame1 = {
      operation_id: OP_ID,
      operation_type: "RECEIVE_EXTERNAL",
      state: "READY",
      row_version: 2,
      attention_required: false,
      updated_at: "2026-07-18T12:00:00.000Z",
    };
    const frame2 = { ...frame1, state: "RECEIVE_LANDED", row_version: 4 };
    const body = sseStream([
      ": connected\n\n",
      `data: ${JSON.stringify(frame1)}\n\n`,
      `data: ${JSON.stringify(frame2)}\n\n`,
    ]);

    const projections = await collect(
      subscribeToOperation({
        config: { baseUrl: "https://node.example.com", fetchImpl: fetchReturning(body) },
        operationId: OP_ID,
        subscriptionHandle: "sh_secret",
      }),
    );

    expect(projections).toEqual([frame1, frame2]);
  });

  it("reassembles a multi-line data: frame by joining with newlines", async () => {
    const frame = {
      operation_id: OP_ID,
      operation_type: "RECEIVE_EXTERNAL",
      state: "READY",
      row_version: 2,
      attention_required: false,
      updated_at: "2026-07-18T12:00:00.000Z",
    };
    // Split the serialized JSON across two `data:` lines, as a real multi-line SSE proof would —
    // the reader must join them with "\n" (per SSE framing) to reproduce valid JSON.
    const serialized = JSON.stringify(frame);
    const splitAt = serialized.indexOf(",");
    const body = sseStream([
      `data: ${serialized.slice(0, splitAt + 1)}\n`,
      `data: ${serialized.slice(splitAt + 1)}\n\n`,
    ]);

    const projections = await collect(
      subscribeToOperation({
        config: { baseUrl: "https://node.example.com", fetchImpl: fetchReturning(body) },
        operationId: OP_ID,
        subscriptionHandle: "sh_secret",
      }),
    );
    expect(projections).toEqual([frame]);
  });

  it("throws on a frame that does not match the frozen lifecycle projection shape", async () => {
    const body = sseStream([`data: ${JSON.stringify({ not: "a projection" })}\n\n`]);
    await expect(
      collect(
        subscribeToOperation({
          config: { baseUrl: "https://node.example.com", fetchImpl: fetchReturning(body) },
          operationId: OP_ID,
          subscriptionHandle: "sh_secret",
        }),
      ),
    ).rejects.toThrow(/frozen lifecycle projection/);
  });

  it("sends the subscription handle as a bearer token", async () => {
    let capturedAuth: string | null = null;
    const fetchImpl: FetchLike = async (_url, init) => {
      capturedAuth = (init?.headers as Record<string, string>).authorization;
      return new Response(sseStream([]), { status: 200 });
    };
    await collect(
      subscribeToOperation({
        config: { baseUrl: "https://node.example.com", fetchImpl },
        operationId: OP_ID,
        subscriptionHandle: "sh_secret",
      }),
    );
    expect(capturedAuth).toBe("Bearer sh_secret");
  });
});
