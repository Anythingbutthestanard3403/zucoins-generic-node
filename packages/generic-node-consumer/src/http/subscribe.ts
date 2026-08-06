/**
 * Browser-facing operation subscribe stream. Subscription-handle
 * authenticated, lifecycle-projection only — never raw evidence, never proof. This is the "low
 * authority" wake channel; the signed-reporting events route (events.ts) is the only channel the
 * verification pipeline may treat as authenticated (see ingestSubscribeProjection vs
 * ingestEventWake in pipeline.ts).
 */

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";
import type { SubscribeLifecycleProjection } from "../types.js";

/** Minimal SSE frame reader: splits on blank-line frame boundaries, joins multi-line `data:`. */
async function* readSseFrames(
  body: ReadableStream<Uint8Array>,
  signal?: AbortSignal,
): AsyncGenerator<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      if (signal?.aborted) return;
      const { done, value } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      let boundary: number;
      while ((boundary = buffer.indexOf("\n\n")) !== -1) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const dataLines = frame
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).replace(/^ /, ""));
        if (dataLines.length === 0) continue; // comment-only / heartbeat frame
        yield dataLines.join("\n");
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function isSubscribeLifecycleProjection(value: unknown): value is SubscribeLifecycleProjection {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.operation_id === "string" &&
    typeof v.operation_type === "string" &&
    typeof v.state === "string" &&
    typeof v.row_version === "number" &&
    typeof v.attention_required === "boolean" &&
    typeof v.updated_at === "string"
  );
}

export interface SubscribeToOperationInput {
  readonly config: NodeClientConfig;
  readonly operationId: string;
  /** `Bearer sh_…` subscription handle, scoped to this one operation. */
  readonly subscriptionHandle: string;
  readonly signal?: AbortSignal;
}

/**
 * Open the subscribe stream and yield each lifecycle projection frame as it arrives. The
 * generator ends when the node closes the stream, the caller aborts `signal`, or a malformed
 * frame is received (thrown, rather than yielding a guessed shape).
 */
export async function* subscribeToOperation(
  input: SubscribeToOperationInput,
): AsyncGenerator<SubscribeLifecycleProjection> {
  const rawTarget = `/v1/operations/${input.operationId}/subscribe`;
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "GET",
    headers: {
      authorization: `Bearer ${input.subscriptionHandle}`,
      accept: "text/event-stream",
    },
    signal: input.signal,
  });
  await assertOk(response);
  if (response.body === null) {
    throw new Error("subscribe response had no body");
  }
  for await (const data of readSseFrames(response.body, input.signal)) {
    const parsed: unknown = JSON.parse(data);
    if (!isSubscribeLifecycleProjection(parsed)) {
      throw new Error("subscribe frame did not match the frozen lifecycle projection shape");
    }
    yield parsed;
  }
}
